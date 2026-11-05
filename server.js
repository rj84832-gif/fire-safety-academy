// Fire Safety Academy – chhota server (sirf Node.js built-in modules, koi npm install nahi)
// Chalane ke liye:  node server.js   (default http://localhost:3000)
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'data.json');
// फ्लैट मोड में सिर्फ ये फाइलें सार्वजनिक हैं (server.js आदि कभी नहीं)
const FLAT_OK = /^\/(index\.html|sw\.js|manifest\.webmanifest|icon[\w-]*\.(png|svg))$/;
const SESSION_DAYS = 90;
// हर अध्याय को पढ़ने का समय (सेकंड) – अध्याय के शब्दों की गिनती (~65 शब्द/मिनट) से तय किया गया
const REQ = [120, 120, 150, 120, 120, 90, 120];
const PASS_CORRECT = 40;     // 50 me se 40 = 80%
const TOTAL_Q = 50;
// असली बीते समय की जाँच: अध्ययन के सेकंड, सर्वर पर बीते वास्तविक समय से ज्यादा नहीं जुड़ सकते (टेस्ट के लिए STRICT_TIME=0)
const STRICT_TIME = process.env.STRICT_TIME !== '0';

fs.mkdirSync(DATA_DIR, { recursive: true });

/* ---------------- storage ---------------- */
let db = { users: {}, sessions: {}, certs: {} };
try { db = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); } catch (e) { /* pehli baar */ }
db.users = db.users || {}; db.sessions = db.sessions || {}; db.certs = db.certs || {};

let flushTimer = null;
function flushNow() {
  clearTimeout(flushTimer); flushTimer = null;
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, DATA_FILE);
}
function flushSoon() { if (!flushTimer) flushTimer = setTimeout(flushNow, 500); }
process.on('SIGTERM', () => { try { flushNow(); } catch (e) {} process.exit(0); });
process.on('SIGINT', () => { try { flushNow(); } catch (e) {} process.exit(0); });

/* ---------------- helpers ---------------- */
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
function hashPin(pin, salt) { return crypto.scryptSync(pin, salt, 32).toString('hex'); }
function safeEq(a, b) {
  const x = Buffer.from(a, 'hex'), y = Buffer.from(b, 'hex');
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
function clientIp(req) {
  const xf = req.headers['x-forwarded-for'];
  return (xf ? String(xf).split(',')[0].trim() : req.socket.remoteAddress) || 'unknown';
}
function cleanText(s, max) {
  return String(s == null ? '' : s).replace(/[\u0000-\u001f<>]/g, '').trim().slice(0, max);
}

/* rate limits (memory me) */
const loginFails = new Map();   // phone -> {n, until}
const regByIp = new Map();      // ip -> [timestamps]
function locked(phone) {
  const f = loginFails.get(phone);
  return f && f.until > Date.now() ? Math.ceil((f.until - Date.now()) / 60000) : 0;
}
function failLogin(phone) {
  const f = loginFails.get(phone) || { n: 0, until: 0 };
  f.n += 1; if (f.n >= 5) { f.until = Date.now() + 15 * 60000; f.n = 0; }
  loginFails.set(phone, f);
}
function regAllowed(ip) {
  const now = Date.now(), hour = 3600000;
  const arr = (regByIp.get(ip) || []).filter(t => now - t < hour);
  if (arr.length >= 20) { regByIp.set(ip, arr); return false; }
  arr.push(now); regByIp.set(ip, arr); return true;
}
setInterval(() => { // purane sessions saaf
  const now = Date.now(); let ch = false;
  for (const k in db.sessions) if (now - db.sessions[k].created > SESSION_DAYS * 86400000) { delete db.sessions[k]; ch = true; }
  if (ch) flushSoon();
}, 3600000).unref();

/* progress ko server par validate karte hain, taaki bekaar data na bane */
function sanitizeState(incoming, old, budget) {
  let left = budget === undefined ? Infinity : budget;
  old = old || { days: [], seconds: {}, test: null, cert: null };
  const out = { days: [], seconds: {}, test: null, cert: old.cert || null };
  const inSec = (incoming && incoming.seconds) || {};
  const oldDays = old.days || [];
  for (let i = 0; i < 7; i++) {
    const v = Number(inSec[i]);
    if (oldDays.includes(i)) { out.seconds[i] = REQ[i]; continue; }          // पूरा हो चुका अध्याय
    const prev = Number(old.seconds && old.seconds[i]) || 0;
    let val = Number.isFinite(v) ? Math.min(REQ[i], Math.max(0, Math.floor(v))) : 0;
    if (val > prev) { const take = Math.floor(Math.min(val - prev, left)); left -= take; val = prev + take; }
    out.seconds[i] = val;
  }
  const inDays = Array.isArray(incoming && incoming.days) ? incoming.days : [];
  for (let i = 0; i < 7; i++) {
    if (oldDays.includes(i)) { out.days.push(i); continue; }
    // अध्याय तभी पूरा जब पिछला पूरा हो और उसका पढ़ने का समय पूरा हुआ हो
    if (inDays.includes(i) && out.seconds[i] >= REQ[i] && (i === 0 || out.days.includes(i - 1))) out.days.push(i);
  }
  const t = incoming && incoming.test;
  if (old.cert) {                       // सर्टिफिकेट बनने के बाद टेस्ट रिजल्ट बदला नहीं जा सकता
    out.test = old.test;
  } else if (out.days.length === 7 && t && Number.isInteger(t.correct) && t.correct >= 0 && t.correct <= TOTAL_Q) {
    out.test = {
      correct: t.correct,
      score: Math.round(t.correct / TOTAL_Q * 100),
      pass: t.correct >= PASS_CORRECT,
      date: cleanText(t.date, 30)
    };
  } else if (out.days.length === 7 && old.test) {
    out.test = old.test;
  }
  return out;
}

const ID_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function newCertId() {
  for (;;) {
    const b = crypto.randomBytes(8);
    let id = ''; for (let i = 0; i < 8; i++) id += ID_CHARS[b[i] % ID_CHARS.length];
    id = 'FSA-' + id.slice(0, 4) + '-' + id.slice(4);
    if (!db.certs[id]) return id;
  }
}
const verifyHits = new Map(); // ip -> [timestamps]
function verifyAllowed(ip) {
  const now = Date.now(); const arr = (verifyHits.get(ip) || []).filter(t => now - t < 60000);
  if (arr.length >= 30) { verifyHits.set(ip, arr); return false; }
  arr.push(now); verifyHits.set(ip, arr); return true;
}

/* ---------------- http ---------------- */
function send(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => { size += c.length; if (size > 20000) { reject(new Error('too big')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); } catch (e) { reject(new Error('bad json')); } });
    req.on('error', reject);
  });
}
function authUser(req) {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return null;
  const s = db.sessions[sha(h.slice(7))];
  if (!s || Date.now() - s.created > SESSION_DAYS * 86400000) return null;
  const u = db.users[s.phone];
  return u ? { phone: s.phone, user: u, key: sha(h.slice(7)) } : null;
}
function newSession(phone) {
  const token = crypto.randomBytes(32).toString('hex');
  db.sessions[sha(token)] = { phone, created: Date.now() };
  return token;
}
const publicUser = u => ({ profile: u.profile, state: u.state });

async function api(req, res, url) {
  const route = req.method + ' ' + url;
  try {
    if (route === 'POST /api/translate') {
      const b = await readBody(req);
      const apiKey = process.env.GOOGLE_TRANSLATE_API_KEY || '';
      if (!apiKey) return send(res, 503, { error: 'भाषा अनुवाद सेवा अभी सेट नहीं है। Admin को GOOGLE_TRANSLATE_API_KEY जोड़ना होगा।' });
      const target = String(b.target || '').trim();
      const texts = Array.isArray(b.texts) ? b.texts : [];
      if (!/^[a-zA-Z]{2,3}(?:-[a-zA-Z0-9]{2,8})?$/.test(target) || !texts.length || texts.length > 100 ||
          texts.some(x => typeof x !== 'string' || x.length > 5000) ||
          texts.reduce((n, x) => n + x.length, 0) > 30000) {
        return send(res, 400, { error: 'अनुवाद अनुरोध की सीमा या भाषा कोड सही नहीं है।' });
      }
      const response = await fetch('https://translation.googleapis.com/language/translate/v2?key=' + encodeURIComponent(apiKey), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ q: texts, target, format: 'text', source: 'hi' })
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || !data.data || !Array.isArray(data.data.translations)) {
        return send(res, 502, { error: 'अनुवाद सेवा से जवाब नहीं मिला। API सेटिंग और बिलिंग जाँचें।' });
      }
      return send(res, 200, { translations: data.data.translations.map(x => x.translatedText) });
    }
    if (route === 'POST /api/register') {
      const b = await readBody(req);
      const name = cleanText(b.name, 60), place = cleanText(b.place, 60);
      const phone = String(b.phone || ''), pin = String(b.pin || '');
      if (!name) return send(res, 400, { error: 'कृपया अपना नाम लिखें।' });
      if (!/^[0-9]{10}$/.test(phone)) return send(res, 400, { error: 'कृपया 10 अंकों का सही मोबाइल नंबर लिखें।' });
      if (!/^[0-9]{4}$/.test(pin)) return send(res, 400, { error: 'PIN ठीक 4 अंकों का होना चाहिए।' });
      if (!regAllowed(clientIp(req))) return send(res, 429, { error: 'बहुत ज्यादा रजिस्ट्रेशन। कुछ देर बाद कोशिश करें।' });
      if (db.users[phone]) return send(res, 409, { error: 'यह मोबाइल पहले से रजिस्टर है। कृपया लॉगिन करें।' });
      const salt = crypto.randomBytes(16).toString('hex');
      db.users[phone] = {
        profile: { name, phone, place, date: new Date().toLocaleDateString('hi-IN', { timeZone: 'Asia/Kolkata' }) },
        salt, hash: hashPin(pin, salt),
        state: { days: [], seconds: {}, test: null, cert: null }
      };
      db.users[phone].createdAt = Date.now();
      const token = newSession(phone); flushNow();
      return send(res, 200, { token, ...publicUser(db.users[phone]) });
    }
    if (route === 'POST /api/login') {
      const b = await readBody(req);
      const phone = String(b.phone || ''), pin = String(b.pin || '');
      if (!/^[0-9]{10}$/.test(phone) || !/^[0-9]{4}$/.test(pin)) return send(res, 400, { error: 'मोबाइल नंबर (10 अंक) और PIN (4 अंक) सही भरें।' });
      const mins = locked(phone);
      if (mins) return send(res, 429, { error: `बहुत ज्यादा गलत कोशिशें। ${mins} मिनट बाद फिर कोशिश करें।` });
      const u = db.users[phone];
      if (!u) return send(res, 404, { error: 'यह नंबर रजिस्टर नहीं है। पहले नया रजिस्ट्रेशन करें।' });
      if (!safeEq(u.hash, hashPin(pin, u.salt))) { failLogin(phone); return send(res, 401, { error: 'PIN गलत है। फिर कोशिश करें।' }); }
      loginFails.delete(phone);
      const token = newSession(phone); flushSoon();
      return send(res, 200, { token, ...publicUser(u) });
    }
    if (route === 'GET /api/me') {
      const a = authUser(req); if (!a) return send(res, 401, { error: 'कृपया फिर से लॉगिन करें।' });
      return send(res, 200, publicUser(a.user));
    }
    if (route === 'PUT /api/state') {
      const a = authUser(req); if (!a) return send(res, 401, { error: 'कृपया फिर से लॉगिन करें।' });
      const b = await readBody(req);
      if (!a.user.createdAt) a.user.createdAt = Date.now();
      // कुल पढ़ाई का समय खाते की उम्र (+ 20 सेकंड की छूट, एक बार) से ज्यादा नहीं हो सकता
      const oldSt = a.user.state, credited = REQ.reduce((sum, r, i) => sum + ((oldSt.days || []).includes(i) ? r : (Number(oldSt.seconds && oldSt.seconds[i]) || 0)), 0);
      const budget = STRICT_TIME ? Math.max(0, (Date.now() - a.user.createdAt) / 1000 + 20 - credited) : Infinity;
      a.user.state = sanitizeState(b.state, a.user.state, budget);
      flushSoon();
      return send(res, 200, { state: a.user.state });
    }
    if (route === 'POST /api/certificate') {
      const a = authUser(req); if (!a) return send(res, 401, { error: 'कृपया फिर से लॉगिन करें।' });
      const st = a.user.state;
      if (!st.test || !st.test.pass || st.days.length !== 7) return send(res, 400, { error: 'सर्टिफिकेट के लिए सातों अध्याय पूरे करें और फाइनल टेस्ट पास करें।' });
      if (!st.cert) {
        const b = await readBody(req);
        const name = cleanText(b.name, 60);
        if (!name) return send(res, 400, { error: 'सर्टिफिकेट पर छपने वाला नाम लिखें।' });
        const id = newCertId();
        const issued = new Date().toLocaleDateString('en-IN', { day: '2-digit', month: 'long', year: 'numeric', timeZone: 'Asia/Kolkata' });
        st.cert = { id, name, issued };
        db.certs[id] = { phone: a.phone, name, score: st.test.score, issued };
        flushNow();
      }
      return send(res, 200, { state: st });
    }
    if (req.method === 'GET' && url.startsWith('/api/verify/')) {
      if (!verifyAllowed(clientIp(req))) return send(res, 429, { error: 'बहुत ज्यादा अनुरोध। कुछ देर बाद कोशिश करें।' });
      const id = decodeURIComponent(url.slice(12)).toUpperCase().trim();
      const c = db.certs[id];
      if (!c) return send(res, 404, { valid: false, error: 'यह सर्टिफिकेट ID हमारे रिकॉर्ड में नहीं मिली।' });
      return send(res, 200, { valid: true, id, name: c.name, score: c.score, issued: c.issued, course: 'Fire Safety Awareness & Learning Course' });
    }
    if (route === 'POST /api/logout') {
      const a = authUser(req); if (a) { delete db.sessions[a.key]; flushSoon(); }
      return send(res, 200, { ok: true });
    }
    return send(res, 404, { error: 'Not found' });
  } catch (e) {
    return send(res, 400, { error: 'गलत अनुरोध।' });
  }
}

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.jpg': 'image/jpeg', '.ico': 'image/x-icon', '.json': 'application/json', '.webmanifest': 'application/manifest+json', '.svg': 'image/svg+xml' };
const server = http.createServer((req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  const url = (req.url || '/').split('?')[0];
  if (url.startsWith('/api/')) return api(req, res, url);
  if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }
  if (url === '/healthz') { res.writeHead(200); return res.end('ok'); }
  let rel; try { rel = url === '/' ? '/index.html' : decodeURIComponent(url); } catch (e) { res.writeHead(400); return res.end(); }
  // फाइल पहले public/ में ढूँढो, फिर (सिर्फ अनुमत नामों के लिए) सीधे मुख्य फ़ोल्डर में
  const cands = [];
  const pf = path.normalize(path.join(__dirname, 'public', rel));
  if (pf.startsWith(path.join(__dirname, 'public') + path.sep)) cands.push(pf);
  if (FLAT_OK.test(rel)) cands.push(path.join(__dirname, rel));
  (function tryNext(i) {
    if (i >= cands.length) { res.writeHead(404); return res.end('Not found'); }
    fs.readFile(cands[i], (err, data) => {
      if (err) return tryNext(i + 1);
      res.writeHead(200, { 'Content-Type': MIME[path.extname(cands[i])] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
      res.end(req.method === 'HEAD' ? undefined : data);
    });
  })(0);
});
server.listen(PORT, () => { try { console.log('[check] folder=' + __dirname + ' files=' + fs.readdirSync(__dirname).join(',') + ' index.html=' + fs.existsSync(path.join(__dirname,'index.html'))); } catch (e) {} console.log('Fire Safety Academy chal raha hai: http://localhost:' + PORT + '  (data: ' + DATA_FILE + ')'); });
