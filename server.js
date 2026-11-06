// Fire Safety Academy – chhota server (sirf Node.js built-in modules, koi npm install nahi)
// Chalane ke liye:  node server.js   (default http://localhost:3000)
// Login: sirf Email OTP (Brevo) + Google Sign-In. PIN login band hai.
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
const MAX_SEC = 6 * 3600;   // एक अध्याय में दर्ज होने वाला अधिकतम समय (सेकंड)
const PASS_CORRECT = 40;     // 50 me se 40 = 80%
const TOTAL_Q = 50;

/* ---- OTP / Google settings (Render > Environment me daalo) ---- */
const BREVO_API_KEY = process.env.BREVO_API_KEY || '';
const BREVO_SENDER_EMAIL = process.env.BREVO_SENDER_EMAIL || '';   // Brevo me verify kiya hua email
const BREVO_SENDER_NAME = process.env.BREVO_SENDER_NAME || 'Fire Safety Academy';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const OTP_SECRET = process.env.OTP_SECRET || crypto.randomBytes(32).toString('hex'); // fixed rakhna behtar hai
const OTP_TTL = 5 * 60000;   // 5 minute
const OTP_MAX_TRIES = 5;

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
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/;
function normEmail(s) { return String(s || '').trim().toLowerCase().slice(0, 254); }

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
function hitLimit(map, key, windowMs, max) {   // general rate limiter
  const now = Date.now(); const arr = (map.get(key) || []).filter(t => now - t < windowMs);
  if (arr.length >= max) { map.set(key, arr); return false; }
  arr.push(now); map.set(key, arr); return true;
}

/* OTP store (memory) */
const otps = new Map();          // email -> {hash, exp, tries, last}
const otpByEmail = new Map();    // email -> [timestamps]
const otpByIp = new Map();       // ip -> [timestamps]
const googleByIp = new Map();
setInterval(() => { // purane sessions + OTP saaf
  const now = Date.now(); let ch = false;
  for (const k in db.sessions) if (now - db.sessions[k].created > SESSION_DAYS * 86400000) { delete db.sessions[k]; ch = true; }
  for (const [k, v] of otps) if (v.exp < now) otps.delete(k);
  if (ch) flushSoon();
}, 3600000).unref();
function otpHash(email, otp) { return crypto.createHmac('sha256', OTP_SECRET).update(email + ':' + otp).digest('hex'); }

async function sendOtpEmail(email, otp) {
  const r = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: { 'api-key': BREVO_API_KEY, 'Content-Type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({
      sender: { email: BREVO_SENDER_EMAIL, name: BREVO_SENDER_NAME },
      to: [{ email }],
      subject: 'आपका लॉगिन OTP: ' + otp,
      htmlContent: '<div style="font-family:Arial,sans-serif;font-size:16px">' +
        '<p>Fire Safety Academy में लॉगिन के लिए आपका OTP:</p>' +
        '<p style="font-size:32px;font-weight:bold;letter-spacing:6px">' + otp + '</p>' +
        '<p>यह 5 मिनट तक मान्य है। इसे किसी को न बताएँ।</p>' +
        '<footer class="chapter-credit" style="margin-top:24px;padding:12px 16px;text-align:center;font-size:13px;line-height:1.6;color:#6b7280;border-top:1px solid #e5e7eb">' +
        'यह एप्लीकेशन राजन झा द्वारा निर्मित है। यह सिर्फ़ आपको फायर सेफ्टी के अनुभवों के बारे में जानकारी प्रदान करता है।</footer></div>'
    })
  });
  if (!r.ok) { const t = await r.text().catch(() => ''); console.log('[brevo-error] status=' + r.status + ' ' + t.slice(0, 300)); }
  return r.ok;
}

/* progress ko server par validate karte hain, taaki bekaar data na bane */
function sanitizeState(incoming, old) {
  old = old || { days: [], seconds: {}, test: null, cert: null };
  const out = { days: [], seconds: {}, test: null, cert: old.cert || null };
  const inSec = (incoming && incoming.seconds) || {};
  const oldDays = old.days || [];
  for (let i = 0; i < 7; i++) {
    if (oldDays.includes(i)) {                       // पूरा हो चुका अध्याय: लगा समय वैसा ही रहेगा
      const o = Math.min(MAX_SEC, Math.max(0, Math.floor(Number(old.seconds && old.seconds[i]) || 0)));
      const n = Math.floor(Number(inSec[i]));
      out.seconds[i] = Number.isFinite(n) ? Math.max(o, Math.min(MAX_SEC, n)) : o;   // दोबारा पढ़ने पर समय बढ़ सकता है, घट नहीं सकता
      continue;
    }
    const v = Number(inSec[i]);
    out.seconds[i] = Number.isFinite(v) ? Math.min(MAX_SEC, Math.max(0, Math.floor(v))) : 0;
  }
  const inDays = Array.isArray(incoming && incoming.days) ? incoming.days : [];
  for (let i = 0; i < 7; i++) {
    if (oldDays.includes(i)) { out.days.push(i); continue; }
    // अध्याय तभी पूरा जब पिछला पूरा हो चुका हो (कोई न्यूनतम समय नहीं)
    if (inDays.includes(i) && (i === 0 || out.days.includes(i - 1))) out.days.push(i);
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
// NOTE: session me 'phone' field ka matlab ab "user id" hai (purane users: mobile, naye users: email)
function authUser(req) {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return null;
  const s = db.sessions[sha(h.slice(7))];
  if (!s || Date.now() - s.created > SESSION_DAYS * 86400000) return null;
  const u = db.users[s.phone];
  return u ? { phone: s.phone, user: u, key: sha(h.slice(7)) } : null;
}
function newSession(uid) {
  const token = crypto.randomBytes(32).toString('hex');
  db.sessions[sha(token)] = { phone: uid, created: Date.now() };
  return token;
}
const publicUser = u => ({ profile: u.profile, state: u.state });

function getOrCreateEmailUser(email, name) {
  let u = db.users[email];
  if (!u) {
    u = db.users[email] = {
      profile: {
        name: cleanText(name, 60) || email.split('@')[0].slice(0, 60),
        email, phone: '', place: '',
        date: new Date().toLocaleDateString('hi-IN', { timeZone: 'Asia/Kolkata' })
      },
      state: { days: [], seconds: {}, test: null, cert: null },
      createdAt: Date.now()
    };
  }
  return u;
}

async function api(req, res, url) {
  const route = req.method + ' ' + url;
  try {
    /* ---------- Email OTP: भेजना ---------- */
    if (route === 'POST /api/otp/send') {
      if (!BREVO_API_KEY || !BREVO_SENDER_EMAIL) return send(res, 503, { error: 'OTP सेवा अभी सेट नहीं है।' });
      const b = await readBody(req);
      const email = normEmail(b.email);
      if (!EMAIL_RE.test(email)) return send(res, 400, { error: 'कृपया सही ईमेल लिखें।' });
      const prev = otps.get(email);
      if (prev && Date.now() - prev.last < 60000) return send(res, 429, { error: 'नया OTP 1 मिनट बाद माँगें।' });
      if (!hitLimit(otpByEmail, email, 3600000, 5) || !hitLimit(otpByIp, clientIp(req), 3600000, 15)) {
        return send(res, 429, { error: 'बहुत ज्यादा OTP अनुरोध। कुछ देर बाद कोशिश करें।' });
      }
      const otp = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
      otps.set(email, { hash: otpHash(email, otp), exp: Date.now() + OTP_TTL, tries: 0, last: Date.now() });
      let ok = false;
      try { ok = await sendOtpEmail(email, otp); } catch (e) { ok = false; }
      if (!ok) { otps.delete(email); return send(res, 502, { error: 'ईमेल भेजा नहीं जा सका। कुछ देर बाद कोशिश करें।' }); }
      return send(res, 200, { ok: true });
    }
    /* ---------- Email OTP: जाँचना ---------- */
    if (route === 'POST /api/otp/verify') {
      const b = await readBody(req);
      const email = normEmail(b.email), otp = String(b.otp || '');
      if (!EMAIL_RE.test(email) || !/^[0-9]{6}$/.test(otp)) return send(res, 400, { error: 'ईमेल और 6 अंकों का OTP सही भरें।' });
      const rec = otps.get(email);
      if (!rec || rec.exp < Date.now()) { otps.delete(email); return send(res, 401, { error: 'OTP की समय-सीमा खत्म हो गई। नया OTP माँगें।' }); }
      if (rec.tries >= OTP_MAX_TRIES) { otps.delete(email); return send(res, 429, { error: 'बहुत ज्यादा गलत कोशिशें। नया OTP माँगें।' }); }
      rec.tries += 1;
      if (!safeEq(rec.hash, otpHash(email, otp))) return send(res, 401, { error: 'OTP गलत है।' });
      otps.delete(email);   // एक OTP सिर्फ एक बार चलेगा
      const u = getOrCreateEmailUser(email, b.name);
      if (b.place && !u.profile.place) u.profile.place = cleanText(b.place, 60);
      const token = newSession(email); flushNow();
      return send(res, 200, { token, ...publicUser(u) });
    }
    /* ---------- Google Sign-In ---------- */
    if (route === 'POST /api/google') {
      if (!GOOGLE_CLIENT_ID) return send(res, 503, { error: 'Google लॉगिन अभी सेट नहीं है।' });
      if (!hitLimit(googleByIp, clientIp(req), 3600000, 60)) return send(res, 429, { error: 'बहुत ज्यादा अनुरोध। कुछ देर बाद कोशिश करें।' });
      const b = await readBody(req);
      const cred = String(b.credential || '');
      if (!cred || cred.length > 4000) return send(res, 400, { error: 'गलत अनुरोध।' });
      const r = await fetch('https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(cred));
      const g = await r.json().catch(() => ({}));
      if (!r.ok || g.aud !== GOOGLE_CLIENT_ID || String(g.email_verified) !== 'true' || !g.email ||
          !/^(https:\/\/)?accounts\.google\.com$/.test(g.iss || '') || Number(g.exp) * 1000 < Date.now()) {
        return send(res, 401, { error: 'Google लॉगिन सही नहीं निकला। फिर कोशिश करें।' });
      }
      const email = normEmail(g.email);
      const u = getOrCreateEmailUser(email, g.name);
      const token = newSession(email); flushNow();
      return send(res, 200, { token, ...publicUser(u) });
    }
    /* ---------- अकाउंट डिलीट (Play Store के लिए ज़रूरी) ---------- */
    if (route === 'POST /api/account/delete') {
      const a = authUser(req); if (!a) return send(res, 401, { error: 'कृपया फिर से लॉगिन करें।' });
      for (const k in db.sessions) if (db.sessions[k].phone === a.phone) delete db.sessions[k];
      for (const id in db.certs) if (db.certs[id].phone === a.phone) delete db.certs[id];
      delete db.users[a.phone];
      flushNow();
      return send(res, 200, { ok: true });
    }
    /* ---------- config (client को Google Client ID चाहिए) ---------- */
    if (route === 'GET /api/config') {
      return send(res, 200, { googleClientId: GOOGLE_CLIENT_ID, otpEnabled: !!(BREVO_API_KEY && BREVO_SENDER_EMAIL) });
    }
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
    /* मोबाइल+PIN लॉगिन बंद: अब सिर्फ Email OTP / Google */
    if (route === 'POST /api/register' || route === 'POST /api/login') {
      return send(res, 410, { error: 'अब लॉगिन सिर्फ ईमेल OTP से होता है।' });
    }
    if (route === 'GET /api/me') {
      const a = authUser(req); if (!a) return send(res, 401, { error: 'कृपया फिर से लॉगिन करें।' });
      return send(res, 200, publicUser(a.user));
    }
    if (route === 'PUT /api/state') {
      const a = authUser(req); if (!a) return send(res, 401, { error: 'कृपया फिर से लॉगिन करें।' });
      const b = await readBody(req);
      if (!a.user.createdAt) a.user.createdAt = Date.now();
      a.user.state = sanitizeState(b.state, a.user.state);
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
        let studySeconds = 0;
        for (let i = 0; i < 7; i++) studySeconds += Math.max(0, Math.floor(Number(st.seconds && st.seconds[i]) || 0));
        st.cert = { id, name, issued, studySeconds };
        db.certs[id] = { phone: a.phone, name, score: st.test.score, issued, studySeconds };
        flushNow();
      }
      return send(res, 200, { state: st });
    }
    if (req.method === 'GET' && url.startsWith('/api/verify/')) {
      if (!verifyAllowed(clientIp(req))) return send(res, 429, { error: 'बहुत ज्यादा अनुरोध। कुछ देर बाद कोशिश करें।' });
      const id = decodeURIComponent(url.slice(12)).toUpperCase().trim();
      const c = db.certs[id];
      if (!c) return send(res, 404, { valid: false, error: 'यह सर्टिफिकेट ID हमारे रिकॉर्ड में नहीं मिली।' });
      return send(res, 200, { valid: true, id, name: c.name, score: c.score, issued: c.issued, studySeconds: c.studySeconds, course: 'Fire Safety Awareness & Learning Course' });
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
server.listen(PORT, () => { console.log('[config] BREVO_API_KEY=' + (BREVO_API_KEY ? 'set' : 'MISSING') + ' BREVO_SENDER_EMAIL=' + (BREVO_SENDER_EMAIL ? 'set' : 'MISSING') + ' GOOGLE_CLIENT_ID=' + (GOOGLE_CLIENT_ID ? 'set' : 'MISSING') + ' OTP_SECRET=' + (process.env.OTP_SECRET ? 'set' : 'MISSING')); console.log('Fire Safety Academy chal raha hai: http://localhost:' + PORT + '  (data: ' + DATA_FILE + ')'); });
