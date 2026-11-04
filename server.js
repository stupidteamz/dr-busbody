// DR Bus Body - ระบบใบเสนอราคา / ใบวางบิล / ใบเสร็จรับเงิน
// ไม่ต้องติดตั้งแพ็กเกจเพิ่ม ใช้ Node.js 18 ขึ้นไปเท่านั้น
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const FILE = path.join(DIR, 'data.json');
const SECURE = process.env.COOKIE_SECURE === '1'; // ตั้งเป็น 1 เมื่อใช้ผ่าน https
const DAY = 86400000;

fs.mkdirSync(DIR, { recursive: true });
let DB = { docs: {}, customers: {}, jobs: {}, users: {}, company: {}, sessions: {} };
try { DB = { ...DB, ...JSON.parse(fs.readFileSync(FILE, 'utf8')) }; } catch (e) {}

function persist() {
  const tmp = FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(DB));
  fs.renameSync(tmp, FILE);
}
const uid = () => crypto.randomBytes(8).toString('hex');
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 32).toString('hex');
const safeEq = (a, b) => { const x = Buffer.from(a), y = Buffer.from(b); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const pub = u => ({ id: u.id, name: u.name, username: u.username, role: u.role });

function json(res, code, obj, headers = {}) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
  res.end(JSON.stringify(obj));
}
function body(req) {
  return new Promise((ok, no) => {
    let s = '';
    req.on('data', c => { s += c; if (s.length > 2e6) { req.destroy(); no(new Error('too large')); } });
    req.on('end', () => { try { ok(s ? JSON.parse(s) : {}); } catch (e) { no(e); } });
  });
}
function me(req) {
  const m = /(?:^|;\s*)sid=([a-f0-9]+)/.exec(req.headers.cookie || '');
  if (!m) return null;
  const s = DB.sessions[m[1]];
  if (!s || s.exp < Date.now()) return null;
  return DB.users[s.uid] || null;
}
function startSession(res, user) {
  const t = crypto.randomBytes(32).toString('hex');
  DB.sessions[t] = { uid: user.id, exp: Date.now() + 30 * DAY };
  for (const k of Object.keys(DB.sessions)) if (DB.sessions[k].exp < Date.now()) delete DB.sessions[k];
  persist();
  return { 'Set-Cookie': `sid=${t}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${30 * 86400}${SECURE ? '; Secure' : ''}` };
}

// จำกัดการเดารหัสผ่าน: ผิดเกิน 8 ครั้งใน 10 นาที จะถูกบล็อกชั่วคราว
const fails = {};
const blocked = ip => (fails[ip] || []).filter(t => t > Date.now() - 600000).length >= 8;
const fail = ip => { fails[ip] = (fails[ip] || []).filter(t => t > Date.now() - 600000).concat(Date.now()); };

const admins = () => Object.values(DB.users).filter(u => u.role === 'admin');
const isAdmin = u => u && u.role === 'admin';
const COL = { docs: 'docs', customers: 'customers', jobs: 'jobs' };

async function api(req, res, url) {
  const ip = req.socket.remoteAddress;
  const u = me(req);
  const parts = url.pathname.split('/').filter(Boolean); // ['api', ...]
  const m = req.method, r = parts[1], id = parts[2];

  if (r === 'status' && m === 'GET')
    return json(res, 200, { setup: Object.keys(DB.users).length === 0, me: u ? pub(u) : null });

  if (r === 'setup' && m === 'POST') {
    if (Object.keys(DB.users).length) return json(res, 403, { error: 'ตั้งค่าแล้ว' });
    const b = await body(req);
    const username = String(b.username || '').trim().toLowerCase();
    if (!b.name || !username || String(b.password || '').length < 6) return json(res, 400, { error: 'กรอกให้ครบ และรหัสผ่านอย่างน้อย 6 ตัวอักษร' });
    const salt = uid(), nu = { id: uid(), name: String(b.name).trim(), username, role: 'admin', salt, hash: hashPw(b.password, salt) };
    DB.users[nu.id] = nu; persist();
    return json(res, 200, { me: pub(nu) }, startSession(res, nu));
  }

  if (r === 'login' && m === 'POST') {
    if (blocked(ip)) return json(res, 429, { error: 'ลองผิดหลายครั้งเกินไป กรุณารอสักครู่' });
    const b = await body(req);
    const nu = Object.values(DB.users).find(x => x.username === String(b.username || '').trim().toLowerCase());
    if (!nu || !safeEq(hashPw(String(b.password || ''), nu.salt), nu.hash)) { fail(ip); return json(res, 401, { error: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' }); }
    return json(res, 200, { me: pub(nu) }, startSession(res, nu));
  }

  if (r === 'logout' && m === 'POST') {
    const c = /sid=([a-f0-9]+)/.exec(req.headers.cookie || '');
    if (c) { delete DB.sessions[c[1]]; persist(); }
    return json(res, 200, { ok: true }, { 'Set-Cookie': 'sid=; HttpOnly; Path=/; Max-Age=0' });
  }

  if (!u) return json(res, 401, { error: 'กรุณาเข้าสู่ระบบ' });

  if (r === 'state' && m === 'GET')
    return json(res, 200, {
      docs: Object.values(DB.docs), jobs: Object.values(DB.jobs), cust: Object.values(DB.customers), co: DB.company,
      users: isAdmin(u) ? Object.values(DB.users).map(pub) : []
    });

  if (COL[r] && id) {
    const c = DB[COL[r]];
    if (m === 'PUT') {
      const b = await body(req);
      if (r === 'docs' && b.srcId && Object.values(c).some(x => x.id !== id && x.srcId === b.srcId && x.type === b.type))
        return json(res, 409, { error: 'ออกเอกสารจากใบต้นทางนี้ไปแล้ว ออกซ้ำไม่ได้' });
      b.id = id; c[id] = b; persist();
      return json(res, 200, { ok: true });
    }
    if (m === 'DELETE') {
      if (!isAdmin(u)) return json(res, 403, { error: 'เฉพาะแอดมิน' });
      delete c[id]; persist();
      return json(res, 200, { ok: true });
    }
  }

  if (r === 'company' && m === 'PUT') {
    if (!isAdmin(u)) return json(res, 403, { error: 'เฉพาะแอดมิน' });
    DB.company = await body(req); persist();
    return json(res, 200, { ok: true });
  }

  if (r === 'users' && id) {
    if (!isAdmin(u)) return json(res, 403, { error: 'เฉพาะแอดมิน' });
    if (m === 'PUT') {
      const b = await body(req);
      const old = DB.users[id];
      const username = String(b.username || '').trim().toLowerCase();
      const role = b.role === 'admin' ? 'admin' : 'user';
      if (!b.name || !username) return json(res, 400, { error: 'กรอกชื่อและชื่อผู้ใช้' });
      if (!old && String(b.password || '').length < 6) return json(res, 400, { error: 'รหัสผ่านต้องมีอย่างน้อย 6 ตัวอักษร' });
      if (b.password && String(b.password).length < 6) return json(res, 400, { error: 'รหัสผ่านต้องมีอย่างน้อย 6 ตัวอักษร' });
      if (Object.values(DB.users).some(x => x.username === username && x.id !== id)) return json(res, 400, { error: 'ชื่อผู้ใช้นี้ถูกใช้แล้ว' });
      if (role !== 'admin' && !admins().some(x => x.id !== id)) return json(res, 400, { error: 'ต้องมีแอดมินอย่างน้อย 1 คน' });
      const nu = { ...(old || {}), id, name: String(b.name).trim(), username, role };
      if (b.password) { nu.salt = uid(); nu.hash = hashPw(String(b.password), nu.salt); }
      DB.users[id] = nu;
      if (b.password) for (const k of Object.keys(DB.sessions)) if (DB.sessions[k].uid === id && id !== u.id) delete DB.sessions[k];
      persist();
      return json(res, 200, { ok: true });
    }
    if (m === 'DELETE') {
      if (id === u.id) return json(res, 400, { error: 'ลบตัวเองไม่ได้' });
      delete DB.users[id];
      for (const k of Object.keys(DB.sessions)) if (DB.sessions[k].uid === id) delete DB.sessions[k];
      persist();
      return json(res, 200, { ok: true });
    }
  }
  return json(res, 404, { error: 'not found' });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    if (url.pathname.startsWith('/api/')) return await api(req, res, url);
    if (req.method !== 'GET') { res.writeHead(405); return res.end(); }
    const f = path.join(__dirname, 'public', 'index.html');
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache', 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'SAMEORIGIN' });
    fs.createReadStream(f).pipe(res);
  } catch (e) {
    json(res, 400, { error: 'bad request' });
  }
});
server.listen(PORT, '0.0.0.0', () => console.log(`DR Bus Body พร้อมใช้งานที่ http://localhost:${PORT}`));
