'use strict';

const [major] = process.versions.node.split('.').map(Number);
if (major < 20) {
  console.error('This backend needs Node.js 20 or newer. You have ' + process.versions.node + '.');
  console.error('Download the current LTS version from https://nodejs.org and try again.');
  process.exit(1);
}

const http = require('node:http');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');

try { process.loadEnvFile(path.join(__dirname, '.env')); } catch (e) { /* no .env file: use real environment variables */ }

const { openDb } = require('./lib/db');
const { makeStorage } = require('./lib/storage');
const { parseMultipart } = require('./lib/multipart');
const { hashPassword, verifyPassword, signToken, verifyToken, codesMatch, makeLimiter } = require('./lib/security');

// ---------- Settings ----------
const PORT = Number(process.env.PORT) || 3000;
const JWT_SECRET = process.env.JWT_SECRET || '';
const ADMIN_CODE = (process.env.ADMIN_CODE || '').trim().toUpperCase();
const ORIGINS = (process.env.FRONTEND_URL || '').split(',').map(s => s.trim().replace(/\/+$/, '')).filter(Boolean);
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const DATABASE_URL = (process.env.DATABASE_URL || '').trim();
const SUPABASE_URL = (process.env.SUPABASE_URL || '').trim();
const SUPABASE_SECRET_KEY = (process.env.SUPABASE_SECRET_KEY || '').trim();
const STATIC_DIR = path.resolve(process.env.STATIC_DIR || path.join(__dirname, '..', 'frontend'));

const MAX_PDF = 25 * 1024 * 1024;
const MAX_IMAGE = 5 * 1024 * 1024;
const MAX_FORM = MAX_PDF + MAX_IMAGE + 1024 * 1024;
const MEMBER_TOKEN_SECONDS = 7 * 24 * 3600;
const ADMIN_TOKEN_SECONDS = 12 * 3600;

if (JWT_SECRET.length < 32) {
  console.error('JWT_SECRET is missing or too short. Open backend/.env and set it to a long random string (32+ characters).');
  process.exit(1);
}

if (!DATABASE_URL || !SUPABASE_URL || !SUPABASE_SECRET_KEY) {
  console.error('DATABASE_URL, SUPABASE_URL and SUPABASE_SECRET_KEY must be set in backend/.env (see README.md, "Put the database online").');
  process.exit(1);
}

const storage = makeStorage(SUPABASE_URL, SUPABASE_SECRET_KEY);
let db; // the online database, opened in start() at the bottom

const one = async (sql, params) => (await db.query(sql, params)).rows[0];
const many = async (sql, params) => (await db.query(sql, params)).rows;

const q = {
  userById: id => one('SELECT id, name, email, role FROM users WHERE id = $1', [id]),
  userByEmail: email => one('SELECT * FROM users WHERE lower(email) = lower($1)', [email]),
  addUser: (name, email, hash, role) => db.query('INSERT INTO users (name, email, password_hash, role) VALUES ($1, $2, $3, $4)', [name, email, hash, role]),
  members: () => many("SELECT id, name, email, created_at FROM users WHERE role = 'member' ORDER BY created_at DESC, id DESC"),
  books: () => many('SELECT * FROM books ORDER BY lower(title)'),
  book: id => one('SELECT * FROM books WHERE id = $1', [id]),
  addBook: (title, author, category, pdf, image) => one('INSERT INTO books (title, author, category, pdf_file, image_file) VALUES ($1, $2, $3, $4, $5) RETURNING id', [title, author, category, pdf, image]),
  updateBook: (title, author, category, pdf, image, id) => db.query('UPDATE books SET title = $1, author = $2, category = $3, pdf_file = $4, image_file = $5 WHERE id = $6', [title, author, category, pdf, image, id]),
  deleteBook: id => db.query('DELETE FROM books WHERE id = $1', [id]),
  stats: () => one(`SELECT
    (SELECT COUNT(*) FROM books)::int AS books,
    (SELECT COUNT(*) FROM books WHERE pdf_file IS NOT NULL)::int AS pdfs,
    (SELECT COUNT(*) FROM users WHERE role = 'member')::int AS members`)
};

// ---------- Small helpers ----------
class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

const clean = v => String(v ?? '').trim();
const rand = () => crypto.randomBytes(16).toString('hex');
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const limiter = makeLimiter();
let dummyHash = null; // used so unknown emails take as long to check as real ones

function send(res, status, body) {
  const data = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(data),
    'Cache-Control': 'no-store'
  });
  res.end(data);
}

function clientIp(req) {
  if (TRUST_PROXY) {
    const list = String(req.headers['x-forwarded-for'] || '').split(',').map(s => s.trim()).filter(Boolean);
    if (list.length) return list[list.length - 1]; // the address the one trusted proxy saw
  }
  return req.socket.remoteAddress || 'unknown';
}

function limit(req, bucket, max, minutes) {
  if (!limiter(bucket + ':' + clientIp(req), max, minutes * 60000))
    throw new HttpError(429, 'Too many attempts. Please wait a few minutes and try again.');
}

function readBody(req, max) {
  return new Promise((resolve, reject) => {
    const declared = Number(req.headers['content-length']);
    if (declared > max) return reject(new HttpError(413, 'That upload is too large.'));
    const chunks = [];
    let size = 0, over = false;
    req.on('data', chunk => {
      if (over) return;
      size += chunk.length;
      if (size > max) { over = true; reject(new HttpError(413, 'That upload is too large.')); return; }
      chunks.push(chunk);
    });
    req.on('end', () => { if (!over) resolve(Buffer.concat(chunks)); });
    req.on('error', reject);
  });
}

async function readJson(req) {
  const buf = await readBody(req, 100 * 1024);
  if (!buf.length) return {};
  try {
    const value = JSON.parse(buf.toString('utf8'));
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('not an object');
    return value;
  } catch (e) { throw new HttpError(400, 'Invalid request.'); }
}

async function authenticate(req) {
  const m = /^Bearer (.+)$/.exec(req.headers.authorization || '');
  const payload = m && verifyToken(m[1], JWT_SECRET);
  const user = payload && await q.userById(payload.sub); // role always comes from the database
  if (!user) throw new HttpError(401, 'Please log in again.');
  return user;
}

function needAdmin(user) {
  if (user.role !== 'admin') throw new HttpError(403, 'Only admins can do that.');
}

const bookJson = b => ({
  id: b.id,
  title: b.title,
  author: b.author,
  category: b.category,
  has_pdf: !!b.pdf_file,
  image: b.image_file ? storage.coverUrl(b.image_file) : null
});

// ---------- File checks (we look at the file's real bytes, not its name) ----------
const IMAGE_TYPES = { jpg: 'image/jpeg', png: 'image/png', webp: 'image/webp', gif: 'image/gif' };
const isPdf = b => b.length > 5 && b.toString('latin1', 0, 5) === '%PDF-';
function imageExt(b) {
  if (b.length > 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'jpg';
  if (b.length > 8 && b.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return 'png';
  if (b.length > 12 && b.toString('latin1', 0, 4) === 'RIFF' && b.toString('latin1', 8, 12) === 'WEBP') return 'webp';
  if (b.length > 6 && ['GIF87a', 'GIF89a'].includes(b.toString('latin1', 0, 6))) return 'gif';
  return null;
}

async function readBookForm(req) {
  const type = req.headers['content-type'] || '';
  if (!/^multipart\/form-data/i.test(type)) throw new HttpError(400, 'Invalid request.');
  const { fields, files } = parseMultipart(await readBody(req, MAX_FORM), type);

  const title = clean(fields.title), author = clean(fields.author), category = clean(fields.category);
  if (!title || !author) throw new HttpError(400, 'Title and author are required');
  if (title.length > 200 || author.length > 200 || category.length > 60)
    throw new HttpError(400, 'Title and author must be under 200 characters, category under 60.');

  let pdf = null, image = null;
  if (files.pdf) {
    if (files.pdf.data.length > MAX_PDF) throw new HttpError(400, 'The PDF must be under 25 MB.');
    if (!isPdf(files.pdf.data)) throw new HttpError(400, 'Choose a PDF file.');
    pdf = files.pdf.data;
  }
  if (files.image) {
    if (files.image.data.length > MAX_IMAGE) throw new HttpError(400, 'The cover image must be under 5 MB.');
    const ext = imageExt(files.image.data);
    if (!ext) throw new HttpError(400, 'The cover must be a JPG, PNG, WEBP or GIF image.');
    image = { data: files.image.data, ext };
  }
  return { title, author, category: category || null, pdf, image };
}

// ---------- Accounts ----------
function readAccount(b) {
  const name = clean(b.name), email = clean(b.email).toLowerCase(), password = String(b.password ?? '');
  if (!name || !email || password.length < 8)
    throw new HttpError(400, 'Enter your name, email, and a password of 8+ characters');
  if (name.length > 100 || email.length > 200 || !EMAIL_RE.test(email))
    throw new HttpError(400, 'Enter a valid name and email address');
  if (password.length > 200) throw new HttpError(400, 'That password is too long (200 characters at most).');
  return { name, email, password };
}

async function createUser(account, role, duplicateMessage) {
  const hash = await hashPassword(account.password);
  try {
    await q.addUser(account.name, account.email, hash, role);
  } catch (e) {
    if (e.code === '23505') throw new HttpError(409, duplicateMessage);
    throw e;
  }
}

// ---------- API routes ----------
async function handleApi(req, res, p) {
  const method = req.method;

  if (p === '/api/auth/register' && method === 'POST') {
    limit(req, 'register', 20, 60);
    await createUser(readAccount(await readJson(req)), 'member', 'An account with this email already exists');
    return send(res, 201, { ok: true });
  }

  if (p === '/api/auth/register-admin' && method === 'POST') {
    limit(req, 'register-admin', 5, 15);
    const b = await readJson(req);
    const account = readAccount(b);
    if (!ADMIN_CODE) throw new HttpError(403, 'Admin sign up is turned off on this server.');
    if (!codesMatch(clean(b.code).toUpperCase(), ADMIN_CODE))
      throw new HttpError(403, 'That admin access code is not correct');
    await createUser(account, 'admin', 'An account with this email already exists');
    return send(res, 201, { ok: true });
  }

  if (p === '/api/auth/login' && method === 'POST') {
    limit(req, 'login', 20, 15);
    const b = await readJson(req);
    const email = clean(b.email).toLowerCase(), password = String(b.password ?? '');
    const portal = b.portal === 'admin' ? 'admin' : 'member';
    if (!email || !password || password.length > 200) throw new HttpError(401, 'Invalid email or password');

    const user = await q.userByEmail(email);
    if (!dummyHash) dummyHash = await hashPassword('not-a-real-password');
    const ok = await verifyPassword(password, user ? user.password_hash : dummyHash);
    if (!user || !ok) throw new HttpError(401, 'Invalid email or password');

    if (portal === 'admin' && user.role !== 'admin')
      throw new HttpError(403, 'This is not a staff account. Use the member log in.');
    if (portal === 'member' && user.role === 'admin')
      throw new HttpError(403, 'This is a staff account. Use the staff log in.');

    const token = signToken({ sub: user.id, role: user.role, name: user.name }, JWT_SECRET,
      user.role === 'admin' ? ADMIN_TOKEN_SECONDS : MEMBER_TOKEN_SECONDS);
    return send(res, 200, { token, role: user.role, name: user.name });
  }

  // Everything below needs a logged-in user.
  const user = await authenticate(req);

  if (p === '/api/books' && method === 'GET') {
    return send(res, 200, (await q.books()).map(bookJson));
  }

  if (p === '/api/books' && method === 'POST') {
    needAdmin(user);
    const f = await readBookForm(req);
    const pdfName = f.pdf ? rand() + '.pdf' : null;
    const imageName = f.image ? rand() + '.' + f.image.ext : null;
    try {
      if (pdfName) await storage.savePdf(pdfName, f.pdf);
      if (imageName) await storage.saveCover(imageName, f.image.data, IMAGE_TYPES[f.image.ext]);
      const row = await q.addBook(f.title, f.author, f.category, pdfName, imageName);
      return send(res, 201, { ok: true, id: row.id });
    } catch (e) {
      await storage.removePdf(pdfName); await storage.removeCover(imageName);
      throw e;
    }
  }

  const m = /^\/api\/books\/(\d+)(\/pdf)?$/.exec(p);
  if (m) {
    const id = Number(m[1]);
    const book = await q.book(id);

    if (m[2] && method === 'GET') {
      if (!book || !book.pdf_file) throw new HttpError(404, 'No PDF for this book yet');
      let upstream;
      try { upstream = await storage.getPdf(book.pdf_file); } catch (e) { throw new HttpError(404, 'No PDF for this book yet'); }
      const data = Buffer.from(await upstream.arrayBuffer());
      const slug = book.title.replace(/[^\w\- ]+/g, '').trim().replace(/\s+/g, '-').slice(0, 60) || 'book';
      res.writeHead(200, {
        'Content-Type': 'application/pdf',
        'Content-Length': data.length,
        'Content-Disposition': 'inline; filename="' + slug + '.pdf"',
        'Cache-Control': 'private, no-store'
      });
      return res.end(data);
    }

    if (!m[2] && method === 'PUT') {
      needAdmin(user);
      if (!book) throw new HttpError(404, 'Book not found');
      const f = await readBookForm(req);
      const pdfName = f.pdf ? rand() + '.pdf' : book.pdf_file;
      const imageName = f.image ? rand() + '.' + f.image.ext : book.image_file;
      try {
        if (f.pdf) await storage.savePdf(pdfName, f.pdf);
        if (f.image) await storage.saveCover(imageName, f.image.data, IMAGE_TYPES[f.image.ext]);
        await q.updateBook(f.title, f.author, f.category, pdfName, imageName, id);
      } catch (e) {
        if (f.pdf) await storage.removePdf(pdfName);
        if (f.image) await storage.removeCover(imageName);
        throw e;
      }
      if (f.pdf) await storage.removePdf(book.pdf_file);       // old files go only after success
      if (f.image) await storage.removeCover(book.image_file);
      return send(res, 200, { ok: true });
    }

    if (!m[2] && method === 'DELETE') {
      needAdmin(user);
      if (!book) throw new HttpError(404, 'Book not found');
      await q.deleteBook(id);
      await storage.removePdf(book.pdf_file);
      await storage.removeCover(book.image_file);
      return send(res, 200, { ok: true });
    }
    throw new HttpError(405, 'Method not allowed');
  }

  if (p === '/api/admin/stats' && method === 'GET') {
    needAdmin(user);
    return send(res, 200, await q.stats());
  }

  if (p === '/api/admin/members' && method === 'GET') {
    needAdmin(user);
    return send(res, 200, await q.members());
  }

  throw new HttpError(404, 'Not found');
}

// ---------- Cover images (public) and the website files ----------
const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png',
  '.webp': 'image/webp', '.gif': 'image/gif', '.svg': 'image/svg+xml', '.ico': 'image/x-icon'
};

async function streamFile(req, res, file, headers) {
  const st = await fsp.stat(file);
  if (!st.isFile()) throw new HttpError(404, 'Not found');
  res.writeHead(200, { ...headers, 'Content-Length': st.size });
  if (req.method === 'HEAD') return res.end();
  const stream = fs.createReadStream(file);
  stream.on('error', () => res.destroy());
  stream.pipe(res);
}

async function serveSite(req, res, p) {
  let rel;
  try { rel = decodeURIComponent(p); } catch (e) { throw new HttpError(400, 'Bad request'); }
  if (rel.includes('\0') || rel.split('/').some(part => part.startsWith('.'))) throw new HttpError(404, 'Not found');
  if (rel.endsWith('/')) rel += 'index.html';
  const file = path.join(STATIC_DIR, rel);
  const type = MIME[path.extname(file).toLowerCase()];
  if (!file.startsWith(STATIC_DIR + path.sep) || !type) throw new HttpError(404, 'Not found');
  try {
    await streamFile(req, res, file, {
      'Content-Type': type,
      'Cache-Control': type.startsWith('image/') ? 'public, max-age=3600' : 'no-cache'
    });
  } catch (e) { throw e instanceof HttpError ? e : new HttpError(404, 'Not found'); }
}

// ---------- Server ----------
function setCors(req, res) {
  const origin = req.headers.origin;
  if (!origin) return;
  if (!ORIGINS.length) res.setHeader('Access-Control-Allow-Origin', '*');
  else if (ORIGINS.includes(origin)) { res.setHeader('Access-Control-Allow-Origin', origin); res.setHeader('Vary', 'Origin'); }
  else return;
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  res.setHeader('Access-Control-Max-Age', '600');
}

const hasSite = fs.existsSync(path.join(STATIC_DIR, 'index.html'));

const server = http.createServer(async (req, res) => {
  try {
    setCors(req, res);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'same-origin');
    res.setHeader('X-Frame-Options', 'DENY');

    const p = new URL(req.url, 'http://localhost').pathname;
    if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

    if (p.startsWith('/api/')) return await handleApi(req, res, p);

    if (req.method === 'GET' || req.method === 'HEAD') {
      if (hasSite) return await serveSite(req, res, p);
      if (p === '/') return send(res, 200, { ok: true, message: 'Library API is running.' });
    }
    throw new HttpError(404, 'Not found');
  } catch (e) {
    if (res.headersSent) return res.destroy();
    if (e instanceof HttpError || e.status === 400) {
      if (e.status === 413) res.setHeader('Connection', 'close');
      return send(res, e.status, { error: e.message });
    }
    console.error(e);
    send(res, 500, { error: 'Something went wrong. Try again.' });
  }
});

async function start() {
  db = await openDb(DATABASE_URL);
  await storage.setup();
  server.listen(PORT, () => {
    console.log('Library backend running on http://localhost:' + PORT + ' (database and files are online)');
    if (hasSite) console.log('Website: open http://localhost:' + PORT + ' in your browser.');
    if (!ADMIN_CODE) console.warn('WARNING: ADMIN_CODE is not set, so nobody can sign up as an admin.');
    if (!ORIGINS.length) console.warn('Note: FRONTEND_URL is empty, so any website may call this API. Set it before going live.');
  });
}

start().catch(e => { console.error('Could not start: ' + e.message); process.exit(1); });

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => { server.close(() => { (db ? db.end() : Promise.resolve()).finally(() => process.exit(0)); }); setTimeout(() => process.exit(0), 3000).unref(); });
}
