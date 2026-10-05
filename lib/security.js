'use strict';
const crypto = require('node:crypto');

// ---------- Passwords (scrypt, built into Node) ----------
const scrypt = (password, salt) =>
  new Promise((resolve, reject) =>
    crypto.scrypt(password, salt, 64, (err, key) => (err ? reject(err) : resolve(key))));

async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(password, salt);
  return 's1$' + salt.toString('hex') + '$' + key.toString('hex');
}

async function verifyPassword(password, stored) {
  const [version, salt, hash] = String(stored).split('$');
  if (version !== 's1' || !salt || !hash) return false;
  const key = await scrypt(password, Buffer.from(salt, 'hex'));
  const want = Buffer.from(hash, 'hex');
  return want.length === key.length && crypto.timingSafeEqual(key, want);
}

// ---------- Login tokens (JWT, HS256) ----------
const b64u = v => Buffer.from(v).toString('base64url');

function signToken(payload, secret, ttlSeconds) {
  const now = Math.floor(Date.now() / 1000);
  const head = b64u(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64u(JSON.stringify({ ...payload, iat: now, exp: now + ttlSeconds }));
  const sig = crypto.createHmac('sha256', secret).update(head + '.' + body).digest('base64url');
  return head + '.' + body + '.' + sig;
}

function verifyToken(token, secret) {
  const parts = String(token).split('.');
  if (parts.length !== 3) return null;
  const [head, body, sig] = parts;
  const want = crypto.createHmac('sha256', secret).update(head + '.' + body).digest();
  const got = Buffer.from(sig, 'base64url');
  if (got.length !== want.length || !crypto.timingSafeEqual(got, want)) return null;
  try {
    if (JSON.parse(Buffer.from(head, 'base64url')).alg !== 'HS256') return null;
    const payload = JSON.parse(Buffer.from(body, 'base64url'));
    if (!payload.exp || payload.exp < Date.now() / 1000) return null;
    return payload;
  } catch (e) { return null; }
}

// ---------- Secret code comparison (constant time) ----------
function codesMatch(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

// ---------- Simple in-memory rate limiter ----------
function makeLimiter() {
  const hits = new Map();
  setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of hits) if (entry.reset < now) hits.delete(key);
  }, 60000).unref();
  // Returns true while the caller is still under the limit.
  return (key, max, windowMs) => {
    const now = Date.now();
    let entry = hits.get(key);
    if (!entry || entry.reset < now) { entry = { count: 0, reset: now + windowMs }; hits.set(key, entry); }
    entry.count++;
    return entry.count <= max;
  };
}

module.exports = { hashPassword, verifyPassword, signToken, verifyToken, codesMatch, makeLimiter };
