'use strict';
const crypto = require('node:crypto');
const express = require('express');

const COOKIE = 'sag_sid';
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/;
const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 64 };

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p });
  return `scrypt$${SCRYPT.N}$${salt.toString('base64')}$${hash.toString('base64')}`;
}

function verifyPassword(password, stored) {
  try {
    const [scheme, n, saltB64, hashB64] = stored.split('$');
    if (scheme !== 'scrypt') return false;
    const expected = Buffer.from(hashB64, 'base64');
    const actual = crypto.scryptSync(password, Buffer.from(saltB64, 'base64'), expected.length, {
      N: parseInt(n, 10), r: SCRYPT.r, p: SCRYPT.p,
    });
    return crypto.timingSafeEqual(actual, expected);
  } catch (_) {
    return false;
  }
}

// Verified on unknown emails so response time does not reveal whether an account exists.
const DUMMY_HASH = hashPassword('dummy-password-for-timing');

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

function parseCookies(header = '') {
  const out = {};
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function cookieString(value, { secure, maxAgeSec }) {
  return [`${COOKIE}=${value}`, 'Path=/', 'HttpOnly', 'SameSite=Lax', `Max-Age=${maxAgeSec}`, secure ? 'Secure' : null]
    .filter(Boolean).join('; ');
}

function createAuth({ db, config, authLimiter }) {
  const router = express.Router();

  function createSession(res, userId) {
    const token = crypto.randomBytes(32).toString('base64url');
    const now = Date.now();
    const maxAgeSec = config.sessionDays * 86400;
    db.prepare('INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?,?,?,?)')
      .run(sha256(token), userId, now, now + maxAgeSec * 1000);
    res.setHeader('Set-Cookie', cookieString(token, { secure: config.cookieSecure, maxAgeSec }));
  }

  /** Attaches req.user when a valid session cookie is present. */
  function loadUser(req, _res, next) {
    const token = parseCookies(req.headers.cookie)[COOKIE];
    if (token) {
      const row = db.prepare(
        `SELECT u.id, u.email FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = ? AND s.expires_at > ?`
      ).get(sha256(token), Date.now());
      if (row) req.user = { id: row.id, email: row.email };
    }
    next();
  }

  function requireAuth(req, res, next) {
    if (!req.user) return res.status(401).json({ error: 'unauthenticated', message: 'Please log in.' });
    return next();
  }

  router.post('/register', authLimiter, (req, res) => {
    const { email, password } = req.body || {};
    if (typeof email !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ error: 'invalid_input', message: 'Email and password are required.' });
    }
    const normEmail = email.trim().toLowerCase();
    if (!EMAIL_RE.test(normEmail)) return res.status(400).json({ error: 'invalid_input', message: 'Enter a valid email address.' });
    if (password.length < 10 || password.length > 128) {
      return res.status(400).json({ error: 'invalid_input', message: 'Password must be 10 to 128 characters.' });
    }
    if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(normEmail)) {
      return res.status(409).json({ error: 'conflict', message: 'An account with this email already exists.' });
    }
    const id = crypto.randomUUID();
    db.prepare('INSERT INTO users (id, email, password_hash, created_at) VALUES (?,?,?,?)')
      .run(id, normEmail, hashPassword(password), Date.now());
    createSession(res, id);
    return res.status(201).json({ user: { id, email: normEmail } });
  });

  router.post('/login', authLimiter, (req, res) => {
    const { email, password } = req.body || {};
    if (typeof email !== 'string' || typeof password !== 'string' || password.length > 128) {
      return res.status(400).json({ error: 'invalid_input', message: 'Email and password are required.' });
    }
    const user = db.prepare('SELECT id, email, password_hash FROM users WHERE email = ?').get(email.trim().toLowerCase());
    const ok = verifyPassword(password, user ? user.password_hash : DUMMY_HASH);
    if (!user || !ok) return res.status(401).json({ error: 'invalid_credentials', message: 'Incorrect email or password.' });
    createSession(res, user.id);
    return res.json({ user: { id: user.id, email: user.email } });
  });

  router.post('/logout', (req, res) => {
    const token = parseCookies(req.headers.cookie)[COOKIE];
    if (token) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha256(token));
    res.setHeader('Set-Cookie', cookieString('', { secure: config.cookieSecure, maxAgeSec: 0 }));
    res.json({ ok: true });
  });

  router.get('/me', requireAuth, (req, res) => res.json({ user: req.user }));

  return { router, loadUser, requireAuth };
}

module.exports = { createAuth, hashPassword, verifyPassword, sha256 };
