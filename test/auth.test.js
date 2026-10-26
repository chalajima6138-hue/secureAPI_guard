'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { startEnv, client, registerUser } = require('./helpers');

test('registration, login, logout and session protection', async (t) => {
  const env = await startEnv();
  t.after(() => env.close());
  const c = client(env.base);

  assert.strictEqual((await c.get('/api/auth/me')).status, 401, 'unauthenticated /me');
  assert.strictEqual((await c.get('/api/apis')).status, 401);
  assert.strictEqual((await c.get('/api/dashboard/summary')).status, 401);
  assert.strictEqual((await c.get('/api/events')).status, 401);

  // validation
  assert.strictEqual((await c.post('/api/auth/register', { email: 'nope', password: 'longenoughpassword' })).status, 400);
  assert.strictEqual((await c.post('/api/auth/register', { email: 'a@example.com', password: 'short' })).status, 400);
  assert.strictEqual((await c.post('/api/auth/register', { email: 'a@example.com', password: 'x'.repeat(200) })).status, 400);
  assert.strictEqual((await c.post('/api/auth/register', { email: { $ne: 1 }, password: 'longenoughpassword' })).status, 400);
  assert.strictEqual((await c.post('/api/auth/register', {})).status, 400);

  const reg = await c.post('/api/auth/register', { email: 'Alice@Example.com', password: 'correct-horse-battery' });
  assert.strictEqual(reg.status, 201);
  assert.strictEqual(reg.json.user.email, 'alice@example.com');
  assert.strictEqual((await c.get('/api/auth/me')).status, 200, 'registration logs the user in');

  // cookie flags
  const cookie = reg.setCookie[0];
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Lax/);
  assert.match(cookie, /Path=\//);

  // duplicate
  const dup = await client(env.base).post('/api/auth/register', { email: 'alice@example.com', password: 'another-long-password' });
  assert.strictEqual(dup.status, 409);

  // password is hashed, not stored in plain text
  const row = env.db.prepare('SELECT password_hash FROM users WHERE email = ?').get('alice@example.com');
  assert.ok(row.password_hash.startsWith('scrypt$'));
  assert.ok(!row.password_hash.includes('correct-horse-battery'));

  // logout destroys the session server-side
  const sessionCookie = reg.setCookie[0].split(';')[0];
  assert.strictEqual((await c.post('/api/auth/logout')).status, 200);
  assert.strictEqual((await c.get('/api/auth/me')).status, 401);
  const replay = await fetch(`${env.base}/api/auth/me`, { headers: { cookie: sessionCookie } });
  assert.strictEqual(replay.status, 401, 'old session token must not work after logout');

  // login
  const c2 = client(env.base);
  const bad = await c2.post('/api/auth/login', { email: 'alice@example.com', password: 'wrong-password-here' });
  assert.strictEqual(bad.status, 401);
  const unknown = await c2.post('/api/auth/login', { email: 'ghost@example.com', password: 'wrong-password-here' });
  assert.strictEqual(unknown.status, 401);
  assert.strictEqual(bad.json.message, unknown.json.message, 'no account enumeration');
  const ok = await c2.post('/api/auth/login', { email: 'ALICE@example.com', password: 'correct-horse-battery' });
  assert.strictEqual(ok.status, 200);
  assert.strictEqual((await c2.get('/api/auth/me')).status, 200);
});

test('Secure cookie attribute is set when COOKIE_SECURE is enabled', async (t) => {
  const env = await startEnv({ cookieSecure: true });
  t.after(() => env.close());
  const res = await client(env.base).post('/api/auth/register', { email: 'sec@example.com', password: 'correct-horse-battery' });
  assert.match(res.setCookie[0], /Secure/);
});

test('CSRF guard: cross-origin and non-JSON state-changing requests are rejected', async (t) => {
  const env = await startEnv();
  t.after(() => env.close());
  const { c } = await registerUser(env.base);
  const cross = await c.post('/api/apis', { name: 'x' }, { origin: 'http://evil.example' });
  assert.strictEqual(cross.status, 403);
  const form = await fetch(`${env.base}/api/auth/login`, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'email=a&password=b',
  });
  assert.strictEqual(form.status, 415);
  const malformed = await fetch(`${env.base}/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{bad' });
  assert.strictEqual(malformed.status, 400);
  assert.ok(!malformed.headers.has('x-powered-by'));
});

test('security headers on pages and API responses; no stack traces', async (t) => {
  const env = await startEnv();
  t.after(() => env.close());
  for (const path of ['/', '/api/health']) {
    const res = await fetch(env.base + path);
    assert.match(res.headers.get('content-security-policy'), /default-src 'self'/);
    assert.match(res.headers.get('content-security-policy'), /frame-ancestors 'none'/);
    assert.strictEqual(res.headers.get('x-content-type-options'), 'nosniff');
    assert.strictEqual(res.headers.get('x-frame-options'), 'DENY');
    assert.strictEqual(res.headers.get('referrer-policy'), 'no-referrer');
    assert.strictEqual(res.headers.get('x-powered-by'), null);
  }
  const missing = await fetch(`${env.base}/api/nope`);
  assert.strictEqual(missing.status, 404);
  assert.ok(!(await missing.text()).includes('at '), 'no stack trace');
});

test('HSTS only in production config', async (t) => {
  const env = await startEnv({ production: true, cookieSecure: true });
  t.after(() => env.close());
  const res = await fetch(`${env.base}/api/health`);
  assert.match(res.headers.get('strict-transport-security'), /max-age=/);
});

test('auth endpoints are rate limited', async (t) => {
  const env = await startEnv({ authRateLimit: { windowMs: 60000, max: 5 } });
  t.after(() => env.close());
  const c = client(env.base);
  const statuses = [];
  for (let i = 0; i < 8; i += 1) statuses.push((await c.post('/api/auth/login', { email: 'x@example.com', password: 'wrong-password-1' })).status);
  assert.deepStrictEqual(statuses.slice(0, 5), [401, 401, 401, 401, 401]);
  assert.ok(statuses.slice(5).every((s) => s === 429), `expected 429s after limit, got ${statuses}`);
});
