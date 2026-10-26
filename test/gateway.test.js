'use strict';
const http = require('node:http');
const test = require('node:test');
const assert = require('node:assert');
const { startEnv, registerUser, addApi, viaGateway } = require('./helpers');

const XSS = '%3Cscript%3Ealert(1)%3C%2Fscript%3E';
const SQLI = encodeURIComponent("' UNION SELECT username,password FROM users--");

async function setup(apiExtra = {}, cfg = {}, appOptions = {}) {
  const env = await startEnv(cfg, appOptions);
  const { c } = await registerUser(env.base);
  const { api, key } = await addApi(c, env, apiExtra);
  return { env, c, api, key };
}

test('gateway authentication: missing, wrong and cross-API keys get an identical 401', async (t) => {
  const { env, c, api, key } = await setup();
  t.after(() => env.close());
  const other = await addApi(c, env, { name: 'Other' });
  const noKey = await fetch(`${env.base}/gateway/${api.id}/x`);
  const wrong = await viaGateway(env, api, 'sag_wrong', '/x');
  const cross = await viaGateway(env, api, other.key, '/x');
  const unknownApi = await viaGateway(env, { id: 'nonexistent' }, key, '/x');
  const bodies = await Promise.all([noKey, wrong, cross, unknownApi].map(async (r) => [r.status, await r.text()]));
  for (const [status, body] of bodies) { assert.strictEqual(status, 401); assert.strictEqual(body, bodies[0][1]); }
  assert.strictEqual(env.backend.received.length, 0, 'unauthenticated traffic never reaches the backend');
  assert.strictEqual(env.db.prepare('SELECT COUNT(*) AS n FROM requests').get().n, 0, 'unauthenticated traffic is not recorded as customer data');
});

test('normal requests are forwarded intact with tracing and without leaking the guard key', async (t) => {
  const { env, api, key } = await setup();
  t.after(() => env.close());
  const res = await viaGateway(env, api, key, '/v1/products?limit=10&name=widget', { headers: { authorization: 'Bearer customer-secret', 'x-custom': 'yes' } });
  assert.strictEqual(res.status, 200);
  assert.strictEqual((await res.json()).url, '/v1/products?limit=10&name=widget');
  assert.strictEqual(res.headers.get('x-guard-action'), 'allowed');
  const requestId = res.headers.get('x-request-id');
  assert.match(requestId, /^[0-9a-f-]{36}$/);
  const got = env.backend.received[0];
  assert.strictEqual(got.headers['x-request-id'], requestId);
  assert.strictEqual(got.headers['x-guard-key'], undefined, 'guard key must not reach the backend');
  assert.strictEqual(got.headers.authorization, 'Bearer customer-secret', "customer's own auth passes through to their backend");
  assert.strictEqual(got.headers['x-custom'], 'yes');
  assert.strictEqual(env.db.prepare('SELECT outcome FROM requests WHERE id = ?').get(requestId).outcome, 'allowed');
});

test('POST bodies (JSON) are forwarded byte-for-byte', async (t) => {
  const { env, api, key } = await setup();
  t.after(() => env.close());
  const payload = JSON.stringify({ name: 'Widget', qty: 3, note: 'plain text' });
  const res = await viaGateway(env, api, key, '/orders', { method: 'POST', body: payload, headers: { 'content-type': 'application/json' } });
  assert.strictEqual(res.status, 200);
  assert.strictEqual(env.backend.received[0].body, payload);
  assert.strictEqual(env.backend.received[0].method, 'POST');
});

test('upstream base path is honoured and dot-segments cannot escape it', async (t) => {
  const { env, c } = await setup();
  t.after(() => env.close());
  const created = await addApi(c, env, { upstreamUrl: `${env.backend.url}/v2` });
  // fetch() normalises dot-segments client-side, so send raw paths exactly as an attacker's client would.
  const raw = (path) => new Promise((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port: env.port, method: 'GET', path, headers: { 'x-guard-key': created.key } }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    r.on('error', reject); r.end();
  });
  const base = `/gateway/${created.api.id}`;
  assert.deepStrictEqual(
    [await raw(`${base}/users/1`), await raw(`${base}/../../admin`), await raw(`${base}/%2e%2e/%2e%2e/admin`), await raw(`${base}/a/..%2f..%2fadmin`)],
    [200, 200, 200, 200]);
  assert.deepStrictEqual(env.backend.received.map((r) => r.url.split('?')[0]), ['/v2/users/1', '/v2/admin', '/v2/admin', '/v2/a/..%2f..%2fadmin']);
});

test('monitoring mode: suspicious requests are recorded AND forwarded', async (t) => {
  const { env, api, key } = await setup({ mode: 'monitoring' });
  t.after(() => env.close());
  const res = await viaGateway(env, api, key, `/search?q=${SQLI}`);
  assert.strictEqual(res.status, 200, 'monitoring never blocks');
  assert.strictEqual(res.headers.get('x-guard-action'), 'logged');
  assert.strictEqual(env.backend.received.length, 1, 'request reached the backend');
  const req = env.db.prepare('SELECT * FROM requests WHERE id = ?').get(res.headers.get('x-request-id'));
  assert.strictEqual(req.outcome, 'logged');
  assert.strictEqual(req.suspicious, 1);
  const events = env.db.prepare('SELECT * FROM events WHERE request_id = ?').all(req.id);
  assert.ok(events.length >= 1);
  assert.ok(events.every((e) => e.action === 'logged' && e.response_status === 200 && e.category === 'sql_injection'));
  assert.ok(events.some((e) => e.rule_id === 'sqli-union-select'));
});

test('blocking mode: matching requests get 403 and never reach the backend', async (t) => {
  const { env, api, key } = await setup({ mode: 'blocking', confirmBlocking: true });
  t.after(() => env.close());
  const res = await viaGateway(env, api, key, `/search?q=${XSS}`);
  assert.strictEqual(res.status, 403);
  const body = await res.json();
  assert.strictEqual(body.error, 'request_blocked');
  assert.ok(body.requestId);
  assert.ok(!JSON.stringify(body).includes('script') && !JSON.stringify(body).includes('xss'), 'response does not reveal rule details');
  assert.strictEqual(env.backend.received.length, 0, 'blocked request must not reach the backend');
  const req = env.db.prepare('SELECT * FROM requests WHERE id = ?').get(body.requestId);
  assert.strictEqual(req.outcome, 'blocked');
  assert.strictEqual(env.db.prepare('SELECT action FROM events WHERE request_id = ?').get(body.requestId).action, 'blocked');
  // a clean request still passes in blocking mode
  assert.strictEqual((await viaGateway(env, api, key, '/search?q=shoes')).status, 200);
  assert.strictEqual(env.backend.received.length, 1);
});

test('blocking mode inspects JSON bodies, form bodies, paths and headers', async (t) => {
  const { env, api, key } = await setup({ mode: 'blocking', confirmBlocking: true });
  t.after(() => env.close());
  const json = await viaGateway(env, api, key, '/c', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ a: { b: ['ok', '<img src=x onerror=alert(1)>'] } }) });
  const form = await viaGateway(env, api, key, '/c', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'user=admin%27+OR+%271%27%3D%271&x=1' });
  const path = await viaGateway(env, api, key, `/files/${XSS}`);
  const header = await viaGateway(env, api, key, '/h', { headers: { 'user-agent': "' UNION SELECT 1,2--" } });
  assert.deepStrictEqual([json.status, form.status, path.status, header.status], [403, 403, 403, 403]);
  assert.strictEqual(env.backend.received.length, 0);
});

test('block threshold: lower-severity matches are logged but not blocked when below the threshold', async (t) => {
  const { env, api, key } = await setup({ mode: 'blocking', confirmBlocking: true, blockThreshold: 'high' });
  t.after(() => env.close());
  const low = await viaGateway(env, api, key, '/p?x=document.cookie');
  assert.strictEqual(low.status, 200);
  assert.strictEqual(low.headers.get('x-guard-action'), 'logged');
  assert.strictEqual(env.db.prepare('SELECT outcome FROM requests WHERE id = ?').get(low.headers.get('x-request-id')).outcome, 'logged');
  assert.strictEqual((await viaGateway(env, api, key, `/p?x=${XSS}`)).status, 403);
});

test('invalid requests: oversized bodies and unsupported methods are rejected before the backend', async (t) => {
  const { env, api, key } = await setup({ maxBodyKb: 1 });
  t.after(() => env.close());
  const big = await viaGateway(env, api, key, '/up', { method: 'POST', body: 'a'.repeat(2048), headers: { 'content-type': 'text/plain' } });
  assert.strictEqual(big.status, 413);
  // chunked body without Content-Length that grows past the limit
  const chunked = await new Promise((resolve, reject) => {
    const r = http.request(`${env.base}/gateway/${api.id}/up`, { method: 'POST', headers: { 'x-guard-key': key, 'content-type': 'text/plain' } }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    r.on('error', (e) => (e.code === 'ECONNRESET' ? resolve(413) : reject(e)));
    r.write('b'.repeat(900)); r.write('b'.repeat(900)); r.end();
  });
  assert.strictEqual(chunked, 413);
  const trace = await new Promise((resolve, reject) => {
    const r = http.request(`${env.base}/gateway/${api.id}/x`, { method: 'TRACE', headers: { 'x-guard-key': key } }, (res) => { res.resume(); resolve(res.statusCode); });
    r.on('error', reject); r.end();
  });
  assert.strictEqual(trace, 405);
  assert.strictEqual(env.backend.received.length, 0);
  const rows = env.db.prepare("SELECT outcome FROM requests WHERE outcome = 'rejected'").all();
  assert.strictEqual(rows.length, 3, 'rejections are recorded separately from inspected/blocked');
});

test('upstream failures: unreachable backend gives 502, slow backend gives 504, both recorded as errors', async (t) => {
  const { env, c, api, key } = await setup();
  t.after(() => env.close());
  const slow = await viaGateway(env, api, key, '/slow');
  assert.strictEqual(slow.status, 504);
  assert.strictEqual((await slow.json()).error, 'upstream_timeout');

  const dead = await addApi(c, env, { upstreamUrl: 'http://127.0.0.1:1' });
  const refused = await viaGateway(env, dead.api, dead.key, '/x');
  assert.strictEqual(refused.status, 502);
  const text = await refused.text();
  assert.ok(!text.includes('127.0.0.1') && !text.includes('ECONNREFUSED'), 'no internal details leak');

  const errs = env.db.prepare('SELECT COUNT(*) AS n FROM requests WHERE upstream_error = 1').get().n;
  assert.strictEqual(errs, 2);
  const view = (await c.get(`/api/apis/${dead.api.id}`)).json.api;
  assert.strictEqual(view.health, 'unavailable');
  assert.strictEqual(view.connectionStatus, 'active');
});

test('upstream redirects are passed to the client, never followed', async (t) => {
  const { env, api, key } = await setup();
  t.after(() => env.close());
  const res = await viaGateway(env, api, key, '/redirect');
  assert.strictEqual(res.status, 302);
  assert.match(res.headers.get('location'), /169\.254\.169\.254/);
  assert.strictEqual(env.backend.received.length, 1, 'gateway did not follow the redirect itself');
});

test('inspection errors: monitoring fails open, blocking fails closed, both recorded', async (t) => {
  const boom = () => { throw new Error('detector crashed'); };
  const mon = await setup({ mode: 'monitoring' }, {}, { inspect: boom });
  t.after(() => mon.env.close());
  const ok = await viaGateway(mon.env, mon.api, mon.key, '/x');
  assert.strictEqual(ok.status, 200);
  assert.strictEqual(mon.env.db.prepare('SELECT outcome FROM requests WHERE id = ?').get(ok.headers.get('x-request-id')).outcome, 'inspection_error');

  const blk = await setup({ mode: 'blocking', confirmBlocking: true }, {}, { inspect: boom });
  t.after(() => blk.env.close());
  const denied = await viaGateway(blk.env, blk.api, blk.key, '/x');
  assert.strictEqual(denied.status, 503);
  assert.strictEqual(blk.env.backend.received.length, 0);
  assert.ok(!(await denied.text()).includes('crashed'));
});

test('gateway rate limiting returns 429 and the backend is protected', async (t) => {
  const { env, api, key } = await setup({}, { gatewayRateLimit: { windowMs: 60000, max: 3 } });
  t.after(() => env.close());
  const statuses = [];
  for (let i = 0; i < 6; i += 1) statuses.push((await viaGateway(env, api, key, '/x')).status);
  assert.deepStrictEqual(statuses, [200, 200, 200, 429, 429, 429]);
  assert.strictEqual(env.backend.received.length, 3);
});

test('stored data never contains credentials or request bodies', async (t) => {
  const { env, api, key } = await setup({ mode: 'blocking', confirmBlocking: true });
  t.after(() => env.close());
  await viaGateway(env, api, key, '/login?token=URLTOKEN123', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer SECRETBEARER999', cookie: 'sid=COOKIEVALUE777' },
    body: JSON.stringify({ password: 'hunter2-PASSWORD', note: '<script>alert(1)</script>' }),
  });
  const dump = JSON.stringify([
    env.db.prepare('SELECT * FROM requests').all(), env.db.prepare('SELECT * FROM events').all(),
  ]);
  for (const secret of ['SECRETBEARER999', 'COOKIEVALUE777', 'hunter2-PASSWORD', 'URLTOKEN123', 'alert(1)', key]) {
    assert.ok(!dump.includes(secret), `${secret} must not be stored`);
  }
});

test('log-injection: control characters in paths and keys are neutralised before storage', async (t) => {
  const { env, api, key } = await setup({ mode: 'monitoring' });
  t.after(() => env.close());
  await viaGateway(env, api, key, '/a%0d%0aFAKE-LOG-LINE%20level=error');
  await viaGateway(env, api, key, '/k', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ '<script>\n\r"fake": 1': 'x' }) });
  const paths = env.db.prepare('SELECT path FROM requests').all().map((r) => r.path);
  const locs = env.db.prepare('SELECT location FROM events').all().map((r) => r.location);
  for (const v of [...paths, ...locs]) assert.ok(!/[\r\n\x00-\x1f]/.test(v), `unsafe characters in ${JSON.stringify(v)}`);
});
