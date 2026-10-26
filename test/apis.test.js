'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { startEnv, registerUser, addApi, viaGateway } = require('./helpers');
const { isPrivateAddress, parseUpstreamUrl } = require('../src/ssrf');
const { loadConfig } = require('../src/config');

test('API registration: validation, one-time key, hashed storage', async (t) => {
  const env = await startEnv();
  t.after(() => env.close());
  const { c } = await registerUser(env.base);

  const valid = { name: 'Orders', environment: 'production', upstreamUrl: env.backend.url };
  for (const bad of [
    { ...valid, name: '' }, { ...valid, name: 'x'.repeat(81) }, { ...valid, environment: 'prod' },
    { ...valid, upstreamUrl: 'not a url' }, { ...valid, upstreamUrl: 'ftp://example.com' }, { ...valid, mode: 'kill' },
    { ...valid, blockThreshold: 'extreme' }, { ...valid, maxBodyKb: 0 }, { ...valid, maxBodyKb: 99999 }, { ...valid, maxBodyKb: '5' },
    { ...valid, upstreamUrl: 'http://user:pw@example.com' }, { ...valid, upstreamUrl: `${env.backend.url}/x?y=1` },
  ]) {
    assert.strictEqual((await c.post('/api/apis', bad)).status, 400, `should reject ${JSON.stringify(bad)}`);
  }

  // blocking needs explicit acknowledgement
  assert.strictEqual((await c.post('/api/apis', { ...valid, mode: 'blocking' })).status, 400);

  const res = await c.post('/api/apis', valid);
  assert.strictEqual(res.status, 201);
  assert.match(res.json.apiKey, /^sag_[A-Za-z0-9_-]{30,}$/);
  assert.strictEqual(res.json.api.mode, 'monitoring', 'safe default is monitoring');
  assert.strictEqual(res.json.api.connectionStatus, 'awaiting_traffic');
  assert.strictEqual(res.json.api.health, 'unknown');
  assert.ok(!JSON.stringify(res.json.api).includes(res.json.apiKey));

  // key shown only once; only a hash is stored
  const again = await c.get(`/api/apis/${res.json.api.id}`);
  assert.ok(!again.text.includes(res.json.apiKey));
  assert.ok(!again.text.includes('key_hash') && !again.text.includes('keyHash'));
  const stored = env.db.prepare('SELECT key_hash, key_prefix FROM apis WHERE id = ?').get(res.json.api.id);
  assert.notStrictEqual(stored.key_hash, res.json.apiKey);
  assert.strictEqual(stored.key_hash.length, 64);

  // blocking with acknowledgement
  const blocking = await c.post('/api/apis', { ...valid, name: 'B', mode: 'blocking', confirmBlocking: true });
  assert.strictEqual(blocking.status, 201);
  assert.strictEqual(blocking.json.api.mode, 'blocking');

  // switching to blocking later also needs acknowledgement
  assert.strictEqual((await c.patch(`/api/apis/${res.json.api.id}`, { mode: 'blocking' })).status, 400);
  assert.strictEqual((await c.patch(`/api/apis/${res.json.api.id}`, { mode: 'blocking', confirmBlocking: true })).status, 200);
});

test('API key rotation invalidates the old key', async (t) => {
  const env = await startEnv();
  t.after(() => env.close());
  const { c } = await registerUser(env.base);
  const { api, key } = await addApi(c, env);
  assert.strictEqual((await viaGateway(env, api, key, '/ok')).status, 200);
  const rotated = await c.post(`/api/apis/${api.id}/rotate-key`);
  assert.strictEqual(rotated.status, 200);
  assert.strictEqual((await viaGateway(env, api, key, '/ok')).status, 401, 'old key rejected');
  assert.strictEqual((await viaGateway(env, api, rotated.json.apiKey, '/ok')).status, 200, 'new key accepted');
});

test('API limit per customer', async (t) => {
  const env = await startEnv({ maxApisPerCustomer: 2 });
  t.after(() => env.close());
  const { c } = await registerUser(env.base);
  await addApi(c, env); await addApi(c, env);
  const third = await c.post('/api/apis', { name: 'x', environment: 'development', upstreamUrl: env.backend.url });
  assert.strictEqual(third.status, 409);
});

test('customer data isolation: APIs, configuration, events and metrics', async (t) => {
  const env = await startEnv();
  t.after(() => env.close());
  const a = await registerUser(env.base, 'alice');
  const b = await registerUser(env.base, 'bob');
  const { api, key } = await addApi(a.c, env, { name: 'Alice API' });
  await viaGateway(env, api, key, '/items?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E');
  await viaGateway(env, api, key, '/items?ok=1');

  assert.strictEqual((await a.c.get('/api/events')).json.events.length, 1);
  const eventId = (await a.c.get('/api/events')).json.events[0].id;

  // Bob sees nothing of Alice's
  assert.deepStrictEqual((await b.c.get('/api/apis')).json.apis, []);
  assert.deepStrictEqual((await b.c.get('/api/events')).json.events, []);
  const sum = (await b.c.get('/api/dashboard/summary')).json;
  assert.strictEqual(sum.totals.inspected, 0);
  assert.strictEqual(sum.apis.length, 0);

  // Direct object access is a 404 (existence is not leaked)
  assert.strictEqual((await b.c.get(`/api/apis/${api.id}`)).status, 404);
  assert.strictEqual((await b.c.patch(`/api/apis/${api.id}`, { name: 'hijacked', mode: 'blocking', confirmBlocking: true })).status, 404);
  assert.strictEqual((await b.c.post(`/api/apis/${api.id}/rotate-key`)).status, 404);
  assert.strictEqual((await b.c.del(`/api/apis/${api.id}`)).status, 404);
  assert.strictEqual((await b.c.get(`/api/events/${eventId}`)).status, 404);
  assert.strictEqual((await b.c.get(`/api/events?apiId=${api.id}`)).status, 404);
  assert.strictEqual((await b.c.get(`/api/dashboard/summary?apiId=${api.id}`)).status, 404);
  assert.strictEqual((await b.c.get(`/api/dashboard/timeseries?apiId=${api.id}`)).status, 404);

  // Alice's API is unchanged
  const after = (await a.c.get(`/api/apis/${api.id}`)).json.api;
  assert.strictEqual(after.name, 'Alice API');
  assert.strictEqual(after.mode, 'monitoring');
  assert.strictEqual((await a.c.get(`/api/events/${eventId}`)).status, 200);
});

test('SSRF: prohibited upstream destinations are refused at registration', async (t) => {
  const env = await startEnv({ allowPrivateUpstreams: false, allowHttpUpstreams: true });
  t.after(() => env.close());
  const { c } = await registerUser(env.base);
  const targets = [
    'http://localhost:8080', 'http://127.0.0.1', 'http://127.1', 'http://2130706433', 'http://0x7f000001',
    'http://169.254.169.254/latest/meta-data', 'http://[::1]', 'http://[::ffff:127.0.0.1]', 'http://10.0.0.5', 'http://172.16.4.4',
    'http://192.168.0.10', 'http://metadata.google.internal', 'http://foo.localhost', 'http://db.internal', 'http://0.0.0.0', 'http://[fd00::1]',
  ];
  for (const upstreamUrl of targets) {
    const res = await c.post('/api/apis', { name: 'x', environment: 'development', upstreamUrl });
    assert.strictEqual(res.status, 400, `${upstreamUrl} should be refused, got ${res.status}`);
  }
  assert.strictEqual(env.db.prepare('SELECT COUNT(*) AS n FROM apis').get().n, 0);
});

test('SSRF: https required when http upstreams are disabled; unit checks', () => {
  const prod = loadConfig({}, { allowHttpUpstreams: false, allowPrivateUpstreams: false });
  assert.strictEqual(parseUpstreamUrl('http://example.com', prod).ok, false);
  assert.strictEqual(parseUpstreamUrl('https://example.com/v1/', prod).normalized, 'https://example.com/v1');
  for (const ip of ['127.0.0.1', '10.255.255.255', '169.254.169.254', '192.168.1.1', '172.31.0.1', '100.64.0.1', '::1', 'fe80::1', '::ffff:10.0.0.1']) {
    assert.strictEqual(isPrivateAddress(ip), true, ip);
  }
  for (const ip of ['8.8.8.8', '1.1.1.1', '93.184.216.34', '2606:4700:4700::1111']) assert.strictEqual(isPrivateAddress(ip), false, ip);
});

test('SSRF: gateway refuses to connect to private upstreams even if a record slipped through', async (t) => {
  const env = await startEnv({ allowPrivateUpstreams: false });
  t.after(() => env.close());
  const { c } = await registerUser(env.base);
  // Create a legitimate record, then simulate stored/rebinding data pointing at private destinations.
  env.config.allowPrivateUpstreams = true;
  const { api, key } = await addApi(c, env);
  env.config.allowPrivateUpstreams = false;
  for (const target of [env.backend.url, `http://localhost:${env.backend.port}`]) {
    env.db.prepare('UPDATE apis SET upstream_url = ? WHERE id = ?').run(target, api.id);
    const before = env.backend.received.length;
    const res = await viaGateway(env, api, key, '/secret');
    assert.strictEqual(res.status, 502, target);
    assert.strictEqual(env.backend.received.length, before, `backend must not be contacted for ${target}`);
  }
});

test('SSRF: link-local/metadata addresses stay blocked even when private upstreams are allowed for development', async (t) => {
  const env = await startEnv({ allowPrivateUpstreams: true });
  t.after(() => env.close());
  const { c } = await registerUser(env.base);
  for (const upstreamUrl of ['http://169.254.169.254/latest/meta-data', 'http://[fe80::1]', 'http://0.0.0.0', 'http://metadata.google.internal', 'http://[::ffff:169.254.169.254]', 'http://2852039166']) {
    assert.strictEqual((await c.post('/api/apis', { name: 'x', environment: 'development', upstreamUrl })).status, 400, upstreamUrl);
  }
  // loopback remains allowed in this development-only mode (used by the test backends)
  assert.strictEqual((await c.post('/api/apis', { name: 'ok', environment: 'development', upstreamUrl: env.backend.url })).status, 201);
  // and the gateway re-checks at connect time
  const { api, key } = await addApi(c, env);
  env.db.prepare('UPDATE apis SET upstream_url = ? WHERE id = ?').run('http://169.254.169.254', api.id);
  assert.strictEqual((await viaGateway(env, api, key, '/latest/meta-data')).status, 502);
});
