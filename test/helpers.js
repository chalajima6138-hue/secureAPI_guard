'use strict';
const http = require('node:http');
const { createApp } = require('../src/app');
const { loadConfig } = require('../src/config');

function listen(server) {
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}

/** Controlled local backend that records everything it receives. */
async function startBackend() {
  const received = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      received.push({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString() });
      if (req.url.startsWith('/slow')) return; // never responds
      if (req.url.startsWith('/redirect')) { res.writeHead(302, { Location: 'http://169.254.169.254/latest/meta-data/' }); return res.end(); }
      res.writeHead(200, { 'content-type': 'application/json', connection: 'close' });
      return res.end(JSON.stringify({ ok: true, url: req.url }));
    });
  });
  const port = await listen(server);
  return { port, url: `http://127.0.0.1:${port}`, received, close: () => { server.closeAllConnections(); return new Promise((r) => server.close(r)); } };
}

async function startEnv(configOverrides = {}, appOptions = {}) {
  const config = loadConfig({}, {
    dbPath: ':memory:',
    allowPrivateUpstreams: true, // tests use loopback backends
    upstreamTimeoutMs: 400,
    authRateLimit: { windowMs: 60000, max: 1000 },
    apiRateLimit: { windowMs: 60000, max: 100000 },
    gatewayRateLimit: { windowMs: 60000, max: 100000 },
    ...configOverrides,
  });
  const ctx = createApp({ config, ...appOptions });
  const server = http.createServer(ctx.app);
  const port = await listen(server);
  const backend = await startBackend();
  const base = `http://127.0.0.1:${port}`;
  return {
    ...ctx, base, backend, port,
    async close() {
      await backend.close();
      server.closeAllConnections();
      await new Promise((r) => server.close(r));
      ctx.close();
    },
  };
}

/** Minimal cookie-aware JSON client. */
function client(base) {
  let cookie = '';
  async function call(method, path, body, headers = {}) {
    const res = await fetch(base + path, {
      method,
      headers: { ...(body !== undefined ? { 'content-type': 'application/json' } : {}), ...(cookie ? { cookie } : {}), ...headers },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      redirect: 'manual',
    });
    const set = res.headers.getSetCookie();
    if (set.length) {
      const first = set[0].split(';')[0];
      cookie = first.endsWith('=') ? '' : first;
    }
    let json = null;
    const text = await res.text();
    try { json = JSON.parse(text); } catch (_) { /* not json */ }
    return { status: res.status, json, text, headers: res.headers, setCookie: set };
  }
  return {
    get: (p, h) => call('GET', p, undefined, h),
    post: (p, b, h) => call('POST', p, b === undefined ? undefined : b, h),
    patch: (p, b, h) => call('PATCH', p, b, h),
    del: (p, h) => call('DELETE', p, undefined, h),
  };
}

let counter = 0;
async function registerUser(base, label = 'user') {
  counter += 1;
  const c = client(base);
  const email = `${label}${counter}@example.com`;
  const res = await c.post('/api/auth/register', { email, password: 'correct-horse-battery' });
  if (res.status !== 201) throw new Error(`register failed: ${res.status} ${res.text}`);
  return { c, email, user: res.json.user };
}

async function addApi(c, env, extra = {}) {
  const res = await c.post('/api/apis', {
    name: 'Test API', environment: 'development', upstreamUrl: env.backend.url, ...extra,
  });
  if (res.status !== 201) throw new Error(`addApi failed: ${res.status} ${res.text}`);
  return { api: res.json.api, key: res.json.apiKey };
}

/** Send a request through the gateway. */
function viaGateway(env, api, key, path, { method = 'GET', body, headers = {} } = {}) {
  return fetch(`${env.base}/gateway/${api.id}${path}`, {
    method,
    headers: { 'x-guard-key': key, ...headers },
    body,
    redirect: 'manual',
  });
}

module.exports = { startEnv, startBackend, client, registerUser, addApi, viaGateway };
