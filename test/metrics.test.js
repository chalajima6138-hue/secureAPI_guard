'use strict';
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert');
const { startEnv, registerUser, addApi, viaGateway } = require('./helpers');

const XSS = '%3Cscript%3Ealert(1)%3C%2Fscript%3E';
const SQLI = encodeURIComponent("' UNION SELECT username,password FROM users--");

test('dashboard shows honest empty states for a new customer', async (t) => {
  const env = await startEnv();
  t.after(() => env.close());
  const { c } = await registerUser(env.base);
  const s = (await c.get('/api/dashboard/summary')).json;
  assert.deepStrictEqual(s.totals, { inspected: 0, allowed: 0, blocked: 0, suspicious: 0, rejected: 0, errors: 0 });
  assert.deepStrictEqual([s.byCategory, s.apis], [[], []]);
  const ts = (await c.get('/api/dashboard/timeseries')).json;
  assert.ok(ts.points.length >= 24 && ts.points.every((p) => p.inspected === 0));
  assert.deepStrictEqual((await c.get('/api/events')).json, { events: [], nextBefore: null });
  assert.strictEqual((await c.get('/api/dashboard/summary?range=1y')).status, 400);
});

test('metrics, events and event details match the traffic actually sent', async (t) => {
  const env = await startEnv();
  t.after(() => env.close());
  const { c } = await registerUser(env.base);
  const one = await addApi(c, env, { name: 'Monitored', mode: 'monitoring' });
  const two = await addApi(c, env, { name: 'Enforced', mode: 'blocking', confirmBlocking: true, maxBodyKb: 1 });

  for (let i = 0; i < 3; i += 1) await viaGateway(env, one.api, one.key, `/ok?i=${i}`);
  await viaGateway(env, one.api, one.key, `/s?q=${XSS}`);
  await viaGateway(env, one.api, one.key, `/s?q=${XSS}&b=2`);
  await viaGateway(env, one.api, one.key, `/s?q=${SQLI}`);
  assert.strictEqual((await viaGateway(env, two.api, two.key, `/s?q=${XSS}`)).status, 403);
  assert.strictEqual((await viaGateway(env, two.api, two.key, '/fine')).status, 200);
  assert.strictEqual((await viaGateway(env, two.api, two.key, '/big', { method: 'POST', body: 'x'.repeat(4000), headers: { 'content-type': 'text/plain' } })).status, 413);

  const s = (await c.get('/api/dashboard/summary')).json;
  // inspected = allowed + blocked; rejected-before-inspection is reported separately
  assert.deepStrictEqual(s.totals, { inspected: 8, allowed: 7, blocked: 1, suspicious: 4, rejected: 1, errors: 0 });
  assert.deepStrictEqual(Object.fromEntries(s.byCategory.map((r) => [r.category, r.count])), { xss: 3, sql_injection: 1 });
  const per = Object.fromEntries(s.apis.map((a) => [a.name, a.totals]));
  assert.deepStrictEqual(per.Monitored, { inspected: 6, allowed: 6, blocked: 0, suspicious: 3, rejected: 0, errors: 0 });
  assert.deepStrictEqual(per.Enforced, { inspected: 2, allowed: 1, blocked: 1, suspicious: 1, rejected: 1, errors: 0 });
  const byName = Object.fromEntries(s.apis.map((a) => [a.name, a]));
  assert.strictEqual(byName.Monitored.connectionStatus, 'active');
  assert.strictEqual(byName.Monitored.health, 'healthy');

  // filtering and time series are consistent with the summary
  const f = (await c.get(`/api/dashboard/summary?apiId=${two.api.id}`)).json;
  assert.deepStrictEqual(f.totals, per.Enforced);
  const series = (await c.get('/api/dashboard/timeseries?range=24h')).json;
  const sum = (k) => series.points.reduce((a, p) => a + p[k], 0);
  assert.deepStrictEqual([sum('inspected'), sum('suspicious'), sum('blocked')], [8, 4, 1]);
  for (const range of ['7d', '30d']) {
    const r = (await c.get(`/api/dashboard/timeseries?range=${range}`)).json;
    assert.strictEqual(r.points.reduce((a, p) => a + p.inspected, 0), 8, range);
  }
  assert.strictEqual((await c.get(`/api/dashboard/timeseries?apiId=${one.api.id}`)).json.points.reduce((a, p) => a + p.inspected, 0), 6);

  // an old last-seen timestamp turns the connection idle
  env.db.prepare('UPDATE apis SET last_seen_at = ? WHERE id = ?').run(Date.now() - 3600e3, one.api.id);
  assert.strictEqual((await c.get(`/api/apis/${one.api.id}`)).json.api.connectionStatus, 'idle');

  // events list, filters, severity/category
  const all = (await c.get('/api/events?limit=100')).json.events;
  assert.strictEqual(all.length, 4);
  assert.deepStrictEqual(all.map((e) => e.ts), [...all.map((e) => e.ts)].sort((a, b) => b - a), 'newest first');
  assert.strictEqual((await c.get('/api/events?category=xss')).json.events.length, 3);
  assert.strictEqual((await c.get('/api/events?category=sql_injection')).json.events.length, 1);
  assert.strictEqual((await c.get('/api/events?category=bogus')).status, 400);
  assert.strictEqual((await c.get(`/api/events?apiId=${two.api.id}`)).json.events[0].action, 'blocked');
  assert.strictEqual((await c.get('/api/events?before=garbage')).status, 400);

  // pagination with one event per page returns every event exactly once
  const seen = [];
  let cursor = null;
  for (let i = 0; i < 10; i += 1) {
    const page = (await c.get(`/api/events?limit=1${cursor ? `&before=${cursor}` : ''}`)).json;
    seen.push(...page.events.map((e) => e.id));
    cursor = page.nextBefore;
    if (!cursor) break;
  }
  assert.deepStrictEqual([...seen].sort(), all.map((e) => e.id).sort());

  // event investigation: safe details only
  const blocked = all.find((e) => e.action === 'blocked');
  const detail = (await c.get(`/api/events/${blocked.id}`)).json.event;
  assert.strictEqual(detail.apiName, 'Enforced');
  assert.strictEqual(detail.ruleId, 'xss-script-tag');
  assert.strictEqual(detail.outcome, 'blocked');
  assert.strictEqual(detail.responseStatus, 403);
  assert.strictEqual(detail.mode, 'blocking');
  assert.match(detail.explanation, /script tag/i);
  assert.ok(detail.requestId && detail.ts && detail.path === '/s');
  assert.deepStrictEqual(Object.keys(detail).filter((k) => /body|header|cookie|authorization|key|stack/i.test(k)), ['bodyInspected']);
  assert.strictEqual((await c.get('/api/events/00000000-0000-0000-0000-000000000000')).status, 404);

  // deleting an API removes its records
  await c.del(`/api/apis/${two.api.id}`);
  assert.strictEqual(env.db.prepare('SELECT COUNT(*) AS n FROM requests WHERE api_id = ?').get(two.api.id).n, 0);
  assert.strictEqual(env.db.prepare('SELECT COUNT(*) AS n FROM events WHERE api_id = ?').get(two.api.id).n, 0);
  assert.strictEqual((await viaGateway(env, two.api, two.key, '/x')).status, 401, 'deleted API no longer accepts traffic');
});

test('static pages: served, CSP-compatible (no inline script/style/handlers), no placeholder statistics', () => {
  const dir = path.join(__dirname, '..', 'public');
  for (const page of ['index.html', 'login.html', 'register.html', 'dashboard.html']) {
    const html = fs.readFileSync(path.join(dir, page), 'utf8');
    assert.ok(!/<script(?![^>]*\bsrc=)[^>]*>/i.test(html), `${page}: inline <script>`);
    assert.ok(!/\sstyle\s*=/i.test(html), `${page}: inline style attribute`);
    assert.ok(!/\son[a-z]+\s*=/i.test(html), `${page}: inline event handler`);
  }
  const dash = fs.readFileSync(path.join(dir, 'dashboard.html'), 'utf8');
  assert.ok(!/>\s*\d{2,}\s*</.test(dash), 'dashboard has no hard-coded statistics');
  const js = fs.readFileSync(path.join(dir, 'js', 'dashboard.js'), 'utf8');
  assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write/.test(js), 'dashboard renders data with textContent only');
});

test('landing, auth and dashboard pages are served', async (t) => {
  const env = await startEnv();
  t.after(() => env.close());
  for (const p of ['/', '/login', '/register', '/dashboard', '/css/app.css', '/js/dashboard.js']) {
    const res = await fetch(env.base + p);
    assert.strictEqual(res.status, 200, p);
    assert.match(res.headers.get('content-security-policy'), /script-src 'self'/, p);
  }
  const home = await (await fetch(env.base)).text();
  assert.match(home, /Current limitations/);
  assert.match(home, /heuristic/i);
});
