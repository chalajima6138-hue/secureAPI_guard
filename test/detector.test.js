'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { inspect, meetsThreshold, highestSeverity } = require('../src/inspection/detector');

const q = (value) => inspect({ path: '/items', query: { q: value } });
const ids = (r) => r.findings.map((f) => f.ruleId);

test('benign inputs produce no findings', () => {
  for (const v of ['laptop', 'john.doe@example.com', 'blue shoes size 42', 'Tom & Jerry', "O'Brien", 'select a seat', 'price < 20 and > 5']) {
    assert.deepStrictEqual(ids(q(v)), [], `false positive on: ${v}`);
  }
});

test('detects classic SQL injection payloads', () => {
  const cases = {
    "' OR '1'='1": 'sqli-tautology-quoted',
    "1 OR 1=1": 'sqli-tautology-numeric',
    "x' UNION SELECT username,password FROM users--": 'sqli-union-select',
    "1; DROP TABLE users": 'sqli-stacked-query',
    "admin'--": 'sqli-comment-terminator',
    "1 AND SLEEP(5)": 'sqli-time-based',
    "1 union/**/select 1,2": 'sqli-union-select',
    "SELECT * FROM information_schema.tables": 'sqli-schema-probe',
  };
  for (const [payload, rule] of Object.entries(cases)) {
    assert.ok(ids(q(payload)).includes(rule), `${payload} should trigger ${rule}, got ${ids(q(payload))}`);
  }
});

test('detects XSS payloads', () => {
  const cases = {
    '<script>alert(1)</script>': 'xss-script-tag',
    '<img src=x onerror=alert(1)>': 'xss-event-handler',
    'javascript:alert(1)': 'xss-javascript-uri',
    '<iframe src="//evil.test"></iframe>': 'xss-embedding-tag',
    '<svg/onload=alert(1)>': 'xss-event-handler',
  };
  for (const [payload, rule] of Object.entries(cases)) {
    assert.ok(ids(q(payload)).includes(rule), `${payload} should trigger ${rule}, got ${ids(q(payload))}`);
  }
});

test('detects URL-encoded, double-encoded and entity-encoded payloads', () => {
  assert.ok(ids(q('%3Cscript%3Ealert(1)%3C/script%3E')).includes('xss-script-tag'));
  assert.ok(ids(q('%253Cscript%253E')).includes('xss-script-tag'));
  assert.ok(ids(q('&lt;script&gt;')).includes('xss-script-tag'));
  assert.ok(ids(q("%27%20OR%20%271%27%3D%271")).includes('sqli-tautology-quoted'));
});

test('inspects nested JSON bodies, keys and headers', () => {
  const r = inspect({
    path: '/api',
    body: { user: { profile: [{ bio: '<script>x</script>' }] }, 'a\' OR \'1\'=\'1': 1 },
    headers: { 'user-agent': "' UNION SELECT 1--" },
  });
  const locs = r.findings.map((f) => f.location);
  assert.ok(locs.some((l) => l.startsWith('body.user.profile[0].bio')));
  assert.ok(locs.some((l) => l.includes('<key>')));
  assert.ok(locs.includes('header:user-agent'));
});

test('does not inspect authorization or cookie headers', () => {
  const r = inspect({ path: '/', headers: { authorization: "' OR '1'='1", cookie: '<script>' } });
  assert.deepStrictEqual(r.findings, []);
});

test('severity helpers', () => {
  const r = q('<script>1</script>');
  assert.strictEqual(highestSeverity(r.findings), 'high');
  assert.strictEqual(meetsThreshold(r.findings, 'high'), true);
  const low = q('document.cookie');
  assert.strictEqual(meetsThreshold(low.findings, 'medium'), false);
  assert.strictEqual(meetsThreshold(low.findings, 'low'), true);
});

test('bounded work on hostile input (deep nesting, huge strings)', () => {
  let deep = 'x';
  for (let i = 0; i < 200; i += 1) deep = { a: deep };
  const start = Date.now();
  const r = inspect({ path: '/', body: deep });
  assert.strictEqual(r.truncated, true);
  inspect({ path: '/', query: { q: 'a'.repeat(5_000_000) } });
  assert.ok(Date.now() - start < 2000, 'inspection should stay fast');
});
