'use strict';
const crypto = require('node:crypto');
const http = require('node:http');
const https = require('node:https');
const express = require('express');
const { sha256 } = require('./auth');
const { rateLimit } = require('./middleware/security');
const detector = require('./inspection/detector');
const net = require('node:net');
const { createSafeLookup, isProhibitedAddress } = require('./ssrf');

const ALLOWED_METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);
const HOP_BY_HOP = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade']);
const MAX_STORED_FINDINGS = 10;

/** Make a user-controlled value safe to store and log: printable ASCII only, bounded length. */
function sanitizeLog(value, max) {
  return String(value).replace(/[^\x20-\x7e]/g, '?').slice(0, max);
}
const sanitizeLocation = (v) => String(v).replace(/[^A-Za-z0-9_.:\[\]<>-]/g, '_').slice(0, 60);

function safeEqualHex(a, b) {
  const ba = Buffer.from(a, 'hex');
  const bb = Buffer.from(b, 'hex');
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}

function logJson(config, entry) {
  if (config.logRequests) process.stdout.write(`${JSON.stringify(entry)}\n`);
}

function createGateway({ db, config, inspect = detector.inspect }) {
  const router = express.Router();
  const safeLookup = createSafeLookup(config);
  const ipLimiter = rateLimit({ ...config.gatewayRateLimit });
  const apiLimiter = rateLimit({ ...config.gatewayRateLimit, keyFn: (req) => req.guardApi.id });
  router.rateLimiters = [ipLimiter, apiLimiter];

  const insertRequest = db.prepare(
    `INSERT INTO requests (id, customer_id, api_id, ts, method, path, outcome, response_status, upstream_error, suspicious,
       highest_severity, body_inspected, mode, duration_ms) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
  );
  const insertEvent = db.prepare(
    `INSERT INTO events (id, request_id, customer_id, api_id, ts, category, severity, rule_id, explanation, location, action,
       response_status, duration_ms) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`
  );

  function record(ctx, outcome, status, { upstreamError = false } = {}) {
    if (ctx.recorded) return;
    ctx.recorded = true;
    const duration = Math.round(performance.now() - ctx.start);
    try {
      db.exec('BEGIN');
      insertRequest.run(ctx.requestId, ctx.api.customer_id, ctx.api.id, ctx.ts, ctx.method, ctx.safePath, outcome, status,
        upstreamError ? 1 : 0, ctx.findings.length ? 1 : 0, detector.highestSeverity(ctx.findings), ctx.bodyInspected ? 1 : 0, ctx.api.mode, duration);
      const action = outcome === 'blocked' ? 'blocked' : 'logged';
      for (const f of ctx.findings.slice(0, MAX_STORED_FINDINGS)) {
        insertEvent.run(crypto.randomUUID(), ctx.requestId, ctx.api.customer_id, ctx.api.id, ctx.ts, f.category, f.severity, f.ruleId,
          f.explanation, sanitizeLocation(f.location), action, status, duration);
      }
      db.exec('COMMIT');
    } catch (err) {
      try { db.exec('ROLLBACK'); } catch (_) { /* no open transaction */ }
      logJson({ logRequests: true }, { level: 'error', msg: 'failed to record request', requestId: ctx.requestId, error: err.message });
    }
    logJson(config, { level: 'info', requestId: ctx.requestId, apiId: ctx.api.id, method: ctx.method, path: ctx.safePath, outcome, status, durationMs: duration });
  }

  function readBody(req, limit) {
    return new Promise((resolve, reject) => {
      const chunks = [];
      let size = 0;
      req.on('data', (chunk) => {
        size += chunk.length;
        if (size > limit) {
          req.removeAllListeners('data');
          req.resume();
          reject(Object.assign(new Error('too large'), { code: 'E2BIG' }));
          return;
        }
        chunks.push(chunk);
      });
      req.on('end', () => resolve(Buffer.concat(chunks)));
      req.on('error', reject);
    });
  }

  /** Parse the body for inspection only; the original bytes are what get forwarded. */
  function bodyForInspection(buf, contentType = '') {
    if (!buf.length) return { value: undefined, inspected: true };
    const type = contentType.toLowerCase();
    const text = buf.toString('utf8');
    if (type.includes('json')) {
      try { return { value: JSON.parse(text), inspected: true }; } catch (_) { return { value: text, inspected: true }; }
    }
    if (type.includes('application/x-www-form-urlencoded')) {
      const obj = {};
      for (const [k, v] of new URLSearchParams(text)) obj[k] = k in obj ? [].concat(obj[k], v) : v;
      return { value: obj, inspected: true };
    }
    if (type.startsWith('text/') || type.includes('xml')) return { value: text, inspected: true };
    return { value: undefined, inspected: false }; // multipart and binary payloads are NOT inspected
  }

  function forward(req, res, ctx, bodyBuf, action) {
    const { api } = ctx;
    const target = new URL(api.upstream_url);
    const basePath = target.pathname.replace(/\/+$/, '');
    const headers = {};
    for (const [k, v] of Object.entries(req.headers)) {
      if (HOP_BY_HOP.has(k) || ['host', 'x-guard-key', 'content-length', 'expect'].includes(k)) continue;
      headers[k] = v;
    }
    headers.host = target.host;
    headers['x-request-id'] = ctx.requestId;
    const prior = req.headers['x-forwarded-for'];
    headers['x-forwarded-for'] = [prior, req.socket.remoteAddress].filter(Boolean).join(', ');
    if (bodyBuf.length) headers['content-length'] = String(bodyBuf.length);

    const lib = target.protocol === 'https:' ? https : http;
    let finished = false;
    let deadline = null;
    const fail = (status, error, message) => {
      if (finished) return;
      finished = true;
      clearTimeout(deadline);
      if (!res.headersSent) {
        res.status(status).json({ error, message, requestId: ctx.requestId });
        record(ctx, ctx.outcomeOnForward, status, { upstreamError: true });
      } else {
        record(ctx, ctx.outcomeOnForward, res.statusCode, { upstreamError: true });
        res.destroy();
      }
    };

    // Node does not call `lookup` for IP literals, so check them explicitly at connect time.
    const literal = target.hostname.replace(/^\[|\]$/g, '');
    if (net.isIP(literal) && isProhibitedAddress(literal, config)) {
      fail(502, 'upstream_unavailable', 'The upstream API could not be reached.');
      return;
    }

    const proxyReq = lib.request({
      protocol: target.protocol,
      hostname: target.hostname.replace(/^\[|\]$/g, ''),
      port: target.port || undefined,
      method: ctx.method,
      path: `${basePath}${ctx.pathname}${ctx.search}`,
      headers,
      lookup: safeLookup, // re-checks the resolved address at connect time (defeats DNS rebinding)
      timeout: config.upstreamTimeoutMs,
    }, (proxyRes) => {
      const outHeaders = {};
      for (const [k, v] of Object.entries(proxyRes.headers)) if (!HOP_BY_HOP.has(k)) outHeaders[k] = v;
      outHeaders['x-request-id'] = ctx.requestId;
      outHeaders['x-guard-action'] = action;
      res.writeHead(proxyRes.statusCode, outHeaders);
      proxyRes.pipe(res);
      proxyRes.on('end', () => {
        if (finished) return;
        finished = true;
        clearTimeout(deadline);
        record(ctx, ctx.outcomeOnForward, proxyRes.statusCode);
      });
      proxyRes.on('error', () => fail(502, 'upstream_unavailable', 'The upstream API failed while responding.'));
    });
    deadline = setTimeout(() => proxyReq.destroy(Object.assign(new Error('deadline'), { code: 'ETIMEDOUT' })), config.upstreamTimeoutMs * 3);
    proxyReq.on('timeout', () => proxyReq.destroy(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })));
    proxyReq.on('error', (err) => {
      if (err.code === 'ETIMEDOUT') fail(504, 'upstream_timeout', 'The upstream API did not respond in time.');
      else fail(502, 'upstream_unavailable', 'The upstream API could not be reached.');
    });
    proxyReq.end(bodyBuf);
  }

  async function handle(req, res) {
    const api = req.guardApi;
    const ctx = {
      api,
      requestId: crypto.randomUUID(),
      start: performance.now(),
      ts: Date.now(),
      method: req.method,
      findings: [],
      bodyInspected: false,
      recorded: false,
    };
    res.setHeader('X-Request-Id', ctx.requestId);
    const url = new URL(req.url, 'http://gateway.local');
    ctx.pathname = url.pathname;
    ctx.search = url.search;
    ctx.safePath = sanitizeLog(url.pathname, 200);
    db.prepare('UPDATE apis SET last_seen_at = ? WHERE id = ?').run(ctx.ts, api.id);

    if (!ALLOWED_METHODS.has(req.method)) {
      record(ctx, 'rejected', 405);
      return res.status(405).json({ error: 'method_not_allowed', message: 'Method not supported.', requestId: ctx.requestId });
    }
    const limit = api.max_body_kb * 1024;
    const declared = parseInt(req.headers['content-length'] || '0', 10);
    if (declared > limit) {
      record(ctx, 'rejected', 413);
      res.setHeader('Connection', 'close');
      return res.status(413).json({ error: 'payload_too_large', message: 'Request body exceeds the configured limit.', requestId: ctx.requestId });
    }

    let bodyBuf;
    try {
      bodyBuf = await readBody(req, limit);
    } catch (err) {
      if (err.code === 'E2BIG') {
        record(ctx, 'rejected', 413);
        res.setHeader('Connection', 'close');
        return res.status(413).json({ error: 'payload_too_large', message: 'Request body exceeds the configured limit.', requestId: ctx.requestId });
      }
      record(ctx, 'rejected', 400);
      return res.status(400).json({ error: 'bad_request', message: 'Could not read the request body.', requestId: ctx.requestId });
    }

    let query = {};
    for (const [k, v] of url.searchParams) query[k] = k in query ? [].concat(query[k], v) : v;
    const parsedBody = bodyForInspection(bodyBuf, req.headers['content-type']);
    ctx.bodyInspected = parsedBody.inspected;

    let inspectionFailed = false;
    try {
      ctx.findings = inspect({ path: url.pathname, query, headers: req.headers, body: parsedBody.value }).findings;
    } catch (err) {
      inspectionFailed = true;
      ctx.findings = [];
      logJson({ logRequests: true }, { level: 'error', msg: 'inspection failed', requestId: ctx.requestId, error: err.message });
    }

    if (inspectionFailed) {
      ctx.outcomeOnForward = 'inspection_error';
      if (api.mode === 'blocking') { // fail closed when enforcing
        record(ctx, 'inspection_error', 503);
        return res.status(503).json({ error: 'inspection_unavailable', message: 'Request could not be inspected.', requestId: ctx.requestId });
      }
      return forward(req, res, ctx, bodyBuf, 'uninspected'); // fail open when only monitoring
    }

    if (api.mode === 'blocking' && detector.meetsThreshold(ctx.findings, api.block_threshold)) {
      record(ctx, 'blocked', 403);
      return res.status(403).json({ error: 'request_blocked', message: 'Request blocked by security policy.', requestId: ctx.requestId });
    }
    ctx.outcomeOnForward = ctx.findings.length ? 'logged' : 'allowed';
    return forward(req, res, ctx, bodyBuf, ctx.findings.length ? 'logged' : 'allowed');
  }

  function authenticate(req, res, next) {
    const api = db.prepare('SELECT * FROM apis WHERE id = ?').get(req.params.apiId);
    const key = req.headers['x-guard-key'];
    // Identical response whether the API id or the key is wrong.
    if (!api || typeof key !== 'string' || !safeEqualHex(sha256(key), api.key_hash)) {
      return res.status(401).json({ error: 'invalid_api_key', message: 'Missing or invalid X-Guard-Key.' });
    }
    req.guardApi = api;
    return next();
  }

  router.use('/:apiId', ipLimiter, authenticate, apiLimiter, (req, res, next) => {
    handle(req, res).catch(next);
  });

  return router;
}

module.exports = { createGateway, sanitizeLog };
