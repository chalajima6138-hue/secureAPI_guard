'use strict';
const crypto = require('node:crypto');
const express = require('express');
const { sha256 } = require('../auth');
const { parseUpstreamUrl, resolveAndCheck } = require('../ssrf');

const ENVIRONMENTS = ['development', 'staging', 'production'];
const MODES = ['monitoring', 'blocking'];
const THRESHOLDS = ['low', 'medium', 'high'];
const ACTIVE_WINDOW_MS = 15 * 60 * 1000;

/** Public representation of an API. Never includes the key or its hash. */
function apiView(db, row) {
  const recent = db.prepare(
    `SELECT upstream_error FROM requests WHERE api_id = ? AND outcome != 'rejected' ORDER BY ts DESC LIMIT 20`
  ).all(row.id);
  let health = 'unknown';
  if (recent.length) {
    const ratio = recent.filter((r) => r.upstream_error).length / recent.length;
    health = ratio === 0 ? 'healthy' : ratio < 0.5 ? 'degraded' : 'unavailable';
  }
  let connectionStatus = 'awaiting_traffic';
  if (row.last_seen_at) connectionStatus = Date.now() - row.last_seen_at <= ACTIVE_WINDOW_MS ? 'active' : 'idle';
  return {
    id: row.id,
    name: row.name,
    environment: row.environment,
    upstreamUrl: row.upstream_url,
    mode: row.mode,
    blockThreshold: row.block_threshold,
    maxBodyKb: row.max_body_kb,
    keyPrefix: row.key_prefix,
    createdAt: row.created_at,
    lastSeenAt: row.last_seen_at,
    connectionStatus,
    health,
    gatewayPath: `/gateway/${row.id}`,
  };
}

function newKey() {
  const key = `sag_${crypto.randomBytes(24).toString('base64url')}`;
  return { key, hash: sha256(key), prefix: key.slice(0, 8) };
}

function createApisRouter({ db, config, requireAuth }) {
  const router = express.Router();
  router.use(requireAuth);

  const owned = (req) => db.prepare('SELECT * FROM apis WHERE id = ? AND customer_id = ?').get(req.params.id, req.user.id);
  const notFound = (res) => res.status(404).json({ error: 'not_found', message: 'API not found.' });

  async function validateFields(body, { partial }) {
    const errors = [];
    const out = {};
    const has = (k) => body[k] !== undefined;
    if (!partial || has('name')) {
      if (typeof body.name !== 'string' || !body.name.trim() || body.name.trim().length > 80) errors.push('Name must be 1 to 80 characters.');
      else out.name = body.name.trim();
    }
    if (!partial || has('environment')) {
      if (!ENVIRONMENTS.includes(body.environment)) errors.push(`Environment must be one of: ${ENVIRONMENTS.join(', ')}.`);
      else out.environment = body.environment;
    }
    if (!partial || has('upstreamUrl')) {
      const parsed = parseUpstreamUrl(body.upstreamUrl, config);
      if (!parsed.ok) errors.push(parsed.error);
      else if (!(await resolveAndCheck(parsed.url.hostname, config))) errors.push('The upstream host could not be resolved or resolves to a prohibited address.');
      else out.upstream_url = parsed.normalized;
    }
    if (has('mode')) {
      if (!MODES.includes(body.mode)) errors.push('Mode must be monitoring or blocking.');
      else out.mode = body.mode;
    }
    if (has('blockThreshold')) {
      if (!THRESHOLDS.includes(body.blockThreshold)) errors.push('Block threshold must be low, medium or high.');
      else out.block_threshold = body.blockThreshold;
    }
    if (has('maxBodyKb')) {
      if (!Number.isInteger(body.maxBodyKb) || body.maxBodyKb < 1 || body.maxBodyKb > 1024) errors.push('Max body size must be an integer from 1 to 1024 KB.');
      else out.max_body_kb = body.maxBodyKb;
    }
    return { errors, out };
  }

  router.get('/', (req, res) => {
    const rows = db.prepare('SELECT * FROM apis WHERE customer_id = ? ORDER BY created_at DESC').all(req.user.id);
    res.json({ apis: rows.map((r) => apiView(db, r)) });
  });

  router.post('/', async (req, res) => {
    const body = req.body || {};
    const count = db.prepare('SELECT COUNT(*) AS n FROM apis WHERE customer_id = ?').get(req.user.id).n;
    if (count >= config.maxApisPerCustomer) return res.status(409).json({ error: 'limit_reached', message: `You can register up to ${config.maxApisPerCustomer} APIs.` });
    const { errors, out } = await validateFields(body, { partial: false });
    if (out.mode === 'blocking' && body.confirmBlocking !== true) errors.push('Blocking mode rejects traffic. Set confirmBlocking to true to acknowledge this.');
    if (errors.length) return res.status(400).json({ error: 'invalid_input', message: errors[0], errors });
    const key = newKey();
    const id = crypto.randomUUID();
    db.prepare(
      `INSERT INTO apis (id, customer_id, name, environment, upstream_url, mode, block_threshold, max_body_kb, key_hash, key_prefix, created_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?)`
    ).run(id, req.user.id, out.name, out.environment, out.upstream_url, out.mode || 'monitoring', out.block_threshold || 'medium', out.max_body_kb || 256, key.hash, key.prefix, Date.now());
    // The key is returned exactly once.
    return res.status(201).json({ api: apiView(db, db.prepare('SELECT * FROM apis WHERE id = ?').get(id)), apiKey: key.key });
  });

  router.get('/:id', (req, res) => {
    const row = owned(req);
    if (!row) return notFound(res);
    return res.json({ api: apiView(db, row) });
  });

  router.patch('/:id', async (req, res) => {
    const row = owned(req);
    if (!row) return notFound(res);
    const body = req.body || {};
    const { errors, out } = await validateFields(body, { partial: true });
    if (out.mode === 'blocking' && row.mode !== 'blocking' && body.confirmBlocking !== true) errors.push('Blocking mode rejects traffic. Set confirmBlocking to true to acknowledge this.');
    if (errors.length) return res.status(400).json({ error: 'invalid_input', message: errors[0], errors });
    const cols = Object.keys(out);
    if (cols.length) {
      db.prepare(`UPDATE apis SET ${cols.map((c) => `${c} = ?`).join(', ')} WHERE id = ? AND customer_id = ?`)
        .run(...cols.map((c) => out[c]), row.id, req.user.id);
    }
    return res.json({ api: apiView(db, owned(req)) });
  });

  router.post('/:id/rotate-key', (req, res) => {
    const row = owned(req);
    if (!row) return notFound(res);
    const key = newKey();
    db.prepare('UPDATE apis SET key_hash = ?, key_prefix = ? WHERE id = ? AND customer_id = ?').run(key.hash, key.prefix, row.id, req.user.id);
    return res.json({ api: apiView(db, owned(req)), apiKey: key.key });
  });

  router.delete('/:id', (req, res) => {
    const row = owned(req);
    if (!row) return notFound(res);
    db.prepare('DELETE FROM apis WHERE id = ? AND customer_id = ?').run(row.id, req.user.id);
    return res.json({ ok: true });
  });

  return router;
}

module.exports = { createApisRouter, apiView };
