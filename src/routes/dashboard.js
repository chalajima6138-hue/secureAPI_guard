'use strict';
const express = require('express');
const { apiView } = require('./apis');

const RANGES = {
  '24h': { ms: 24 * 3600e3, bucket: 3600e3 },
  '7d': { ms: 7 * 24 * 3600e3, bucket: 6 * 3600e3 },
  '30d': { ms: 30 * 24 * 3600e3, bucket: 24 * 3600e3 },
};
const OK = "('allowed','logged','blocked')";

/**
 * Metric definitions (all scoped to the logged-in customer):
 *  inspected  = requests that reached inspection and were decided (allowed + blocked)
 *  allowed    = forwarded to the upstream (outcome allowed or logged)
 *  blocked    = rejected by the gateway before reaching the upstream
 *  suspicious = requests with at least one rule match (may be allowed in monitoring mode)
 *  rejected   = refused before inspection (unsupported method, oversize body)
 *  errors     = upstream failures or inspection failures
 */
function createDashboardRouter({ db, requireAuth }) {
  const router = express.Router();
  router.use(requireAuth);

  function scope(req, res) {
    const range = RANGES[req.query.range || '24h'];
    if (!range) { res.status(400).json({ error: 'invalid_input', message: 'range must be 24h, 7d or 30d.' }); return null; }
    let apiId = null;
    if (req.query.apiId !== undefined) {
      if (typeof req.query.apiId !== 'string') { res.status(400).json({ error: 'invalid_input', message: 'Invalid apiId.' }); return null; }
      const owned = db.prepare('SELECT id FROM apis WHERE id = ? AND customer_id = ?').get(req.query.apiId, req.user.id);
      if (!owned) { res.status(404).json({ error: 'not_found', message: 'API not found.' }); return null; }
      apiId = owned.id;
    }
    return { range, since: Date.now() - range.ms, apiId };
  }

  const totalsSql = (extra) => `SELECT
      COUNT(CASE WHEN outcome IN ${OK} THEN 1 END) AS inspected,
      COUNT(CASE WHEN outcome IN ('allowed','logged') THEN 1 END) AS allowed,
      COUNT(CASE WHEN outcome = 'blocked' THEN 1 END) AS blocked,
      COUNT(CASE WHEN suspicious = 1 THEN 1 END) AS suspicious,
      COUNT(CASE WHEN outcome = 'rejected' THEN 1 END) AS rejected,
      COUNT(CASE WHEN upstream_error = 1 OR outcome = 'inspection_error' THEN 1 END) AS errors
    FROM requests WHERE customer_id = ? AND ts >= ? ${extra}`;

  router.get('/summary', (req, res) => {
    const s = scope(req, res);
    if (!s) return;
    const params = [req.user.id, s.since];
    const totals = db.prepare(totalsSql(s.apiId ? 'AND api_id = ?' : '')).get(...params, ...(s.apiId ? [s.apiId] : []));
    const byCategory = db.prepare(
      `SELECT category, COUNT(*) AS count FROM events WHERE customer_id = ? AND ts >= ? ${s.apiId ? 'AND api_id = ?' : ''}
       GROUP BY category ORDER BY count DESC`
    ).all(...params, ...(s.apiId ? [s.apiId] : []));
    const bySeverity = db.prepare(
      `SELECT severity, COUNT(*) AS count FROM events WHERE customer_id = ? AND ts >= ? ${s.apiId ? 'AND api_id = ?' : ''}
       GROUP BY severity`
    ).all(...params, ...(s.apiId ? [s.apiId] : []));
    const apis = db.prepare('SELECT * FROM apis WHERE customer_id = ? ORDER BY created_at DESC').all(req.user.id).map((row) => {
      const t = db.prepare(totalsSql('AND api_id = ?')).get(req.user.id, s.since, row.id);
      return { ...apiView(db, row), totals: t };
    });
    res.json({ range: req.query.range || '24h', totals, byCategory, bySeverity, apis });
  });

  router.get('/timeseries', (req, res) => {
    const s = scope(req, res);
    if (!s) return;
    const b = s.range.bucket; // server-side constant; inlined because bound JS numbers are REAL in node:sqlite (would force float division)
    if (!Number.isInteger(b)) throw new Error('bucket must be an integer');
    const rows = db.prepare(
      `SELECT (ts / ${b}) * ${b} AS t,
         COUNT(CASE WHEN outcome IN ${OK} THEN 1 END) AS inspected,
         COUNT(CASE WHEN suspicious = 1 THEN 1 END) AS suspicious,
         COUNT(CASE WHEN outcome = 'blocked' THEN 1 END) AS blocked
       FROM requests WHERE customer_id = ? AND ts >= ? ${s.apiId ? 'AND api_id = ?' : ''}
       GROUP BY t ORDER BY t`
    ).all(req.user.id, s.since, ...(s.apiId ? [s.apiId] : []));
    const byT = new Map(rows.map((r) => [r.t, r]));
    const points = [];
    for (let t = Math.floor(s.since / b) * b; t <= Date.now(); t += b) {
      const r = byT.get(t);
      points.push({ t, inspected: r ? r.inspected : 0, suspicious: r ? r.suspicious : 0, blocked: r ? r.blocked : 0 });
    }
    res.json({ bucketMs: b, points });
  });

  return router;
}

function createEventsRouter({ db, requireAuth }) {
  const router = express.Router();
  router.use(requireAuth);

  router.get('/', (req, res) => {
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 25, 1), 100);
    const where = ['e.customer_id = ?'];
    const params = [req.user.id];
    if (req.query.apiId !== undefined) {
      const owned = typeof req.query.apiId === 'string' && db.prepare('SELECT id FROM apis WHERE id = ? AND customer_id = ?').get(req.query.apiId, req.user.id);
      if (!owned) return res.status(404).json({ error: 'not_found', message: 'API not found.' });
      where.push('e.api_id = ?'); params.push(owned.id);
    }
    if (req.query.category !== undefined) {
      if (!['sql_injection', 'xss'].includes(req.query.category)) return res.status(400).json({ error: 'invalid_input', message: 'Unknown category.' });
      where.push('e.category = ?'); params.push(req.query.category);
    }
    if (req.query.before !== undefined) {
      // Composite cursor "<ts>_<id>" so events sharing a millisecond are neither skipped nor repeated.
      const m = typeof req.query.before === 'string' && req.query.before.match(/^(\d{1,15})_([0-9a-f-]{36})$/);
      if (!m) return res.status(400).json({ error: 'invalid_input', message: 'Invalid cursor.' });
      where.push('(e.ts < ? OR (e.ts = ? AND e.id > ?))'); params.push(Number(m[1]), Number(m[1]), m[2]);
    }
    const rows = db.prepare(
      `SELECT e.id, e.request_id AS requestId, e.api_id AS apiId, a.name AS apiName, e.ts, e.category, e.severity, e.rule_id AS ruleId,
              e.action, e.response_status AS responseStatus
       FROM events e JOIN apis a ON a.id = e.api_id WHERE ${where.join(' AND ')} ORDER BY e.ts DESC, e.id LIMIT ?`
    ).all(...params, limit);
    const last = rows[rows.length - 1];
    res.json({ events: rows, nextBefore: rows.length === limit ? `${last.ts}_${last.id}` : null });
  });

  router.get('/:id', (req, res) => {
    const row = db.prepare(
      `SELECT e.id, e.request_id AS requestId, e.api_id AS apiId, a.name AS apiName, a.environment, e.ts, e.category, e.severity,
              e.rule_id AS ruleId, e.explanation, e.location, e.action, e.response_status AS responseStatus, e.duration_ms AS durationMs,
              r.method, r.path, r.outcome, r.mode, r.body_inspected AS bodyInspected
       FROM events e JOIN apis a ON a.id = e.api_id JOIN requests r ON r.id = e.request_id
       WHERE e.id = ? AND e.customer_id = ?`
    ).get(req.params.id, req.user.id);
    if (!row) return res.status(404).json({ error: 'not_found', message: 'Event not found.' });
    return res.json({ event: row });
  });

  return router;
}

module.exports = { createDashboardRouter, createEventsRouter };
