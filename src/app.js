'use strict';
const path = require('node:path');
const express = require('express');
const { loadConfig } = require('./config');
const { openDatabase } = require('./db');
const { securityHeaders, rateLimit, csrfGuard } = require('./middleware/security');
const { createAuth } = require('./auth');
const { createApisRouter } = require('./routes/apis');
const { createDashboardRouter, createEventsRouter } = require('./routes/dashboard');
const { createGateway } = require('./gateway');

function createApp({ config = loadConfig(), inspect } = {}) {
  const db = openDatabase(config.dbPath || ':memory:');
  const app = express();
  app.disable('x-powered-by');
  if (config.trustProxy) app.set('trust proxy', 1);

  // The gateway comes first: it handles raw bodies itself and proxies responses from customer backends,
  // so the dashboard CSP and JSON body parser must not apply to it.
  const gateway = createGateway({ db, config, inspect });
  app.use('/gateway', gateway);

  app.use(securityHeaders({ production: config.production }));

  const authLimiter = rateLimit({ ...config.authRateLimit, message: 'Too many attempts. Try again in a minute.' });
  const apiLimiter = rateLimit({ ...config.apiRateLimit });
  const auth = createAuth({ db, config, authLimiter });

  app.use('/api', apiLimiter, express.json({ limit: '16kb' }), csrfGuard(), auth.loadUser);
  app.use('/api/auth', auth.router);
  app.use('/api/apis', createApisRouter({ db, config, requireAuth: auth.requireAuth }));
  app.use('/api/dashboard', createDashboardRouter({ db, requireAuth: auth.requireAuth }));
  app.use('/api/events', createEventsRouter({ db, requireAuth: auth.requireAuth }));
  app.get('/api/health', (_req, res) => res.json({ status: 'ok' }));
  app.use('/api', (_req, res) => res.status(404).json({ error: 'not_found', message: 'Unknown endpoint.' }));

  app.use(express.static(path.join(__dirname, '..', 'public'), { extensions: ['html'], index: 'index.html' }));

  // Error handler: never leak stack traces or internals.
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, _next) => {
    if (err.type === 'entity.too.large') return res.status(413).json({ error: 'payload_too_large', message: 'Request body too large.' });
    if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'invalid_json', message: 'Malformed JSON body.' });
    process.stderr.write(`${JSON.stringify({ level: 'error', msg: 'unhandled', error: err.message })}\n`);
    return res.status(500).json({ error: 'server_error', message: 'Something went wrong.' });
  });

  const limiters = [authLimiter, apiLimiter, ...gateway.rateLimiters];
  return { app, db, config, resetRateLimits: () => limiters.forEach((l) => l.reset && l.reset()), close: () => db.close() };
}

module.exports = { createApp };
