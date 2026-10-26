'use strict';

function bool(value, fallback) {
  if (value === undefined || value === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
}

function int(value, fallback) {
  const n = parseInt(value, 10);
  return Number.isFinite(n) ? n : fallback;
}

/** Build configuration from environment variables (overridable for tests). */
function loadConfig(env = process.env, overrides = {}) {
  const nodeEnv = env.NODE_ENV || 'development';
  const production = nodeEnv === 'production';
  const config = {
    nodeEnv,
    production,
    host: env.HOST || '127.0.0.1', // local by default; set HOST deliberately to expose
    port: int(env.PORT, 3000),
    dbPath: env.DB_PATH || (production ? '' : './data/secureapi-guard.db'),
    cookieSecure: bool(env.COOKIE_SECURE, production),
    trustProxy: bool(env.TRUST_PROXY, false),
    sessionDays: int(env.SESSION_DAYS, 7),
    // Upstreams on loopback/private networks are refused unless explicitly allowed (local development only).
    allowPrivateUpstreams: bool(env.ALLOW_PRIVATE_UPSTREAMS, false),
    allowHttpUpstreams: bool(env.ALLOW_HTTP_UPSTREAMS, !production),
    upstreamTimeoutMs: int(env.UPSTREAM_TIMEOUT_MS, 10000),
    maxApisPerCustomer: int(env.MAX_APIS_PER_CUSTOMER, 10),
    authRateLimit: { windowMs: 60000, max: int(env.AUTH_RATE_LIMIT, 10) },
    apiRateLimit: { windowMs: 60000, max: int(env.API_RATE_LIMIT, 300) },
    gatewayRateLimit: { windowMs: 60000, max: int(env.GATEWAY_RATE_LIMIT, 600) },
    logRequests: bool(env.LOG_REQUESTS, !production ? false : true),
  };
  return Object.assign(config, overrides);
}

/** Refuse to start in production with unsafe settings. */
function validateConfig(config) {
  const problems = [];
  if (config.production) {
    if (!config.cookieSecure) problems.push('COOKIE_SECURE must be true in production (serve over HTTPS).');
    if (config.allowPrivateUpstreams) problems.push('ALLOW_PRIVATE_UPSTREAMS must be false in production (SSRF risk).');
    if (config.allowHttpUpstreams) problems.push('ALLOW_HTTP_UPSTREAMS must be false in production.');
    if (!config.dbPath) problems.push('DB_PATH must point to a persistent volume in production.');
    if (!config.trustProxy) problems.push('TRUST_PROXY should be true when running behind a TLS-terminating proxy, otherwise client IPs and rate limits are wrong.');
  }
  return problems;
}

module.exports = { loadConfig, validateConfig };
