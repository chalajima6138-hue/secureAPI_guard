'use strict';

/** Security headers for the dashboard/app pages (not applied to proxied gateway responses). */
function securityHeaders({ production }) {
  return (req, res, next) => {
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
        "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    );
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.removeHeader('X-Powered-By');
    if (production) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
  };
}

/** Fixed-window in-memory limiter. Single-process only; use a shared store when scaling out. */
function rateLimit({ windowMs, max, keyFn, message = 'Too many requests. Please slow down.' }) {
  const hits = new Map();
  const timer = setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits) if (v.reset <= now) hits.delete(k);
  }, Math.min(windowMs, 60000));
  timer.unref();

  const middleware = (req, res, next) => {
    const key = keyFn ? keyFn(req) : req.ip;
    const now = Date.now();
    let entry = hits.get(key);
    if (!entry || entry.reset <= now) {
      entry = { count: 0, reset: now + windowMs };
      hits.set(key, entry);
    }
    entry.count += 1;
    res.setHeader('RateLimit-Limit', String(max));
    res.setHeader('RateLimit-Remaining', String(Math.max(0, max - entry.count)));
    if (entry.count > max) {
      res.setHeader('Retry-After', String(Math.ceil((entry.reset - now) / 1000)));
      return res.status(429).json({ error: 'rate_limited', message });
    }
    return next();
  };
  middleware.reset = () => hits.clear();
  return middleware;
}

/**
 * CSRF defence for cookie-authenticated JSON endpoints: SameSite=Lax cookies, plus
 * state-changing requests must be application/json and, when an Origin header is sent, same-origin.
 */
function csrfGuard() {
  return (req, res, next) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
    const origin = req.headers.origin;
    if (origin) {
      let ok = false;
      try {
        ok = new URL(origin).host === req.headers.host;
      } catch (_) {
        ok = false;
      }
      if (!ok) return res.status(403).json({ error: 'csrf', message: 'Cross-origin request rejected.' });
    }
    const hasBody = req.headers['content-length'] && req.headers['content-length'] !== '0';
    if (hasBody && !req.is('application/json')) {
      return res.status(415).json({ error: 'unsupported_media_type', message: 'Use application/json.' });
    }
    return next();
  };
}

module.exports = { securityHeaders, rateLimit, csrfGuard };
