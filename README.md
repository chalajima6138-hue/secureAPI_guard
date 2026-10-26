# SecureAPI Guard

A gateway that sits in front of a customer's API, inspects each request for **SQL injection** and **XSS**
patterns, records security events, and shows them on a private per-customer dashboard.

Status: **pilot build.** Everything under "Verified" below has been exercised by automated tests or an
end-to-end run. Everything under "Not implemented / known limitations" is not available, and the product
UI and landing page say so.

```
Customer application ──▶ SecureAPI Guard gateway ──▶ Customer backend API
   (sends X-Guard-Key)      │ auth key → API → customer
                            │ method + size checks
                            │ inspect (SQLi / XSS rules)
                            │ monitoring: log + forward   blocking: 403, never forwarded
                            ▼
                     SQLite: requests + events ──▶ authenticated dashboard (customer-scoped)
```

## Quick start (local)

Requires Node.js 22.5+ (uses the built-in `node:sqlite`; it prints no warning via the npm scripts).

```bash
npm install
npm test            # 41 automated tests
npm start           # http://127.0.0.1:3000  (loopback only by default)
```

To protect a backend that runs on your own machine during development, allow loopback upstreams explicitly:

```bash
ALLOW_PRIVATE_UPSTREAMS=true npm start
```

## Customer workflow

1. Open `/register`, create an account. Passwords are hashed with scrypt; sessions are server-side.
2. On the dashboard choose **Add API**: name, environment, backend address, mode (default **monitoring**),
   block threshold, max body size. Choosing blocking requires an explicit acknowledgement.
3. The API key (`sag_…`) is displayed **once**. Only its SHA-256 is stored. Rotate it from "Manage".
4. Route traffic through the gateway. The dashboard shows **awaiting traffic** until the first request is seen,
   because registering an API does not protect it by itself.

```bash
# Instead of:  curl https://api.example.com/v1/products?limit=10
curl "https://guard.example.com/gateway/<api-id>/v1/products?limit=10" \
  -H "X-Guard-Key: sag_xxxxxxxx"

# POST with a JSON body
curl -X POST "https://guard.example.com/gateway/<api-id>/v1/comments" \
  -H "X-Guard-Key: sag_xxxxxxxx" -H "Content-Type: application/json" \
  -d '{"text":"hello"}'
```

Response headers added by the gateway: `X-Request-Id` (also sent to your backend), `X-Guard-Action`
(`allowed` or `logged`). A blocked request returns `403 {"error":"request_blocked","requestId":…}`.

Integration notes for customers:
- The `X-Guard-Key` header is removed before forwarding. Your own `Authorization`/cookies pass through to your backend and are never stored.
- Keep the key on your server or proxy. Do not embed it in browser or mobile code.
- Lock your backend so it only accepts traffic from the gateway (network rule or shared secret). Otherwise callers can bypass protection.
- Upstream redirects are returned to the client, not followed. WebSocket/upgrade requests are not supported.

### Enforcement modes

| Mode | Suspicious request | Event stored | Reaches backend |
|---|---|---|---|
| monitoring (default) | allowed | yes (`logged`) | yes |
| blocking | matches at/above threshold: `403` | yes (`blocked`) | **no** |
| blocking, below threshold | allowed | yes (`logged`) | yes |

"Blocked" is only recorded when the gateway actually rejected the request before forwarding.
If inspection itself throws: monitoring fails open (forwarded, recorded as `inspection_error`); blocking fails closed (`503`).

### Metric definitions (all scoped to the logged-in customer)

- **Inspected** = allowed + blocked (requests that reached inspection and received a decision)
- **Allowed** = forwarded to the backend (including logged-but-forwarded)
- **Blocked** = rejected by the gateway
- **Suspicious** = requests with at least one rule match (may have been allowed in monitoring mode)
- **Rejected** = refused before inspection (unsupported method, oversize body); reported separately
- **Errors** = upstream timeouts/failures and inspection failures
- An **event** is one rule match; one request can produce several events.

## What is inspected

Path, query string, `User-Agent`/`Referer`/`Origin`/`X-Forwarded-Host` headers, and JSON, form-encoded and
text/XML bodies (keys and values, nested). Input is URL-decoded (up to 3 passes), HTML-entity decoded,
case-folded, and SQL inline comments are stripped before matching. `Authorization` and `Cookie` are never read.
Work per request is bounded (string length, node count, depth). Multipart and binary bodies are **not** inspected
(recorded per request as `body_inspected = 0`).

## Architecture

| Component | File |
|---|---|
| Express app, wiring | `src/app.js`, `src/server.js` |
| Configuration + production validation | `src/config.js` |
| SQLite schema | `src/db.js` |
| Detection rules | `src/inspection/detector.js` |
| Gateway (auth, limits, inspect, enforce, forward, record) | `src/gateway.js` |
| Auth, sessions | `src/auth.js` |
| API registration (SSRF checks, key issuing) | `src/routes/apis.js`, `src/ssrf.js` |
| Metrics, events | `src/routes/dashboard.js` |
| Headers, rate limiting, CSRF guard | `src/middleware/security.js` |
| Frontend (vanilla JS, no inline script/style) | `public/` |

Security controls implemented: scrypt password hashing; HttpOnly + SameSite=Lax (+ Secure in production) session
cookie with server-side revocation; Origin check and JSON-only requirement on state-changing calls; per-IP rate limits
on auth, dashboard API and gateway (plus per-API gateway limit); strict CSP, `X-Frame-Options`, `nosniff`,
`Referrer-Policy`, HSTS in production; owner-scoped queries with 404 for foreign objects; SSRF validation at
registration **and** at connect time (private/loopback/link-local/metadata ranges, IPv6 and IPv4-mapped forms,
numeric/hex IP forms, DNS results checked at connect, redirects never followed); upstream timeouts; request-size limits;
log-injection sanitisation; no stack traces in responses; dashboard renders all data via `textContent`.

## Configuration

See `.env.example`. In production (`NODE_ENV=production`) the process **refuses to start** unless
`COOKIE_SECURE` is on, `ALLOW_PRIVATE_UPSTREAMS=false`, `ALLOW_HTTP_UPSTREAMS=false`, `DB_PATH` is set and `TRUST_PROXY=true`.
Link-local / cloud-metadata addresses are blocked even in development.

## Deployment guide (controlled pilot)

1. Provision one instance with a persistent volume. Terminate TLS at a reverse proxy (nginx, Caddy, a cloud LB) and forward to `127.0.0.1:PORT`. The proxy must set `X-Forwarded-For`, and `TRUST_PROXY=true` must be set. Do not expose the Node port directly.
2. Set environment (example):
   `NODE_ENV=production DB_PATH=/var/lib/secureapi-guard/app.db COOKIE_SECURE=true TRUST_PROXY=true ALLOW_HTTP_UPSTREAMS=false`
3. Run under a process supervisor (systemd) as an unprivileged user. `npm ci --omit=dev && npm start`.
4. Check `GET /api/health`, then register a test account and run the customer workflow against a test backend.
5. **Backups:** SQLite in WAL mode. Use `sqlite3 app.db ".backup /backups/app-$(date +%F).db"` (or snapshot the volume) on a schedule; test restores.
6. **Rollback:** keep the previous release directory; stop the service, switch the symlink, restart. The schema is created idempotently (`CREATE TABLE IF NOT EXISTS`); there are no destructive migrations yet. Take a backup before any upgrade.
7. **Logs:** with `LOG_REQUESTS=true` (default in production) one JSON line per request goes to stdout (request id, API id, method, sanitised path, outcome, status, duration). Ship to your log system; alert on rising `5xx`, `inspection_error`, and 429s.
8. **Secrets:** there are no application secrets in config today (API keys and session tokens are random and stored hashed). Keep `.env` and the DB file readable only by the service user.
9. **Data retention:** requests/events are kept indefinitely; add a retention job before real traffic volumes.

## Verified

Run on this build (Node 22): `npm test` → **41 tests, 41 pass**. Covers: detector rules incl. encodings, false-positive samples
and bounded work; registration/login/logout/session revocation/cookie flags/no enumeration; CSRF guard; security headers/HSTS;
auth rate limiting; API validation, one-time/hashed keys, rotation, per-customer limit; customer isolation (APIs, events, metrics,
direct-object access); SSRF (registration, connect time, always-blocked ranges); gateway auth, forwarding fidelity, base-path
confinement, monitoring vs blocking, thresholds, oversize/method rejection, upstream 502/504, redirects not followed,
inspection-failure behaviour, gateway rate limiting, no credentials/bodies stored, log-injection sanitisation; metric accuracy,
time series, pagination, event details.

Also executed against a real `npm start` process with a separate backend: the 12-step acceptance flow (two customers) and the
dashboard JavaScript run in jsdom (empty states, key display, hostile API name rendered as inert text, live metrics, SVG chart, event detail).

## Not implemented / known limitations

- **Not visually reviewed in a real browser.** The UI logic is tested in jsdom; layout, responsiveness and dark mode have not been checked on actual devices.
- Detection is heuristic. It misses obfuscated or novel payloads and will flag some legitimate input (for example text containing `' or 1=1`). Tune with monitoring mode first. It is not a substitute for parameterized queries, output encoding, authN/authZ.
- Only SQLi and XSS. No response inspection, no multipart/binary body inspection, no WebSocket/HTTP upgrade, no path-traversal/SSRF/command-injection rules.
- Account features missing: email verification, password reset, MFA, per-account lockout (only per-IP rate limiting), account deletion.
- Rate limits are in-memory and per process; they reset on restart and do not work across multiple instances.
- Single instance, local SQLite (`node:sqlite` is flagged experimental by Node). No migration tooling, no retention/archival.
- Encoded slashes (`%2f`) in request paths are forwarded as-is; the backend's own path normalisation applies.
- Streaming responses are piped without a size cap. No load testing or performance benchmarking has been done, so no throughput or latency figures are claimed.
- No independent penetration test has been performed. A security review and controlled pilot are required before real customers depend on this service.
