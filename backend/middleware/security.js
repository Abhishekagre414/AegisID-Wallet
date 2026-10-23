import crypto from 'crypto';

const isProd = () => process.env.NODE_ENV === 'production';

/* ---- Issuer authentication ------------------------------------------------ *
 * Issuing, revoking and listing issued credentials are issuer-side operations.
 * They require the `x-api-key` header to match an operator key:
 *   ISSUER_API_KEYS="alice:<key>,bob:<key>"   one key per operator (recorded in the audit log)
 *   ISSUER_API_KEY=<key>                      single shared key (operator name "admin")
 *  - production: at least one key is mandatory (server.js refuses to start without one)
 *  - development: if none is set, auth is disabled so the demo "just works" (warning logged)
 */
export const MIN_KEY_LENGTH = 24;
let operators = [];
let generatedKey = false;

export function parseOperators(env = process.env) {
  const ops = [];
  for (const entry of (env.ISSUER_API_KEYS || '').split(',').map(s => s.trim()).filter(Boolean)) {
    const i = entry.indexOf(':');
    const name = entry.slice(0, i);
    const key = entry.slice(i + 1);
    if (i < 1 || !/^[A-Za-z0-9_.-]{1,32}$/.test(name) || !key) {
      throw new Error('ISSUER_API_KEYS entries must look like name:key (name: letters, digits, _ . -).');
    }
    ops.push({ name, key });
  }
  if (env.ISSUER_API_KEY) ops.push({ name: 'admin', key: env.ISSUER_API_KEY });
  return ops;
}

export function initIssuerAuth() {
  operators = parseOperators();
  generatedKey = false;
  if (!operators.length && isProd()) {
    const key = crypto.randomBytes(24).toString('base64url');
    operators = [{ name: 'admin', key }];
    generatedKey = true;
    console.warn('[security] No issuer key configured. Generated a temporary one for this process:');
    console.warn(`[security]   ${key}`);
  } else if (!operators.length) {
    console.warn('[security] No issuer key configured: issuer endpoints are OPEN (development mode only).');
  }
  return { required: operators.length > 0, generated: generatedKey, operators: operators.map(o => o.name) };
}

export const issuerAuthRequired = () => operators.length > 0;

function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

/** Sets req.operator (the authenticated operator's name) for the audit log. */
export function requireIssuerAuth(req, res, next) {
  if (!operators.length) { req.operator = 'dev-open'; return next(); }
  const provided = req.get('x-api-key');
  let match = null;
  if (provided) for (const op of operators) if (safeEqual(provided, op.key)) match = op;
  if (match) { req.operator = match.name; return next(); }
  req.authFailed = true;
  return res.status(401).json({ success: false, error: 'Issuer access key required (x-api-key).' });
}

/**
 * Refuse to boot a production server with unsafe configuration.
 * Returns { errors, warnings }; server.js exits when there are errors.
 */
export function validateProductionConfig(env = process.env) {
  const errors = [];
  const warnings = [];
  if (env.NODE_ENV !== 'production') return { errors, warnings };

  let ops = [];
  try { ops = parseOperators(env); } catch (e) { errors.push(e.message); }
  if (!ops.length) errors.push('Set ISSUER_API_KEY (or ISSUER_API_KEYS) so issuer endpoints are protected.');
  for (const o of ops) {
    if (o.key.length < MIN_KEY_LENGTH) errors.push(`Issuer key for "${o.name}" must be at least ${MIN_KEY_LENGTH} characters.`);
  }
  if (!env.ISSUER_MASTER_SECRET || env.ISSUER_MASTER_SECRET.length < 32) {
    errors.push('Set ISSUER_MASTER_SECRET (>= 32 chars). Without it issuer signing keys are written to disk.');
  }
  let url = null;
  try { url = new URL(env.APP_URL || ''); } catch { /* handled below */ }
  if (!url) errors.push('Set APP_URL to the public https URL of this deployment.');
  else if (['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)) warnings.push('APP_URL points at localhost: credential status URLs will only work on this machine.');
  else if (url.protocol !== 'https:') errors.push('APP_URL must use https in production.');
  if (!env.DATA_DIR) warnings.push('DATA_DIR is not set: state is stored inside the app directory. Mount a persistent disk and set DATA_DIR.');
  return { errors, warnings };
}

/* ---- Rate limiting (fixed window, per IP, in memory) ---------------------- */
export function rateLimit({ windowMs = 60_000, max = 60 } = {}) {
  const hits = new Map();
  const timer = setInterval(() => {
    const now = Date.now();
    for (const [ip, e] of hits) if (e.reset < now) hits.delete(ip);
  }, windowMs);
  timer.unref();

  return (req, res, next) => {
    const now = Date.now();
    const key = req.ip || 'unknown';
    let e = hits.get(key);
    if (!e || e.reset < now) { e = { count: 0, reset: now + windowMs }; hits.set(key, e); }
    e.count += 1;
    res.set('RateLimit-Limit', String(max));
    res.set('RateLimit-Remaining', String(Math.max(0, max - e.count)));
    if (e.count > max) {
      res.set('Retry-After', String(Math.ceil((e.reset - now) / 1000)));
      return res.status(429).json({ success: false, error: 'Too many requests. Please slow down.' });
    }
    next();
  };
}

/* ---- Security headers ------------------------------------------------------ */
export function securityHeaders(req, res, next) {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Content-Security-Policy': [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com data:",
      "img-src 'self' data: blob:",
      "connect-src 'self'",
      "worker-src 'self' blob:",
      "object-src 'none'",
      "base-uri 'self'",
      "frame-ancestors 'none'"
    ].join('; ')
  });
  if (isProd()) res.set('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
  next();
}

/** CORS allow-list from CORS_ORIGIN (comma separated). Same-origin only when unset in production. */
export function corsOptions() {
  const list = (process.env.CORS_ORIGIN || '').split(',').map(s => s.trim()).filter(Boolean);
  if (list.length) return { origin: list };
  if (isProd()) return { origin: false };
  return { origin: ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:5000'] };
}
