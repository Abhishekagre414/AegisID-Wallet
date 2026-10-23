import express from 'express';
import cors from 'cors';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

import { resolveDID } from './crypto/didKey.js';
import { verifyVerifiableCredential, verifyVerifiablePresentation } from './crypto/credentials.js';
import { issuerService, CREDENTIAL_TEMPLATES } from './services/issuerService.js';
import { revocationRegistry } from './services/revocationRegistry.js';
import { persistentChallengeStore as challengeStore } from './services/persistentChallengeStore.js';
import { audit, getAudit, dbHealthy } from './services/db.js';
import { HttpError } from './services/errors.js';
import {
  initIssuerAuth, issuerAuthRequired, requireIssuerAuth,
  rateLimit, securityHeaders, corsOptions
} from './middleware/security.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FRONTEND_DIST = path.join(__dirname, '..', 'frontend', 'dist');

// Verifier policy shared by the VC and VP endpoints.
const verifierOptions = () => ({
  isTrustedIssuer: (did, types) => issuerService.isTrustedIssuer(did, types),
  isRevoked: (vc) => issuerService.isRevoked(vc)
});

const wrap = (fn) => (req, res, next) => {
  try { fn(req, res); } catch (err) { next(err); }
};

export function createApp() {
  initIssuerAuth();
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1);

  app.use(securityHeaders);
  app.use(cors(corsOptions()));
  app.use(express.json({ limit: '1mb' }));
  app.use('/api', rateLimit({ windowMs: 60_000, max: 120 }));

  const strict = rateLimit({ windowMs: 60_000, max: 30 });

  // Failed issuer authentication is security-relevant: record who (IP) tried what.
  app.use('/api', (req, res, next) => {
    res.on('finish', () => {
      if (req.authFailed) audit('unauthenticated', 'auth-failed', `${req.method} ${req.path} from ${req.ip}`);
    });
    next();
  });

  app.get('/api/health', (req, res) => {
    res.json({
      status: 'ok',
      system: 'Decentralized Identity (DID) & Verifiable Credentials Engine',
      standard: 'W3C did:key & VC Data Model 1.1',
      cryptography: 'Ed25519 (EdDSA) / SHA-256 / JCS',
      issuerAuthRequired: issuerAuthRequired(),
      timestamp: new Date().toISOString()
    });
  });

  // Does the UI need to ask for an issuer key? (never reveals the key itself)
  app.get('/api/auth/status', (req, res) => res.json({ success: true, required: issuerAuthRequired() }));
  // Readiness: the process is up AND its database answers (used by container health checks).
  app.get('/api/ready', (req, res) => {
    const ok = dbHealthy();
    res.status(ok ? 200 : 503).json({ status: ok ? 'ready' : 'database unavailable' });
  });

  app.get('/api/auth/check', requireIssuerAuth, (req, res) => res.json({ success: true }));

  // 1. DID resolution (holders generate their own keys in the browser; the server never sees them)
  app.get('/api/did/resolve/:did', wrap((req, res) => {
    try {
      res.json({ success: true, didDocument: resolveDID(req.params.did) });
    } catch (err) {
      throw new HttpError(400, err.message);
    }
  }));

  // 2. Issuers & templates
  app.get('/api/issuers', wrap((req, res) => res.json({ success: true, issuers: issuerService.getIssuers() })));
  app.get('/api/templates', (req, res) => res.json({ success: true, templates: CREDENTIAL_TEMPLATES }));

  app.post('/api/credentials/issue', requireIssuerAuth, strict, wrap((req, res) => {
    const { issuerId, subjectDid, claims, credentialType, expirationDays } = req.body || {};
    if (!issuerId || !subjectDid || !claims || !credentialType) {
      throw new HttpError(400, 'Missing required fields: issuerId, subjectDid, claims, credentialType.');
    }
    const credential = issuerService.issueCredential({
      issuerIdOrDid: issuerId, subjectDid, claims, credentialType,
      expirationDays: expirationDays ?? 365
    });
    audit(req.operator, 'issue', `${credentialType} ${credential.id} by ${issuerId}`);
    res.json({ success: true, message: 'Credential successfully issued and signed.', credential });
  }));

  app.get('/api/audit', requireIssuerAuth, wrap((req, res) => res.json({ success: true, audit: getAudit(200) })));

  app.get('/api/credentials/issued', requireIssuerAuth, wrap((req, res) => {
    res.json({ success: true, issued: issuerService.getIssuedCredentials() });
  }));

  // 3. Verification
  app.post('/api/credentials/verify', strict, wrap((req, res) => {
    const { credential } = req.body || {};
    if (!credential) throw new HttpError(400, 'Credential object is required for verification.');
    res.json({ success: true, report: verifyVerifiableCredential(credential, verifierOptions()) });
  }));

  // 4. Presentations: the verifier issues a single-use challenge, the holder signs over it
  app.get('/api/verifier/challenge', strict, wrap((req, res) => {
    const domain = typeof req.query.domain === 'string' ? req.query.domain.slice(0, 253) : null;
    res.json({ success: true, ...challengeStore.create(domain || null) });
  }));

  app.post('/api/presentation/verify', strict, wrap((req, res) => {
    const { presentation } = req.body || {};
    if (!presentation) throw new HttpError(400, 'Presentation object is required.');
    const report = verifyVerifiablePresentation(presentation, { ...verifierOptions(), challenges: challengeStore });
    res.json({ success: true, report });
  }));

  // 5. Revocation (StatusList2021)
  app.get('/api/status/list/:issuerId', wrap((req, res) => {
    res.json(issuerService.getStatusListCredential(req.params.issuerId));
  }));
  app.get('/api/revocation/status/:id', wrap((req, res) => {
    res.json({ success: true, status: revocationRegistry.getStatus(req.params.id) });
  }));
  app.get('/api/revocation/list', requireIssuerAuth, wrap((req, res) => {
    const list = revocationRegistry.getAll();
    res.json({ success: true, count: list.length, revocations: list });
  }));
  app.post('/api/revocation/revoke', requireIssuerAuth, strict, wrap((req, res) => {
    const { credentialId, reason } = req.body || {};
    if (!credentialId) throw new HttpError(400, 'credentialId is required.');
    // "revoked by" is the authenticated operator, never a client-supplied name.
    const record = issuerService.revoke(credentialId, reason, req.operator);
    audit(req.operator, 'revoke', `${credentialId} (${String(reason || '').slice(0, 100)})`);
    res.json({ success: true, message: 'Credential successfully revoked.', record });
  }));
  app.post('/api/revocation/unrevoke', requireIssuerAuth, strict, wrap((req, res) => {
    const { credentialId } = req.body || {};
    if (!credentialId) throw new HttpError(400, 'credentialId is required.');
    const unrevoked = issuerService.unrevoke(credentialId);
    audit(req.operator, 'unrevoke', credentialId);
    res.json({
      success: true,
      unrevoked,
      message: unrevoked ? 'Credential unrevoked / restored to active.' : 'Credential was not in revocation list.'
    });
  }));

  // Unknown API routes -> JSON 404
  app.use('/api', (req, res) => res.status(404).json({ success: false, error: 'Not found.' }));

  // Production frontend (SPA fallback)
  if (fs.existsSync(FRONTEND_DIST)) {
    app.use(express.static(FRONTEND_DIST));
    app.use((req, res, next) => {
      if (req.method === 'GET') return res.sendFile(path.join(FRONTEND_DIST, 'index.html'));
      next();
    });
  }

  // Central error handler: no stack traces or internals leak to clients.
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    if (err.type === 'entity.parse.failed') return res.status(400).json({ success: false, error: 'Invalid JSON body.' });
    if (err.type === 'entity.too.large') return res.status(413).json({ success: false, error: 'Request body too large.' });
    const status = err.status && err.status < 500 ? err.status : 500;
    if (status === 500) console.error('[error]', err);
    res.status(status).json({ success: false, error: status === 500 ? 'Internal server error.' : err.message });
  });

  return app;
}
