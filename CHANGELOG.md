# Changelog

## 2.1.0

### Production hardening
- **Durable storage.** All server state moved from JSON files to one SQLite database (`aegis.db`, WAL, `synchronous=FULL`, built-in `node:sqlite`, no new dependency). Index allocation, revocation and issuance are transactional, so a crash can no longer lose a revocation or re-use a status index. v2.0 JSON state is imported automatically on first start (files are renamed `*.migrated`).
- **Challenges persist and are atomic.** Presentation challenges live in the database and `consume()` is atomic, so two concurrent submissions of one presentation cannot both succeed, and a restart no longer invalidates pending challenges.
- **Data minimisation.** The issuer stores issuance metadata only. Claim values and the credential body are no longer retained anywhere on the server.
- **Per-operator keys and audit log.** `ISSUER_API_KEYS=name:key,...` gives each operator their own key; actions (issue, revoke, unrevoke, failed logins) are recorded in an audit table (`GET /api/audit`). "Revoked by" is the authenticated operator, never a client-supplied value.
- **Fail-fast configuration.** In production the server refuses to start without issuer keys (>= 24 chars), `ISSUER_MASTER_SECRET` (>= 32 chars) and an https `APP_URL`.
- **Operations.** `/api/ready` checks the database (used by the Docker health check and Render), graceful shutdown on SIGTERM/SIGINT, `npm run backup` (consistent online backup via `VACUUM INTO`), `docker-compose.yml` now requires the secrets, `render.yaml` uses a persistent disk (paid plan).
- Requires **Node >= 22.13**.

### Tests
- New `frontend/test/walletStorage.test.js` (11 tests): vault create/lock/unlock, wrong passphrase, AES-GCM tamper detection, no plaintext secrets, fresh IV per save, legacy migration, credential store, log cap, encrypted backup, reset.
- New `frontend/test/e2e.test.js`: real HTTP backend + browser wallet code through issue -> vault -> selective presentation -> verify -> replay -> tamper -> stolen credential -> revoke/restore.
- New `backend/test/production.test.js` (10 tests): restart durability across real processes, atomic challenge consume, metadata-only issuer storage (also scans the files on disk for claim values), operator auth, audit log, production config guard.
- New `backend/test/hardening.test.js` (12 tests): challenge audience binding, single use, eviction and size bound; rate limiter (429, Retry-After, per-IP, window reset); StatusList2021 bit allocation, MSB-first encoding and persistence.
- Fixed `walletStorage.js` importing `./vaultCrypto` without an extension, which broke it under plain Node (and therefore under `node --test`).

## 2.0.0

Security and correctness release based on a code review of v1.

### Fixed (functional bugs)
- **Selective disclosure verified as invalid.** v1 deleted claims from the credential before presenting, which broke the issuer's signature, so the headline feature failed its own verifier. v2 uses salted-hash commitments (SD-JWT style): subsets of claims verify.
- **Playground "signature" did not sign the message.** It returned the signature of an empty presentation. It now signs the real text (with a domain-separation prefix) and verifies it.
- **Presentation nonce/domain were not signed**, so they could be swapped freely. Proof options are now hashed with the document.
- `package-lock.json` was git-ignored although the Dockerfile uses `npm ci`; it is now tracked.

### Security
- Presentations require a verifier-issued, single-use, expiring challenge and matching audience (replay protection).
- Holder binding: credential subject must equal the presenting holder.
- Trusted-issuer registry; issuers are checked against the credential type they are allowed to issue.
- Issuer endpoints (issue, revoke, unrevoke, list) require `ISSUER_API_KEY` (mandatory in production).
- Holder private keys are generated and used only in the browser; server endpoints that accepted or generated them were removed.
- Wallet vault encrypted at rest (AES-256-GCM, PBKDF2-SHA256 310k), passphrase unlock, 10-minute auto-lock, encrypted identity backups. Legacy plaintext wallets are migrated.
- Issuer keys can be derived from `ISSUER_MASTER_SECRET` (nothing private on disk); otherwise stored with mode 0600 and git-ignored.
- Strict input validation (DID format, claim names/types/size, expiry range), rate limiting, CSP and other security headers, restricted CORS, 1 MB body limit, no stack traces in errors, atomic file writes, non-root Docker user.

### Standards
- Revocation is now real **StatusList2021** (bitstring, signed list at `/api/status/list/:issuerId`) instead of an ID map.
- JCS canonicalization hardened (rejects non-finite numbers, handles `undefined` like `JSON.stringify`), cross-checked against the browser implementation.
- `ZK` wording removed: the feature is selective disclosure, not zero-knowledge.

### Developer experience
- Test suites: 19 backend tests, 5 browser/backend compatibility tests (`npm test`).
- `app.js`/`server.js` split so the API can be tested; `.env.example` documents all settings.
- Removed `vercel.json` (serverless is incompatible with the stateful backend).

### Upgrade notes
- **Credentials issued by v1 do not verify under v2** (the signed bytes changed: proof options are now hashed in, and claims are committed rather than inline). Delete `backend/data/` and re-issue. The v1 issuer keys in `data/issuers.json` should be considered compromised if that file was ever shared.
- Existing browser wallets are migrated into the encrypted vault the first time you create a passphrase.
