# AegisID: Decentralized Identity (DID) Wallet Using Verifiable Credentials

A full-stack **decentralized identity wallet and verification ecosystem** built on W3C **DID Core** (`did:key`) and the W3C **Verifiable Credentials Data Model 1.1**, using **Ed25519** signatures with no blockchain dependency.

> v2 fixes the main security and correctness gaps found in a review of v1 (see [CHANGELOG.md](CHANGELOG.md)). Selective disclosure now genuinely works and verifies, presentations are replay-protected, issuers are checked against a trust registry, the holder's private key never leaves the browser, and the wallet is encrypted at rest.

---

## Architecture

```
                 +----------------------------------------------+
                 |  Issuer (server-side signing, API-key gated) |
                 |  GovTrust · MIT · CyberMesh · FinGuard       |
                 +----------------------------------------------+
                      |                              |
   1. signed VC + salted        3. signs & publishes a StatusList2021
      disclosures (Ed25519)        revocation list (/api/status/list/:id)
                      v                              v
+-----------------------------------+      +------------------------------------+
|  Holder Wallet (browser only)     |      |  Verifier                          |
|  - keys generated & used locally  |  VP  |  - issues single-use challenges    |
|  - AES-256-GCM encrypted vault    | ---> |  - signature + trust registry      |
|  - picks claims to reveal         |  2.  |  - disclosure commitments          |
|  - signs presentation locally     |      |  - expiry, revocation, holder bind |
+-----------------------------------+      +------------------------------------+
```

## What it demonstrates

| Area | How it works |
|---|---|
| **Identifiers** | `did:key` (Ed25519, multicodec `0xed01`, base58btc). Resolution needs no network. |
| **Signing** | Data-Integrity style: `Ed25519(SHA-256(JCS(proofOptions)) ‖ SHA-256(JCS(document)))`. Proof metadata (`created`, `verificationMethod`, `challenge`, `domain`) is covered by the signature. |
| **Canonicalization** | RFC 8785 (JCS) for I-JSON data. Browser and backend implementations are tested against each other. |
| **Selective disclosure** | SD-JWT-style salted-hash commitments. The issuer signs only `credentialSubject = { id, _sd: [digests] }`; claim values travel as unsigned `disclosures` `[salt, name, value]`. A holder drops the claims it wants to hide and the issuer signature **still verifies**. Salts prevent brute-forcing hidden values from the digests. |
| **Presentations** | Signed by the holder in the browser over a **verifier-issued, single-use, expiring challenge** and an audience `domain`. Replay is rejected; the credential's subject must equal the presenting holder (stolen credentials are useless). |
| **Trust** | The verifier only accepts issuers in its registry that are authorised for the credential type. A self-issued "GovTrust" credential fails. |
| **Revocation** | W3C **StatusList2021**: each credential gets a bit in its issuer's 131,072-entry list, published as a signed `StatusList2021Credential`. Issuers can revoke and restore. |
| **Wallet security** | Private key is generated and used only in the browser, stored in an AES-256-GCM vault (PBKDF2-SHA256, 310k iterations), auto-locks after 10 min, backups are passphrase-encrypted. |

> "Selective disclosure" here is hash-based, not zero-knowledge. It hides undisclosed claims but does not prove predicates such as "age > 18" without revealing a value. Real ZK predicates would need BBS+ signatures or zk-SNARKs.

## Technology stack

| Layer | Technologies |
|---|---|
| Frontend | React 19, Vite, `@noble/curves` (Ed25519), `@noble/hashes`, WebCrypto (PBKDF2/AES-GCM), Lucide, QRCode, Canvas-Confetti |
| Backend | Node.js ≥ 20, Express 5, Node `crypto` (Ed25519, SHA-256, HKDF), `bs58` |
| Standards | W3C DID Core (`did:key`), VC Data Model 1.1, StatusList2021, RFC 8785 JCS, SD-JWT-style disclosure |

## Quick start

```bash
# terminal 1: backend (http://localhost:5000)
cd backend && npm install && npm run dev

# terminal 2: frontend dev server with proxy (http://localhost:3000)
cd frontend && npm install && npm run dev
```

Or build and run everything on one port: `npm run build && npm start` (or `./start.sh` / `start.bat`).

In development the issuer endpoints are open (a warning is logged). **Production refuses to start** unless `ISSUER_API_KEY`(`S`), `ISSUER_MASTER_SECRET` and an https `APP_URL` are set. See `.env.example` and [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md). Requires Node >= 22.13.

### Tests

```bash
npm run install:all   # once
npm test              # backend suite + browser/backend crypto-compatibility suite
```

The tests cover JCS, did:key, issuing/verifying, tamper detection, selective disclosure (valid, forged, duplicated), trust registry, expiry, revocation via StatusList, challenge binding, replay and expiry, holder binding, API authentication, input validation and security headers. One suite signs presentations with the **browser** code and verifies them with the **backend** code.

## Demo walkthrough (viva)

1. **Create the wallet.** Choose a passphrase (≥ 10 chars). The Ed25519 key and your `did:key:z6Mk…` are generated locally and stored encrypted.
2. **Issue.** *Issuer Portal* → (enter the issuer key if the server requires one) → pick *University Degree* → **Sign & Issue**. The credential lands in your wallet; its signed body contains only digests, not claims.
3. **Inspect.** In the wallet, open the credential JSON and note `credentialSubject._sd` plus the separate `disclosures`.
4. **Selective presentation.** Click **Present (Selective)**, untick e.g. CGPA and honors, and **Sign & Generate Verifiable Presentation**. The wallet requests a challenge from the verifier, signs locally and drops the hidden disclosures. Copy the presentation JSON.
5. **Verify.** *Verifier Inspector* → paste the presentation → **Run Cryptographic Audit**. All checks pass and the report lists only the claims you revealed.
6. **Replay attack.** Verify the *same* presentation again. It is rejected (`challengeValid: false`, unknown or already used).
7. **Tamper attack.** Click **Simulate Tampering Attack**. A revealed claim value is altered; the disclosure no longer matches the issuer's signed commitment and verification fails.
8. **Forged issuer.** Anyone can create a validly *signed* credential with their own key, but it fails `issuerTrusted`.
9. **Revocation.** *Issuer Portal* → revoke the credential → re-verify: signature is intact but `notRevoked` fails. **Restore** to reactivate.

## API overview

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /api/health`, `/api/ready`, `/api/auth/status` | – | Liveness; readiness (database check); whether an issuer key is required |
| `GET /api/audit` | issuer key | Operator audit log (issue, revoke, failed logins) |
| `GET /api/did/resolve/:did` | – | Resolve `did:key` to a DID Document |
| `GET /api/issuers`, `/api/templates` | – | Issuer and template metadata (no keys) |
| `POST /api/credentials/issue` | issuer key | Issue a credential (validated, type-checked) |
| `GET /api/credentials/issued` | issuer key | Issuer audit log |
| `POST /api/credentials/verify` | – | Verify a credential |
| `GET /api/verifier/challenge?domain=` | – | Single-use presentation challenge (5 min) |
| `POST /api/presentation/verify` | – | Verify a presentation (consumes the challenge) |
| `GET /api/status/list/:issuerId` | – | Signed StatusList2021 revocation list |
| `POST /api/revocation/revoke` · `/unrevoke` · `GET /api/revocation/list` | issuer key | Manage revocation |

There is intentionally **no** endpoint that generates holder keys or signs presentations: private keys never reach the server.

## Security model and known limitations

- **Issuer keys** are derived (HKDF) from `ISSUER_MASTER_SECRET` and never stored; production refuses to start without it. A real issuer should still use an HSM/KMS.
- **Issuer access** uses API keys: one per operator (`ISSUER_API_KEYS`) so every issue/revoke is attributed in the audit log. A larger deployment would add SSO/OIDC.
- **State is durable but single-node.** Revocations, status lists, issuance metadata, challenges and the audit log are in one SQLite database on a persistent disk (WAL, fsync on commit). Run **one instance**; horizontal scaling needs a networked database, and the in-memory per-IP rate limiter would need a shared store too. Back up with `npm run backup`.
- **The issuer retains no personal data**: only metadata (type, subject DID, dates, status index). Claim values live in the holder's wallet.
- **Verifier-side revocation** reads the status list locally (same server). A third-party verifier would fetch and check the signed list at `credentialStatus.statusListCredential`.
- **did:key has no key rotation or recovery.** Losing the passphrase or key means losing the identity.
- **The wallet passphrase has no recovery.** A forgotten passphrase means the vault cannot be decrypted (an encrypted identity backup can be exported).
- **Hash-based selective disclosure is not zero-knowledge** and is linkable across presentations of the same credential (the signature and digests repeat).
- Not covered: a third-party security audit, DDoS protection beyond per-IP rate limiting (put a CDN/WAF in front), and a browser-level UI test suite.

## Viva / interview Q&A

**Q1: What is a DID?** A globally unique identifier controlled by its subject, not issued by a central registry. In `did:key` the identifier *is* the public key (multicodec `0xed01` + Ed25519 key, base58btc), so any verifier can resolve it offline.

**Q2: Why canonicalize JSON (RFC 8785)?** Signatures cover bytes. Key order and whitespace must not change those bytes, so we canonicalize before hashing.

**Q3: VC vs VP?** A VC is an issuer's signed assertion about a subject. A VP is signed by the *holder*, carries one or more VCs (or parts of them) and proves the holder controls the subject DID, bound to a verifier's challenge and domain.

**Q4: How does your selective disclosure work, and why does the issuer signature still verify?** The issuer signs salted hash commitments to each claim, not the claims. The holder reveals only some `[salt, name, value]` triples; the verifier recomputes each digest and checks it is among the signed ones. Hidden claims stay hidden; the signed document is unchanged.

**Q5: Is that zero-knowledge?** No. It is selective disclosure. ZK would let you prove a predicate (e.g. over 18) without revealing the value, which needs BBS+ or a SNARK.

**Q6: How do you stop replay of a captured presentation?** The verifier issues a random, expiring, single-use challenge bound to an audience. The holder signs over challenge and domain (they are part of the proof options that are hashed). The verifier consumes the challenge on first use.

**Q7: A forger creates a perfectly signed credential with their own key. Why is it rejected?** A valid signature only proves *some* key signed it. Trust comes from the issuer registry: the verifier checks the issuer DID is known and authorised for that credential type.

**Q8: Why StatusList2021 instead of a revoked-IDs list?** The verifier checks one bit in a large public list, so the issuer cannot tell *which* credential is being checked, and the list stays a fixed, compact, signed artifact.

**Q9: Where does the holder's private key live?** Generated in the browser, kept in an AES-256-GCM vault keyed by PBKDF2 from the passphrase, and used only for local signing. The server has no endpoint that accepts or produces holder keys.

## License

MIT License. Built for Decentralized Identity (DID) research and CIS projects.
