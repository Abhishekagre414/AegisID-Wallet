# AegisID Production Deployment Guide

## Production checklist (read this first)

The server **refuses to start** in production (`NODE_ENV=production`) unless these are set:

| Variable | Requirement | Why |
|---|---|---|
| `ISSUER_API_KEY` or `ISSUER_API_KEYS` | >= 24 chars each. `ISSUER_API_KEYS=alice:key,bob:key` gives one key per operator | Protects issue/revoke; operator names go in the audit log |
| `ISSUER_MASTER_SECRET` | >= 32 chars, keep it secret and never change it | Derives issuer signing keys. Changing it changes every issuer DID and invalidates issued credentials |
| `APP_URL` | public `https://` URL | Embedded in credential status URLs |
| `DATA_DIR` | a **persistent** disk/volume (warning if unset) | Holds `aegis.db` (revocations, status lists, issuance metadata, audit log) |

Generate secrets:
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"
```

Rules for real production:
1. **Persistent storage is mandatory.** On a host that wipes its disk (Render free plan, most PaaS without a disk), a restart would make revoked credentials valid again.
2. **Run exactly one instance.** State is SQLite on one disk. Do not enable autoscaling or multiple replicas.
3. **Back up regularly:** `npm run backup` (consistent online copy via `VACUUM INTO`, written to `DATA_DIR/backups/`). Copy it off the machine, and test a restore.
4. **Back up `ISSUER_MASTER_SECRET` separately** (password manager/secret store). Without it you cannot re-create the issuer keys.
5. Put the app behind HTTPS (Render, Caddy, nginx or a cloud load balancer). The app sets HSTS in production.
6. Watch `/api/ready` (returns 503 if the database is unavailable) and review `GET /api/audit` (needs an issuer key).
7. Optionally put a CDN/WAF in front for DDoS protection; the built-in rate limiting is per IP and per process.
8. Needs **Node >= 22.13** (uses the built-in `node:sqlite`).

---

## Deployment Strategy Options

| Target Platform | Recommended For | Notes |
|---|---|---|
| **Docker Compose on a VPS** | Real production | Persistent named volume, secrets required by the compose file |
| **Render.com (paid plan + disk)** | Real production, simplest | `render.yaml` provisions a 1 GB persistent disk. The **free plan is demo-only** |
| **Local / Intranet** | College lab, presentation | `npm start`, no persistence guarantees needed |

## Option 1: One-Command Local Production Run

In the project root, run (for a local demo; set the variables above for anything public):
```bash
# 1. Build frontend and install dependencies
npm run build

# 2. Start unified server
npm start
```

The unified Node.js server will serve both:
- The React Frontend at: `http://localhost:5000`
- The REST API at: `http://localhost:5000/api`

---

## Option 2: Deploying to Render.com (paid plan + disk for production)

Render provides automatic SSL certificates (`https://your-app.onrender.com`).

> **Persistent disks need a paid plan.** `render.yaml` uses `plan: starter` with a disk mounted at `/var/data` (`DATA_DIR`). On the free plan the disk is wiped on every restart, so use it for demos only.

### Method A: Using `render.yaml` (Blueprint)
1. Push this project to GitHub.
2. Log into [Render Dashboard](https://dashboard.render.com).
3. Click **New +** -> **Blueprint**.
4. Select your GitHub repository.
5. Render will automatically detect `render.yaml` and configure:
   - Build Command: `npm run build`
   - Start Command: `npm start`
6. Render prompts for `APP_URL` (a `sync: false` value): enter `https://<your-service>.onrender.com`. Then click **Apply**. The secrets are generated for you; copy `ISSUER_API_KEY` from the dashboard.

### Method B: Manual Web Service
- **Build Command**: `npm run build`
- **Start Command**: `npm start`
- **Environment Variables**:
  - `NODE_ENV`: `production`
  - `PORT`: `10000`
  - `APP_URL`: `https://your-service-name.onrender.com`

---

## Option 3: Docker & Docker Compose (Any Cloud VPS)

### Using Docker Compose
Create a `.env` next to `docker-compose.yml` (never commit it):
```bash
APP_URL=https://id.example.com
ISSUER_API_KEY=<24+ chars>
ISSUER_MASTER_SECRET=<32+ chars>
# ISSUER_API_KEYS=alice:<key>,bob:<key>   # optional, per-operator keys
```
```bash
docker compose up -d --build   # refuses to start if a required value is missing
docker compose logs -f
docker compose exec aegis-id-wallet node backend/scripts/backup.js   # backup inside the volume
```
Data lives in the `aegis_data` volume (`/app/backend/data`). Do not run `docker run` without a volume and the secrets: the database and signing keys would not survive a container rebuild.

---

## Option 4: Deploying to Railway.app

1. Go to [railway.app](https://railway.app) and click **New Project** -> **Deploy from GitHub repo**.
2. Railway runs `npm run build` then `npm start`. Under Settings -> Domains, click **Generate Domain**.
3. **Add a Volume** (Settings -> Volumes) mounted at `/data` and set `DATA_DIR=/data`. Without a volume the database is lost on redeploy.
4. Set the variables: `NODE_ENV=production`, `APP_URL=https://<your-domain>`, `ISSUER_API_KEY`, `ISSUER_MASTER_SECRET`, `DATA_DIR=/data`.
5. Keep the replica count at 1.

---

## Option 5: Vercel (not supported)

Serverless platforms are a poor fit for this backend: it keeps revocation lists, issuance metadata and
single-use verifier challenges in a SQLite file, and serverless functions have
neither a persistent filesystem nor a long-lived process. The previous `vercel.json` has been removed.
Use Render, Railway, Docker or any VPS instead.

---

## 🔐 Environment Variables Reference

| Variable | Default | Description |
|---|---|---|
| `PORT` | `5000` | Port for the unified server |
| `NODE_ENV` | `development` | `production` enables HSTS, same-origin-only CORS and the fail-fast configuration checks |
| `APP_URL` | `http://localhost:5000` | Public URL used inside `credentialStatus` / status-list URLs. **Required (https) in production** |
| `ISSUER_API_KEY` | _(none)_ | Shared issuer key (`x-api-key`, operator name `admin`). >= 24 chars; **required in production** unless `ISSUER_API_KEYS` is set |
| `ISSUER_API_KEYS` | _(none)_ | Per-operator keys: `alice:key,bob:key`. Operator names appear in the audit log |
| `ISSUER_MASTER_SECRET` | _(none)_ | Derives all issuer signing keys (HKDF). >= 32 chars; **required in production**. Changing it changes the issuer DIDs |
| `DATA_DIR` | `backend/data` | Where `aegis.db` lives. Point at a persistent disk/volume |
| `CORS_ORIGIN` | _(none)_ | Comma-separated allowed browser origins. Empty = same-origin only in production |

---|---|---|
| `PORT` | `5000` | Port for the unified server |
| `NODE_ENV` | `development` | `production` enables HSTS, mandatory issuer key and same-origin-only CORS |
| `APP_URL` | `http://localhost:5000` | Public URL used inside `credentialStatus` / status-list URLs |
| `ISSUER_API_KEY` | _(none)_ | Protects issue / revoke / list endpoints (`x-api-key`). Mandatory in production; a random one is generated and logged if unset |
| `ISSUER_MASTER_SECRET` | _(none)_ | Derives all issuer signing keys (HKDF) so no private key is stored on disk. Changing it changes the issuer DIDs |
| `CORS_ORIGIN` | _(none)_ | Comma-separated allowed browser origins. Empty = same-origin only in production |

---

## 🛡️ Post-deploy verification

Run these against your live URL after the first deploy:

- [ ] `GET /api/ready` returns `200`
- [ ] `GET /api/auth/status` returns `{"required": true}`
- [ ] Issuing without the key returns `401`; with the key it succeeds
- [ ] Issue a credential, revoke it, then **restart the service** and verify it is still revoked
- [ ] `GET /api/status/list/issuer-edu` returns a signed `StatusList2021Credential` whose URLs start with your `APP_URL`
- [ ] `npm run backup` produces a file, and you have copied it off the machine
