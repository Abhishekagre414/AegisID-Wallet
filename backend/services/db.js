import fs from 'fs';
import path from 'path';
import { DatabaseSync } from 'node:sqlite';
import { DATA_DIR, dataPath } from './storage.js';

/**
 * Durable state lives in one SQLite database (WAL, synchronous=FULL):
 *   status_lists  StatusList2021 bitstrings and the next free index per issuer
 *   revocations   revocation audit records
 *   issued        issuance METADATA ONLY (no claim values are retained)
 *   challenges    single-use presentation challenges (survive restarts)
 *   audit         who did what (issuer operators)
 *
 * Every multi-step change runs inside a transaction, so a crash can never leave a half-applied
 * revocation or a re-used status index. Use a persistent disk and a SINGLE instance.
 */
export const DB_FILE = path.join(DATA_DIR, 'aegis.db');
export const db = new DatabaseSync(DB_FILE);

db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA synchronous = FULL;
  PRAGMA busy_timeout = 5000;

  CREATE TABLE IF NOT EXISTS status_lists (
    issuer_id  TEXT PRIMARY KEY,
    next_index INTEGER NOT NULL,
    bits       BLOB NOT NULL
  );
  CREATE TABLE IF NOT EXISTS revocations (
    credential_id TEXT PRIMARY KEY,
    revoked_at    TEXT NOT NULL,
    reason        TEXT NOT NULL,
    revoked_by    TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS issued (
    credential_id   TEXT PRIMARY KEY,
    issuer_id       TEXT NOT NULL,
    issuer_name     TEXT NOT NULL,
    issuer_did      TEXT NOT NULL,
    subject_did     TEXT NOT NULL,
    credential_type TEXT NOT NULL,
    status_index    INTEGER NOT NULL,
    issuance_date   TEXT NOT NULL,
    expiration_date TEXT,
    seq             INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS issued_seq ON issued(seq DESC);
  CREATE TABLE IF NOT EXISTS challenges (
    challenge  TEXT PRIMARY KEY,
    domain     TEXT,
    expires_at INTEGER NOT NULL,
    seq        INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS challenges_exp ON challenges(expires_at);
  CREATE TABLE IF NOT EXISTS audit (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       TEXT NOT NULL,
    operator TEXT NOT NULL,
    action   TEXT NOT NULL,
    detail   TEXT NOT NULL
  );
`);

/** Run `fn` atomically. Nested calls simply join the outer transaction. */
let depth = 0;
export function tx(fn) {
  if (depth > 0) return fn();
  db.exec('BEGIN IMMEDIATE');
  depth++;
  try {
    const out = fn();
    db.exec('COMMIT');
    return out;
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  } finally {
    depth--;
  }
}

export function audit(operator, action, detail = '') {
  db.prepare('INSERT INTO audit (ts, operator, action, detail) VALUES (?, ?, ?, ?)')
    .run(new Date().toISOString(), String(operator || 'unknown').slice(0, 64), action, String(detail).slice(0, 500));
}

export const getAudit = (limit = 200) =>
  db.prepare('SELECT ts, operator, action, detail FROM audit ORDER BY id DESC LIMIT ?').all(limit);

export function dbHealthy() {
  try { return db.prepare('SELECT 1 AS ok').get().ok === 1; } catch { return false; }
}

export function closeDb() {
  try { db.close(); } catch { /* already closed */ }
}

/* ---- One-time import of v2.0 JSON state (never touches claim values) ------------------- */
function migrateLegacyJson() {
  const read = (f) => { try { return JSON.parse(fs.readFileSync(dataPath(f), 'utf-8')); } catch { return null; } };
  const done = [];

  const lists = read('statusLists.json');
  if (lists) {
    tx(() => {
      for (const [id, l] of Object.entries(lists)) {
        db.prepare('INSERT OR IGNORE INTO status_lists (issuer_id, next_index, bits) VALUES (?, ?, ?)')
          .run(id, l.nextIndex, Buffer.from(l.bits, 'base64'));
      }
    });
    done.push('statusLists.json');
  }
  const revs = read('revocations.json');
  if (revs) {
    tx(() => {
      for (const r of Object.values(revs)) {
        db.prepare('INSERT OR IGNORE INTO revocations VALUES (?, ?, ?, ?)')
          .run(r.credentialId, r.revokedAt, r.revocationReason || '', r.revokedBy || 'Issuer');
      }
    });
    done.push('revocations.json');
  }
  const issued = read('issuedCredentials.json');
  if (Array.isArray(issued)) {
    tx(() => {
      issued.slice().reverse().forEach((r, i) => {
        db.prepare('INSERT OR IGNORE INTO issued VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(
          r.credentialId, r.issuerId, r.issuerName, r.issuerDid, r.subjectDid, r.credentialType,
          r.statusIndex, r.issuanceDate, r.expirationDate || null, i + 1
        );
      });
    });
    done.push('issuedCredentials.json'); // claim values in the old file are deliberately not imported
  }
  for (const f of done) {
    try { fs.renameSync(dataPath(f), dataPath(`${f}.migrated`)); } catch { /* best effort */ }
  }
  if (done.length) console.log(`[db] imported legacy state from ${done.join(', ')} (renamed *.migrated; delete them once verified)`);
}
migrateLegacyJson();
