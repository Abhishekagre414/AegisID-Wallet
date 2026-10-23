import crypto from 'crypto';
import { db, tx } from './db.js';

const TTL_MS = 5 * 60 * 1000;
const MAX_ENTRIES = 10_000;

/**
 * SQLite-backed twin of ChallengeStore (same interface). Challenges survive restarts and
 * `consume` is atomic: of two concurrent verifications of one presentation, exactly one wins.
 */
export class PersistentChallengeStore {
  constructor({ ttlMs = TTL_MS } = {}) { this.ttlMs = ttlMs; }

  create(domain = null) {
    const challenge = crypto.randomBytes(18).toString('base64url');
    const expiresAt = Date.now() + this.ttlMs;
    tx(() => {
      db.prepare('DELETE FROM challenges WHERE expires_at < ?').run(Date.now());
      const { n } = db.prepare('SELECT COUNT(*) AS n FROM challenges').get();
      if (n >= MAX_ENTRIES) {
        db.prepare('DELETE FROM challenges WHERE challenge IN (SELECT challenge FROM challenges ORDER BY seq LIMIT ?)')
          .run(n - MAX_ENTRIES + 1);
      }
      const { s } = db.prepare('SELECT COALESCE(MAX(seq), 0) + 1 AS s FROM challenges').get();
      db.prepare('INSERT INTO challenges (challenge, domain, expires_at, seq) VALUES (?, ?, ?, ?)')
        .run(challenge, domain, expiresAt, s);
    });
    return { challenge, domain, expiresAt: new Date(expiresAt).toISOString() };
  }

  validate(challenge, domain) {
    if (typeof challenge !== 'string') return { ok: false, reason: 'no challenge in proof.' };
    const row = db.prepare('SELECT domain, expires_at FROM challenges WHERE challenge = ?').get(challenge);
    if (!row) return { ok: false, reason: 'unknown or already used (possible replay).' };
    if (row.expires_at < Date.now()) {
      db.prepare('DELETE FROM challenges WHERE challenge = ?').run(challenge);
      return { ok: false, reason: 'challenge expired.' };
    }
    if (row.domain && row.domain !== domain) {
      return { ok: false, reason: `audience mismatch (expected domain "${row.domain}").` };
    }
    return { ok: true };
  }

  /** Returns true only for the single caller that actually removed the challenge. */
  consume(challenge) {
    return db.prepare('DELETE FROM challenges WHERE challenge = ?').run(challenge).changes === 1;
  }
}

export const persistentChallengeStore = new PersistentChallengeStore();
