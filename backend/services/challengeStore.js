import crypto from 'crypto';

const TTL_MS = 5 * 60 * 1000;
const MAX_ENTRIES = 10_000;

/**
 * Verifier-issued, single-use challenges. A presentation is only accepted if it is signed
 * over a challenge this verifier issued, for the audience (domain) it was issued for,
 * before it expired, and exactly once. That is what stops replay of a captured presentation.
 */
export class ChallengeStore {
  constructor({ ttlMs = TTL_MS } = {}) {
    this.ttlMs = ttlMs;
    this.challenges = new Map();
  }

  create(domain = null) {
    this.#evict();
    const challenge = crypto.randomBytes(18).toString('base64url');
    const expiresAt = Date.now() + this.ttlMs;
    this.challenges.set(challenge, { domain, expiresAt });
    return { challenge, domain, expiresAt: new Date(expiresAt).toISOString() };
  }

  validate(challenge, domain) {
    if (typeof challenge !== 'string') return { ok: false, reason: 'no challenge in proof.' };
    const entry = this.challenges.get(challenge);
    if (!entry) return { ok: false, reason: 'unknown or already used (possible replay).' };
    if (entry.expiresAt < Date.now()) {
      this.challenges.delete(challenge);
      return { ok: false, reason: 'challenge expired.' };
    }
    if (entry.domain && entry.domain !== domain) {
      return { ok: false, reason: `audience mismatch (expected domain "${entry.domain}").` };
    }
    return { ok: true };
  }

  /** Returns true only if this call removed the challenge (i.e. it had not been used yet). */
  consume(challenge) {
    return this.challenges.delete(challenge);
  }

  #evict() {
    const now = Date.now();
    for (const [key, v] of this.challenges) if (v.expiresAt < now) this.challenges.delete(key);
    while (this.challenges.size >= MAX_ENTRIES) {
      this.challenges.delete(this.challenges.keys().next().value);
    }
  }
}

export const challengeStore = new ChallengeStore();
