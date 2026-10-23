import zlib from 'zlib';
import { db, tx } from './db.js';

/** StatusList2021 recommends >= 131,072 entries so that one credential hides in a crowd. */
export const STATUS_LIST_SIZE = 131_072;
const LIST_BYTES = STATUS_LIST_SIZE / 8;

/**
 * Revocation via W3C StatusList2021-style bitstrings, persisted in SQLite.
 *
 * Every credential gets a (statusListIndex) slot in its issuer's list at issuance time.
 * Revoking flips that bit; the issuer then publishes the list as a signed
 * StatusList2021Credential at /api/status/list/:issuerId. Verifiers look at the bit instead
 * of asking "is credential X revoked?". A per-credential audit record (reason, time, operator)
 * is kept alongside. Index allocation and bit flips are transactional.
 */
class RevocationRegistry {
  #ensure(issuerId) {
    db.prepare('INSERT OR IGNORE INTO status_lists (issuer_id, next_index, bits) VALUES (?, 0, ?)')
      .run(issuerId, Buffer.alloc(LIST_BYTES));
  }

  #bits(issuerId) {
    this.#ensure(issuerId);
    return Buffer.from(db.prepare('SELECT bits FROM status_lists WHERE issuer_id = ?').get(issuerId).bits);
  }

  /** Reserve the next free status slot for a new credential. */
  allocateIndex(issuerId) {
    return tx(() => {
      this.#ensure(issuerId);
      const { next_index: next } = db.prepare('SELECT next_index FROM status_lists WHERE issuer_id = ?').get(issuerId);
      if (next >= STATUS_LIST_SIZE) throw new Error('Status list is full for this issuer.');
      db.prepare('UPDATE status_lists SET next_index = ? WHERE issuer_id = ?').run(next + 1, issuerId);
      return next;
    });
  }

  #setBit(issuerId, index, value) {
    const bytes = this.#bits(issuerId);
    if (value) bytes[index >> 3] |= (0x80 >> (index & 7)); // MSB-first, as in StatusList2021
    else bytes[index >> 3] &= ~(0x80 >> (index & 7));
    db.prepare('UPDATE status_lists SET bits = ? WHERE issuer_id = ?').run(bytes, issuerId);
  }

  /** Is the status slot (issuerId, index) revoked? */
  isIndexRevoked(issuerId, index) {
    const i = Number(index);
    if (!Number.isInteger(i) || i < 0 || i >= STATUS_LIST_SIZE) return false;
    return (this.#bits(issuerId)[i >> 3] & (0x80 >> (i & 7))) !== 0;
  }

  /** GZIP + Base64 encoded list, as carried in StatusList2021Credential.encodedList. */
  encodedList(issuerId) {
    return zlib.gzipSync(this.#bits(issuerId)).toString('base64');
  }

  isRevoked(credentialId) {
    return !!credentialId && !!db.prepare('SELECT 1 FROM revocations WHERE credential_id = ?').get(credentialId);
  }

  revoke({ credentialId, issuerId, statusIndex }, reason = 'Revoked by issuer authority', revokedBy = 'Issuer') {
    if (!credentialId) throw new Error('Credential ID is required.');
    const record = {
      credentialId,
      revoked: true,
      revokedAt: new Date().toISOString(),
      revocationReason: String(reason).slice(0, 200),
      revokedBy: String(revokedBy).slice(0, 100)
    };
    tx(() => {
      if (statusIndex !== undefined && statusIndex !== null) this.#setBit(issuerId, statusIndex, true);
      db.prepare('INSERT OR REPLACE INTO revocations VALUES (?, ?, ?, ?)')
        .run(credentialId, record.revokedAt, record.revocationReason, record.revokedBy);
    });
    return record;
  }

  unrevoke({ credentialId, issuerId, statusIndex }) {
    return tx(() => {
      if (statusIndex !== undefined && statusIndex !== null) this.#setBit(issuerId, statusIndex, false);
      return db.prepare('DELETE FROM revocations WHERE credential_id = ?').run(credentialId).changes > 0;
    });
  }

  #row = (r) => ({
    credentialId: r.credential_id, revoked: true, revokedAt: r.revoked_at,
    revocationReason: r.reason, revokedBy: r.revoked_by
  });

  getStatus(credentialId) {
    const r = db.prepare('SELECT * FROM revocations WHERE credential_id = ?').get(credentialId);
    return r ? this.#row(r) : { credentialId, revoked: false, status: 'Active' };
  }

  getAll() {
    return db.prepare('SELECT * FROM revocations ORDER BY revoked_at DESC').all().map(this.#row);
  }
}

export const revocationRegistry = new RevocationRegistry();
