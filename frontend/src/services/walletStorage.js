import { deriveKey, encryptJson, decryptJson, randomBytes, toB64, fromB64, KDF_ITERATIONS } from './vaultCrypto.js';

/**
 * Encrypted wallet vault.
 *
 * Everything (identity incl. private key, credentials, activity log) lives in ONE
 * AES-256-GCM blob in localStorage, keyed from the user's passphrase with PBKDF2.
 * While unlocked, the decrypted state is held in memory and the synchronous accessors below
 * read from it; every mutation re-encrypts and persists in the background.
 * Locking (or closing the tab) drops the key and the plaintext.
 */
const VAULT_KEY = 'aegis_vault_v2';
const LEGACY = { identity: 'aegis_holder_identity', vault: 'aegis_credential_vault', logs: 'aegis_activity_logs' };
export const MIN_PASSPHRASE_LENGTH = 10;

let state = null;      // { identity, credentials, logs } while unlocked
let cryptoKey = null;
let kdf = null;        // { salt, iterations }
let queue = Promise.resolve();

const readLegacy = (k) => { try { return JSON.parse(localStorage.getItem(k)); } catch { return null; } };
const wipeLegacy = () => Object.values(LEGACY).forEach(k => localStorage.removeItem(k));

function persist() {
  queue = queue.then(async () => {
    if (!state || !cryptoKey) return;
    const blob = await encryptJson(cryptoKey, state);
    localStorage.setItem(VAULT_KEY, JSON.stringify({
      v: 2, kdf: { salt: toB64(kdf.salt), iterations: kdf.iterations }, ...blob
    }));
  }).catch(err => console.error('Vault persist failed:', err));
  return queue;
}

export const walletStorage = {
  hasVault: () => !!localStorage.getItem(VAULT_KEY),
  hasLegacyData: () => !!localStorage.getItem(LEGACY.identity),
  isUnlocked: () => state !== null,

  /** Create a new vault (migrating any old plaintext wallet data found in this browser). */
  async create(passphrase) {
    if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
      throw new Error(`Passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters.`);
    }
    kdf = { salt: randomBytes(16), iterations: KDF_ITERATIONS };
    cryptoKey = await deriveKey(passphrase, kdf.salt, kdf.iterations);
    state = {
      identity: readLegacy(LEGACY.identity),
      credentials: readLegacy(LEGACY.vault) || [],
      logs: readLegacy(LEGACY.logs) || []
    };
    await persist();
    wipeLegacy(); // the plaintext private key must not linger next to the encrypted vault
  },

  async unlock(passphrase) {
    const stored = JSON.parse(localStorage.getItem(VAULT_KEY));
    const salt = fromB64(stored.kdf.salt);
    const key = await deriveKey(passphrase, salt, stored.kdf.iterations);
    try {
      state = await decryptJson(key, stored);
    } catch {
      throw new Error('Incorrect passphrase.');
    }
    cryptoKey = key;
    kdf = { salt, iterations: stored.kdf.iterations };
  },

  lock() { state = null; cryptoKey = null; kdf = null; },

  /** Forget the vault entirely (forgotten passphrase). Irreversible. */
  reset() {
    localStorage.removeItem(VAULT_KEY);
    wipeLegacy();
    walletStorage.lock();
  },

  // ---- Identity ----
  getIdentity: () => state?.identity ?? null,
  setIdentity(identity) { state.identity = identity; persist(); },
  clearIdentity() { state.identity = null; persist(); },

  // ---- Credential vault ----
  getCredentials: () => state?.credentials ?? [],
  saveCredential(vc) {
    if (!state || !vc || !vc.id) return false;
    const i = state.credentials.findIndex(c => c.id === vc.id);
    if (i >= 0) state.credentials[i] = vc; else state.credentials.unshift(vc);
    walletStorage.logActivity('Received Credential', `Received ${vc.type?.[1] || 'Credential'} (${vc.id.slice(0, 20)}...)`);
    return true;
  },
  removeCredential(id) {
    state.credentials = state.credentials.filter(c => c.id !== id);
    walletStorage.logActivity('Deleted Credential', `Removed credential ${id.slice(0, 20)}...`);
  },

  // ---- Activity log ----
  getLogs: () => state?.logs ?? [],
  logActivity(action, description) {
    if (!state) return;
    state.logs.unshift({
      id: crypto.randomUUID().slice(0, 8), action, description, timestamp: new Date().toISOString()
    });
    state.logs = state.logs.slice(0, 50);
    persist();
  },

  /** Passphrase-encrypted identity backup file (string). Never contains the key in plaintext. */
  async exportIdentityBackup(passphrase) {
    if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
      throw new Error(`Backup passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters.`);
    }
    const salt = randomBytes(16);
    const key = await deriveKey(passphrase, salt, KDF_ITERATIONS);
    const blob = await encryptJson(key, { identity: state.identity });
    return JSON.stringify({
      format: 'aegisid-identity-backup', v: 1, did: state.identity.did,
      kdf: { name: 'PBKDF2-SHA256', salt: toB64(salt), iterations: KDF_ITERATIONS }, cipher: 'AES-256-GCM', ...blob
    }, null, 2);
  }
};
