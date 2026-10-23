import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

// Minimal in-memory localStorage so the real vault module can run under Node.
const store = new Map();
globalThis.localStorage = {
  getItem: (k) => (store.has(k) ? store.get(k) : null),
  setItem: (k, v) => { store.set(k, String(v)); },
  removeItem: (k) => { store.delete(k); },
  clear: () => store.clear()
};

const { walletStorage, MIN_PASSPHRASE_LENGTH } = await import('../src/services/walletStorage.js');
const { deriveKey, decryptJson, fromB64 } = await import('../src/services/vaultCrypto.js');

const PASS = 'correct horse battery';
const identity = {
  did: 'did:key:z6MkTestIdentity1234567890',
  publicKeyMultibase: 'z6MkTestIdentity1234567890',
  privateKeyMultibase: 'zSuperSecretPrivateKeyMaterial0001',
  privateKeyHex: 'deadbeefcafebabe0011223344556677'
};
const vc = (n) => ({ id: `urn:uuid:cred-${n}-aaaaaaaaaaaaaaaaaaaa`, type: ['VerifiableCredential', 'T'] });

/** The vault persists asynchronously; wait until the stored blob satisfies `cond`. */
async function waitFor(cond, ms = 5000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const raw = localStorage.getItem('aegis_vault_v2');
    if (raw && cond(raw)) return raw;
    await new Promise(r => setTimeout(r, 20));
  }
  throw new Error('vault was not persisted in time');
}
const flush = async () => {
  const before = localStorage.getItem('aegis_vault_v2');
  return waitFor(raw => raw !== before);
};

beforeEach(() => { localStorage.clear(); walletStorage.lock(); });

test('rejects a passphrase shorter than the minimum', async () => {
  await assert.rejects(walletStorage.create('short'), /at least/);
  assert.ok(!walletStorage.hasVault());
  assert.equal(MIN_PASSPHRASE_LENGTH, 10);
});

test('create -> lock -> unlock round-trips identity and credentials', async () => {
  await walletStorage.create(PASS);
  assert.ok(walletStorage.hasVault() && walletStorage.isUnlocked());

  walletStorage.setIdentity(identity);
  await flush();
  walletStorage.saveCredential(vc(1));
  await flush();

  walletStorage.lock();
  assert.ok(!walletStorage.isUnlocked());
  assert.equal(walletStorage.getIdentity(), null);
  assert.deepEqual(walletStorage.getCredentials(), []);

  await walletStorage.unlock(PASS);
  assert.deepEqual(walletStorage.getIdentity(), identity);
  assert.equal(walletStorage.getCredentials().length, 1);
});

test('a wrong passphrase is rejected and the wallet stays locked', async () => {
  await walletStorage.create(PASS);
  walletStorage.lock();
  await assert.rejects(walletStorage.unlock('definitely not it'), /Incorrect passphrase/);
  assert.ok(!walletStorage.isUnlocked());
  assert.equal(walletStorage.getIdentity(), null);
});

test('nothing sensitive is stored in plaintext', async () => {
  await walletStorage.create(PASS);
  walletStorage.setIdentity(identity);
  const raw = await flush();
  for (const v of Object.values(identity)) assert.ok(!raw.includes(v), `plaintext leak: ${v}`);
  assert.ok(!raw.includes('privateKey'));
});

test('a tampered vault fails authentication (AES-GCM)', async () => {
  await walletStorage.create(PASS);
  walletStorage.setIdentity(identity);
  const raw = await flush();
  walletStorage.lock();

  const blob = JSON.parse(raw);
  const bytes = fromB64(blob.ct);
  bytes[0] ^= 0x01;
  blob.ct = btoa(String.fromCharCode(...bytes));
  localStorage.setItem('aegis_vault_v2', JSON.stringify(blob));

  await assert.rejects(walletStorage.unlock(PASS), /Incorrect passphrase/);
  assert.ok(!walletStorage.isUnlocked());
});

test('every save uses a fresh IV and the stored KDF parameters', async () => {
  await walletStorage.create(PASS);
  const first = JSON.parse(localStorage.getItem('aegis_vault_v2'));
  walletStorage.setIdentity(identity);
  const second = JSON.parse(await flush());
  assert.notEqual(first.iv, second.iv);
  assert.equal(first.kdf.salt, second.kdf.salt);
  assert.ok(second.kdf.iterations >= 310_000);
});

test('legacy plaintext wallets are migrated into the vault and wiped', async () => {
  localStorage.setItem('aegis_holder_identity', JSON.stringify(identity));
  localStorage.setItem('aegis_credential_vault', JSON.stringify([vc(7)]));
  assert.ok(walletStorage.hasLegacyData());

  await walletStorage.create(PASS);
  assert.deepEqual(walletStorage.getIdentity(), identity);
  assert.equal(walletStorage.getCredentials().length, 1);
  assert.equal(localStorage.getItem('aegis_holder_identity'), null);
  assert.equal(localStorage.getItem('aegis_credential_vault'), null);
});

test('saving the same credential twice updates it; removing deletes it', async () => {
  await walletStorage.create(PASS);
  assert.ok(walletStorage.saveCredential(vc(1)));
  assert.ok(walletStorage.saveCredential({ ...vc(1), extra: true }));
  assert.equal(walletStorage.getCredentials().length, 1);
  assert.ok(walletStorage.getCredentials()[0].extra);
  assert.ok(!walletStorage.saveCredential({ no: 'id' }));

  walletStorage.removeCredential(vc(1).id);
  assert.equal(walletStorage.getCredentials().length, 0);
});

test('the activity log is capped at 50 entries, newest first', async () => {
  await walletStorage.create(PASS);
  for (let i = 0; i < 60; i++) walletStorage.logActivity('Test', `entry ${i}`);
  const logs = walletStorage.getLogs();
  assert.equal(logs.length, 50);
  assert.equal(logs[0].description, 'entry 59');
});

test('identity backup is passphrase-encrypted and restorable', async () => {
  await walletStorage.create(PASS);
  walletStorage.setIdentity(identity);

  await assert.rejects(walletStorage.exportIdentityBackup('short'), /at least/);

  const file = await walletStorage.exportIdentityBackup('another long passphrase');
  // The DID (public) is deliberately visible; private material must not be.
  for (const v of [identity.privateKeyMultibase, identity.privateKeyHex]) assert.ok(!file.includes(v));

  const b = JSON.parse(file);
  assert.equal(b.format, 'aegisid-identity-backup');
  assert.equal(b.did, identity.did);
  const key = await deriveKey('another long passphrase', fromB64(b.kdf.salt), b.kdf.iterations);
  assert.deepEqual((await decryptJson(key, b)).identity, identity);
  await assert.rejects(decryptJson(await deriveKey('wrong passphrase!!', fromB64(b.kdf.salt), b.kdf.iterations), b));
});

test('reset forgets the vault entirely', async () => {
  await walletStorage.create(PASS);
  walletStorage.setIdentity(identity);
  await flush();
  walletStorage.reset();
  assert.ok(!walletStorage.hasVault() && !walletStorage.isUnlocked());
});
