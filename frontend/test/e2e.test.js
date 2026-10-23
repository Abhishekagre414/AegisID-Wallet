import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';

/**
 * End-to-end: real HTTP backend + the browser wallet code (vault, key generation, presenting).
 * issue (issuer API) -> store in encrypted vault -> lock/unlock -> present selectively ->
 * verify -> replay -> tamper -> revoke.
 */
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-e2e-'));
process.env.DATA_DIR = tmp;
process.env.ISSUER_API_KEY = 'e2e-issuer-key';
process.env.ISSUER_MASTER_SECRET = 'e2e-master-secret';
process.env.APP_URL = 'http://localhost:5998';

const mem = new Map();
globalThis.localStorage = {
  getItem: (k) => (mem.has(k) ? mem.get(k) : null),
  setItem: (k, v) => { mem.set(k, String(v)); },
  removeItem: (k) => { mem.delete(k); },
  clear: () => mem.clear()
};

const { createApp } = await import('../../backend/app.js');
const { generateIdentity, createPresentation } = await import('../src/services/didCrypto.js');
const { walletStorage } = await import('../src/services/walletStorage.js');

const KEY = { 'x-api-key': 'e2e-issuer-key' };
const DOMAIN = 'verifier.example.com';
let server, base;

const api = (method, p, body, headers = {}) => fetch(base + p, {
  method, headers: { 'content-type': 'application/json', ...headers },
  body: body === undefined ? undefined : JSON.stringify(body)
}).then(async r => ({ status: r.status, body: await r.json() }));

async function persisted() {  // let the vault's background write finish
  await new Promise(r => setTimeout(r, 400));
}
async function present(identity, vc, claims) {
  const ch = (await api('GET', `/api/verifier/challenge?domain=${DOMAIN}`)).body;
  return createPresentation({ identity, credentials: [{ vc, claims }], challenge: ch.challenge, domain: DOMAIN });
}

before(async () => {
  server = createApp().listen(0);
  await new Promise(r => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => { server.close(); fs.rmSync(tmp, { recursive: true, force: true }); });

test('full lifecycle: issue, store, selectively present, verify, replay, tamper, revoke', async () => {
  // 1. Holder creates an encrypted wallet and identity in the "browser"
  await walletStorage.create('e2e passphrase long enough');
  const identity = generateIdentity();
  walletStorage.setIdentity(identity);

  // 2. Issuer issues (auth required)
  const claims = { degreeName: 'BTech', cgpa: '8.95', honors: 'Distinction' };
  const body = { issuerId: 'issuer-edu', subjectDid: identity.did, claims, credentialType: 'UniversityDegreeCredential' };
  assert.equal((await api('POST', '/api/credentials/issue', body)).status, 401, 'no key -> rejected');
  const issued = await api('POST', '/api/credentials/issue', body, KEY);
  assert.equal(issued.status, 200);
  const vc = issued.body.credential;

  // 3. Wallet stores it; it survives lock/unlock
  assert.ok(walletStorage.saveCredential(vc));
  await persisted();
  walletStorage.lock();
  assert.equal(walletStorage.getCredentials().length, 0, 'locked wallet exposes nothing');
  await walletStorage.unlock('e2e passphrase long enough');
  const stored = walletStorage.getCredentials()[0];
  assert.equal(stored.id, vc.id);

  // 4. Selective presentation verifies and reveals only the chosen claim
  const vp = await present(walletStorage.getIdentity(), stored, ['degreeName']);
  assert.ok(!JSON.stringify(vp).includes('8.95') && !JSON.stringify(vp).includes('Distinction'));
  const ok = await api('POST', '/api/presentation/verify', { presentation: vp });
  assert.ok(ok.body.report.valid, ok.body.report.errors.join('; '));
  assert.deepEqual(ok.body.report.credentialsReport[0].revealedClaims, { degreeName: 'BTech' });

  // 5. Replay of the same presentation is rejected
  const replay = await api('POST', '/api/presentation/verify', { presentation: vp });
  assert.ok(!replay.body.report.valid && !replay.body.report.checks.challengeValid);

  // 6. Tampering with a revealed value is rejected
  const vp2 = await present(identity, stored, ['degreeName']);
  vp2.verifiableCredential[0].disclosures[0][2] = 'PhD';
  const tampered = await api('POST', '/api/presentation/verify', { presentation: vp2 });
  assert.ok(!tampered.body.report.valid);

  // 7. A different holder cannot present this credential
  const thief = generateIdentity();
  const stolen = await present(thief, stored, ['degreeName']);
  const stolenR = (await api('POST', '/api/presentation/verify', { presentation: stolen })).body.report;
  assert.ok(!stolenR.valid && !stolenR.checks.holderBound);

  // 8. Revocation is enforced on the next presentation, and restoring re-enables it
  assert.equal((await api('POST', '/api/revocation/revoke', { credentialId: vc.id, reason: 'e2e' }, KEY)).status, 200);
  const revoked = (await api('POST', '/api/presentation/verify', { presentation: await present(identity, stored, ['degreeName']) })).body.report;
  assert.ok(!revoked.valid && revoked.credentialsReport[0].checks.notRevoked === false);

  await api('POST', '/api/revocation/unrevoke', { credentialId: vc.id }, KEY);
  const restored = (await api('POST', '/api/presentation/verify', { presentation: await present(identity, stored, ['degreeName']) })).body.report;
  assert.ok(restored.valid, restored.errors.join('; '));
});
