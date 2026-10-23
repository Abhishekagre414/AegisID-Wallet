import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateIdentity, createPresentation, signSandboxMessage, verifySandboxMessage, canonicalize } from '../src/services/didCrypto.js';
import { deriveKey, encryptJson, decryptJson, randomBytes } from '../src/services/vaultCrypto.js';
import { getClaims } from '../src/services/credentialUtils.js';
// The backend is the reference verifier: browser-made artifacts must pass it.
import { canonicalize as backendCanonicalize } from '../../backend/crypto/jcs.js';
import { resolveDID, generateDIDKeyPair } from '../../backend/crypto/didKey.js';
import { issueVerifiableCredential, verifyVerifiablePresentation } from '../../backend/crypto/credentials.js';
import { ChallengeStore } from '../../backend/services/challengeStore.js';

test('browser and backend canonicalization agree', () => {
  const samples = [
    { b: [1, 2.5, -0, 1e21, 'é\u2028"'], a: { z: null, y: true } },
    { 'ключ': 'значение', n: 0.000001, big: 123456789012345680000 }
  ];
  for (const s of samples) assert.equal(canonicalize(s), backendCanonicalize(s));
});

test('browser-generated identity is a valid did:key the backend can resolve', () => {
  const id = generateIdentity();
  assert.match(id.did, /^did:key:z6Mk/);
  assert.equal(resolveDID(id.did).verificationMethod[0].publicKeyMultibase, id.publicKeyMultibase);
});

test('a presentation signed in the browser verifies on the backend, with selective disclosure', () => {
  const holder = generateIdentity();
  const issuer = generateDIDKeyPair();
  const vc = issueVerifiableCredential({
    issuerDid: issuer.did, issuerPrivateKey: issuer.privateKeyMultibase, subjectDid: holder.did,
    claims: { degreeName: 'BTech', cgpa: '8.95', studentId: 'S-123' }, credentialType: 'UniversityDegreeCredential'
  });
  assert.deepEqual(getClaims(vc), { degreeName: 'BTech', cgpa: '8.95', studentId: 'S-123' });

  const store = new ChallengeStore();
  const c = store.create('verifier.example.com');
  const vp = createPresentation({
    identity: holder, credentials: [{ vc, claims: ['degreeName'] }],
    challenge: c.challenge, domain: 'verifier.example.com'
  });
  assert.ok(!JSON.stringify(vp).includes('8.95') && !JSON.stringify(vp).includes('S-123'), 'hidden claims must not leave the wallet');

  const opts = { isTrustedIssuer: (d) => d === issuer.did, challenges: store };
  const report = verifyVerifiablePresentation(vp, opts);
  assert.ok(report.valid, report.errors.join('; '));
  assert.deepEqual(report.credentialsReport[0].revealedClaims, { degreeName: 'BTech' });
  assert.ok(!verifyVerifiablePresentation(vp, opts).valid, 'replay rejected');
});

test('sandbox signatures verify for the right message only', () => {
  const id = generateIdentity();
  const sig = signSandboxMessage(id, 'login nonce 42');
  assert.ok(verifySandboxMessage(id.did, 'login nonce 42', sig));
  assert.ok(!verifySandboxMessage(id.did, 'login nonce 43', sig));
});

test('vault encryption round-trips and rejects a wrong passphrase', async () => {
  const salt = randomBytes(16);
  const key = await deriveKey('correct horse battery', salt, 1000);
  const blob = await encryptJson(key, { secret: 'k', n: [1, 2, 3] });
  assert.ok(!JSON.stringify(blob).includes('secret'));
  assert.deepEqual(await decryptJson(key, blob), { secret: 'k', n: [1, 2, 3] });
  await assert.rejects(decryptJson(await deriveKey('wrong passphrase!', salt, 1000), blob));
});
