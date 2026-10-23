import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateDIDKeyPair, resolveDID, sign, verify, keyPairFromSeed } from '../crypto/didKey.js';
import { canonicalize } from '../crypto/jcs.js';
import {
  issueVerifiableCredential, verifyVerifiableCredential,
  issueVerifiablePresentation, verifyVerifiablePresentation
} from '../crypto/credentials.js';
import { ChallengeStore } from '../services/challengeStore.js';

const claims = { degreeName: 'BTech CS', cgpa: '8.95', graduationYear: 2024, isOver18: true };

function setup() {
  const issuer = generateDIDKeyPair();
  const holder = generateDIDKeyPair();
  const vc = issueVerifiableCredential({
    issuerDid: issuer.did, issuerPrivateKey: issuer.privateKeyMultibase, issuerName: 'Test Uni',
    subjectDid: holder.did, claims, credentialType: 'UniversityDegreeCredential'
  });
  const trusted = { isTrustedIssuer: (did) => did === issuer.did };
  return { issuer, holder, vc, trusted };
}

test('JCS: key order and whitespace do not change the canonical form', () => {
  assert.equal(canonicalize({ b: 1, a: [true, null, 'x'] }), canonicalize({ a: [true, null, 'x'], b: 1 }));
  assert.equal(canonicalize({ b: 1, a: 2 }), '{"a":2,"b":1}');
  assert.throws(() => canonicalize({ a: NaN }));
});

test('did:key round trip, resolution and signatures', () => {
  const kp = generateDIDKeyPair();
  assert.match(kp.did, /^did:key:z6Mk/);
  assert.equal(resolveDID(kp.did).verificationMethod[0].publicKeyMultibase, kp.publicKeyMultibase);
  const sig = sign('hello', kp.privateKeyMultibase);
  assert.ok(verify('hello', sig, kp.did));
  assert.ok(!verify('hellp', sig, kp.did));
  assert.ok(!verify('hello', 'zNotASignature', kp.did));
  assert.equal(keyPairFromSeed(Buffer.alloc(32, 7)).did, keyPairFromSeed(Buffer.alloc(32, 7)).did);
});

test('VC issues, verifies, and exposes only committed claims', () => {
  const { vc, trusted } = setup();
  assert.equal(vc.credentialSubject.cgpa, undefined, 'claims must not be in the signed subject');
  const r = verifyVerifiableCredential(vc, trusted);
  assert.ok(r.valid, r.errors.join('; '));
  assert.deepEqual(r.revealedClaims, claims);
});

test('tampering with signed fields is detected', () => {
  const { vc, trusted } = setup();
  for (const mutate of [
    v => { v.expirationDate = '2099-01-01T00:00:00.000Z'; },
    v => { v.issuer.name = 'Evil Uni'; },
    v => { v.credentialSubject._sd.pop(); }
  ]) {
    const copy = structuredClone(vc);
    mutate(copy);
    const r = verifyVerifiableCredential(copy, trusted);
    assert.ok(!r.valid && !r.checks.signatureValid);
  }
});

test('tampering with a disclosed value is detected by the commitments', () => {
  const { vc, trusted } = setup();
  const copy = structuredClone(vc);
  const gpa = copy.disclosures.find(d => d[1] === 'cgpa');
  gpa[2] = '10.0';
  const r = verifyVerifiableCredential(copy, trusted);
  assert.ok(r.checks.signatureValid);
  assert.ok(!r.checks.disclosuresValid && !r.valid);
});

test('selective disclosure: a subset of claims still verifies and hides the rest', () => {
  const { vc, trusted } = setup();
  const partial = { ...vc, disclosures: vc.disclosures.filter(d => d[1] === 'degreeName') };
  const r = verifyVerifiableCredential(partial, trusted);
  assert.ok(r.valid, r.errors.join('; '));
  assert.deepEqual(r.revealedClaims, { degreeName: 'BTech CS' });
  assert.ok(!JSON.stringify(partial).includes('8.95'));
});

test('disclosures cannot be forged, duplicated or reuse reserved names', () => {
  const { vc, trusted } = setup();
  const forged = { ...vc, disclosures: [...vc.disclosures, ['abc', 'salary', 999999]] };
  assert.ok(!verifyVerifiableCredential(forged, trusted).checks.disclosuresValid);
  const dup = { ...vc, disclosures: [vc.disclosures[0], vc.disclosures[0]] };
  assert.ok(!verifyVerifiableCredential(dup, trusted).checks.disclosuresValid);
});

test('self-issued credentials from an unknown issuer are rejected by the trust registry', () => {
  const { holder } = setup();
  const attacker = generateDIDKeyPair();
  const forged = issueVerifiableCredential({
    issuerDid: attacker.did, issuerPrivateKey: attacker.privateKeyMultibase, issuerName: 'GovTrust National Identity Authority',
    subjectDid: holder.did, claims: { fullName: 'X' }, credentialType: 'NationalIDCredential'
  });
  const r = verifyVerifiableCredential(forged, { isTrustedIssuer: () => false });
  assert.ok(r.checks.signatureValid, 'signature itself is fine');
  assert.ok(!r.checks.issuerTrusted && !r.valid);
});

test('expiry and revocation are enforced', () => {
  const { vc, trusted } = setup();
  const future = Date.now() + 2 * 365 * 24 * 3600 * 1000;
  assert.ok(!verifyVerifiableCredential(vc, { ...trusted, now: future }).checks.notExpired);
  const r = verifyVerifiableCredential(vc, { ...trusted, isRevoked: () => true });
  assert.ok(!r.checks.notRevoked && !r.valid);
});

test('presentation: holder-signed, challenge-bound and replay-protected', () => {
  const { holder, vc, trusted } = setup();
  const store = new ChallengeStore();
  const opts = { ...trusted, challenges: store };
  const present = (challenge, domain) => issueVerifiablePresentation({
    holderDid: holder.did, holderPrivateKey: holder.privateKeyMultibase,
    verifiableCredentials: [{ ...vc, disclosures: vc.disclosures.filter(d => d[1] === 'isOver18') }],
    challenge, domain
  });

  const c = store.create('verifier.example.com');
  const vp = present(c.challenge, 'verifier.example.com');
  const first = verifyVerifiablePresentation(vp, opts);
  assert.ok(first.valid, first.errors.join('; '));
  assert.deepEqual(first.credentialsReport[0].revealedClaims, { isOver18: true });

  const replay = verifyVerifiablePresentation(vp, opts);
  assert.ok(!replay.valid && !replay.checks.challengeValid, 'replay must fail');

  // Changing the challenge breaks the holder's signature (it is now covered by the proof).
  const c2 = store.create('verifier.example.com');
  const swapped = structuredClone(present(c2.challenge, 'verifier.example.com'));
  swapped.proof.challenge = 'attacker-chosen';
  assert.ok(!verifyVerifiablePresentation(swapped, opts).checks.holderSignatureValid);

  // Wrong audience
  const c3 = store.create('bank.example.com');
  const wrongAud = verifyVerifiablePresentation(present(c3.challenge, 'evil.example.com'), opts);
  assert.ok(!wrongAud.valid && !wrongAud.checks.challengeValid);

  // Challenge never issued by this verifier
  assert.ok(!verifyVerifiablePresentation(present('made-up', null), opts).checks.challengeValid);
});

test('presentation: a stolen credential cannot be presented by a different holder', () => {
  const { vc, trusted } = setup();
  const thief = generateDIDKeyPair();
  const store = new ChallengeStore();
  const c = store.create(null);
  const vp = issueVerifiablePresentation({
    holderDid: thief.did, holderPrivateKey: thief.privateKeyMultibase,
    verifiableCredentials: [vc], challenge: c.challenge
  });
  const r = verifyVerifiablePresentation(vp, { ...trusted, challenges: store });
  assert.ok(r.checks.holderSignatureValid && !r.checks.holderBound && !r.valid);
});

test('challenges expire', () => {
  const store = new ChallengeStore({ ttlMs: -1 });
  const c = store.create(null);
  assert.equal(store.validate(c.challenge, null).ok, false);
});
