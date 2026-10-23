import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';

// Configure the environment BEFORE the app (and its singletons) are imported.
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-test-'));
process.env.DATA_DIR = tmp;
process.env.ISSUER_API_KEY = 'test-issuer-key';
process.env.ISSUER_MASTER_SECRET = 'unit-test-master-secret';
process.env.APP_URL = 'http://localhost:5999';

const { createApp } = await import('../app.js');
const { generateDIDKeyPair } = await import('../crypto/didKey.js');
const { issueVerifiablePresentation } = await import('../crypto/credentials.js');

let server, base;
const holder = generateDIDKeyPair();
const KEY = { 'x-api-key': 'test-issuer-key' };
const post = (p, body, headers = {}) => fetch(base + p, {
  method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body)
}).then(async r => ({ status: r.status, body: await r.json() }));
const get = (p, headers = {}) => fetch(base + p, { headers }).then(async r => ({ status: r.status, body: await r.json() }));

before(async () => {
  server = createApp().listen(0);
  await new Promise(r => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => { server.close(); fs.rmSync(tmp, { recursive: true, force: true }); });

const eduClaims = { studentName: 'Test User', degreeName: 'BTech', cgpa: '8.9', graduationYear: 2024 };
const issueEdu = () => post('/api/credentials/issue', {
  issuerId: 'issuer-edu', subjectDid: holder.did, claims: eduClaims, credentialType: 'UniversityDegreeCredential', expirationDays: 30
}, KEY);

test('issuer endpoints require the issuer key', async () => {
  assert.equal((await post('/api/credentials/issue', {})).status, 401);
  assert.equal((await post('/api/revocation/revoke', { credentialId: 'x' })).status, 401);
  assert.equal((await get('/api/credentials/issued')).status, 401);
  assert.equal((await get('/api/credentials/issued', { 'x-api-key': 'wrong' })).status, 401);
  assert.equal((await get('/api/credentials/issued', KEY)).status, 200);
  assert.equal((await get('/api/auth/status')).body.required, true);
});

test('issuance validates input', async () => {
  const bad = (over) => post('/api/credentials/issue', {
    issuerId: 'issuer-edu', subjectDid: holder.did, claims: eduClaims, credentialType: 'UniversityDegreeCredential', ...over
  }, KEY);
  assert.equal((await bad({ credentialType: 'NationalIDCredential' })).status, 400); // issuer not authorised
  assert.equal((await bad({ subjectDid: 'did:web:example.com' })).status, 400);
  assert.equal((await bad({ claims: { 'bad key!': 1 } })).status, 400);
  assert.equal((await bad({ claims: { nested: { a: 1 } } })).status, 400);
  assert.equal((await bad({ expirationDays: -5 })).status, 400);
});

test('issue -> verify -> revoke -> restore through the StatusList', async () => {
  const issued = await issueEdu();
  assert.equal(issued.status, 200);
  const vc = issued.body.credential;
  assert.equal(vc.credentialStatus.type, 'StatusList2021Entry');
  assert.ok(Array.isArray(vc.disclosures));

  let v = await post('/api/credentials/verify', { credential: vc });
  assert.ok(v.body.report.valid, v.body.report.errors.join('; '));

  assert.equal((await post('/api/revocation/revoke', { credentialId: vc.id, reason: 'test' }, KEY)).status, 200);
  v = await post('/api/credentials/verify', { credential: vc });
  assert.ok(!v.body.report.valid && !v.body.report.checks.notRevoked);

  const list = (await get('/api/status/list/issuer-edu')).body;
  assert.ok(list.type.includes('StatusList2021Credential') && list.proof);

  assert.equal((await post('/api/revocation/unrevoke', { credentialId: vc.id }, KEY)).status, 200);
  v = await post('/api/credentials/verify', { credential: vc });
  assert.ok(v.body.report.valid);

  assert.equal((await post('/api/revocation/revoke', { credentialId: 'urn:uuid:never-issued' }, KEY)).status, 404);
});

test('presentation flow over HTTP: challenge, selective disclosure, replay rejected', async () => {
  const vc = (await issueEdu()).body.credential;
  const ch = (await get('/api/verifier/challenge?domain=verifier.example.com')).body;
  const vp = issueVerifiablePresentation({
    holderDid: holder.did, holderPrivateKey: holder.privateKeyMultibase,
    verifiableCredentials: [{ ...vc, disclosures: vc.disclosures.filter(d => d[1] === 'degreeName') }],
    challenge: ch.challenge, domain: 'verifier.example.com'
  });
  const ok = await post('/api/presentation/verify', { presentation: vp });
  assert.ok(ok.body.report.valid, ok.body.report.errors.join('; '));
  assert.deepEqual(ok.body.report.credentialsReport[0].revealedClaims, { degreeName: 'BTech' });

  const replay = await post('/api/presentation/verify', { presentation: vp });
  assert.ok(!replay.body.report.valid && !replay.body.report.checks.challengeValid);
});

test('private keys are never accepted or generated by the server', async () => {
  assert.equal((await post('/api/presentation/create', { holderPrivateKey: 'x' })).status, 404);
  assert.equal((await post('/api/did/generate', {})).status, 404);
});

test('malformed and oversized bodies get clean errors', async () => {
  const r = await fetch(base + '/api/credentials/verify', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{nope' });
  assert.equal(r.status, 400);
  const big = await fetch(base + '/api/credentials/verify', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ x: 'a'.repeat(2_000_000) }) });
  assert.equal(big.status, 413);
});

test('security headers are set and issuer keys are not stored on disk with a master secret', async () => {
  const r = await fetch(base + '/api/health');
  assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
  assert.ok(r.headers.get('content-security-policy').includes("default-src 'self'"));
  const stored = JSON.parse(fs.readFileSync(path.join(tmp, 'issuers.json'), 'utf-8'));
  assert.ok(stored.every(i => !i.keyPair), 'no private keys in issuers.json');
});

test('readiness endpoint, operator attribution and audit trail', async () => {
  assert.equal((await get('/api/ready')).status, 200);
  const vc = (await issueEdu()).body.credential;
  await post('/api/revocation/revoke', { credentialId: vc.id, reason: 'audit test', revokedBy: 'spoofed-name' }, KEY);
  const rev = (await get('/api/revocation/list', KEY)).body.revocations.find(r => r.credentialId === vc.id);
  assert.equal(rev.revokedBy, 'admin', 'revokedBy comes from the authenticated operator, not the request body');

  assert.equal((await get('/api/audit')).status, 401);
  await new Promise(r => setTimeout(r, 50)); // the failed-auth entry is written when the response finishes
  const audit = (await get('/api/audit', KEY)).body.audit;
  assert.ok(audit.some(a => a.action === 'issue' && a.operator === 'admin'));
  assert.ok(audit.some(a => a.action === 'revoke' && a.operator === 'admin'));
  assert.ok(audit.some(a => a.action === 'auth-failed'));
});

test('the issued-credentials list exposes metadata only (no claims, no credential body)', async () => {
  const vc = (await issueEdu()).body.credential;
  const rec = (await get('/api/credentials/issued', KEY)).body.issued.find(r => r.credentialId === vc.id);
  assert.ok(rec && rec.subjectDid === holder.did);
  assert.equal(rec.credential, undefined);
  assert.ok(!JSON.stringify(rec).includes('Test User'));
});
