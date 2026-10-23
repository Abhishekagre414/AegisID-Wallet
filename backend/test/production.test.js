import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';

const here = path.dirname(fileURLToPath(import.meta.url));
const backendDir = path.join(here, '..');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-prod-'));
process.env.DATA_DIR = tmp;
process.env.ISSUER_MASTER_SECRET = 'production-test-master-secret-0123456789';
process.env.APP_URL = 'https://aegis.example.com';

const { PersistentChallengeStore } = await import('../services/persistentChallengeStore.js');
const { parseOperators, validateProductionConfig, requireIssuerAuth, initIssuerAuth } = await import('../middleware/security.js');
const { issuerService } = await import('../services/issuerService.js');
const { revocationRegistry } = await import('../services/revocationRegistry.js');
const { audit, getAudit, dbHealthy, closeDb, db } = await import('../services/db.js');
const { generateDIDKeyPair } = await import('../crypto/didKey.js');

after(() => { closeDb(); fs.rmSync(tmp, { recursive: true, force: true }); });

/** Run a snippet in a fresh Node process against the same DATA_DIR: a real "server restart". */
const inFreshProcess = (code) => execFileSync(process.execPath,
  ['--disable-warning=ExperimentalWarning', '--input-type=module', '-e', code],
  { cwd: backendDir, env: { ...process.env, DATA_DIR: tmp }, encoding: 'utf-8' }).trim();

/* ---------------- Durability ---------------- */
test('revocations and status indexes survive a process restart', () => {
  const idx = revocationRegistry.allocateIndex('issuer-edu');
  revocationRegistry.revoke({ credentialId: 'urn:uuid:persist-me', issuerId: 'issuer-edu', statusIndex: idx }, 'test', 'alice');
  db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); // what a clean shutdown flushes

  const out = inFreshProcess(`
    const { revocationRegistry: r } = await import('./services/revocationRegistry.js');
    const next = r.allocateIndex('issuer-edu');
    console.log(JSON.stringify({ revoked: r.isIndexRevoked('issuer-edu', ${idx}), rec: r.getStatus('urn:uuid:persist-me'), next }));
  `);
  const got = JSON.parse(out.split('\n').pop());
  assert.equal(got.revoked, true, 'revoked credential must stay revoked after a restart');
  assert.equal(got.rec.revokedBy, 'alice');
  assert.equal(got.next, idx + 1, 'indexes are never reused');
});

test('pending challenges survive a restart and are single-use across processes', () => {
  const out = inFreshProcess(`
    const { PersistentChallengeStore: S } = await import('./services/persistentChallengeStore.js');
    const s = new S();
    const c = s.create('bank.example.com').challenge;
    console.log(c);
  `);
  const challenge = out.split('\n').pop();
  const again = inFreshProcess(`
    const { PersistentChallengeStore: S } = await import('./services/persistentChallengeStore.js');
    const s = new S();
    console.log(JSON.stringify({ ok: s.validate('${challenge}', 'bank.example.com').ok, first: s.consume('${challenge}'), second: s.consume('${challenge}') }));
  `);
  assert.deepEqual(JSON.parse(again.split('\n').pop()), { ok: true, first: true, second: false });
});

/* ---------------- Persistent challenge store semantics ---------------- */
test('persistent challenges: audience, expiry, unknown values and atomic consume', async () => {
  assert.ok(dbHealthy());
  const Store = PersistentChallengeStore;
  const s = new Store();
  const { challenge } = s.create('bank.example.com');
  assert.equal(s.validate(challenge, 'evil.example.com').ok, false);
  assert.ok(s.validate(challenge, 'bank.example.com').ok);
  assert.equal(s.consume(challenge), true);
  assert.equal(s.consume(challenge), false, 'second consume must lose');
  assert.equal(s.validate(challenge, 'bank.example.com').ok, false);
  assert.equal(s.validate('never-issued', null).ok, false);
  assert.equal(s.validate(undefined, null).ok, false);

  const expiring = new Store({ ttlMs: -1 });
  assert.equal(expiring.validate(expiring.create(null).challenge, null).ok, false);
});

/* ---------------- Data minimisation ---------------- */
test('the issuer retains metadata only, never claim values', async () => {
  const dbmod = { db };
  const holder = generateDIDKeyPair();
  const vc = issuerService.issueCredential({
    issuerIdOrDid: 'issuer-edu', subjectDid: holder.did, credentialType: 'UniversityDegreeCredential',
    claims: { studentName: 'Very Secret Name', cgpa: '9.99' }, expirationDays: 30
  });
  const records = issuerService.getIssuedCredentials();
  const rec = records.find(r => r.credentialId === vc.id);
  assert.ok(rec && rec.subjectDid === holder.did && rec.credentialType === 'UniversityDegreeCredential');
  assert.equal(rec.credential, undefined);

  const dump = JSON.stringify(dbmod.db.prepare('SELECT * FROM issued').all())
    + JSON.stringify(dbmod.db.prepare('SELECT * FROM audit').all());
  assert.ok(!dump.includes('Very Secret Name') && !dump.includes('9.99'));
  for (const f of fs.readdirSync(tmp)) {
    const raw = fs.readFileSync(path.join(tmp, f)).toString('latin1');
    assert.ok(!raw.includes('Very Secret Name'), `claim value found on disk in ${f}`);
  }
});

/* ---------------- Operators and audit ---------------- */
test('operator keys: parsing, authentication by name, shared key fallback', () => {
  const ops = parseOperators({ ISSUER_API_KEYS: 'alice:aaaaaaaaaaaaaaaaaaaaaaaaaa, bob:bbbbbbbbbbbbbbbbbbbbbbbbbb', ISSUER_API_KEY: 'shared-key-shared-key-shared' });
  assert.deepEqual(ops.map(o => o.name), ['alice', 'bob', 'admin']);
  assert.throws(() => parseOperators({ ISSUER_API_KEYS: 'nocolon' }));
  assert.throws(() => parseOperators({ ISSUER_API_KEYS: 'bad name!:key' }));

  const prev = { a: process.env.ISSUER_API_KEYS, b: process.env.ISSUER_API_KEY };
  process.env.ISSUER_API_KEYS = 'alice:aaaaaaaaaaaaaaaaaaaaaaaaaa,bob:bbbbbbbbbbbbbbbbbbbbbbbbbb';
  delete process.env.ISSUER_API_KEY;
  initIssuerAuth();
  const call = (key) => {
    const req = { get: () => key };
    const res = { code: 200, status(c) { this.code = c; return this; }, json() { return this; } };
    let next = false;
    requireIssuerAuth(req, res, () => { next = true; });
    return { next, code: res.code, operator: req.operator };
  };
  assert.deepEqual(call('bbbbbbbbbbbbbbbbbbbbbbbbbb'), { next: true, code: 200, operator: 'bob' });
  assert.equal(call('aaaaaaaaaaaaaaaaaaaaaaaaaa').operator, 'alice');
  assert.equal(call('wrong').code, 401);
  assert.equal(call(undefined).code, 401);
  process.env.ISSUER_API_KEYS = prev.a ?? ''; if (prev.b) process.env.ISSUER_API_KEY = prev.b;
});

test('audit log records operator actions, newest first', () => {
  audit('alice', 'revoke', 'urn:uuid:1');
  audit('bob', 'issue', 'urn:uuid:2');
  const log = getAudit(5);
  assert.equal(log[0].operator, 'bob');
  assert.equal(log[1].action, 'revoke');
  assert.ok(dbHealthy());
});

/* ---------------- Production config guard ---------------- */
const good = {
  NODE_ENV: 'production', ISSUER_API_KEY: 'k'.repeat(32), ISSUER_MASTER_SECRET: 's'.repeat(40),
  APP_URL: 'https://aegis.example.com', DATA_DIR: '/var/data'
};
test('production config: a safe configuration passes cleanly', () => {
  assert.deepEqual(validateProductionConfig(good), { errors: [], warnings: [] });
});
test('production config: unsafe settings are refused', () => {
  const errs = (over) => validateProductionConfig({ ...good, ...over }).errors;
  assert.ok(errs({ ISSUER_API_KEY: '' }).length);
  assert.ok(errs({ ISSUER_API_KEY: 'short' }).length);
  assert.ok(errs({ ISSUER_MASTER_SECRET: '' }).length);
  assert.ok(errs({ ISSUER_MASTER_SECRET: 'too-short' }).length);
  assert.ok(errs({ APP_URL: '' }).length);
  assert.ok(errs({ APP_URL: 'http://aegis.example.com' }).length, 'plain http is refused');
  assert.ok(errs({ ISSUER_API_KEY: '', ISSUER_API_KEYS: 'alice:' + 'a'.repeat(30) }).length === 0, 'per-operator keys are enough');
});
test('production config: localhost and missing DATA_DIR only warn; development is never blocked', () => {
  const r = validateProductionConfig({ ...good, APP_URL: 'http://localhost:5000', DATA_DIR: '' });
  assert.equal(r.errors.length, 0);
  assert.equal(r.warnings.length, 2);
  assert.deepEqual(validateProductionConfig({ NODE_ENV: 'development' }), { errors: [], warnings: [] });
});
