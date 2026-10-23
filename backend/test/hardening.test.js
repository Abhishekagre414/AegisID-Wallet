import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';

// Registry/storage read DATA_DIR at import time, so set it first.
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-hardening-'));
process.env.DATA_DIR = tmp;

const { ChallengeStore } = await import('../services/challengeStore.js');
const { rateLimit } = await import('../middleware/security.js');
const { revocationRegistry, STATUS_LIST_SIZE } = await import('../services/revocationRegistry.js');
const zlib = await import('zlib');

/* ---------------- ChallengeStore ---------------- */
test('challenge: unknown values are rejected', () => {
  const s = new ChallengeStore();
  assert.equal(s.validate('never-issued', null).ok, false);
  assert.equal(s.validate(undefined, null).ok, false);
  assert.equal(s.validate(12345, null).ok, false);
});

test('challenge: single use once consumed', () => {
  const s = new ChallengeStore();
  const { challenge } = s.create(null);
  assert.ok(s.validate(challenge, null).ok);
  s.consume(challenge);
  assert.equal(s.validate(challenge, null).ok, false);
});

test('challenge: bound to the audience it was issued for', () => {
  const s = new ChallengeStore();
  const { challenge } = s.create('bank.example.com');
  const bad = s.validate(challenge, 'evil.example.com');
  assert.equal(bad.ok, false);
  assert.match(bad.reason, /audience/);
  assert.ok(s.validate(challenge, 'bank.example.com').ok);
  assert.equal(s.validate(challenge, undefined).ok, false);
});

test('challenge: a challenge issued without a domain is accepted for any domain', () => {
  const s = new ChallengeStore();
  const { challenge } = s.create(null);
  assert.ok(s.validate(challenge, 'anything.example.com').ok);
});

test('challenge: expired entries are evicted and the store is size-bounded', () => {
  const s = new ChallengeStore({ ttlMs: -1 });
  s.create(null);
  s.create(null);
  s.create(null); // each create evicts the already-expired ones
  assert.ok(s.challenges.size <= 1);

  const live = new ChallengeStore();
  const first = live.create(null).challenge;
  for (let i = 0; i < 10_050; i++) live.create(null);
  assert.ok(live.challenges.size <= 10_000, 'memory must stay bounded');
  assert.equal(live.validate(first, null).ok, false, 'oldest entry is dropped first');
});

test('challenge: values are unguessable and unique', () => {
  const s = new ChallengeStore();
  const set = new Set(Array.from({ length: 500 }, () => s.create(null).challenge));
  assert.equal(set.size, 500);
  for (const c of set) assert.ok(c.length >= 24);
});

/* ---------------- Rate limiter ---------------- */
function run(limiter, ip) {
  const headers = {};
  const res = {
    code: 200, body: null,
    set(k, v) { headers[k] = v; return this; },
    status(c) { this.code = c; return this; },
    json(b) { this.body = b; return this; }
  };
  let passed = false;
  limiter({ ip }, res, () => { passed = true; });
  return { passed, res, headers };
}

test('rate limit: blocks after max, sets Retry-After, isolates clients', () => {
  const limiter = rateLimit({ windowMs: 60_000, max: 3 });
  for (let i = 0; i < 3; i++) assert.ok(run(limiter, '1.1.1.1').passed);
  const blocked = run(limiter, '1.1.1.1');
  assert.ok(!blocked.passed);
  assert.equal(blocked.res.code, 429);
  assert.ok(Number(blocked.headers['Retry-After']) >= 1);
  assert.equal(blocked.headers['RateLimit-Remaining'], '0');
  assert.ok(run(limiter, '2.2.2.2').passed, 'another IP is unaffected');
});

test('rate limit: the window resets', async () => {
  const limiter = rateLimit({ windowMs: 50, max: 1 });
  assert.ok(run(limiter, '3.3.3.3').passed);
  assert.ok(!run(limiter, '3.3.3.3').passed);
  await new Promise(r => setTimeout(r, 80));
  assert.ok(run(limiter, '3.3.3.3').passed);
});

/* ---------------- StatusList2021 bitstring ---------------- */
test('status list: indexes are allocated per issuer and bits flip independently', () => {
  const a = revocationRegistry.allocateIndex('issuer-a');
  const b = revocationRegistry.allocateIndex('issuer-a');
  const other = revocationRegistry.allocateIndex('issuer-b');
  assert.deepEqual([a, b, other], [0, 1, 0]);

  revocationRegistry.revoke({ credentialId: 'urn:uuid:x', issuerId: 'issuer-a', statusIndex: b });
  assert.ok(revocationRegistry.isIndexRevoked('issuer-a', b));
  assert.ok(!revocationRegistry.isIndexRevoked('issuer-a', a));
  assert.ok(!revocationRegistry.isIndexRevoked('issuer-b', other));
  assert.ok(revocationRegistry.isRevoked('urn:uuid:x'));

  assert.ok(revocationRegistry.unrevoke({ credentialId: 'urn:uuid:x', issuerId: 'issuer-a', statusIndex: b }));
  assert.ok(!revocationRegistry.isIndexRevoked('issuer-a', b));
  assert.ok(!revocationRegistry.unrevoke({ credentialId: 'urn:uuid:x', issuerId: 'issuer-a' }));
});

test('status list: out-of-range or non-integer indexes are never "revoked"', () => {
  for (const i of [-1, 1.5, 'abc', STATUS_LIST_SIZE, STATUS_LIST_SIZE + 5, NaN]) {
    assert.equal(revocationRegistry.isIndexRevoked('issuer-a', i), false);
  }
});

test('status list: encodedList is MSB-first gzip+base64 of the right size', () => {
  const idx = revocationRegistry.allocateIndex('issuer-c'); // 0
  revocationRegistry.revoke({ credentialId: 'urn:uuid:c0', issuerId: 'issuer-c', statusIndex: idx });
  const raw = zlib.gunzipSync(Buffer.from(revocationRegistry.encodedList('issuer-c'), 'base64'));
  assert.equal(raw.length, STATUS_LIST_SIZE / 8);
  assert.equal(raw[0], 0x80, 'index 0 is the most significant bit of byte 0');
  assert.ok(raw.subarray(1).every(b => b === 0));
});

test('status list: state is stored in SQLite and survives reopening', async () => {
  const { db, closeDb } = await import('../services/db.js');
  const row = db.prepare('SELECT next_index FROM status_lists WHERE issuer_id = ?').get('issuer-a');
  assert.equal(row.next_index, 2);
  assert.ok(db.prepare('SELECT 1 FROM status_lists WHERE issuer_id = ?').get('issuer-c'));
  closeDb();
  fs.rmSync(tmp, { recursive: true, force: true });
});
