import crypto from 'crypto';
import bs58 from 'bs58';

const ED25519_MULTICODEC_PREFIX = Buffer.from([0xed, 0x01]);
const SPKI_ED25519_HEADER = Buffer.from('302a300506032b6570032100', 'hex');
const PKCS8_ED25519_HEADER = Buffer.from('302e020100300506032b657004220420', 'hex');

export const DID_KEY_REGEX = /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{40,50}$/;

function exportKeyPair(publicKey, privateKey) {
  const rawPublicKey = publicKey.export({ type: 'spki', format: 'der' }).subarray(12);
  const rawPrivateKey = privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(16);

  const multicodecPub = Buffer.concat([ED25519_MULTICODEC_PREFIX, rawPublicKey]);
  const multibasePub = 'z' + bs58.encode(multicodecPub);

  return {
    did: `did:key:${multibasePub}`,
    publicKeyMultibase: multibasePub,
    privateKeyMultibase: 'z' + bs58.encode(rawPrivateKey),
    publicKeyHex: rawPublicKey.toString('hex'),
    privateKeyHex: rawPrivateKey.toString('hex')
  };
}

/** Generate a new Ed25519 keypair and derive its W3C did:key identifier. */
export function generateDIDKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return exportKeyPair(publicKey, privateKey);
}

/** Deterministically rebuild a keypair from a 32-byte Ed25519 seed. */
export function keyPairFromSeed(seed32) {
  if (!Buffer.isBuffer(seed32) || seed32.length !== 32) {
    throw new Error('Ed25519 seed must be exactly 32 bytes.');
  }
  const privateKey = privateKeyFromRaw(seed32);
  const publicKey = crypto.createPublicKey(privateKey);
  return exportKeyPair(publicKey, privateKey);
}

export function publicKeyFromRaw(rawBuffer) {
  return crypto.createPublicKey({
    key: Buffer.concat([SPKI_ED25519_HEADER, rawBuffer]),
    format: 'der',
    type: 'spki'
  });
}

export function privateKeyFromRaw(rawBuffer) {
  return crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_HEADER, rawBuffer]),
    format: 'der',
    type: 'pkcs8'
  });
}

/** Extract the raw 32-byte Ed25519 public key from a did:key string. */
export function extractPublicKeyFromDID(did) {
  if (typeof did !== 'string' || !did.startsWith('did:key:z')) {
    throw new Error(`Invalid did:key format: ${did}`);
  }
  const decoded = bs58.decode(did.slice('did:key:z'.length));

  if (decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new Error('Unsupported key algorithm in DID. Only Ed25519 (0xed01) is supported.');
  }
  if (decoded.length !== 34) {
    throw new Error('Invalid Ed25519 public key length in DID.');
  }
  return Buffer.from(decoded.subarray(2));
}

/** Resolve a did:key into a standard W3C DID Document. */
export function resolveDID(did) {
  extractPublicKeyFromDID(did); // validates
  const multibasePub = did.slice('did:key:'.length);
  const verificationMethodId = `${did}#${multibasePub}`;

  return {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/ed25519-2020/v1'
    ],
    id: did,
    verificationMethod: [
      {
        id: verificationMethodId,
        type: 'Ed25519VerificationKey2020',
        controller: did,
        publicKeyMultibase: multibasePub
      }
    ],
    authentication: [verificationMethodId],
    assertionMethod: [verificationMethodId],
    capabilityInvocation: [verificationMethodId],
    capabilityDelegation: [verificationMethodId]
  };
}

function decodePrivateKey(privateKeyRawOrMultibase) {
  if (Buffer.isBuffer(privateKeyRawOrMultibase)) return privateKeyRawOrMultibase;
  if (typeof privateKeyRawOrMultibase !== 'string') throw new Error('Invalid private key.');
  return privateKeyRawOrMultibase.startsWith('z')
    ? Buffer.from(bs58.decode(privateKeyRawOrMultibase.slice(1)))
    : Buffer.from(privateKeyRawOrMultibase, 'hex');
}

/** Sign bytes with an Ed25519 private key; returns a multibase (base58btc) signature. */
export function sign(message, privateKey) {
  const key = privateKeyFromRaw(decodePrivateKey(privateKey));
  const data = Buffer.isBuffer(message) ? message : Buffer.from(message, 'utf-8');
  return 'z' + bs58.encode(crypto.sign(null, data, key));
}

/** Verify an Ed25519 signature against a did:key (or raw hex public key). Never throws. */
export function verify(message, signatureMultibase, publicKeyOrDID) {
  try {
    const rawPub = typeof publicKeyOrDID === 'string' && publicKeyOrDID.startsWith('did:key:')
      ? extractPublicKeyFromDID(publicKeyOrDID)
      : Buffer.from(publicKeyOrDID, 'hex');

    if (typeof signatureMultibase !== 'string' || !signatureMultibase.startsWith('z')) return false;
    const sigBytes = Buffer.from(bs58.decode(signatureMultibase.slice(1)));
    if (sigBytes.length !== 64) return false;

    const data = Buffer.isBuffer(message) ? message : Buffer.from(message, 'utf-8');
    return crypto.verify(null, data, publicKeyFromRaw(rawPub), sigBytes);
  } catch {
    return false;
  }
}
