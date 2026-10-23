/**
 * Client-side DID + Verifiable Presentation cryptography.
 *
 * The holder's private key is generated, stored (encrypted) and used ONLY in the browser.
 * Nothing in this file talks to the network. The byte formats here must stay identical to
 * backend/crypto/{jcs,proof,credentials}.js; `npm test` checks the two implementations
 * against each other (browser-signed presentations are verified by the backend code).
 */
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, concatBytes, utf8ToBytes } from '@noble/hashes/utils';
import bs58 from 'bs58';

const ED25519_MULTICODEC = Uint8Array.of(0xed, 0x01);
const VC_CONTEXT = [
  'https://www.w3.org/2018/credentials/v1',
  'https://w3id.org/security/suites/ed25519-2020/v1'
];
export const SANDBOX_PREFIX = 'AegisID-sandbox-v1:';

/** RFC 8785 (JCS) canonical JSON for I-JSON data. */
export function canonicalize(value) {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'string': return JSON.stringify(value);
    case 'boolean': return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) throw new TypeError('Cannot canonicalize a non-finite number.');
      return JSON.stringify(value);
    case 'object': {
      if (Array.isArray(value)) {
        return '[' + value.map(v => (v === undefined || typeof v === 'function' ? 'null' : canonicalize(v))).join(',') + ']';
      }
      const parts = [];
      for (const key of Object.keys(value).sort()) {
        const v = value[key];
        if (v === undefined || typeof v === 'function') continue;
        parts.push(JSON.stringify(key) + ':' + canonicalize(v));
      }
      return '{' + parts.join(',') + '}';
    }
    default: throw new TypeError(`Cannot canonicalize value of type ${typeof value}.`);
  }
}

export function identityFromPrivateKey(privateKey) {
  const publicKey = ed25519.getPublicKey(privateKey);
  const publicKeyMultibase = 'z' + bs58.encode(concatBytes(ED25519_MULTICODEC, publicKey));
  return {
    did: `did:key:${publicKeyMultibase}`,
    publicKeyMultibase,
    privateKeyMultibase: 'z' + bs58.encode(privateKey),
    publicKeyHex: bytesToHex(publicKey),
    privateKeyHex: bytesToHex(privateKey)
  };
}

/** Generate a new holder identity (keypair + did:key) locally, from the OS CSPRNG. */
export function generateIdentity() {
  return identityFromPrivateKey(ed25519.utils.randomPrivateKey());
}

const privateKeyOf = (identity) => bs58.decode(identity.privateKeyMultibase.slice(1));

export function signingInput(document, proofOptions) {
  const options = { '@context': document['@context'], ...proofOptions };
  return concatBytes(
    sha256(utf8ToBytes(canonicalize(options))),
    sha256(utf8ToBytes(canonicalize(document)))
  );
}

export function createProof(document, { identity, proofPurpose, challenge, domain }) {
  const proofOptions = {
    type: 'Ed25519Signature2020',
    created: new Date().toISOString(),
    verificationMethod: `${identity.did}#${identity.publicKeyMultibase}`,
    proofPurpose,
    ...(challenge ? { challenge } : {}),
    ...(domain ? { domain } : {})
  };
  const signature = ed25519.sign(signingInput(document, proofOptions), privateKeyOf(identity));
  return { ...proofOptions, proofValue: 'z' + bs58.encode(signature) };
}

/**
 * Build a Verifiable Presentation, signed locally by the holder.
 *
 * `credentials` is a list of { vc, claims }:
 *   vc     = the holder's copy (signed VC + all `disclosures`)
 *   claims = names of the claims to reveal; every other disclosure is dropped.
 */
export function createPresentation({ identity, credentials, challenge, domain }) {
  if (!challenge) throw new Error('A verifier challenge is required.');
  const verifiableCredential = credentials.map(({ vc, claims }) => {
    const chosen = new Set(claims);
    const { disclosures, ...signedPart } = vc;
    return Array.isArray(disclosures)
      ? { ...signedPart, disclosures: disclosures.filter(d => chosen.has(d[1])) }
      : signedPart; // legacy credential without selective disclosure
  });

  const unsigned = {
    '@context': VC_CONTEXT,
    id: `urn:uuid:${crypto.randomUUID()}`,
    type: ['VerifiablePresentation'],
    holder: identity.did,
    verifiableCredential
  };
  return { ...unsigned, proof: createProof(unsigned, { identity, proofPurpose: 'authentication', challenge, domain }) };
}

/** Sign free text in the sandbox. A fixed prefix keeps these signatures from ever being valid for real credentials. */
export function signSandboxMessage(identity, message) {
  const sig = ed25519.sign(utf8ToBytes(SANDBOX_PREFIX + message), privateKeyOf(identity));
  return 'z' + bs58.encode(sig);
}

export function verifySandboxMessage(did, message, signatureMultibase) {
  try {
    const decoded = bs58.decode(did.slice('did:key:z'.length));
    const publicKey = decoded.slice(2);
    return ed25519.verify(bs58.decode(signatureMultibase.slice(1)), utf8ToBytes(SANDBOX_PREFIX + message), publicKey);
  } catch {
    return false;
  }
}
