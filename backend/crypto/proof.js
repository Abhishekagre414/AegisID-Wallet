import crypto from 'crypto';
import { canonicalize } from './jcs.js';
import { sign, verify } from './didKey.js';

/**
 * Data-Integrity style proofs (Ed25519Signature2020-like).
 *
 *   signingInput = SHA-256(JCS(proofOptions)) || SHA-256(JCS(document))
 *
 * Hashing the proof options together with the document means metadata such as
 * `created`, `proofPurpose`, `verificationMethod`, `challenge` and `domain` is covered by
 * the signature. (Previously only the document was signed, so a presentation's nonce
 * could be swapped freely without invalidating it.)
 */
const sha256 = (data) => crypto.createHash('sha256').update(data).digest();

export function buildSigningInput(document, proofOptions) {
  const options = { '@context': document['@context'], ...proofOptions };
  return Buffer.concat([
    sha256(canonicalize(options)),
    sha256(canonicalize(document))
  ]);
}

export function createProof(document, { did, privateKey, proofPurpose, challenge, domain, created }) {
  const multibasePub = did.slice('did:key:'.length);
  const proofOptions = {
    type: 'Ed25519Signature2020',
    created: created || new Date().toISOString(),
    verificationMethod: `${did}#${multibasePub}`,
    proofPurpose,
    ...(challenge ? { challenge } : {}),
    ...(domain ? { domain } : {})
  };
  const proofValue = sign(buildSigningInput(document, proofOptions), privateKey);
  return { ...proofOptions, proofValue };
}

/**
 * Verify `proof` over `document` for the DID that is supposed to have signed it.
 * Returns { valid, reason }.
 */
export function verifyProof(document, proof, expectedDid, expectedPurpose) {
  if (!proof || typeof proof !== 'object' || typeof proof.proofValue !== 'string') {
    return { valid: false, reason: 'Missing proof or proofValue.' };
  }
  if (proof.type !== 'Ed25519Signature2020') {
    return { valid: false, reason: `Unsupported proof type: ${proof.type}` };
  }
  if (expectedPurpose && proof.proofPurpose !== expectedPurpose) {
    return { valid: false, reason: `Proof purpose must be "${expectedPurpose}".` };
  }
  const expectedVm = `${expectedDid}#${expectedDid.slice('did:key:'.length)}`;
  if (proof.verificationMethod !== expectedVm) {
    return { valid: false, reason: 'verificationMethod does not belong to the expected signer DID.' };
  }

  const { proofValue, ...proofOptions } = proof;
  const ok = verify(buildSigningInput(document, proofOptions), proofValue, expectedDid);
  return ok ? { valid: true } : { valid: false, reason: 'Signature does not match the signed content.' };
}
