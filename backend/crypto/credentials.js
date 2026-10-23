import crypto from 'crypto';
import { extractPublicKeyFromDID, DID_KEY_REGEX } from './didKey.js';
import { canonicalize } from './jcs.js';
import { createProof, verifyProof } from './proof.js';

export { canonicalize as canonicalizeJson } from './jcs.js';

const VC_CONTEXT = [
  'https://www.w3.org/2018/credentials/v1',
  'https://w3id.org/security/suites/ed25519-2020/v1'
];
const CLOCK_SKEW_MS = 5 * 60 * 1000;
const RESERVED_CLAIMS = new Set(['id', '_sd', '_sd_alg']);

const sha256Base64Url = (data) => crypto.createHash('sha256').update(data).digest('base64url');

/* ------------------------------------------------------------------ *
 * Selective disclosure (salted-hash commitments, SD-JWT style)
 *
 * The issuer signs only `credentialSubject = { id, _sd: [digest, ...] }`, where
 *   digest = base64url(SHA-256(JCS([salt, claimName, claimValue])))
 * The claim values themselves travel *outside* the signed document as `disclosures`.
 * A holder can drop any disclosure before presenting; the issuer signature still
 * verifies, and the verifier only learns the claims it is given. Salts stop a verifier
 * from brute-forcing hidden low-entropy values (e.g. `isOver18`) from the digests.
 * ------------------------------------------------------------------ */
export function disclosureDigest(disclosure) {
  return sha256Base64Url(canonicalize(disclosure));
}

export function buildDisclosures(claims) {
  return Object.entries(claims)
    .filter(([key]) => !RESERVED_CLAIMS.has(key))
    .map(([key, value]) => [crypto.randomBytes(16).toString('base64url'), key, value]);
}

/** Check disclosures against the signed `_sd` commitments. Returns { ok, claims, error }. */
export function resolveDisclosures(credentialSubject, disclosures) {
  const committed = Array.isArray(credentialSubject?._sd) ? new Set(credentialSubject._sd) : null;

  // Credentials without commitments (e.g. a StatusList2021Credential, or a VC issued with
  // selectiveDisclosure:false) carry their claims in plain, fully signed, inside credentialSubject.
  if (!committed) {
    const { id, ...claims } = credentialSubject || {};
    return { ok: true, claims };
  }
  if (credentialSubject._sd_alg && credentialSubject._sd_alg !== 'sha-256') {
    return { ok: false, claims: {}, error: `Unsupported _sd_alg: ${credentialSubject._sd_alg}` };
  }

  const list = disclosures === undefined ? [] : disclosures;
  if (!Array.isArray(list)) return { ok: false, claims: {}, error: 'disclosures must be an array.' };

  const claims = {};
  const seenDigests = new Set();
  for (const d of list) {
    if (!Array.isArray(d) || d.length !== 3 || typeof d[0] !== 'string' || typeof d[1] !== 'string') {
      return { ok: false, claims: {}, error: 'Malformed disclosure (expected [salt, name, value]).' };
    }
    const [, name] = d;
    if (RESERVED_CLAIMS.has(name) || name.startsWith('_')) {
      return { ok: false, claims: {}, error: `Disclosure uses reserved claim name "${name}".` };
    }
    const digest = disclosureDigest(d);
    if (!committed.has(digest)) {
      return { ok: false, claims: {}, error: `Disclosure for "${name}" does not match any value signed by the issuer.` };
    }
    if (seenDigests.has(digest) || Object.hasOwn(claims, name)) {
      return { ok: false, claims: {}, error: `Duplicate disclosure for "${name}".` };
    }
    seenDigests.add(digest);
    claims[name] = d[2];
  }
  return { ok: true, claims };
}

/* ------------------------------------------------------------------ *
 * Issuance
 * ------------------------------------------------------------------ */

/** Sign an arbitrary unsigned VC document as `issuerDid`. */
export function signCredentialDocument({ unsignedVC, issuerDid, issuerPrivateKey }) {
  const proof = createProof(unsignedVC, {
    did: issuerDid,
    privateKey: issuerPrivateKey,
    proofPurpose: 'assertionMethod'
  });
  return { ...unsignedVC, proof };
}

/**
 * Create a W3C Verifiable Credential signed with Ed25519.
 * Returns the signed VC with its (unsigned) `disclosures` attached, i.e. the holder's copy.
 */
export function issueVerifiableCredential({
  issuerDid,
  issuerPrivateKey,
  issuerName,
  subjectDid,
  claims,
  credentialType = 'IdentityCredential',
  expirationDays = 365,
  credentialStatus = null,
  selectiveDisclosure = true
}) {
  if (!issuerDid || !issuerPrivateKey || !subjectDid || !claims || typeof claims !== 'object') {
    throw new Error('Missing required parameters for credential issuance.');
  }
  if (!DID_KEY_REGEX.test(subjectDid)) throw new Error('subjectDid must be a valid did:key identifier.');

  const issuanceDate = new Date().toISOString();
  const expirationDate = expirationDays
    ? new Date(Date.now() + expirationDays * 24 * 60 * 60 * 1000).toISOString()
    : null;

  let credentialSubject;
  let disclosures = null;
  if (selectiveDisclosure) {
    disclosures = buildDisclosures(claims);
    credentialSubject = {
      id: subjectDid,
      _sd: disclosures.map(disclosureDigest).sort(), // sorted so order leaks nothing
      _sd_alg: 'sha-256'
    };
  } else {
    credentialSubject = { id: subjectDid, ...claims };
  }

  const unsignedVC = {
    '@context': VC_CONTEXT,
    id: `urn:uuid:${crypto.randomUUID()}`,
    type: ['VerifiableCredential', credentialType],
    issuer: issuerName ? { id: issuerDid, name: issuerName } : issuerDid,
    issuanceDate,
    ...(expirationDate ? { expirationDate } : {}),
    credentialSubject,
    ...(credentialStatus ? { credentialStatus } : {})
  };

  const signed = signCredentialDocument({ unsignedVC, issuerDid, issuerPrivateKey });
  return disclosures ? { ...signed, disclosures } : signed;
}

/* ------------------------------------------------------------------ *
 * Verification
 * ------------------------------------------------------------------ */

/**
 * Verify a Verifiable Credential (optionally with attached `disclosures`).
 *
 * options:
 *   isTrustedIssuer(did, credentialTypes) -> boolean   (omit to skip the trust check)
 *   isRevoked(vc) -> boolean                            (omit to skip the revocation check)
 *   now: Date.now() override (tests)
 */
export function verifyVerifiableCredential(vc, options = {}) {
  const { isTrustedIssuer, isRevoked, now = Date.now() } = options;

  const result = {
    valid: false,
    credentialId: vc?.id || null,
    checks: {
      structureValid: false,
      issuerResolved: false,
      ...(isTrustedIssuer ? { issuerTrusted: false } : {}),
      signatureValid: false,
      disclosuresValid: false,
      notExpired: false,
      ...(isRevoked ? { notRevoked: false } : {})
    },
    issuerDid: null,
    subjectDid: null,
    credentialType: null,
    revealedClaims: {},
    errors: [],
    details: {}
  };

  try {
    if (!vc || typeof vc !== 'object' || Array.isArray(vc)) {
      result.errors.push('Credential is not a valid JSON object.');
      return result;
    }
    if (!vc.proof || typeof vc.proof.proofValue !== 'string') {
      result.errors.push('Credential has no cryptographic proof or proofValue.');
      return result;
    }

    const types = Array.isArray(vc.type) ? vc.type : [vc.type];
    const contexts = Array.isArray(vc['@context']) ? vc['@context'] : [vc['@context']];
    if (!types.includes('VerifiableCredential') || contexts[0] !== VC_CONTEXT[0] || !vc.credentialSubject) {
      result.errors.push('Not a W3C Verifiable Credential (check @context, type and credentialSubject).');
      return result;
    }
    result.checks.structureValid = true;
    result.credentialType = vc.type;
    result.subjectDid = vc.credentialSubject?.id;

    // Issuer DID
    const issuerDid = typeof vc.issuer === 'object' ? vc.issuer?.id : vc.issuer;
    result.issuerDid = issuerDid;
    if (typeof issuerDid !== 'string' || !issuerDid.startsWith('did:key:')) {
      result.errors.push(`Invalid or unsupported issuer DID: ${issuerDid}`);
      return result;
    }
    try {
      extractPublicKeyFromDID(issuerDid);
      result.checks.issuerResolved = true;
    } catch (e) {
      result.errors.push(`Failed to resolve issuer DID: ${e.message}`);
      return result;
    }

    // Is this issuer one the verifier trusts, and is it allowed to issue this credential type?
    if (isTrustedIssuer) {
      result.checks.issuerTrusted = !!isTrustedIssuer(issuerDid, types);
      if (!result.checks.issuerTrusted) {
        result.errors.push('Issuer is not in the verifier\'s trusted issuer registry (or is not authorised for this credential type).');
      }
    }

    // Signature over the signed document (the unsigned `disclosures` are excluded here;
    // they are validated against the signed commitments below).
    const { proof, disclosures, ...signedDoc } = vc;
    const sig = verifyProof(signedDoc, proof, issuerDid, 'assertionMethod');
    result.checks.signatureValid = sig.valid;
    if (!sig.valid) {
      result.errors.push(`Cryptographic signature verification failed. Document has been tampered with or signature is invalid. (${sig.reason})`);
    }

    // Selective-disclosure commitments
    const sd = resolveDisclosures(vc.credentialSubject, disclosures);
    result.checks.disclosuresValid = sd.ok;
    if (sd.ok) result.revealedClaims = sd.claims;
    else result.errors.push(sd.error);

    // Dates
    const issued = vc.issuanceDate ? Date.parse(vc.issuanceDate) : NaN;
    let datesOk = true;
    if (Number.isNaN(issued)) {
      datesOk = false;
      result.errors.push('Credential has no valid issuanceDate.');
    } else if (issued > now + CLOCK_SKEW_MS) {
      datesOk = false;
      result.errors.push('Credential issuanceDate is in the future.');
    }
    if (vc.expirationDate) {
      const exp = Date.parse(vc.expirationDate);
      if (Number.isNaN(exp)) {
        datesOk = false;
        result.errors.push('Credential has an invalid expirationDate.');
      } else if (exp < now) {
        datesOk = false;
        result.errors.push(`Credential expired on ${vc.expirationDate}`);
      }
    }
    result.checks.notExpired = datesOk;

    // Revocation
    if (isRevoked) {
      const revoked = !!isRevoked(vc);
      result.checks.notRevoked = !revoked;
      if (revoked) result.errors.push('Credential has been revoked by the issuer.');
    }

    result.valid = Object.values(result.checks).every(v => v === true);
    return result;
  } catch (err) {
    result.errors.push(`Verification exception: ${err.message}`);
    result.valid = false;
    return result;
  }
}

/* ------------------------------------------------------------------ *
 * Presentations
 * ------------------------------------------------------------------ */

/**
 * Build and sign a Verifiable Presentation (reference implementation; the browser wallet
 * has its own equivalent in frontend/src/services/didCrypto.js so the holder key never
 * leaves the device).
 *
 * `verifiableCredentials` are holder copies; pass each with only the `disclosures` you
 * want to reveal.
 */
export function issueVerifiablePresentation({
  holderDid,
  holderPrivateKey,
  verifiableCredentials = [],
  challenge,
  domain = null
}) {
  if (!holderDid || !holderPrivateKey) {
    throw new Error('Holder DID and Private Key are required to create a presentation.');
  }
  if (!challenge) throw new Error('A verifier challenge is required to create a presentation.');

  const unsignedVP = {
    '@context': VC_CONTEXT,
    id: `urn:uuid:${crypto.randomUUID()}`,
    type: ['VerifiablePresentation'],
    holder: holderDid,
    verifiableCredential: verifiableCredentials
  };

  const proof = createProof(unsignedVP, {
    did: holderDid,
    privateKey: holderPrivateKey,
    proofPurpose: 'authentication',
    challenge,
    domain
  });
  return { ...unsignedVP, proof };
}

/**
 * Verify a Verifiable Presentation and every credential inside it.
 *
 * options (in addition to the VC options):
 *   challenges: { validate(challenge, domain) -> {ok, reason}, consume(challenge) }
 *   expectedChallenge / expectedDomain: simple equality checks when no store is used
 */
export function verifyVerifiablePresentation(vp, options = {}) {
  const { challenges, expectedChallenge, expectedDomain } = options;

  const result = {
    valid: false,
    presentationId: vp?.id || null,
    holderDid: vp?.holder || null,
    checks: {
      vpStructureValid: false,
      holderSignatureValid: false,
      ...(challenges || expectedChallenge ? { challengeValid: false } : {}),
      holderBound: false,
      credentialsAllValid: false
    },
    credentialsReport: [],
    errors: []
  };

  try {
    const types = Array.isArray(vp?.type) ? vp.type : [vp?.type];
    if (!vp || !types.includes('VerifiablePresentation') || !vp.proof || typeof vp.proof.proofValue !== 'string' ||
        typeof vp.holder !== 'string' || !DID_KEY_REGEX.test(vp.holder)) {
      result.errors.push('Invalid presentation format: missing proof, or holder is not a valid did:key.');
      return result;
    }
    result.checks.vpStructureValid = true;

    // Holder authentication (covers credentials, disclosures, challenge and domain)
    const { proof, ...unsignedVP } = vp;
    const sig = verifyProof(unsignedVP, proof, vp.holder, 'authentication');
    result.checks.holderSignatureValid = sig.valid;
    if (!sig.valid) result.errors.push(`Holder presentation signature verification failed. (${sig.reason})`);

    // Challenge / domain binding (anti-replay). Only checked once the signature is good so
    // that forged presentations cannot burn a legitimate challenge.
    if ('challengeValid' in result.checks) {
      if (!sig.valid) {
        result.checks.challengeValid = false;
      } else if (challenges) {
        let c = challenges.validate(proof.challenge, proof.domain);
        // consume() is atomic: if a concurrent request used it first, this one is a replay.
        if (c.ok && challenges.consume(proof.challenge) === false) {
          c = { ok: false, reason: 'unknown or already used (possible replay).' };
        }
        result.checks.challengeValid = c.ok;
        if (!c.ok) result.errors.push(`Presentation challenge rejected: ${c.reason}`);
      } else {
        result.checks.challengeValid =
          proof.challenge === expectedChallenge &&
          (expectedDomain === undefined || proof.domain === expectedDomain);
        if (!result.checks.challengeValid) result.errors.push('Presentation challenge or domain does not match what the verifier expects.');
      }
    }

    // Credentials
    const credentials = Array.isArray(vp.verifiableCredential)
      ? vp.verifiableCredential
      : (vp.verifiableCredential ? [vp.verifiableCredential] : []);

    // Holder binding: a credential may only be presented by the subject it was issued to.
    result.checks.holderBound = credentials.length > 0 &&
      credentials.every(vc => vc?.credentialSubject?.id === vp.holder);
    if (!result.checks.holderBound) {
      result.errors.push('Presentation holder does not match the credential subject (credential was not issued to this holder).');
    }

    let allCredsValid = credentials.length > 0;
    credentials.forEach((vc, i) => {
      const vcReport = verifyVerifiableCredential(vc, options);
      result.credentialsReport.push(vcReport);
      if (!vcReport.valid) {
        allCredsValid = false;
        vcReport.errors.forEach(e => result.errors.push(`Credential ${i + 1}: ${e}`));
      }
    });
    result.checks.credentialsAllValid = allCredsValid;

    result.valid = Object.values(result.checks).every(v => v === true);
    return result;
  } catch (err) {
    result.errors.push(`Presentation verification exception: ${err.message}`);
    result.valid = false;
    return result;
  }
}
