import crypto from 'crypto';
import { generateDIDKeyPair, keyPairFromSeed } from '../crypto/didKey.js';
import { issueVerifiableCredential, signCredentialDocument } from '../crypto/credentials.js';
import { revocationRegistry, STATUS_LIST_SIZE } from './revocationRegistry.js';
import { dataPath, readJson, writeJson } from './storage.js';
import { db, tx } from './db.js';
import { HttpError } from './errors.js';

const ISSUERS_FILE = dataPath('issuers.json');

const ISSUER_DEFS = [
  { id: 'issuer-gov', name: 'GovTrust National Identity Authority', type: 'gov',
    description: 'Federal Bureau of Digital Identity & Citizenship', supportedTypes: ['NationalIDCredential'] },
  { id: 'issuer-edu', name: 'Metropolitan Institute of Technology', type: 'university',
    description: 'Accredited University Registry & Academic Records', supportedTypes: ['UniversityDegreeCredential'] },
  { id: 'issuer-corp', name: 'CyberMesh Technologies Group', type: 'enterprise',
    description: 'Global Enterprise Identity & Human Resources', supportedTypes: ['EmploymentCredential'] },
  { id: 'issuer-fin', name: 'FinGuard Compliance & KYC Authority', type: 'finance',
    description: 'Decentralized Finance Regulatory & Identity Cleared Entity', supportedTypes: ['KYCVerificationCredential'] }
];

const MAX_CLAIMS = 40;
const MAX_CLAIMS_BYTES = 16 * 1024;

const appUrl = () =>
  (process.env.APP_URL || `http://localhost:${process.env.PORT || 5000}`).replace(/\/+$/, '');

export const CREDENTIAL_TEMPLATES = [
  {
    type: "NationalIDCredential",
    name: "National Identity Card",
    icon: "ShieldCheck",
    issuerType: "gov",
    description: "Official government-backed digital citizen identification credential.",
    defaultClaims: {
      fullName: "Siddharth Verma",
      dateOfBirth: "1998-05-14",
      nationality: "IN",
      documentNumber: "IND-8829-4410-X",
      addressCity: "Bangalore",
      isOver18: true
    }
  },
  {
    type: "UniversityDegreeCredential",
    name: "B.Tech Computer Science Degree",
    icon: "GraduationCap",
    issuerType: "university",
    description: "Accredited bachelor's degree certification issued by metropolitan academic institute.",
    defaultClaims: {
      studentName: "Siddharth Verma",
      degreeName: "Bachelor of Technology in Computer Science",
      graduationYear: 2024,
      cgpa: "8.95",
      honors: "First Class with Distinction",
      faculty: "School of Engineering & Computing"
    }
  },
  {
    type: "EmploymentCredential",
    name: "Enterprise Employment Verification",
    icon: "Briefcase",
    issuerType: "enterprise",
    description: "Corporate proof of employment, role, security clearance, and active standing.",
    defaultClaims: {
      employeeName: "Siddharth Verma",
      companyName: "CyberMesh Technologies Inc.",
      jobTitle: "Senior Systems Architect",
      department: "Distributed Systems & Identity",
      startDate: "2024-07-01",
      employmentStatus: "Full-Time",
      securityClearanceLevel: "Level 3 - Confidential"
    }
  },
  {
    type: "KYCVerificationCredential",
    name: "Verified Investor / KYC Badge",
    icon: "Award",
    issuerType: "finance",
    description: "Anti-Money Laundering (AML) and Level-2 Know Your Customer regulatory clearance.",
    defaultClaims: {
      subjectName: "Siddharth Verma",
      kycLevel: "Tier 2 - Verified Investor",
      jurisdiction: "Global/IN",
      sanctionsScreening: "Passed - Clean Record",
      riskScore: "Low (0.02)",
      validUntil: "2027-12-31"
    }
  }
];


/**
 * Issuer keys:
 *  - If ISSUER_MASTER_SECRET is set, every issuer key is derived from it with HKDF, so no
 *    private key is ever written to disk and issuers survive redeploys on ephemeral hosts.
 *  - Otherwise keys are generated once and stored in data/issuers.json (mode 0600). That is
 *    fine for local demos but must not be committed (data/ is git-ignored).
 */
function deriveKeyPair(issuerId) {
  const seed = crypto.hkdfSync('sha256', process.env.ISSUER_MASTER_SECRET, 'aegisid-issuer-v1', issuerId, 32);
  return keyPairFromSeed(Buffer.from(seed));
}

class IssuerService {
  constructor() {
    this.issuers = [];
    this.init();
  }

  init() {
    const useDerived = !!process.env.ISSUER_MASTER_SECRET;
    const stored = readJson(ISSUERS_FILE, []);
    const byId = new Map(stored.map(i => [i.id, i]));
    let dirty = false;

    this.issuers = ISSUER_DEFS.map(def => {
      let keyPair;
      if (useDerived) {
        keyPair = deriveKeyPair(def.id);
      } else {
        keyPair = byId.get(def.id)?.keyPair;
        if (!keyPair) { keyPair = generateDIDKeyPair(); dirty = true; }
      }
      return { ...def, did: keyPair.did, keyPair };
    });

    // Persist: with a master secret only public data is stored; otherwise the keys too.
    const persisted = this.issuers.map(i => {
      const { keyPair, ...pub } = i;
      return useDerived ? pub : { ...pub, keyPair };
    });
    const needsRewrite = dirty || useDerived !== stored.every(i => !i.keyPair) || stored.length !== persisted.length;
    if (needsRewrite) {
      try { writeJson(ISSUERS_FILE, persisted, { secret: !useDerived }); }
      catch (err) { console.error('Failed to write issuers:', err.message); }
    }

  }

  getIssuers() {
    return this.issuers.map(i => ({
      id: i.id, name: i.name, type: i.type, description: i.description, did: i.did, supportedTypes: i.supportedTypes
    }));
  }

  getIssuerById(idOrDid) {
    return this.issuers.find(i => i.id === idOrDid || i.did === idOrDid);
  }

  /** Verifier trust policy: known issuer, and authorised for at least one of the credential's types. */
  isTrustedIssuer(did, credentialTypes = []) {
    const issuer = this.issuers.find(i => i.did === did);
    if (!issuer) return false;
    return credentialTypes.some(t => issuer.supportedTypes.includes(t));
  }

  #record = (r) => r && ({
    credentialId: r.credential_id, issuerId: r.issuer_id, issuerName: r.issuer_name, issuerDid: r.issuer_did,
    subjectDid: r.subject_did, credentialType: r.credential_type, statusIndex: r.status_index,
    issuanceDate: r.issuance_date, expirationDate: r.expiration_date
  });

  getRecord(credentialId) {
    return this.#record(db.prepare('SELECT * FROM issued WHERE credential_id = ?').get(credentialId));
  }

  /** Is this VC revoked? Uses its StatusList entry; falls back to the audit log for older credentials. */
  isRevoked(vc) {
    const issuerDid = typeof vc.issuer === 'object' ? vc.issuer?.id : vc.issuer;
    const issuer = this.issuers.find(i => i.did === issuerDid);
    const status = vc.credentialStatus;
    if (issuer && status?.type === 'StatusList2021Entry' && status.statusPurpose === 'revocation') {
      return revocationRegistry.isIndexRevoked(issuer.id, status.statusListIndex);
    }
    return revocationRegistry.isRevoked(vc.id);
  }

  #validateClaims(claims) {
    if (!claims || typeof claims !== 'object' || Array.isArray(claims)) {
      throw new HttpError(400, 'claims must be an object.');
    }
    const keys = Object.keys(claims);
    if (keys.length === 0 || keys.length > MAX_CLAIMS) throw new HttpError(400, `claims must contain 1-${MAX_CLAIMS} entries.`);
    if (Buffer.byteLength(JSON.stringify(claims)) > MAX_CLAIMS_BYTES) throw new HttpError(400, 'claims payload is too large.');
    for (const [k, v] of Object.entries(claims)) {
      if (!/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(k)) throw new HttpError(400, `Invalid claim name "${k}".`);
      if (!['string', 'number', 'boolean'].includes(typeof v) || (typeof v === 'number' && !Number.isFinite(v))) {
        throw new HttpError(400, `Claim "${k}" must be a string, finite number or boolean.`);
      }
    }
  }

  issueCredential({ issuerIdOrDid, subjectDid, claims, credentialType, expirationDays }) {
    const issuer = this.getIssuerById(issuerIdOrDid);
    if (!issuer) throw new HttpError(404, `Issuer '${issuerIdOrDid}' not found.`);
    if (!issuer.supportedTypes.includes(credentialType)) {
      throw new HttpError(400, `${issuer.name} is not authorised to issue "${credentialType}" credentials.`);
    }
    if (typeof subjectDid !== 'string' || !/^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{40,50}$/.test(subjectDid)) {
      throw new HttpError(400, 'subjectDid must be a valid did:key identifier.');
    }
    this.#validateClaims(claims);
    const days = Number(expirationDays);
    if (!Number.isInteger(days) || days < 1 || days > 3650) throw new HttpError(400, 'expirationDays must be an integer between 1 and 3650.');

    const statusIndex = revocationRegistry.allocateIndex(issuer.id);
    const listUrl = `${appUrl()}/api/status/list/${issuer.id}`;

    const vc = issueVerifiableCredential({
      issuerDid: issuer.did,
      issuerPrivateKey: issuer.keyPair.privateKeyMultibase,
      issuerName: issuer.name,
      subjectDid,
      claims,
      credentialType,
      expirationDays: days,
      credentialStatus: {
        id: `${listUrl}#${statusIndex}`,
        type: 'StatusList2021Entry',
        statusPurpose: 'revocation',
        statusListIndex: String(statusIndex),
        statusListCredential: listUrl
      }
    });

    // Data minimisation: only metadata is retained. Claim values and the credential itself live
    // with the holder; the issuer keeps nothing that could leak personal data.
    tx(() => {
      const { s: seq } = db.prepare('SELECT COALESCE(MAX(seq), 0) + 1 AS s FROM issued').get();
      db.prepare('INSERT INTO issued VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(
        vc.id, issuer.id, issuer.name, issuer.did, subjectDid, credentialType,
        statusIndex, vc.issuanceDate, vc.expirationDate || null, seq
      );
    });

    return vc;
  }

  getIssuedCredentials() {
    return db.prepare('SELECT * FROM issued ORDER BY seq DESC LIMIT 1000').all().map(r => ({
      ...this.#record(r),
      isRevoked: revocationRegistry.isRevoked(r.credential_id)
    }));
  }

  revoke(credentialId, reason, revokedBy) {
    const record = this.getRecord(credentialId);
    if (!record) throw new HttpError(404, 'Credential was not issued by this issuer service.');
    return revocationRegistry.revoke(
      { credentialId, issuerId: record.issuerId, statusIndex: record.statusIndex }, reason, revokedBy
    );
  }

  unrevoke(credentialId) {
    const record = this.getRecord(credentialId);
    if (!record) throw new HttpError(404, 'Credential was not issued by this issuer service.');
    return revocationRegistry.unrevoke({ credentialId, issuerId: record.issuerId, statusIndex: record.statusIndex });
  }

  /** The issuer's current revocation list as a signed StatusList2021Credential. */
  getStatusListCredential(issuerId) {
    const issuer = this.getIssuerById(issuerId);
    if (!issuer) throw new HttpError(404, 'Unknown issuer.');
    const id = `${appUrl()}/api/status/list/${issuer.id}`;
    return signCredentialDocument({
      issuerDid: issuer.did,
      issuerPrivateKey: issuer.keyPair.privateKeyMultibase,
      unsignedVC: {
        '@context': [
          'https://www.w3.org/2018/credentials/v1',
          'https://w3id.org/vc/status-list/2021/v1'
        ],
        id,
        type: ['VerifiableCredential', 'StatusList2021Credential'],
        issuer: issuer.did,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: `${id}#list`,
          type: 'StatusList2021',
          statusPurpose: 'revocation',
          size: STATUS_LIST_SIZE,
          encodedList: revocationRegistry.encodedList(issuer.id)
        }
      }
    });
  }
}

export const issuerService = new IssuerService();
