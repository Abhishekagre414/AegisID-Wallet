const API_BASE = '/api';
const KEY_STORAGE = 'aegis_issuer_key'; // sessionStorage: cleared when the tab closes

export const issuerKey = {
  get: () => { try { return sessionStorage.getItem(KEY_STORAGE) || ''; } catch { return ''; } },
  set: (k) => { try { sessionStorage.setItem(KEY_STORAGE, k); } catch { /* ignore */ } },
  clear: () => { try { sessionStorage.removeItem(KEY_STORAGE); } catch { /* ignore */ } }
};

async function request(path, { method = 'GET', body } = {}) {
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const key = issuerKey.get();
  if (key) headers['x-api-key'] = key;

  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined
  });
  try {
    return await res.json();
  } catch {
    return { success: false, error: `Unexpected response (${res.status}).` };
  }
}

export const api = {
  checkHealth: () => request('/health'),

  // DID resolution (keys are generated locally in the browser, see didCrypto.js)
  resolveDID: (did) => request(`/did/resolve/${encodeURIComponent(did)}`),

  // Issuer side (needs the issuer key when the server requires one)
  getAuthStatus: () => request('/auth/status'),
  checkIssuerKey: () => request('/auth/check'),
  getIssuers: () => request('/issuers'),
  getTemplates: () => request('/templates'),
  issueCredential: (payload) => request('/credentials/issue', { method: 'POST', body: payload }),
  getIssuedHistory: () => request('/credentials/issued'),

  // Verifier side
  verifyCredential: (credential) => request('/credentials/verify', { method: 'POST', body: { credential } }),
  getChallenge: (domain) => request(`/verifier/challenge?domain=${encodeURIComponent(domain || '')}`),
  verifyPresentation: (presentation) => request('/presentation/verify', { method: 'POST', body: { presentation } }),

  // Revocation
  getRevocationStatus: (credentialId) => request(`/revocation/status/${encodeURIComponent(credentialId)}`),
  revokeCredential: (credentialId, reason, revokedBy) =>
    request('/revocation/revoke', { method: 'POST', body: { credentialId, reason, revokedBy } }),
  unrevokeCredential: (credentialId) => request('/revocation/unrevoke', { method: 'POST', body: { credentialId } }),
  getRevocationList: () => request('/revocation/list')
};
