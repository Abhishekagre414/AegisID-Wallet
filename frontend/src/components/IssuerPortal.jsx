import React, { useState, useEffect } from 'react';
import {
  Building2, ShieldCheck, CheckCircle2, AlertTriangle, Send,
  RefreshCw, Eye, QrCode, Ban, Undo2, Copy, Check, FileBadge,
  Sparkles
} from 'lucide-react';
import { api, issuerKey } from '../services/api';
import { walletStorage } from '../services/walletStorage';
import QrModal from './QrModal';

export default function IssuerPortal({ currentHolderDid, onCredentialIssued }) {
  const [issuers, setIssuers] = useState([]);
  const [selectedIssuer, setSelectedIssuer] = useState(null);
  const [templates, setTemplates] = useState([]);
  const [selectedTemplate, setSelectedTemplate] = useState(null);
  const [subjectDid, setSubjectDid] = useState(currentHolderDid || '');
  const [claims, setClaims] = useState({});
  const [expirationDays, setExpirationDays] = useState(365);
  const [issuing, setIssuing] = useState(false);
  const [issuedHistory, setIssuedHistory] = useState([]);
  const [latestIssuedVc, setLatestIssuedVc] = useState(null);
  const [qrModalData, setQrModalData] = useState(null);
  const [copiedIssuerDid, setCopiedIssuerDid] = useState(false);
  const [revocationReason, setRevocationReason] = useState('Administrative action / Revoked by issuer');
  const [targetRevokeId, setTargetRevokeId] = useState(null);
  const [authRequired, setAuthRequired] = useState(false);
  const [authed, setAuthed] = useState(!!issuerKey.get());
  const [keyInput, setKeyInput] = useState('');
  const [authError, setAuthError] = useState('');

  useEffect(() => {
    api.getAuthStatus().then(r => setAuthRequired(!!r.required)).catch(() => {});
    loadData();
  }, []);

  const handleSaveKey = async () => {
    issuerKey.set(keyInput.trim());
    const r = await api.checkIssuerKey();
    if (r.success) {
      setAuthed(true);
      setAuthError('');
      setKeyInput('');
      loadData();
    } else {
      issuerKey.clear();
      setAuthed(false);
      setAuthError(r.error || 'Invalid issuer key.');
    }
  };

  useEffect(() => {
    if (currentHolderDid && !subjectDid) {
      setSubjectDid(currentHolderDid);
    }
  }, [currentHolderDid]);

  const loadData = async () => {
    try {
      const [issuersRes, templatesRes, historyRes] = await Promise.all([
        api.getIssuers(),
        api.getTemplates(),
        api.getIssuedHistory()
      ]);

      if (issuersRes.success && issuersRes.issuers.length > 0) {
        setIssuers(issuersRes.issuers);
        setSelectedIssuer(issuersRes.issuers[0]);
      }

      if (templatesRes.success && templatesRes.templates.length > 0) {
        setTemplates(templatesRes.templates);
        selectTemplate(templatesRes.templates[0]);
      }

      if (historyRes.success) {
        setIssuedHistory(historyRes.issued);
      }
    } catch (err) {
      console.error('Failed to load issuer data:', err);
    }
  };

  const selectTemplate = (template) => {
    setSelectedTemplate(template);
    setClaims({ ...template.defaultClaims });
  };

  const handleClaimChange = (key, val) => {
    setClaims(prev => ({ ...prev, [key]: val }));
  };

  const handleIssue = async (e) => {
    e.preventDefault();
    if (!selectedIssuer || !selectedTemplate || !subjectDid) {
      alert('Please fill in all required fields.');
      return;
    }

    setIssuing(true);
    try {
      const res = await api.issueCredential({
        issuerId: selectedIssuer.id,
        subjectDid: subjectDid.trim(),
        claims,
        credentialType: selectedTemplate.type,
        expirationDays: Number(expirationDays)
      });

      if (res.success && res.credential) {
        setLatestIssuedVc(res.credential);
        // Automatically save to local wallet if issuing to current holder!
        if (subjectDid.trim() === currentHolderDid) {
          walletStorage.saveCredential(res.credential);
          if (onCredentialIssued) onCredentialIssued(res.credential);
        }
        // Refresh history
        const historyRes = await api.getIssuedHistory();
        if (historyRes.success) setIssuedHistory(historyRes.issued);
      } else {
        alert('Failed to issue credential: ' + (res.error || 'Unknown error'));
      }
    } catch (err) {
      alert('Issuance error: ' + err.message);
    } finally {
      setIssuing(false);
    }
  };

  const handleRevoke = async () => {
    if (!targetRevokeId) return;
    try {
      const res = await api.revokeCredential(targetRevokeId, revocationReason, selectedIssuer?.name || 'Issuer');
      if (res.success) {
        setTargetRevokeId(null);
        // Refresh history
        const historyRes = await api.getIssuedHistory();
        if (historyRes.success) setIssuedHistory(historyRes.issued);
      } else {
        alert('Revocation failed: ' + res.error);
      }
    } catch (err) {
      alert('Revocation error: ' + err.message);
    }
  };

  const handleUnrevoke = async (credentialId) => {
    try {
      const res = await api.unrevokeCredential(credentialId);
      if (res.success) {
        const historyRes = await api.getIssuedHistory();
        if (historyRes.success) setIssuedHistory(historyRes.issued);
      } else {
        alert('Unrevoke failed: ' + res.error);
      }
    } catch (err) {
      alert('Unrevoke error: ' + err.message);
    }
  };

  return (
    <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '28px' }}>
      {authRequired && !authed && (
        <div className="glass-panel" style={{ padding: '18px 22px', border: '1px solid rgba(245, 158, 11, 0.35)' }}>
          <div style={{ fontSize: '0.9rem', fontWeight: 700, color: '#fbbf24', marginBottom: '6px' }}>
            Issuer access key required
          </div>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '10px' }}>
            Issuing, revoking and viewing issued credentials are restricted to the issuer operator. Enter the
            server's ISSUER_API_KEY. It is kept only for this browser tab.
          </p>
          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
            <input
              type="password"
              value={keyInput}
              onChange={(e) => setKeyInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') handleSaveKey(); }}
              placeholder="Issuer API key"
              style={{
                flex: 1, minWidth: '220px', padding: '8px 12px', borderRadius: 'var(--radius-sm)',
                background: 'rgba(7, 10, 18, 0.8)', border: '1px solid var(--border-subtle)',
                color: 'var(--text-main)', fontSize: '0.85rem'
              }}
            />
            <button type="button" onClick={handleSaveKey} className="btn btn-primary" style={{ fontSize: '0.8rem' }}>
              Unlock issuer actions
            </button>
          </div>
          {authError && <div role="alert" style={{ color: '#fb7185', fontSize: '0.8rem', marginTop: '8px' }}>{authError}</div>}
        </div>
      )}

      {/* Top Banner */}
      <div className="glass-panel glow-card" style={{ padding: '28px', border: '1px solid var(--border-glow)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '20px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
              <span className="badge badge-cyan">
                <Building2 size={12} />
                Trusted Issuer Console
              </span>
              <span className="badge badge-emerald">W3C Compliant Signer</span>
            </div>
            <h2 style={{ fontSize: '1.6rem', fontWeight: 800, letterSpacing: '-0.02em', marginBottom: '8px' }}>
              Enterprise Credential Issuance & Revocation
            </h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', maxWidth: '640px' }}>
              Digitally sign tamper-evident Verifiable Credentials using Ed25519 cryptography. Manage revocation registry status in real-time.
            </p>
          </div>
        </div>

        {/* Issuer Selector Cards */}
        <div style={{
          marginTop: '24px',
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))',
          gap: '12px'
        }}>
          {issuers.map((issuer) => {
            const isSelected = selectedIssuer?.id === issuer.id;
            return (
              <div
                key={issuer.id}
                onClick={() => setSelectedIssuer(issuer)}
                style={{
                  background: isSelected ? 'rgba(56, 189, 248, 0.12)' : 'rgba(7, 10, 18, 0.6)',
                  border: isSelected ? '1px solid #38bdf8' : '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-md)',
                  padding: '16px',
                  cursor: 'pointer',
                  transition: 'all 0.2s ease',
                  boxShadow: isSelected ? '0 0 20px rgba(56, 189, 248, 0.2)' : 'none'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                  <span style={{ fontSize: '0.75rem', color: isSelected ? '#38bdf8' : 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>
                    {issuer.type}
                  </span>
                  {isSelected && <CheckCircle2 size={16} color="#38bdf8" />}
                </div>
                <h4 style={{ fontSize: '0.95rem', fontWeight: 700, marginBottom: '4px' }}>
                  {issuer.name}
                </h4>
                <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  {issuer.description}
                </p>
              </div>
            );
          })}
        </div>

        {/* Selected Issuer DID Bar */}
        {selectedIssuer && (
          <div style={{
            marginTop: '16px',
            background: 'rgba(7, 10, 18, 0.7)',
            padding: '12px 16px',
            borderRadius: 'var(--radius-md)',
            border: '1px solid var(--border-subtle)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '10px'
          }}>
            <div style={{ minWidth: 0, overflow: 'hidden' }}>
              <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)', display: 'block' }}>
                ACTIVE ISSUER SIGNING DID
              </span>
              <span className="font-mono" style={{ fontSize: '0.8rem', color: '#38bdf8', wordBreak: 'break-all' }}>
                {selectedIssuer.did}
              </span>
            </div>
            <button
              onClick={() => {
                navigator.clipboard.writeText(selectedIssuer.did);
                setCopiedIssuerDid(true);
                setTimeout(() => setCopiedIssuerDid(false), 2000);
              }}
              className="btn btn-secondary"
              style={{ padding: '6px 12px', fontSize: '0.75rem' }}
            >
              {copiedIssuerDid ? <Check size={14} color="#34d399" /> : <Copy size={14} />}
              <span>{copiedIssuerDid ? 'Copied' : 'Copy Issuer DID'}</span>
            </button>
          </div>
        )}
      </div>

      {/* Issuance Studio Form */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'minmax(320px, 1.2fr) minmax(300px, 1fr)',
        gap: '24px'
      }}>
        {/* Form Column */}
        <form onSubmit={handleIssue} className="glass-panel" style={{ padding: '24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
            <FileBadge size={20} color="#38bdf8" />
            <h3 style={{ fontSize: '1.2rem', fontWeight: 700 }}>
              Issue Verifiable Credential
            </h3>
          </div>

          {/* Template Selector */}
          <div style={{ marginBottom: '18px' }}>
            <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '6px' }}>
              CREDENTIAL SCHEMA TEMPLATE
            </label>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
              {templates.map(tpl => (
                <button
                  type="button"
                  key={tpl.type}
                  onClick={() => selectTemplate(tpl)}
                  style={{
                    padding: '10px',
                    borderRadius: 'var(--radius-sm)',
                    border: selectedTemplate?.type === tpl.type ? '1px solid #38bdf8' : '1px solid var(--border-subtle)',
                    background: selectedTemplate?.type === tpl.type ? 'rgba(56, 189, 248, 0.15)' : 'rgba(7, 10, 18, 0.6)',
                    color: selectedTemplate?.type === tpl.type ? '#ffffff' : 'var(--text-muted)',
                    textAlign: 'left',
                    cursor: 'pointer',
                    fontSize: '0.8rem',
                    fontWeight: 600
                  }}
                >
                  {tpl.name}
                </button>
              ))}
            </div>
          </div>

          {/* Recipient Subject DID */}
          <div style={{ marginBottom: '18px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-dim)' }}>
                RECIPIENT SUBJECT DID (did:key)
              </label>
              {currentHolderDid && (
                <button
                  type="button"
                  onClick={() => setSubjectDid(currentHolderDid)}
                  style={{ background: 'none', border: 'none', color: '#38bdf8', fontSize: '0.75rem', cursor: 'pointer' }}
                >
                  Use My Wallet DID
                </button>
              )}
            </div>
            <input
              type="text"
              required
              value={subjectDid}
              onChange={(e) => setSubjectDid(e.target.value)}
              placeholder="did:key:z6M..."
              className="font-mono"
              style={{
                width: '100%',
                padding: '10px 14px',
                borderRadius: 'var(--radius-sm)',
                background: 'rgba(7, 10, 18, 0.8)',
                border: '1px solid var(--border-subtle)',
                color: 'var(--text-main)',
                fontSize: '0.85rem'
              }}
            />
          </div>

          {/* Dynamic Claims Form */}
          <div style={{ marginBottom: '18px' }}>
            <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '8px' }}>
              CREDENTIAL CLAIMS / ATTRIBUTES
            </label>
            <div style={{
              display: 'flex',
              flexDirection: 'column',
              gap: '10px',
              background: 'rgba(7, 10, 18, 0.6)',
              padding: '14px',
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--border-subtle)'
            }}>
              {Object.entries(claims).map(([key, val]) => (
                <div key={key}>
                  <label style={{ fontSize: '0.75rem', color: 'var(--text-dim)', display: 'block', marginBottom: '4px', textTransform: 'capitalize' }}>
                    {key.replace(/([A-Z])/g, ' $1')}
                  </label>
                  <input
                    type={typeof val === 'boolean' ? 'checkbox' : 'text'}
                    checked={typeof val === 'boolean' ? val : undefined}
                    value={typeof val === 'boolean' ? undefined : val}
                    onChange={(e) => handleClaimChange(key, typeof val === 'boolean' ? e.target.checked : e.target.value)}
                    style={{
                      width: typeof val === 'boolean' ? 'auto' : '100%',
                      padding: typeof val === 'boolean' ? '0' : '8px 12px',
                      borderRadius: 'var(--radius-sm)',
                      background: 'rgba(7, 10, 18, 0.9)',
                      border: '1px solid var(--border-subtle)',
                      color: 'var(--text-main)',
                      fontSize: '0.85rem',
                      accentColor: '#38bdf8'
                    }}
                  />
                </div>
              ))}
            </div>
          </div>

          {/* Expiration Days */}
          <div style={{ marginBottom: '22px' }}>
            <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '6px' }}>
              EXPIRATION VALIDITY (DAYS)
            </label>
            <input
              type="number"
              min="1"
              value={expirationDays}
              onChange={(e) => setExpirationDays(e.target.value)}
              style={{
                width: '100%',
                padding: '8px 12px',
                borderRadius: 'var(--radius-sm)',
                background: 'rgba(7, 10, 18, 0.8)',
                border: '1px solid var(--border-subtle)',
                color: 'var(--text-main)',
                fontSize: '0.85rem'
              }}
            />
          </div>

          <button
            type="submit"
            disabled={issuing}
            className="btn btn-primary"
            style={{ width: '100%', padding: '12px' }}
          >
            {issuing ? <RefreshCw size={16} className="animate-spin" /> : <Send size={16} />}
            <span>{issuing ? 'Signing with Ed25519...' : 'Sign & Issue W3C Credential'}</span>
          </button>
        </form>

        {/* Latest Issued Preview & Info Column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {latestIssuedVc ? (
            <div className="glass-panel glow-card animate-fade-in" style={{ padding: '24px', border: '1px solid rgba(16, 185, 129, 0.4)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
                <span className="badge badge-emerald">
                  <Sparkles size={12} />
                  Newly Issued & Signed!
                </span>
                <button
                  onClick={() => setQrModalData({
                    title: 'Issued Credential QR',
                    payload: latestIssuedVc,
                    description: 'Recipient can scan this QR code to claim the credential into their wallet.'
                  })}
                  className="btn btn-secondary"
                  style={{ padding: '4px 10px', fontSize: '0.75rem' }}
                >
                  <QrCode size={14} />
                  <span>QR Code</span>
                </button>
              </div>

              <h4 style={{ fontSize: '1.1rem', fontWeight: 700, marginBottom: '6px' }}>
                {latestIssuedVc.type?.[1]}
              </h4>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-dim)', marginBottom: '14px' }}>
                ID: {latestIssuedVc.id}
              </p>

              <div style={{
                background: 'rgba(7, 10, 18, 0.8)',
                padding: '12px',
                borderRadius: 'var(--radius-sm)',
                border: '1px solid var(--border-subtle)',
                marginBottom: '16px'
              }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)', display: 'block', marginBottom: '6px' }}>
                  CRYPTOGRAPHIC PROOF SUITE
                </span>
                <div style={{ fontSize: '0.75rem', color: '#38bdf8', wordBreak: 'break-all' }} className="font-mono">
                  <strong>Type:</strong> {latestIssuedVc.proof?.type}<br />
                  <strong>Signature:</strong> {latestIssuedVc.proof?.proofValue?.slice(0, 36)}...
                </div>
              </div>

              {subjectDid === currentHolderDid && (
                <div style={{
                  background: 'rgba(56, 189, 248, 0.1)',
                  padding: '10px',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: '0.8rem',
                  color: '#38bdf8',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px'
                }}>
                  <CheckCircle2 size={16} />
                  <span>Automatically saved to your Personal Wallet Vault!</span>
                </div>
              )}
            </div>
          ) : (
            <div className="glass-panel" style={{
              padding: '36px 20px',
              textAlign: 'center',
              border: '1px dashed var(--border-subtle)'
            }}>
              <ShieldCheck size={40} color="#38bdf8" style={{ margin: '0 auto 12px' }} />
              <h4 style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '6px' }}>Ready to Issue</h4>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                Select a schema, verify the recipient's DID, and click Issue. The credential will be cryptographically signed with the selected authority's Ed25519 key.
              </p>
            </div>
          )}

          {/* Revocation Guide Info */}
          <div className="glass-panel" style={{ padding: '20px' }}>
            <h4 style={{ fontSize: '0.95rem', fontWeight: 700, marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Ban size={16} color="#fb7185" />
              <span>Real-Time Revocation Registry</span>
            </h4>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', lineHeight: 1.6 }}>
              Verifiable Credentials reference a revocation registry status list. When an issuer revokes a credential, verifiers will immediately reject presentations of it during real-time signature and status audits.
            </p>
          </div>
        </div>
      </div>

      {/* Issued Credentials Audit Table & Revocation Controller */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <div>
            <h3 style={{ fontSize: '1.2rem', fontWeight: 700 }}>
              Issued Credentials & Revocation Registry ({issuedHistory.length})
            </h3>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              Complete on-ledger audit trail of all credentials issued by this enterprise.
            </p>
          </div>
          <button
            onClick={loadData}
            className="btn btn-secondary"
            style={{ padding: '6px 12px', fontSize: '0.75rem' }}
          >
            <RefreshCw size={14} />
            <span>Refresh Status</span>
          </button>
        </div>

        {issuedHistory.length === 0 ? (
          <p style={{ color: 'var(--text-dim)', fontSize: '0.85rem', textAlign: 'center', padding: '24px 0' }}>
            No credentials issued yet.
          </p>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8rem', textAlign: 'left' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-dim)' }}>
                  <th style={{ padding: '10px 12px' }}>CREDENTIAL TYPE</th>
                  <th style={{ padding: '10px 12px' }}>ISSUER</th>
                  <th style={{ padding: '10px 12px' }}>RECIPIENT DID</th>
                  <th style={{ padding: '10px 12px' }}>ISSUED AT</th>
                  <th style={{ padding: '10px 12px' }}>STATUS</th>
                  <th style={{ padding: '10px 12px', textAlign: 'right' }}>ACTION</th>
                </tr>
              </thead>
              <tbody>
                {issuedHistory.map((item) => (
                  <tr key={item.credentialId} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.04)' }}>
                    <td style={{ padding: '12px', fontWeight: 600 }}>
                      {item.credentialType}
                    </td>
                    <td style={{ padding: '12px', color: 'var(--text-muted)' }}>
                      {item.issuerName}
                    </td>
                    <td style={{ padding: '12px' }} className="font-mono">
                      {item.subjectDid.slice(0, 18)}...
                    </td>
                    <td style={{ padding: '12px', color: 'var(--text-dim)' }}>
                      {new Date(item.issuanceDate).toLocaleDateString()}
                    </td>
                    <td style={{ padding: '12px' }}>
                      {item.isRevoked ? (
                        <span className="badge badge-rose">Revoked</span>
                      ) : (
                        <span className="badge badge-emerald">Active</span>
                      )}
                    </td>
                    <td style={{ padding: '12px', textAlign: 'right' }}>
                      {item.isRevoked ? (
                        <button
                          onClick={() => handleUnrevoke(item.credentialId)}
                          className="btn btn-secondary"
                          style={{ padding: '4px 10px', fontSize: '0.75rem' }}
                        >
                          <Undo2 size={12} color="#34d399" />
                          <span>Restore</span>
                        </button>
                      ) : (
                        <button
                          onClick={() => setTargetRevokeId(item.credentialId)}
                          className="btn btn-danger"
                          style={{ padding: '4px 10px', fontSize: '0.75rem' }}
                        >
                          <Ban size={12} />
                          <span>Revoke</span>
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Revocation Reason Modal */}
      {targetRevokeId && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(3, 7, 18, 0.85)',
          backdropFilter: 'blur(10px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
          padding: '20px'
        }}>
          <div className="glass-panel animate-fade-in" style={{
            maxWidth: '460px',
            width: '100%',
            padding: '24px',
            background: '#0d1322',
            border: '1px solid rgba(244, 63, 94, 0.4)'
          }}>
            <h3 style={{ fontSize: '1.15rem', fontWeight: 700, color: '#fb7185', marginBottom: '8px' }}>
              Confirm Credential Revocation
            </h3>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '16px' }}>
              Revoking will immediately mark this credential as invalid across all verifiers and relying parties.
            </p>

            <label style={{ fontSize: '0.75rem', color: 'var(--text-dim)', display: 'block', marginBottom: '4px' }}>
              REVOCATION REASON
            </label>
            <input
              type="text"
              value={revocationReason}
              onChange={(e) => setRevocationReason(e.target.value)}
              style={{
                width: '100%',
                padding: '8px 12px',
                borderRadius: 'var(--radius-sm)',
                background: 'rgba(7, 10, 18, 0.8)',
                border: '1px solid var(--border-subtle)',
                color: 'var(--text-main)',
                fontSize: '0.85rem',
                marginBottom: '20px'
              }}
            />

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
              <button
                onClick={() => setTargetRevokeId(null)}
                className="btn btn-secondary"
                style={{ fontSize: '0.8rem' }}
              >
                Cancel
              </button>
              <button
                onClick={handleRevoke}
                className="btn btn-danger"
                style={{ fontSize: '0.8rem' }}
              >
                Confirm Revoke
              </button>
            </div>
          </div>
        </div>
      )}

      {/* QR Modal */}
      {qrModalData && (
        <QrModal
          isOpen={!!qrModalData}
          onClose={() => setQrModalData(null)}
          title={qrModalData.title}
          payload={qrModalData.payload}
          description={qrModalData.description}
        />
      )}
    </div>
  );
}
