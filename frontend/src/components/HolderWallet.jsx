import React, { useState } from 'react';
import {
  Key, Shield, QrCode, Copy, Check, Eye, Trash2,
  FileCheck, Download, Plus, AlertCircle, Share2,
  Lock, RefreshCw, FileText, CheckCircle2, X
} from 'lucide-react';
import { walletStorage } from '../services/walletStorage';
import { createPresentation } from '../services/didCrypto';
import { getClaims } from '../services/credentialUtils';
import { api } from '../services/api';
import QrModal from './QrModal';

export default function HolderWallet({ identity, onRegenerateIdentity, onSelectCredentialToVerify }) {
  const [credentials, setCredentials] = useState(() => walletStorage.getCredentials());
  const [copiedDid, setCopiedDid] = useState(false);
  const [selectedVc, setSelectedVc] = useState(null);
  const [showJsonModal, setShowJsonModal] = useState(false);
  const [showBackupModal, setShowBackupModal] = useState(false);
  const [showSelectiveModal, setShowSelectiveModal] = useState(false);
  const [targetVcForPresentation, setTargetVcForPresentation] = useState(null);
  const [selectedClaims, setSelectedClaims] = useState({});
  const [nonce, setNonce] = useState('');
  const [domain, setDomain] = useState('verifier.example.com');
  const [generatedPresentation, setGeneratedPresentation] = useState(null);
  const [qrModalData, setQrModalData] = useState(null);
  const [showImportModal, setShowImportModal] = useState(false);
  const [importJson, setImportJson] = useState('');
  const [importError, setImportError] = useState('');

  const refreshCredentials = () => {
    setCredentials(walletStorage.getCredentials());
  };

  const handleCopyDid = () => {
    if (identity?.did) {
      navigator.clipboard.writeText(identity.did);
      setCopiedDid(true);
      setTimeout(() => setCopiedDid(false), 2000);
    }
  };

  const handleDeleteVc = (id) => {
    if (confirm('Are you sure you want to delete this credential from your local vault?')) {
      walletStorage.removeCredential(id);
      refreshCredentials();
    }
  };

  // The verifier issues a single-use challenge; the holder signs over it (anti-replay).
  const requestChallenge = async (forDomain = domain) => {
    try {
      const res = await api.getChallenge(forDomain);
      if (res.success) setNonce(res.challenge);
      else setNonce('');
    } catch {
      setNonce('');
    }
  };

  const handleOpenSelectiveDisclosure = (vc) => {
    setTargetVcForPresentation(vc);
    // Initialize all claims as checked by default
    const initialClaims = {};
    Object.keys(getClaims(vc)).forEach(key => { initialClaims[key] = true; });
    setSelectedClaims(initialClaims);
    setGeneratedPresentation(null);
    setShowSelectiveModal(true);
    requestChallenge();
  };

  const handleGeneratePresentation = async () => {
    if (!targetVcForPresentation || !identity) return;

    try {
      // Always sign over a fresh challenge issued for the audience currently entered.
      const ch = await api.getChallenge(domain);
      if (!ch.success) {
        alert('Could not get a challenge from the verifier: ' + (ch.error || 'is the backend running?'));
        return;
      }
      setNonce(ch.challenge);

      // Signed entirely in the browser: the private key never leaves this device.
      // Only the ticked claims are included; every other disclosure is dropped.
      const revealed = Object.keys(selectedClaims).filter(key => selectedClaims[key]);
      const presentation = createPresentation({
        identity,
        credentials: [{ vc: targetVcForPresentation, claims: revealed }],
        challenge: ch.challenge,
        domain
      });

      setGeneratedPresentation(presentation);
      walletStorage.logActivity(
        'Generated Presentation',
        `Created selective presentation for ${targetVcForPresentation.type?.[1] || 'Credential'}`
      );
    } catch (err) {
      alert('Error creating presentation: ' + err.message);
    }
  };

  const handleImportCredential = () => {
    setImportError('');
    try {
      const parsed = JSON.parse(importJson);
      if (!parsed.id || !parsed.proof) {
        setImportError('Invalid W3C Verifiable Credential: must have an "id" and cryptographic "proof".');
        return;
      }
      walletStorage.saveCredential(parsed);
      refreshCredentials();
      setShowImportModal(false);
      setImportJson('');
    } catch {
      setImportError('Invalid JSON format. Please paste a valid W3C Verifiable Credential JSON.');
    }
  };

  const handleDownloadIdentity = async () => {
    const passphrase = window.prompt('Choose a passphrase to encrypt this backup (min 10 characters). You will need it to restore the key:');
    if (!passphrase) return;
    try {
      const file = await walletStorage.exportIdentityBackup(passphrase);
      const url = URL.createObjectURL(new Blob([file], { type: 'application/json' }));
      const a = document.createElement('a');
      a.href = url;
      a.download = `aegis-identity-backup-${identity.did.slice(-8)}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      alert(err.message);
    }
  };

  return (
    <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '28px' }}>
      {/* Top Banner: Identity Header Card */}
      <div className="glass-panel glow-card" style={{ padding: '28px', border: '1px solid var(--border-glow)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '20px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
              <span className="badge badge-cyan">
                <Lock size={12} />
                Decentralized Identifier (DID)
              </span>
              <span className="badge badge-emerald">Ed25519 Keypair</span>
            </div>
            <h2 style={{ fontSize: '1.6rem', fontWeight: 800, letterSpacing: '-0.02em', marginBottom: '8px' }}>
              Personal Identity Vault
            </h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', maxWidth: '640px' }}>
              Self-sovereign cryptographic identity. Your private keys never leave this device, giving you 100% control over your credentials and disclosures.
            </p>
          </div>

          <div style={{ display: 'flex', gap: '10px' }}>
            <button
              onClick={() => setShowBackupModal(true)}
              className="btn btn-secondary"
              style={{ fontSize: '0.85rem' }}
            >
              <Key size={16} />
              <span>Key & Backup</span>
            </button>
            <button
              onClick={() => setShowImportModal(true)}
              className="btn btn-secondary"
              style={{ fontSize: '0.85rem' }}
            >
              <Plus size={16} />
              <span>Import VC</span>
            </button>
          </div>
        </div>

        {/* DID Display Box */}
        <div style={{
          marginTop: '20px',
          background: 'rgba(7, 10, 18, 0.7)',
          padding: '14px 18px',
          borderRadius: 'var(--radius-md)',
          border: '1px solid var(--border-subtle)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '12px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', minWidth: 0, flex: 1 }}>
            <div style={{
              width: '32px',
              height: '32px',
              borderRadius: '8px',
              background: 'rgba(56, 189, 248, 0.1)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0
            }}>
              <Key size={16} color="#38bdf8" />
            </div>
            <div style={{ minWidth: 0, overflow: 'hidden' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)', display: 'block', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Your W3C did:key Address
              </span>
              <span className="font-mono" style={{
                fontSize: '0.85rem',
                color: '#38bdf8',
                wordBreak: 'break-all',
                fontWeight: 500
              }}>
                {identity?.did || 'Generating DID...'}
              </span>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <button
              onClick={handleCopyDid}
              className="btn btn-secondary"
              style={{ padding: '6px 12px', fontSize: '0.75rem' }}
              title="Copy DID"
            >
              {copiedDid ? <Check size={14} color="#34d399" /> : <Copy size={14} />}
              <span>{copiedDid ? 'Copied' : 'Copy'}</span>
            </button>
            <button
              onClick={() => setQrModalData({
                title: 'Your DID Address',
                payload: identity?.did,
                description: 'Share your DID with issuers to receive signed Verifiable Credentials.'
              })}
              className="btn btn-secondary"
              style={{ padding: '6px 12px', fontSize: '0.75rem' }}
              title="DID QR Code"
            >
              <QrCode size={14} />
              <span>QR Code</span>
            </button>
          </div>
        </div>
      </div>

      {/* Vault Credentials Section */}
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <div>
            <h3 style={{ fontSize: '1.25rem', fontWeight: 700 }}>
              Credentials Vault ({credentials.length})
            </h3>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
              Cryptographically verified assertions issued to your Decentralized Identifier.
            </p>
          </div>
        </div>

        {credentials.length === 0 ? (
          <div className="glass-panel" style={{
            padding: '48px 24px',
            textAlign: 'center',
            border: '1px dashed var(--border-subtle)'
          }}>
            <div style={{
              width: '64px',
              height: '64px',
              borderRadius: '50%',
              background: 'rgba(56, 189, 248, 0.08)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              margin: '0 auto 16px'
            }}>
              <Shield size={32} color="#38bdf8" />
            </div>
            <h4 style={{ fontSize: '1.1rem', fontWeight: 600, marginBottom: '6px' }}>No credentials in vault yet</h4>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', maxWidth: '420px', margin: '0 auto 20px' }}>
              Head over to the <strong>Issuer Portal</strong> tab to issue yourself a National ID, University Degree, or Employment verification.
            </p>
          </div>
        ) : (
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(360px, 1fr))',
            gap: '20px'
          }}>
            {credentials.map((vc) => {
              const credType = vc.type?.[1] || 'VerifiableCredential';
              const issuerName = typeof vc.issuer === 'object' ? vc.issuer.name : 'Verified Authority';

              return (
                <div
                  key={vc.id}
                  className="glass-panel glow-card"
                  style={{
                    padding: '22px',
                    display: 'flex',
                    flexDirection: 'column',
                    justifyContent: 'space-between',
                    gap: '16px',
                    position: 'relative'
                  }}
                >
                  {/* Card Header */}
                  <div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
                      <span className="badge badge-cyan" style={{ fontSize: '0.7rem' }}>
                        <CheckCircle2 size={12} />
                        {credType}
                      </span>
                      <span className="badge badge-emerald" style={{ fontSize: '0.7rem' }}>
                        W3C Signed
                      </span>
                    </div>

                    <h4 style={{ fontSize: '1.15rem', fontWeight: 700, marginBottom: '4px' }}>
                      {credType.replace('Credential', '')}
                    </h4>
                    <p style={{ fontSize: '0.8rem', color: 'var(--text-dim)', marginBottom: '14px' }}>
                      Issued by <strong style={{ color: 'var(--text-main)' }}>{issuerName}</strong>
                    </p>

                    {/* Claims Preview */}
                    <div style={{
                      background: 'rgba(7, 10, 18, 0.6)',
                      borderRadius: 'var(--radius-sm)',
                      padding: '12px',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '8px',
                      fontSize: '0.8rem',
                      border: '1px solid var(--border-subtle)'
                    }}>
                      {Object.entries(getClaims(vc))
                        .slice(0, 4)
                        .map(([key, val]) => (
                          <div key={key} style={{ display: 'flex', justifyContent: 'space-between', gap: '8px' }}>
                            <span style={{ color: 'var(--text-dim)', textTransform: 'capitalize' }}>
                              {key.replace(/([A-Z])/g, ' $1')}:
                            </span>
                            <span style={{ fontWeight: 600, color: 'var(--text-main)', textAlign: 'right' }}>
                              {String(val)}
                            </span>
                          </div>
                        ))}
                    </div>
                  </div>

                  {/* Card Actions */}
                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    borderTop: '1px solid var(--border-subtle)',
                    paddingTop: '14px',
                    gap: '8px',
                    flexWrap: 'wrap'
                  }}>
                    <button
                      onClick={() => handleOpenSelectiveDisclosure(vc)}
                      className="btn btn-primary"
                      style={{ padding: '6px 12px', fontSize: '0.75rem', flex: 1 }}
                    >
                      <Share2 size={14} />
                      <span>Present (Selective)</span>
                    </button>

                    <button
                      onClick={() => {
                        setSelectedVc(vc);
                        setShowJsonModal(true);
                      }}
                      className="btn btn-secondary"
                      style={{ padding: '6px 10px', fontSize: '0.75rem' }}
                      title="Inspect W3C JSON-LD Proof"
                    >
                      <Eye size={14} />
                    </button>

                    <button
                      onClick={() => setQrModalData({
                        title: `${credType} QR`,
                        payload: vc,
                        description: 'Scan with any W3C compliant verifier to validate cryptographic proof.'
                      })}
                      className="btn btn-secondary"
                      style={{ padding: '6px 10px', fontSize: '0.75rem' }}
                      title="View QR Code"
                    >
                      <QrCode size={14} />
                    </button>

                    <button
                      onClick={() => handleDeleteVc(vc.id)}
                      className="btn btn-danger"
                      style={{ padding: '6px 10px', fontSize: '0.75rem' }}
                      title="Remove from Wallet"
                    >
                      <Trash2 size={14} />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Modal: Selective Disclosure & Presentation Generator */}
      {showSelectiveModal && targetVcForPresentation && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(3, 7, 18, 0.85)',
          backdropFilter: 'blur(12px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
          padding: '20px'
        }}>
          <div className="glass-panel animate-fade-in" style={{
            maxWidth: '560px',
            width: '100%',
            padding: '28px',
            maxHeight: '90vh',
            overflowY: 'auto',
            background: '#0d1322',
            border: '1px solid var(--border-glow)'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <Share2 size={22} color="#38bdf8" />
                <h3 style={{ fontSize: '1.25rem', fontWeight: 700 }}>
                  Selective Disclosure Presentation
                </h3>
              </div>
              <button
                onClick={() => setShowSelectiveModal(false)}
                style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
              >
                <X size={20} />
              </button>
            </div>

            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '20px' }}>
              Choose which attributes to reveal to the verifier. You sign this presentation with your Holder private key, binding it to a verifier challenge.
            </p>

            {/* Claims Checkboxes */}
            <div style={{ marginBottom: '20px' }}>
              <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: '8px' }}>
                ATTRIBUTES TO DISCLOSE:
              </label>
              <div style={{
                background: 'rgba(7, 10, 18, 0.7)',
                padding: '12px',
                borderRadius: 'var(--radius-md)',
                display: 'flex',
                flexDirection: 'column',
                gap: '10px',
                border: '1px solid var(--border-subtle)'
              }}>
                {Object.entries(getClaims(targetVcForPresentation))
                  .map(([key, val]) => (
                    <label
                      key={key}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        cursor: 'pointer',
                        padding: '6px 8px',
                        borderRadius: '6px',
                        background: selectedClaims[key] ? 'rgba(56, 189, 248, 0.08)' : 'transparent'
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <input
                          type="checkbox"
                          checked={!!selectedClaims[key]}
                          onChange={(e) => setSelectedClaims({ ...selectedClaims, [key]: e.target.checked })}
                          style={{ cursor: 'pointer', accentColor: '#38bdf8' }}
                        />
                        <span style={{ fontSize: '0.85rem', fontWeight: 500, textTransform: 'capitalize' }}>
                          {key.replace(/([A-Z])/g, ' $1')}
                        </span>
                      </div>
                      <span style={{ fontSize: '0.8rem', color: selectedClaims[key] ? 'var(--text-main)' : 'var(--text-dim)', fontWeight: 600 }}>
                        {selectedClaims[key] ? String(val) : '[Hidden]'}
                      </span>
                    </label>
                  ))}
              </div>
            </div>

            {/* Challenge / Nonce inputs */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '20px' }}>
              <div>
                <label style={{ fontSize: '0.75rem', color: 'var(--text-dim)', display: 'block', marginBottom: '4px' }}>
                  Verifier Challenge (single-use)
                  <button
                    type="button"
                    onClick={() => { setGeneratedPresentation(null); requestChallenge(); }}
                    style={{ marginLeft: '8px', background: 'transparent', border: 'none', color: '#38bdf8', cursor: 'pointer', fontSize: '0.75rem' }}
                  >
                    New challenge
                  </button>
                </label>
                <input
                  type="text"
                  readOnly
                  placeholder="requesting from verifier..."
                  value={nonce}
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
              <div>
                <label style={{ fontSize: '0.75rem', color: 'var(--text-dim)', display: 'block', marginBottom: '4px' }}>
                  Audience Domain
                </label>
                <input
                  type="text"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
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
            </div>

            <button
              onClick={handleGeneratePresentation}
              className="btn btn-primary"
              style={{ width: '100%', marginBottom: '16px' }}
            >
              <Key size={16} />
              <span>Sign & Generate Verifiable Presentation</span>
            </button>

            {/* Generated Presentation Preview */}
            {generatedPresentation && (
              <div className="animate-fade-in" style={{
                background: 'rgba(16, 185, 129, 0.08)',
                border: '1px solid rgba(16, 185, 129, 0.3)',
                padding: '16px',
                borderRadius: 'var(--radius-md)'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#34d399', fontWeight: 600, fontSize: '0.85rem' }}>
                    <CheckCircle2 size={16} />
                    <span>Signed Verifiable Presentation Ready</span>
                  </div>
                  <button
                    onClick={() => setQrModalData({
                      title: 'Verifiable Presentation QR',
                      payload: generatedPresentation,
                      description: 'Present this QR code to the verifier for instant cryptographic verification.'
                    })}
                    className="btn btn-secondary"
                    style={{ padding: '4px 10px', fontSize: '0.75rem' }}
                  >
                    <QrCode size={14} />
                    <span>Presentation QR</span>
                  </button>
                </div>
                <pre className="font-mono" style={{
                  fontSize: '0.75rem',
                  color: 'var(--text-muted)',
                  maxHeight: '120px',
                  overflowY: 'auto',
                  background: 'rgba(0,0,0,0.4)',
                  padding: '8px',
                  borderRadius: '4px'
                }}>
                  {JSON.stringify(generatedPresentation, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Modal: Raw JSON-LD & Proof Inspector */}
      {showJsonModal && selectedVc && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(3, 7, 18, 0.85)',
          backdropFilter: 'blur(12px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
          padding: '20px'
        }}>
          <div className="glass-panel animate-fade-in" style={{
            maxWidth: '680px',
            width: '100%',
            padding: '24px',
            maxHeight: '85vh',
            display: 'flex',
            flexDirection: 'column',
            background: '#0d1322',
            border: '1px solid var(--border-glow)'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <FileText size={20} color="#38bdf8" />
                <h3 style={{ fontSize: '1.15rem', fontWeight: 700 }}>
                  W3C Verifiable Credential Structure & Proof
                </h3>
              </div>
              <button
                onClick={() => setShowJsonModal(false)}
                style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
              >
                <X size={20} />
              </button>
            </div>

            <pre className="font-mono" style={{
              flex: 1,
              overflowY: 'auto',
              background: 'rgba(7, 10, 18, 0.9)',
              padding: '16px',
              borderRadius: 'var(--radius-md)',
              fontSize: '0.8rem',
              color: '#38bdf8',
              border: '1px solid var(--border-subtle)',
              marginBottom: '16px'
            }}>
              {JSON.stringify(selectedVc, null, 2)}
            </pre>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
              <button
                onClick={() => {
                  navigator.clipboard.writeText(JSON.stringify(selectedVc, null, 2));
                  alert('Copied W3C VC JSON to clipboard!');
                }}
                className="btn btn-secondary"
                style={{ fontSize: '0.8rem' }}
              >
                <Copy size={14} />
                <span>Copy JSON</span>
              </button>
              <button
                onClick={() => {
                  if (onSelectCredentialToVerify) {
                    onSelectCredentialToVerify(selectedVc);
                  }
                  setShowJsonModal(false);
                }}
                className="btn btn-primary"
                style={{ fontSize: '0.8rem' }}
              >
                <Shield size={14} />
                <span>Verify in Verifier Station</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal: Key Management & Backup */}
      {showBackupModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(3, 7, 18, 0.85)',
          backdropFilter: 'blur(12px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
          padding: '20px'
        }}>
          <div className="glass-panel animate-fade-in" style={{
            maxWidth: '520px',
            width: '100%',
            padding: '24px',
            background: '#0d1322',
            border: '1px solid var(--border-glow)'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Key size={20} color="#fbbf24" />
                <h3 style={{ fontSize: '1.15rem', fontWeight: 700 }}>
                  Cryptographic Key Management
                </h3>
              </div>
              <button
                onClick={() => setShowBackupModal(false)}
                style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
              >
                <X size={20} />
              </button>
            </div>

            <div style={{
              background: 'rgba(245, 158, 11, 0.1)',
              border: '1px solid rgba(245, 158, 11, 0.25)',
              padding: '12px',
              borderRadius: 'var(--radius-sm)',
              marginBottom: '16px',
              fontSize: '0.8rem',
              color: '#fbbf24'
            }}>
              <AlertCircle size={16} style={{ display: 'inline', marginRight: '6px', verticalAlign: 'text-bottom' }} />
              Keep your private key secure. It provides cryptographic control over your DID and can sign presentations. It is stored encrypted in this browser; backups are encrypted with a passphrase you choose.
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginBottom: '20px' }}>
              <div>
                <label style={{ fontSize: '0.75rem', color: 'var(--text-dim)', display: 'block', marginBottom: '4px' }}>
                  Public Key (Multibase)
                </label>
                <input
                  type="text"
                  readOnly
                  value={identity?.publicKeyMultibase || ''}
                  className="font-mono"
                  style={{
                    width: '100%',
                    padding: '8px',
                    borderRadius: 'var(--radius-sm)',
                    background: 'rgba(0,0,0,0.5)',
                    border: '1px solid var(--border-subtle)',
                    color: '#38bdf8',
                    fontSize: '0.8rem'
                  }}
                />
              </div>

              <div>
                <label style={{ fontSize: '0.75rem', color: 'var(--text-dim)', display: 'block', marginBottom: '4px' }}>
                  Private Key (Multibase)
                </label>
                <input
                  type="password"
                  readOnly
                  value={identity?.privateKeyMultibase || ''}
                  className="font-mono"
                  style={{
                    width: '100%',
                    padding: '8px',
                    borderRadius: 'var(--radius-sm)',
                    background: 'rgba(0,0,0,0.5)',
                    border: '1px solid var(--border-subtle)',
                    color: '#fb7185',
                    fontSize: '0.8rem'
                  }}
                />
              </div>
            </div>

            <div style={{ display: 'flex', gap: '10px' }}>
              <button
                onClick={handleDownloadIdentity}
                className="btn btn-primary"
                style={{ flex: 1, fontSize: '0.8rem' }}
              >
                <Download size={14} />
                <span>Export Encrypted Backup</span>
              </button>
              <button
                onClick={() => {
                  if (confirm('Regenerating your DID creates a new keypair. Your old credentials will no longer belong to the new DID. Proceed?')) {
                    onRegenerateIdentity();
                    setShowBackupModal(false);
                  }
                }}
                className="btn btn-danger"
                style={{ fontSize: '0.8rem' }}
              >
                <RefreshCw size={14} />
                <span>Reset Identity</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal: Import Credential */}
      {showImportModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(3, 7, 18, 0.85)',
          backdropFilter: 'blur(12px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
          padding: '20px'
        }}>
          <div className="glass-panel animate-fade-in" style={{
            maxWidth: '520px',
            width: '100%',
            padding: '24px',
            background: '#0d1322',
            border: '1px solid var(--border-glow)'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Plus size={20} color="#38bdf8" />
                <h3 style={{ fontSize: '1.15rem', fontWeight: 700 }}>Import Verifiable Credential</h3>
              </div>
              <button
                onClick={() => setShowImportModal(false)}
                style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
              >
                <X size={20} />
              </button>
            </div>

            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '12px' }}>
              Paste a signed W3C Verifiable Credential JSON into your local storage vault.
            </p>

            <textarea
              rows={8}
              value={importJson}
              onChange={(e) => setImportJson(e.target.value)}
              placeholder='{"@context": [...], "type": ["VerifiableCredential", ...], "proof": {...}}'
              className="font-mono"
              style={{
                width: '100%',
                padding: '12px',
                borderRadius: 'var(--radius-sm)',
                background: 'rgba(7, 10, 18, 0.8)',
                border: '1px solid var(--border-subtle)',
                color: 'var(--text-main)',
                fontSize: '0.8rem',
                marginBottom: '12px',
                resize: 'vertical'
              }}
            />

            {importError && (
              <p style={{ color: '#fb7185', fontSize: '0.8rem', marginBottom: '12px' }}>
                {importError}
              </p>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
              <button
                onClick={() => setShowImportModal(false)}
                className="btn btn-secondary"
                style={{ fontSize: '0.8rem' }}
              >
                Cancel
              </button>
              <button
                onClick={handleImportCredential}
                className="btn btn-primary"
                style={{ fontSize: '0.8rem' }}
              >
                Save to Vault
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Shared QR Modal */}
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
