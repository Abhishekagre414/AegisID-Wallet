import React, { useState } from 'react';
import {
  CheckCircle2, XCircle, ShieldAlert, ShieldCheck,
  RefreshCw, AlertTriangle, Bug, Sparkles, FileText,
  Copy, Check, ArrowRight
} from 'lucide-react';
import confetti from 'canvas-confetti';
import { api } from '../services/api';

export default function VerifierInspector({ initialCredentialToVerify }) {
  const [inputJson, setInputJson] = useState(() => {
    return initialCredentialToVerify
      ? JSON.stringify(initialCredentialToVerify, null, 2)
      : '';
  });
  const [verifying, setVerifying] = useState(false);
  const [report, setReport] = useState(null);
  const [isTampered, setIsTampered] = useState(false);
  const [copiedReport, setCopiedReport] = useState(false);

  const handleVerify = async (jsonOverride = null) => {
    const raw = jsonOverride !== null ? jsonOverride : inputJson;
    if (!raw.trim()) {
      alert('Please enter or load a Verifiable Credential or Presentation JSON.');
      return;
    }

    setVerifying(true);
    setReport(null);
    try {
      const parsed = JSON.parse(raw);

      // Determine if VP or VC
      let res;
      if (parsed.type?.includes('VerifiablePresentation')) {
        res = await api.verifyPresentation(parsed);
      } else {
        res = await api.verifyCredential(parsed);
      }

      if (res.success) {
        setReport(res.report);
        if (res.report.valid) {
          confetti({
            particleCount: 80,
            spread: 70,
            origin: { y: 0.6 }
          });
        }
      } else {
        alert('Verification endpoint error: ' + res.error);
      }
    } catch {
      alert('Invalid JSON syntax: Please ensure valid JSON format.');
    } finally {
      setVerifying(false);
    }
  };

  const handleSimulateTamper = () => {
    try {
      const parsed = JSON.parse(inputJson);
      const target = Array.isArray(parsed.verifiableCredential) ? parsed.verifiableCredential[0] : parsed;
      if (target?.disclosures?.length) {
        // Forge a disclosed claim value without the issuer's signature
        const d = target.disclosures[0];
        d[2] = String(d[2]) + ' [TAMPERED_FORGERY]';
      } else if (parsed.credentialSubject) {
        // Tamper with first claim or add a fake claim
        const keys = Object.keys(parsed.credentialSubject).filter(k => k !== 'id');
        if (keys.length > 0) {
          const key = keys[0];
          parsed.credentialSubject[key] = parsed.credentialSubject[key] + ' [TAMPERED_FORGERY]';
        } else {
          parsed.credentialSubject.forgedClaim = "Unauthorized Data";
        }
      } else if (parsed.verifiableCredential?.[0]?.credentialSubject) {
        parsed.verifiableCredential[0].credentialSubject.tampered = true;
      } else {
        parsed.tamperedField = "illegal_modification";
      }

      const tamperedStr = JSON.stringify(parsed, null, 2);
      setInputJson(tamperedStr);
      setIsTampered(true);
      handleVerify(tamperedStr);
    } catch {
      alert('Please paste valid JSON before simulating tampering.');
    }
  };

  const handleLoadDemoVC = async () => {
    try {
      const historyRes = await api.getIssuedHistory();
      if (historyRes.success && historyRes.issued.length > 0) {
        const sample = historyRes.issued[0].credential;
        const str = JSON.stringify(sample, null, 2);
        setInputJson(str);
        setIsTampered(false);
        handleVerify(str);
      } else if (!historyRes.success) {
        alert((historyRes.error || 'Could not load issued credentials.') + ' If the server requires an issuer key, enter it in the Issuer Portal tab first.');
      } else {
        alert('No issued credentials found in backend history yet. Head over to the Issuer Portal to issue one first!');
      }
    } catch (err) {
      alert('Failed to load sample: ' + err.message);
    }
  };

  return (
    <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '28px' }}>
      {/* Top Banner */}
      <div className="glass-panel glow-card" style={{ padding: '28px', border: '1px solid var(--border-glow)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '20px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
              <span className="badge badge-cyan">
                <ShieldCheck size={12} />
                Relying Party Inspector
              </span>
              <span className="badge badge-emerald">Real-time Cryptographic Audit</span>
            </div>
            <h2 style={{ fontSize: '1.6rem', fontWeight: 800, letterSpacing: '-0.02em', marginBottom: '8px' }}>
              Trustless Verification Station
            </h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', maxWidth: '640px' }}>
              Verify W3C Verifiable Credentials and Presentations without centralized databases. Reconstruct the Ed25519 signature from the issuer's self-certifying DID.
            </p>
          </div>

          <div style={{ display: 'flex', gap: '10px' }}>
            <button
              onClick={handleLoadDemoVC}
              className="btn btn-secondary"
              style={{ fontSize: '0.85rem' }}
            >
              <FileText size={16} />
              <span>Load Latest Issued Credential</span>
            </button>
            <button
              onClick={handleSimulateTamper}
              className="btn btn-danger"
              style={{ fontSize: '0.85rem' }}
              title="Demonstrate anti-tampering cryptographic protection"
            >
              <Bug size={16} />
              <span>Simulate Tampering Attack</span>
            </button>
          </div>
        </div>
      </div>

      {/* Verification Workspace */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'minmax(320px, 1.1fr) minmax(320px, 1fr)',
        gap: '24px'
      }}>
        {/* Input Column */}
        <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
            <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-dim)' }}>
              VERIFIABLE CREDENTIAL OR PRESENTATION PAYLOAD (JSON)
            </label>
            {isTampered && (
              <span className="badge badge-rose" style={{ fontSize: '0.7rem' }}>
                <AlertTriangle size={10} />
                Tampered Data Loaded
              </span>
            )}
          </div>

          <textarea
            rows={14}
            value={inputJson}
            onChange={(e) => {
              setInputJson(e.target.value);
              setIsTampered(false);
            }}
            placeholder='Paste W3C Verifiable Credential or Presentation JSON here...'
            className="font-mono"
            style={{
              width: '100%',
              flex: 1,
              padding: '14px',
              borderRadius: 'var(--radius-md)',
              background: 'rgba(7, 10, 18, 0.9)',
              border: isTampered ? '1px solid #fb7185' : '1px solid var(--border-subtle)',
              color: isTampered ? '#fca5a5' : '#38bdf8',
              fontSize: '0.8rem',
              marginBottom: '16px',
              resize: 'vertical'
            }}
          />

          <button
            onClick={() => handleVerify()}
            disabled={verifying}
            className="btn btn-primary"
            style={{ width: '100%', padding: '12px' }}
          >
            {verifying ? <RefreshCw size={16} className="animate-spin" /> : <ShieldCheck size={16} />}
            <span>{verifying ? 'Auditing Cryptographic Signatures...' : 'Run Cryptographic Audit'}</span>
          </button>
        </div>

        {/* Results Column */}
        <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column' }}>
          <h3 style={{ fontSize: '1.2rem', fontWeight: 700, marginBottom: '16px' }}>
            Verification Audit Report
          </h3>

          {!report ? (
            <div style={{
              flex: 1,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              textAlign: 'center',
              padding: '40px 20px',
              color: 'var(--text-dim)'
            }}>
              <ShieldCheck size={48} color="rgba(255, 255, 255, 0.15)" style={{ marginBottom: '12px' }} />
              <h4 style={{ fontSize: '1rem', color: 'var(--text-muted)', marginBottom: '4px' }}>
                Awaiting Credential
              </h4>
              <p style={{ fontSize: '0.8rem', maxWidth: '320px' }}>
                Paste a credential or click "Load Latest Issued Credential" to test real-time verification.
              </p>
            </div>
          ) : (
            <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
              {/* Overall Status Banner */}
              <div style={{
                padding: '16px',
                borderRadius: 'var(--radius-md)',
                display: 'flex',
                alignItems: 'center',
                gap: '14px',
                background: report.valid ? 'rgba(16, 185, 129, 0.15)' : 'rgba(244, 63, 94, 0.15)',
                border: `1px solid ${report.valid ? 'rgba(16, 185, 129, 0.4)' : 'rgba(244, 63, 94, 0.4)'}`
              }}>
                {report.valid ? (
                  <CheckCircle2 size={32} color="#34d399" />
                ) : (
                  <XCircle size={32} color="#fb7185" />
                )}
                <div>
                  <h4 style={{ fontSize: '1.1rem', fontWeight: 800, color: report.valid ? '#34d399' : '#fb7185' }}>
                    {report.valid ? 'VERIFICATION SUCCESSFUL: 100% VALID' : 'VERIFICATION FAILED'}
                  </h4>
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                    {report.valid
                      ? 'The digital signature matches the resolved issuer DID and no tampering was detected.'
                      : (report.errors?.[0] || 'One or more cryptographic security checks failed.')}
                  </p>
                </div>
              </div>

              {/* Step-by-Step Security Pipeline Checklist */}
              <div style={{
                background: 'rgba(7, 10, 18, 0.6)',
                borderRadius: 'var(--radius-md)',
                padding: '14px',
                border: '1px solid var(--border-subtle)',
                display: 'flex',
                flexDirection: 'column',
                gap: '10px'
              }}>
                <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-dim)', textTransform: 'uppercase' }}>
                  Cryptographic Security Checks
                </span>

                {/* Checks */}
                {report.checks && Object.entries(report.checks).map(([checkName, passed]) => (
                  <div key={checkName} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '0.8rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      {passed ? (
                        <CheckCircle2 size={16} color="#34d399" />
                      ) : (
                        <XCircle size={16} color="#fb7185" />
                      )}
                      <span style={{ textTransform: 'capitalize', color: passed ? 'var(--text-main)' : '#fb7185' }}>
                        {checkName.replace(/([A-Z])/g, ' $1')}
                      </span>
                    </div>
                    <span style={{
                      fontSize: '0.75rem',
                      fontWeight: 600,
                      color: passed ? '#34d399' : '#fb7185'
                    }}>
                      {passed ? 'PASS' : 'FAIL'}
                    </span>
                  </div>
                ))}
              </div>

              {/* Identity & Metadata info */}
              <div style={{
                background: 'rgba(7, 10, 18, 0.4)',
                padding: '12px',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.75rem',
                display: 'flex',
                flexDirection: 'column',
                gap: '6px',
                color: 'var(--text-muted)'
              }} className="font-mono">
                {report.issuerDid && (
                  <div>
                    <strong style={{ color: 'var(--text-dim)' }}>Issuer DID:</strong> {report.issuerDid}
                  </div>
                )}
                {report.subjectDid && (
                  <div>
                    <strong style={{ color: 'var(--text-dim)' }}>Subject DID:</strong> {report.subjectDid}
                  </div>
                )}
                {report.holderDid && (
                  <div>
                    <strong style={{ color: 'var(--text-dim)' }}>Holder DID:</strong> {report.holderDid}
                  </div>
                )}
                {(() => {
                  const claimSets = report.credentialsReport
                    ? report.credentialsReport.map(r => r.revealedClaims || {})
                    : [report.revealedClaims || {}];
                  const entries = claimSets.flatMap(c => Object.entries(c));
                  return (
                    <div>
                      <strong style={{ color: 'var(--text-dim)' }}>Claims revealed to verifier:</strong>{' '}
                      {entries.length === 0
                        ? '(none)'
                        : entries.map(([k, v]) => `${k}=${String(v)}`).join(', ')}
                    </div>
                  );
                })()}
              </div>

              {/* Action */}
              <button
                onClick={() => {
                  navigator.clipboard.writeText(JSON.stringify(report, null, 2));
                  setCopiedReport(true);
                  setTimeout(() => setCopiedReport(false), 2000);
                }}
                className="btn btn-secondary"
                style={{ fontSize: '0.75rem', alignSelf: 'flex-end' }}
              >
                {copiedReport ? <Check size={14} color="#34d399" /> : <Copy size={14} />}
                <span>{copiedReport ? 'Report Copied' : 'Copy Audit Report'}</span>
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
