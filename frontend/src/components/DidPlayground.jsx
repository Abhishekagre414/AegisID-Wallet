import React, { useState } from 'react';
import {
  Globe, Search, Key, RefreshCw, CheckCircle2,
  Code2, Shield, Layers, Lock, FileSignature, Check
} from 'lucide-react';
import { api } from '../services/api';
import { walletStorage } from '../services/walletStorage';
import { generateIdentity, signSandboxMessage, verifySandboxMessage, SANDBOX_PREFIX } from '../services/didCrypto';

export default function DidPlayground({ currentHolderDid }) {
  const [queryDid, setQueryDid] = useState(currentHolderDid || '');
  const [resolving, setResolving] = useState(false);
  const [didDocument, setDidDocument] = useState(null);
  const [resolveError, setResolveError] = useState('');

  // Signature sandbox state
  const [sandboxMessage, setSandboxMessage] = useState('Decentralized Authentication Challenge: Nonce=984372, Domain=auth.web3.network');
  const [signatureOutput, setSignatureOutput] = useState('');
  const [sigVerificationStatus, setSigVerificationStatus] = useState(null);
  const [signing, setSigning] = useState(false);

  const handleResolve = async (didToResolve = null) => {
    const target = didToResolve || queryDid;
    if (!target.trim()) {
      alert('Please enter a DID to resolve.');
      return;
    }

    setResolving(true);
    setResolveError('');
    try {
      const res = await api.resolveDID(target.trim());
      if (res.success) {
        setDidDocument(res.didDocument);
      } else {
        setResolveError(res.error || 'Failed to resolve DID Document.');
        setDidDocument(null);
      }
    } catch (err) {
      setResolveError('Resolution error: ' + err.message);
      setDidDocument(null);
    } finally {
      setResolving(false);
    }
  };

  const handleGenerateFreshDID = () => {
    // Throw-away identity generated locally for the resolver demo; the key is discarded.
    const { did } = generateIdentity();
    setQueryDid(did);
    handleResolve(did);
  };

  const handleSignSandboxMessage = async () => {
    const id = walletStorage.getIdentity();
    if (!id) {
      alert('Holder identity not found in local storage.');
      return;
    }

    setSigning(true);
    setSigVerificationStatus(null);
    try {
      // Signed locally over the actual message text (with a fixed sandbox prefix), then checked.
      const signature = signSandboxMessage(id, sandboxMessage);
      setSignatureOutput(signature);
      setSigVerificationStatus(verifySandboxMessage(id.did, sandboxMessage, signature) ? 'signed' : null);
    } catch (err) {
      alert('Error signing message: ' + err.message);
    } finally {
      setSigning(false);
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
                <Globe size={12} />
                W3C DID Specification
              </span>
              <span className="badge badge-emerald">did:key Method</span>
            </div>
            <h2 style={{ fontSize: '1.6rem', fontWeight: 800, letterSpacing: '-0.02em', marginBottom: '8px' }}>
              W3C DID Resolver & Cryptographic Playground
            </h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', maxWidth: '640px' }}>
              Explore deterministic resolution of <code className="font-mono" style={{ color: '#38bdf8' }}>did:key</code> identifiers into standard W3C DID Documents without relying on centralized DNS or blockchain RPC nodes.
            </p>
          </div>

          <button
            onClick={handleGenerateFreshDID}
            className="btn btn-primary"
            style={{ fontSize: '0.85rem' }}
          >
            <RefreshCw size={16} />
            <span>Generate Random DID</span>
          </button>
        </div>

        {/* Resolution Bar */}
        <div style={{
          marginTop: '24px',
          display: 'flex',
          gap: '10px',
          flexWrap: 'wrap'
        }}>
          <div style={{ flex: 1, minWidth: '280px', position: 'relative' }}>
            <input
              type="text"
              value={queryDid}
              onChange={(e) => setQueryDid(e.target.value)}
              placeholder="did:key:z6M..."
              className="font-mono"
              style={{
                width: '100%',
                padding: '12px 16px',
                borderRadius: 'var(--radius-md)',
                background: 'rgba(7, 10, 18, 0.8)',
                border: '1px solid var(--border-subtle)',
                color: 'var(--text-main)',
                fontSize: '0.85rem'
              }}
            />
          </div>
          <button
            onClick={() => handleResolve()}
            disabled={resolving}
            className="btn btn-primary"
            style={{ padding: '0 24px' }}
          >
            <Search size={16} />
            <span>{resolving ? 'Resolving...' : 'Resolve DID Document'}</span>
          </button>
        </div>

        {currentHolderDid && (
          <div style={{ marginTop: '10px', display: 'flex', gap: '8px', alignItems: 'center' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>Quick samples:</span>
            <button
              onClick={() => {
                setQueryDid(currentHolderDid);
                handleResolve(currentHolderDid);
              }}
              style={{ background: 'none', border: 'none', color: '#38bdf8', fontSize: '0.75rem', cursor: 'pointer', textDecoration: 'underline' }}
            >
              My Wallet DID
            </button>
          </div>
        )}
      </div>

      {/* DID Document Output & Explainer */}
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(320px, 1.2fr) minmax(300px, 1fr)', gap: '24px' }}>
        <div className="glass-panel" style={{ padding: '24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '14px' }}>
            <Code2 size={20} color="#38bdf8" />
            <h3 style={{ fontSize: '1.15rem', fontWeight: 700 }}>
              Resolved W3C DID Document
            </h3>
          </div>

          {resolveError && (
            <div style={{
              background: 'rgba(244, 63, 94, 0.1)',
              border: '1px solid rgba(244, 63, 94, 0.3)',
              padding: '12px',
              borderRadius: 'var(--radius-sm)',
              color: '#fb7185',
              fontSize: '0.8rem',
              marginBottom: '14px'
            }}>
              {resolveError}
            </div>
          )}

          {didDocument ? (
            <pre className="font-mono animate-fade-in" style={{
              background: 'rgba(7, 10, 18, 0.9)',
              padding: '16px',
              borderRadius: 'var(--radius-md)',
              fontSize: '0.8rem',
              color: '#38bdf8',
              border: '1px solid var(--border-subtle)',
              maxHeight: '400px',
              overflowY: 'auto'
            }}>
              {JSON.stringify(didDocument, null, 2)}
            </pre>
          ) : (
            <div style={{ padding: '40px 0', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.85rem' }}>
              Enter a DID and click "Resolve" to inspect the JSON-LD document.
            </div>
          )}
        </div>

        {/* Theoretical Architecture Explainer */}
        <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Layers size={20} color="#818cf8" />
            <h3 style={{ fontSize: '1.15rem', fontWeight: 700 }}>
              How W3C did:key Works
            </h3>
          </div>

          <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', lineHeight: 1.6, display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div>
              <strong style={{ color: 'var(--text-main)', display: 'block', marginBottom: '4px' }}>
                1. Self-Certifying Identifiers
              </strong>
              Unlike traditional federated identities (Google/OAuth) or DNS domains, a <code className="font-mono" style={{ color: '#38bdf8' }}>did:key</code> embeds the raw cryptographic public key directly inside the identifier string itself.
            </div>

            <div>
              <strong style={{ color: 'var(--text-main)', display: 'block', marginBottom: '4px' }}>
                2. Multicodec & Multibase Prefix
              </strong>
              The Ed25519 public key is prefixed with multicodec <code className="font-mono" style={{ color: '#818cf8' }}>0xed01</code>, and encoded in Base58-btc. This standard format guarantees that any verifier worldwide can decode the public key instantly.
            </div>

            <div>
              <strong style={{ color: 'var(--text-main)', display: 'block', marginBottom: '4px' }}>
                3. Zero Network Dependencies
              </strong>
              No RPC calls, no gas fees, and no blockchain lookups are required. Verification runs locally in the browser or on Node.js with no network calls.
            </div>
          </div>
        </div>
      </div>

      {/* Cryptographic Signing Sandbox */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '14px' }}>
          <FileSignature size={20} color="#38bdf8" />
          <h3 style={{ fontSize: '1.15rem', fontWeight: 700 }}>
            Interactive Ed25519 Digital Signing Sandbox
          </h3>
        </div>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '16px' }}>
          Test signing arbitrary application challenges or login nonces with your Holder identity key. Signing happens locally in your browser; the text is prefixed with <code className="font-mono">{SANDBOX_PREFIX}</code> so a sandbox signature can never be replayed as a credential or presentation proof.
        </p>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '16px' }}>
          <div>
            <label style={{ fontSize: '0.75rem', color: 'var(--text-dim)', display: 'block', marginBottom: '6px' }}>
              CHALLENGE / PAYLOAD TO SIGN
            </label>
            <textarea
              rows={4}
              value={sandboxMessage}
              onChange={(e) => setSandboxMessage(e.target.value)}
              className="font-mono"
              style={{
                width: '100%',
                padding: '10px',
                borderRadius: 'var(--radius-sm)',
                background: 'rgba(7, 10, 18, 0.8)',
                border: '1px solid var(--border-subtle)',
                color: 'var(--text-main)',
                fontSize: '0.8rem'
              }}
            />
          </div>

          <div>
            <label style={{ fontSize: '0.75rem', color: 'var(--text-dim)', display: 'block', marginBottom: '6px' }}>
              RESULTING ED25519 MULTIBASE SIGNATURE
            </label>
            <textarea
              rows={4}
              readOnly
              value={signatureOutput || 'Click "Sign Challenge with Ed25519" below to produce digital signature...'}
              className="font-mono"
              style={{
                width: '100%',
                padding: '10px',
                borderRadius: 'var(--radius-sm)',
                background: 'rgba(7, 10, 18, 0.8)',
                border: '1px solid var(--border-subtle)',
                color: signatureOutput ? '#34d399' : 'var(--text-dim)',
                fontSize: '0.8rem'
              }}
            />
          </div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <button
            onClick={handleSignSandboxMessage}
            disabled={signing}
            className="btn btn-primary"
            style={{ fontSize: '0.85rem' }}
          >
            <Lock size={14} />
            <span>{signing ? 'Signing...' : 'Sign Challenge with Ed25519'}</span>
          </button>

          {sigVerificationStatus === 'signed' && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#34d399', fontSize: '0.85rem', fontWeight: 600 }}>
              <CheckCircle2 size={16} />
              <span>Cryptographic Proof Generated & Bound to Your DID!</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
