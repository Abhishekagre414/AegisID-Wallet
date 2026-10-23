import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import HolderWallet from './components/HolderWallet';
import IssuerPortal from './components/IssuerPortal';
import VerifierInspector from './components/VerifierInspector';
import DidPlayground from './components/DidPlayground';
import UnlockScreen from './components/UnlockScreen';
import { walletStorage } from './services/walletStorage';
import { generateIdentity } from './services/didCrypto';
import { api } from './services/api';
import { Shield, Lock } from 'lucide-react';

const AUTO_LOCK_MS = 10 * 60 * 1000;

export default function App() {
  const [activeTab, setActiveTab] = useState('wallet');
  const [identity, setIdentity] = useState(null);
  const [backendStatus, setBackendStatus] = useState(false);
  const [credentialToVerify, setCredentialToVerify] = useState(null);
  const [toastMessage, setToastMessage] = useState('');
  const [unlocked, setUnlocked] = useState(walletStorage.isUnlocked());

  const lockWallet = () => {
    walletStorage.lock();
    setIdentity(null);
    setCredentialToVerify(null);
    setUnlocked(false);
  };

  useEffect(() => {
    if (unlocked) initApp();
  }, [unlocked]);

  // Auto-lock after 10 minutes without interaction.
  useEffect(() => {
    if (!unlocked) return undefined;
    let timer;
    const reset = () => {
      clearTimeout(timer);
      timer = setTimeout(lockWallet, AUTO_LOCK_MS);
    };
    const events = ['mousemove', 'keydown', 'click', 'touchstart'];
    events.forEach(ev => window.addEventListener(ev, reset));
    reset();
    return () => {
      clearTimeout(timer);
      events.forEach(ev => window.removeEventListener(ev, reset));
    };
  }, [unlocked]);

  const showToast = (msg) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(''), 3000);
  };

  const initApp = async () => {
    // 1. Check backend health
    try {
      const health = await api.checkHealth();
      if (health.status === 'ok') {
        setBackendStatus(true);
      }
    } catch {
      setBackendStatus(false);
    }

    // 2. Load or generate holder identity. Keys are created locally; the server never sees them.
    let currentId = walletStorage.getIdentity();
    if (!currentId) {
      currentId = generateIdentity();
      walletStorage.setIdentity(currentId);
      walletStorage.logActivity('Identity Initialized', `Generated DID ${currentId.did.slice(0, 24)}...`);
    }
    setIdentity(currentId);
  };

  const handleRegenerateIdentity = () => {
    const fresh = generateIdentity();
    walletStorage.setIdentity(fresh);
    setIdentity(fresh);
    walletStorage.logActivity('Identity Regenerated', `New DID ${fresh.did.slice(0, 24)}...`);
    showToast('Generated fresh DID and keypair.');
  };

  const handleSelectCredentialToVerify = (vc) => {
    setCredentialToVerify(vc);
    setActiveTab('verifier');
    showToast('Credential transferred to Verifier Station.');
  };

  if (!unlocked) {
    return <UnlockScreen onUnlocked={() => setUnlocked(true)} />;
  }

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* Toast */}
      {toastMessage && (
        <div style={{
          position: 'fixed',
          top: '20px',
          right: '20px',
          background: 'rgba(56, 189, 248, 0.95)',
          color: '#070a12',
          padding: '10px 18px',
          borderRadius: 'var(--radius-md)',
          fontWeight: 700,
          fontSize: '0.85rem',
          zIndex: 9999,
          boxShadow: '0 8px 24px rgba(0,0,0,0.5)',
          animation: 'fadeIn 0.2s ease'
        }}>
          {toastMessage}
        </div>
      )}

      {/* Navigation */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        backendStatus={backendStatus}
      />

      {/* Main Content Area */}
      <main style={{
        flex: 1,
        maxWidth: '1280px',
        width: '100%',
        margin: '0 auto',
        padding: '32px 24px'
      }}>
        {activeTab === 'wallet' && (
          <HolderWallet
            identity={identity}
            onRegenerateIdentity={handleRegenerateIdentity}
            onSelectCredentialToVerify={handleSelectCredentialToVerify}
          />
        )}

        {activeTab === 'issuer' && (
          <IssuerPortal
            currentHolderDid={identity?.did}
            onCredentialIssued={(newVc) => {
              showToast(`Issued ${newVc.type?.[1] || 'Credential'}!`);
            }}
          />
        )}

        {activeTab === 'verifier' && (
          <VerifierInspector
            initialCredentialToVerify={credentialToVerify}
          />
        )}

        {activeTab === 'playground' && (
          <DidPlayground
            currentHolderDid={identity?.did}
          />
        )}
      </main>

      {/* Footer */}
      <footer style={{
        borderTop: '1px solid var(--border-subtle)',
        background: 'rgba(7, 10, 18, 0.8)',
        backdropFilter: 'blur(10px)',
        padding: '28px 24px',
        marginTop: 'auto'
      }}>
        <div style={{
          maxWidth: '1280px',
          margin: '0 auto',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '16px',
          fontSize: '0.8rem',
          color: 'var(--text-dim)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Shield size={16} color="#38bdf8" />
            <span>AegisID — Decentralized Identity (DID) & Verifiable Credentials</span>
          </div>

          <div style={{ display: 'flex', gap: '20px', flexWrap: 'wrap' }}>
            <span>Standards: W3C DID Core 1.0</span>
            <span>VC Data Model 1.1 / 2.0</span>
            <span>Ed25519 (EdDSA)</span>
            <span>RFC 8785 JCS</span>
            <button
              onClick={lockWallet}
              className="btn btn-secondary"
              style={{ fontSize: '0.75rem', padding: '4px 10px' }}
              title="Encrypt the wallet again and require your passphrase"
            >
              <Lock size={12} />
              <span>Lock wallet</span>
            </button>
          </div>
        </div>
      </footer>
    </div>
  );
}
