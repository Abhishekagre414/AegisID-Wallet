import React, { useState } from 'react';
import { Shield, Lock, KeyRound, AlertTriangle } from 'lucide-react';
import { walletStorage, MIN_PASSPHRASE_LENGTH } from '../services/walletStorage';

const inputStyle = {
  width: '100%',
  padding: '12px 14px',
  borderRadius: 'var(--radius-sm)',
  background: 'rgba(7, 10, 18, 0.8)',
  border: '1px solid var(--border-subtle)',
  color: 'var(--text-main)',
  fontSize: '0.95rem'
};

/** Create or unlock the encrypted wallet vault before anything else is shown. */
export default function UnlockScreen({ onUnlocked }) {
  const exists = walletStorage.hasVault();
  const [passphrase, setPassphrase] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const insecureContext = !window.crypto?.subtle;

  const submit = async (e) => {
    e.preventDefault();
    setError('');
    if (insecureContext) {
      setError('This page needs HTTPS (or http://localhost) so the browser allows encryption.');
      return;
    }
    if (!exists) {
      if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
        setError(`Use at least ${MIN_PASSPHRASE_LENGTH} characters (a few random words works well).`);
        return;
      }
      if (passphrase !== confirm) {
        setError('The two passphrases do not match.');
        return;
      }
    }
    setBusy(true);
    try {
      if (exists) await walletStorage.unlock(passphrase);
      else await walletStorage.create(passphrase);
      setPassphrase('');
      setConfirm('');
      onUnlocked();
    } catch (err) {
      setError(err.message || 'Could not open the wallet.');
    } finally {
      setBusy(false);
    }
  };

  const [confirmErase, setConfirmErase] = useState(false);

  const handleReset = () => {
    try {
      walletStorage.reset();
      localStorage.clear();
      sessionStorage.clear();
    } catch (e) {
      console.error('Wallet reset error:', e);
    }
    window.location.reload();
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '24px' }}>
      <form onSubmit={submit} className="glass-panel glow-card" style={{ width: '100%', maxWidth: '440px', padding: '32px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
          <Shield size={26} color="#38bdf8" />
          <h2 style={{ fontSize: '1.5rem', fontWeight: 800, letterSpacing: '-0.02em' }}>AegisID Wallet</h2>
        </div>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.88rem', marginBottom: '22px' }}>
          {exists
            ? 'Enter your passphrase to decrypt your identity and credentials.'
            : 'Choose a passphrase. Your private key and credentials are encrypted with it (AES-256-GCM) and never leave this browser.'}
        </p>

        <label style={{ fontSize: '0.75rem', color: 'var(--text-dim)', display: 'block', marginBottom: '6px' }}>
          PASSPHRASE
        </label>
        <input
          type="password"
          autoFocus
          autoComplete={exists ? 'current-password' : 'new-password'}
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          style={{ ...inputStyle, marginBottom: '14px' }}
        />

        {!exists && (
          <>
            <label style={{ fontSize: '0.75rem', color: 'var(--text-dim)', display: 'block', marginBottom: '6px' }}>
              CONFIRM PASSPHRASE
            </label>
            <input
              type="password"
              autoComplete="new-password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              style={{ ...inputStyle, marginBottom: '14px' }}
            />
            <div style={{
              display: 'flex', gap: '8px', alignItems: 'flex-start', fontSize: '0.78rem', color: '#fbbf24',
              background: 'rgba(245, 158, 11, 0.1)', border: '1px solid rgba(245, 158, 11, 0.25)',
              padding: '10px', borderRadius: 'var(--radius-sm)', marginBottom: '14px'
            }}>
              <AlertTriangle size={14} style={{ flexShrink: 0, marginTop: '2px' }} />
              <span>There is no recovery. If you forget this passphrase, the vault cannot be decrypted.</span>
            </div>
            {walletStorage.hasLegacyData() && (
              <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '14px' }}>
                An older unencrypted wallet was found in this browser. It will be moved into the encrypted vault.
              </p>
            )}
          </>
        )}

        {error && (
          <div role="alert" style={{ color: '#fb7185', fontSize: '0.82rem', marginBottom: '14px' }}>{error}</div>
        )}

        <button type="submit" disabled={busy} className="btn btn-primary" style={{ width: '100%', justifyContent: 'center' }}>
          {exists ? <Lock size={16} /> : <KeyRound size={16} />}
          <span>{busy ? 'Working...' : exists ? 'Unlock Wallet' : 'Create Encrypted Wallet'}</span>
        </button>

        {exists && (
          <div style={{ marginTop: '16px', textAlign: 'center' }}>
            {!confirmErase ? (
              <button
                type="button"
                onClick={() => setConfirmErase(true)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: 'var(--text-dim)',
                  fontSize: '0.8rem',
                  cursor: 'pointer',
                  textDecoration: 'underline'
                }}
              >
                Forgot passphrase? Erase wallet and start over
              </button>
            ) : (
              <div style={{
                background: 'rgba(239, 68, 68, 0.12)',
                border: '1px solid rgba(239, 68, 68, 0.35)',
                borderRadius: 'var(--radius-sm)',
                padding: '12px'
              }}>
                <p style={{ color: '#f87171', fontSize: '0.8rem', marginBottom: '10px', fontWeight: 600 }}>
                  Delete existing encrypted wallet from this browser?
                </p>
                <div style={{ display: 'flex', gap: '8px', justifyContent: 'center' }}>
                  <button
                    type="button"
                    onClick={handleReset}
                    style={{
                      background: '#ef4444',
                      color: '#ffffff',
                      border: 'none',
                      padding: '7px 14px',
                      borderRadius: 'var(--radius-sm)',
                      fontSize: '0.8rem',
                      fontWeight: 700,
                      cursor: 'pointer'
                    }}
                  >
                    Yes, Erase &amp; Start Fresh
                  </button>
                  <button
                    type="button"
                    onClick={() => setConfirmErase(false)}
                    style={{
                      background: 'rgba(255,255,255,0.1)',
                      color: 'var(--text-main)',
                      border: 'none',
                      padding: '7px 14px',
                      borderRadius: 'var(--radius-sm)',
                      fontSize: '0.8rem',
                      cursor: 'pointer'
                    }}
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </form>
    </div>
  );
}
