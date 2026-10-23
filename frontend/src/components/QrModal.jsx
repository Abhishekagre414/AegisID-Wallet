import React, { useEffect, useState } from 'react';
import QRCode from 'qrcode';
import { X, Copy, Check, Download, ShieldCheck } from 'lucide-react';

// A QR code holds at most ~2953 bytes. Signed credentials / presentations are bigger as
// plain JSON, so we try: raw -> deflate-compressed (AEGIS1:<base64url>) -> clear error.
const QR_OPTS = { margin: 2, width: 300, errorCorrectionLevel: 'L', color: { dark: '#000000', light: '#ffffff' } };

function toBase64Url(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function deflate(text) {
  if (typeof CompressionStream === 'undefined') throw new Error('CompressionStream unsupported');
  const stream = new Blob([text]).stream().pipeThrough(new CompressionStream('deflate-raw'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function buildQr(text) {
  try {
    return { url: await QRCode.toDataURL(text, QR_OPTS), compressed: false };
  } catch { /* too big for a QR as plain text; try compressing */ }
  const packed = 'AEGIS1:' + toBase64Url(await deflate(text));
  return { url: await QRCode.toDataURL(packed, QR_OPTS), compressed: true };
}

export default function QrModal({ isOpen, onClose, title, payload, description }) {
  const [qrUrl, setQrUrl] = useState('');
  const [compressed, setCompressed] = useState(false);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!isOpen || !payload) return undefined;
    let cancelled = false;
    setQrUrl('');
    setError('');
    setCompressed(false);
    const text = typeof payload === 'string' ? payload : JSON.stringify(payload);
    buildQr(text)
      .then(r => { if (!cancelled) { setQrUrl(r.url); setCompressed(r.compressed); } })
      .catch(err => {
        console.error('QR Generation failed:', err);
        if (!cancelled) setError('This payload is too large to fit in a single QR code. Use "Copy Payload" instead.');
      });
    return () => { cancelled = true; };
  }, [isOpen, payload]);

  if (!isOpen) return null;

  const handleCopy = () => {
    const text = typeof payload === 'string' ? payload : JSON.stringify(payload, null, 2);
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    if (!qrUrl) return;
    const a = document.createElement('a');
    a.href = qrUrl;
    a.download = `${title.toLowerCase().replace(/\s+/g, '-')}-qr.png`;
    a.click();
  };

  return (
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
        position: 'relative',
        background: '#0d1322',
        border: '1px solid var(--border-glow)'
      }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <ShieldCheck size={20} color="#38bdf8" />
            <h3 style={{ fontSize: '1.15rem', fontWeight: 700 }}>{title}</h3>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--text-muted)',
              cursor: 'pointer',
              padding: '4px'
            }}
          >
            <X size={20} />
          </button>
        </div>

        {description && (
          <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '16px' }}>
            {description}
          </p>
        )}

        {/* QR Code Container */}
        <div style={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          padding: '16px',
          background: '#ffffff',
          borderRadius: 'var(--radius-md)',
          boxShadow: '0 8px 30px rgba(0,0,0,0.5)',
          marginBottom: '20px'
        }}>
          {qrUrl ? (
            <img src={qrUrl} alt="QR Code" style={{ width: '260px', height: '260px', display: 'block', imageRendering: 'pixelated' }} />
          ) : error ? (
            <div style={{ minHeight: '260px', display: 'flex', alignItems: 'center', textAlign: 'center', color: '#b91c1c', fontSize: '0.85rem', padding: '0 12px' }}>
              {error}
            </div>
          ) : (
            <div style={{ height: '260px', display: 'flex', alignItems: 'center', color: '#666' }}>
              Generating QR...
            </div>
          )}
        </div>

        {compressed && (
          <p style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: '14px' }}>
            Payload is compressed (prefix <code>AEGIS1:</code>, deflate-raw + base64url) to fit the QR.
          </p>
        )}

        {/* Actions */}
        <div style={{ display: 'flex', gap: '10px' }}>
          <button
            onClick={handleCopy}
            className="btn btn-secondary"
            style={{ flex: 1, fontSize: '0.8rem' }}
          >
            {copied ? <Check size={16} color="#34d399" /> : <Copy size={16} />}
            <span>{copied ? 'Copied JSON!' : 'Copy Payload'}</span>
          </button>
          <button
            onClick={handleDownload}
            disabled={!qrUrl}
            className="btn btn-primary"
            style={{ flex: 1, fontSize: '0.8rem' }}
          >
            <Download size={16} />
            <span>Download QR</span>
          </button>
        </div>
      </div>
    </div>
  );
}
