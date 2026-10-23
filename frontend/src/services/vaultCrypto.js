/** Passphrase-based encryption for the wallet vault (PBKDF2-SHA256 -> AES-256-GCM, WebCrypto). */
const enc = new TextEncoder();
const dec = new TextDecoder();
export const KDF_ITERATIONS = 310_000; // OWASP 2023 guidance for PBKDF2-HMAC-SHA256

export const toB64 = (bytes) => {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
};
export const fromB64 = (b64) => Uint8Array.from(atob(b64), c => c.charCodeAt(0));

export const randomBytes = (n) => crypto.getRandomValues(new Uint8Array(n));

export async function deriveKey(passphrase, salt, iterations = KDF_ITERATIONS) {
  const material = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encryptJson(key, value) {
  const iv = randomBytes(12);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(value)));
  return { iv: toB64(iv), ct: toB64(new Uint8Array(ct)) };
}

export async function decryptJson(key, { iv, ct }) {
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(iv) }, key, fromB64(ct));
  return JSON.parse(dec.decode(plain));
}
