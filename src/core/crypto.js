// AES-256-GCM encryption via Web Crypto API.
// Key is derived from the user's login password using PBKDF2. Because the
// derivation is deterministic (password + providerId → key), the same
// credentials reproduce the same key on any device — enabling zero-knowledge
// cross-device restore without ever transmitting the key.

let _encKey = null; // CryptoKey, lives in memory for the session

// ── Key lifecycle ──────────────────────────────────────────────────────────

export async function deriveEncKey(password, providerId) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveBits'],
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      // providerId as salt: deterministic cross-device, unique per account
      salt: new TextEncoder().encode(`tahlk::enc::v1::${providerId}`),
      iterations: 600_000,
      hash: 'SHA-256',
    },
    keyMaterial,
    256,
  );
  _encKey = await crypto.subtle.importKey('raw', bits, 'AES-GCM', true, ['encrypt', 'decrypt']);
  return _encKey;
}

// Export raw key bytes as base64 for KV caching across restarts
export async function exportEncKey(key) {
  const raw = await crypto.subtle.exportKey('raw', key ?? _encKey);
  return btoa(String.fromCharCode(...new Uint8Array(raw)));
}

// Re-import a cached base64 key (no password needed)
export async function importEncKey(b64) {
  const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  _encKey = await crypto.subtle.importKey('raw', bytes, 'AES-GCM', true, ['encrypt', 'decrypt']);
  return _encKey;
}

export function getEncKey() { return _encKey; }
export function setEncKey(k) { _encKey = k; }
export function clearEncKey() { _encKey = null; }

// ── Encrypt / Decrypt ──────────────────────────────────────────────────────

// Returns base64url-encoded: 12-byte IV || ciphertext
export async function encryptText(text, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key ?? _encKey,
    new TextEncoder().encode(text),
  );
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ct), 12);
  return btoa(String.fromCharCode(...out))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export async function decryptText(b64url, key) {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const buf = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: buf.slice(0, 12) },
    key ?? _encKey,
    buf.slice(12),
  );
  return new TextDecoder().decode(plain);
}

export async function encryptJson(obj, key) {
  return encryptText(JSON.stringify(obj), key);
}

export async function decryptJson(b64url, key) {
  return JSON.parse(await decryptText(b64url, key));
}
