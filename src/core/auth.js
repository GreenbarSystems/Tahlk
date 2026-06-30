// Cloud authentication — login, logout, token refresh.
// Access tokens live in memory + KV. The refresh token lives in an httpOnly
// cookie managed by the server. The encryption key is derived at login and
// cached in KV so it survives app restarts without re-asking for a password.

import { kvGet, kvSet, kvRemove } from './storageBackend.js';
import { deriveEncKey, exportEncKey, importEncKey, clearEncKey } from './crypto.js';

const PROVIDER_KEY   = 'note_sync_v1::provider';
const TOKEN_KEY      = 'note_sync_v1::access_token';
const DEVICE_ID_KEY  = 'note_sync_v1::device_id';
const ENC_KEY_KV     = 'note_sync_v1::enc_key_b64';
const SERVER_URL_KEY = 'note_sync_v1::server_url';

const DEFAULT_SERVER = typeof import.meta !== 'undefined' && import.meta.env?.VITE_API_URL
  ? import.meta.env.VITE_API_URL
  : 'https://api.tahlkscribe.com';

let _provider    = null;
let _accessToken = null;

// ── Helpers ────────────────────────────────────────────────────────────────

export function serverUrl() {
  return kvGet(SERVER_URL_KEY) || DEFAULT_SERVER;
}

function deviceId() {
  let id = kvGet(DEVICE_ID_KEY);
  if (!id) {
    id = crypto.randomUUID();
    kvSet(DEVICE_ID_KEY, id);
  }
  return id;
}

// ── Startup ────────────────────────────────────────────────────────────────

// Call once after kvWarmup() on every app launch. Restores auth state and
// re-imports the cached encryption key so sync works without re-login.
export async function initAuth() {
  _provider    = kvGet(PROVIDER_KEY)   ?? null;
  _accessToken = kvGet(TOKEN_KEY)      ?? null;

  if (_provider) {
    const keyB64 = kvGet(ENC_KEY_KV);
    if (keyB64) {
      try { await importEncKey(keyB64); } catch { /* stale key — user needs to re-login */ }
    }
  }
}

// ── Auth state ─────────────────────────────────────────────────────────────

export function getProvider()    { return _provider; }
export function getAccessToken() { return _accessToken; }
export function isAuthenticated() {
  return !!_provider && !!_accessToken;
}

// ── Login ──────────────────────────────────────────────────────────────────

export async function login(email, password) {
  const res = await fetch(`${serverUrl()}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({
      email,
      password,
      deviceId: deviceId(),
      deviceName: navigator.userAgent?.slice(0, 80) ?? 'Desktop',
    }),
  });

  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `Login failed (${res.status})`);
  }

  const { accessToken, provider } = await res.json();

  _accessToken = accessToken;
  _provider    = provider;
  kvSet(TOKEN_KEY,    accessToken);
  kvSet(PROVIDER_KEY, provider);

  // Derive and cache the encryption key while we still have the password
  const encKey = await deriveEncKey(password, provider.id);
  const keyB64 = await exportEncKey(encKey);
  kvSet(ENC_KEY_KV, keyB64);

  return provider;
}

// ── Register ───────────────────────────────────────────────────────────────

export async function register(orgName, email, password, name, betaCode) {
  const res = await fetch(`${serverUrl()}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ orgName, email, password, name, betaCode }),
  });

  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `Registration failed (${res.status})`);
  }

  return res.json(); // { providerId, orgId }
}

// ── Token refresh ──────────────────────────────────────────────────────────

export async function refreshAccessToken() {
  const res = await fetch(`${serverUrl()}/auth/refresh`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ deviceId: deviceId() }),
  });

  if (!res.ok) {
    // Refresh token expired or revoked — clear auth state
    _accessToken = null;
    kvRemove(TOKEN_KEY);
    return null;
  }

  const { accessToken } = await res.json();
  _accessToken = accessToken;
  kvSet(TOKEN_KEY, accessToken);
  return accessToken;
}

// ── Internal authenticated fetch ───────────────────────────────────────────
// Mirrors apiFetch (api.js) but lives here to avoid a circular import:
// api.js already imports from auth.js, so auth.js cannot import from api.js.

async function _authedFetch(path, opts = {}) {
  const hasBody = opts.body !== undefined && opts.body !== null;

  const doFetch = (t) =>
    fetch(`${serverUrl()}${path}`, {
      ...opts,
      credentials: 'include',
      headers: {
        ...(hasBody ? { 'Content-Type': 'application/json' } : {}),
        ...(opts.headers ?? {}),
        ...(t ? { Authorization: `Bearer ${t}` } : {}),
      },
    });

  let res = await doFetch(getAccessToken());
  if (res.status === 401) {
    const newToken = await refreshAccessToken();
    if (!newToken) return res;
    res = await doFetch(newToken);
  }
  return res;
}

// ── BAA ────────────────────────────────────────────────────────────────────

export async function acceptBaa(signedByName) {
  if (!getAccessToken()) throw new Error('Not authenticated');

  const res = await _authedFetch('/api/account/accept-baa', {
    method: 'POST',
    body: JSON.stringify({ version: 'tahlk-baa-v1', signedByName }),
  });

  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `BAA acceptance failed (${res.status})`);
  }

  const data = await res.json();
  // Cache locally so the UI doesn't need to re-fetch immediately
  kvSet('note_sync_v1::baa_accepted_at', data.acceptedAt);
  return data;
}

// ── Password reset ─────────────────────────────────────────────────────────

// Sends a reset email via the server. Always resolves (server returns 200 regardless
// of whether the email exists — prevents user enumeration).
export async function forgotPassword(email) {
  await fetch(`${serverUrl()}/auth/forgot-password`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ email }),
  });
}

// ── Org / provider invite ──────────────────────────────────────────────────

export async function inviteProvider(email, role = 'provider') {
  if (!getAccessToken()) throw new Error('Not authenticated');

  const res = await _authedFetch('/api/org/invite', {
    method: 'POST',
    body:   JSON.stringify({ email, role }),
  });

  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `Invite failed (${res.status})`);
  }
  return res.json();
}

// ── Logout ─────────────────────────────────────────────────────────────────

export async function logout() {
  try {
    await fetch(`${serverUrl()}/auth/logout`, {
      method: 'POST',
      credentials: 'include',
    });
  } catch { /* best-effort */ }

  _accessToken = null;
  _provider    = null;
  kvRemove(TOKEN_KEY);
  kvRemove(PROVIDER_KEY);
  kvRemove(ENC_KEY_KV);
  clearEncKey();
}
