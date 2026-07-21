// KV store + write-through cache (data-access layer).
//
// Talks to SQLite via the platform adapter. The Group-tier RemoteHttpBackend is
// intentionally not imported here, keeping this module group-free. Per-encounter
// key formats live in data/keys.js; warmup eagerly loads only the small,
// app-wide prefixes below.

import { toast } from '../utils/format.js';
import { invoke, isTauri } from '../platform/tauri.js';

const _cache = new Map();

export const EAGER_PREFIXES = [
  'note_provider_v1',
  'note_settings_v1',
  'note_templates_v1',
];

// ── Optimistic-write rollback ──────────────────────────────────────────────
//
// Every write updates the cache BEFORE the backend confirms, so synchronous
// kvGet() stays fast. Without a rollback that optimism is a security hole:
// Rust rejects generic writes to the guarded keys — provider profile, BAA ack,
// retention window, litigation hold — which are precisely the values whose
// integrity matters most. A rejected write used to leave the forged value in
// the cache for the rest of the session while the toast said only "may not be
// saved", and every later kvGet() returned the forgery.
//
// That defeated the C3 provider-profile guard outright: the poisoned name
// flows into computeNoteHash({ signedBy }) — which Rust stores verbatim and
// never recomputes — and into the destruction_log actor. Since the retention
// window and litigation hold became write-protected too, a rejected write
// there would leave the UI believing a legal hold was lifted when Rust had
// refused to lift it.
function _snapshot(key) {
  return { had: _cache.has(key), prior: _cache.get(key) };
}

// Restore `key` to its pre-write state, but ONLY if the cache still holds the
// value we optimistically wrote. A newer legitimate write that landed while
// the failed one was in flight must not be clobbered by a stale snapshot.
function _revert(key, snap, attempted) {
  if (_cache.get(key) !== attempted) return;
  if (snap.had) _cache.set(key, snap.prior);
  else _cache.delete(key);
}

// ── TauriBackend ───────────────────────────────────────────────────────────

const TauriBackend = {
  kind: 'tauri',

  async warmup() {
    await Promise.all(EAGER_PREFIXES.map(async prefix => {
      try {
        const rows = await invoke('kv_list', { prefix });
        if (Array.isArray(rows)) {
          for (const row of rows) {
            if (Array.isArray(row) && row.length === 2) _cache.set(row[0], row[1]);
          }
        }
      } catch (e) {
        console.error('Tauri kv_list failed for ' + prefix, e);
      }
    }));
  },

  // Load specific keys into the cache on demand (lazy per-encounter fetch).
  async ensureKeys(keys) {
    await Promise.all(keys.filter(k => !_cache.has(k)).map(async k => {
      try {
        const v = await invoke('kv_get', { key: k });
        _cache.set(k, v ?? null);
      } catch (e) {
        console.error('Tauri kv_get failed for ' + k, e);
      }
    }));
  },

  getSync(key) {
    return _cache.has(key) ? _cache.get(key) : null;
  },

  setSync(key, value) {
    const snap = _snapshot(key);
    _cache.set(key, value);
    invoke('kv_set', { key, value })
      .catch(e => {
        console.error('Tauri kv_set failed for ' + key, e);
        _revert(key, snap, value);
        toast(`Change was not saved — reverted`, 4500);
      });
  },

  // Durable write: resolves only once the value has reached SQLite.
  // Throws on failure so callers whose correctness depends on persistence
  // (the sign-off hash chain) can fail closed instead of silently diverging.
  async setAsync(key, value) {
    const snap = _snapshot(key);
    _cache.set(key, value);
    try {
      await invoke('kv_set', { key, value });
    } catch (e) {
      console.error('Tauri kv_set failed for ' + key, e);
      // Reverting matters most here: this is the note-content path, and Rust
      // refuses writes to a signed encounter's content. Leaving the rejected
      // text cached would make kvGet() report content the DB never accepted.
      _revert(key, snap, value);
      toast(`Change was not saved — reverted`, 4500);
      throw e;
    }
  },

  removeSync(key) {
    const snap = _snapshot(key);
    _cache.delete(key);
    invoke('kv_remove', { key })
      .catch(e => {
        console.error('Tauri kv_remove failed for ' + key, e);
        // The attempted state is absence, so restore only if nothing has
        // re-populated the key in the meantime.
        if (!_cache.has(key) && snap.had) _cache.set(key, snap.prior);
        toast(`Delete was not saved — reverted`, 4500);
      });
  },

  listKeys(prefix) {
    const out = [];
    _cache.forEach((_, k) => { if (!prefix || k.startsWith(prefix)) out.push(k); });
    return out;
  },
};

// ── LocalStorageBackend (dev / non-Tauri fallback) ─────────────────────────

const LocalStorageBackend = {
  kind: 'local',

  async warmup() {
    EAGER_PREFIXES.forEach(prefix => {
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        if (k && (k === prefix || k.startsWith(prefix + '::'))) {
          try { _cache.set(k, JSON.parse(localStorage.getItem(k))); }
          catch { _cache.set(k, null); }
        }
      }
    });
  },

  // getSync already lazy-reads localStorage on a cache miss, so ensureKeys is
  // a no-op here — kept for backend parity with TauriBackend.
  async ensureKeys() {},

  getSync(key) {
    if (_cache.has(key)) return _cache.get(key);
    try {
      const raw = localStorage.getItem(key);
      const v = raw == null ? null : JSON.parse(raw);
      _cache.set(key, v);
      return v;
    } catch { return null; }
  },

  // Same rollback discipline as TauriBackend. The failure here is a quota or
  // serialization error rather than a Rust guard, but the divergence is
  // identical: a cached value that never reached storage.
  setSync(key, value) {
    const snap = _snapshot(key);
    _cache.set(key, value);
    try { localStorage.setItem(key, JSON.stringify(value)); }
    catch (e) {
      _revert(key, snap, value);
      toast(`Storage error — NOT saved (${e?.name || 'unknown'})`, 4500);
    }
  },

  async setAsync(key, value) {
    const snap = _snapshot(key);
    _cache.set(key, value);
    try {
      localStorage.setItem(key, JSON.stringify(value));
    } catch (e) {
      _revert(key, snap, value);
      toast(`Storage error — NOT saved (${e?.name || 'unknown'})`, 4500);
      throw e;
    }
  },

  removeSync(key) {
    _cache.delete(key);
    try { localStorage.removeItem(key); } catch {}
  },

  listKeys(prefix) {
    const out = new Set();
    _cache.forEach((_, k) => { if (!prefix || k.startsWith(prefix)) out.add(k); });
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && (!prefix || k.startsWith(prefix))) out.add(k);
    }
    return [...out];
  },
};

// ── Active backend + public surface ───────────────────────────────────────

const _backend = isTauri ? TauriBackend : LocalStorageBackend;

export function kvGet(key)          { return _backend.getSync(key); }
export function kvSet(key, value)   { return _backend.setSync(key, value); }
export function kvSetAwait(key, value) { return _backend.setAsync(key, value); }
export function kvRemove(key)       { return _backend.removeSync(key); }
export function kvList(prefix)      { return _backend.listKeys(prefix); }
export async function kvWarmup()    { await _backend.warmup(); }
export async function kvEnsure(keys) { await _backend.ensureKeys(keys); }
// Update the in-memory cache only, without triggering a Tauri kv_set call.
// Used after writes that go through a dedicated command (e.g. set_provider_profile)
// so synchronous kvGet() reads reflect the new value without a full warmup.
export function kvSetCacheOnly(key, value) { _cache.set(key, value); }

export function kvBackendInfo() {
  return { kind: _backend.kind, isTauri };
}
