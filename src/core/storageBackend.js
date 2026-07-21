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
    _cache.set(key, value);
    invoke('kv_set', { key, value })
      .catch(e => {
        console.error('Tauri kv_set failed for ' + key, e);
        toast(`Disk write failed — change may not be saved`, 4500);
      });
  },

  // Durable write: resolves only once the value has reached SQLite.
  // Throws on failure so callers whose correctness depends on persistence
  // (the sign-off hash chain) can fail closed instead of silently diverging.
  async setAsync(key, value) {
    _cache.set(key, value);
    try {
      await invoke('kv_set', { key, value });
    } catch (e) {
      console.error('Tauri kv_set failed for ' + key, e);
      toast(`Disk write failed — change may not be saved`, 4500);
      throw e;
    }
  },

  removeSync(key) {
    _cache.delete(key);
    invoke('kv_remove', { key })
      .catch(e => console.error('Tauri kv_remove failed for ' + key, e));
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

  setSync(key, value) {
    _cache.set(key, value);
    try { localStorage.setItem(key, JSON.stringify(value)); }
    catch (e) { toast(`Storage error — NOT saved (${e?.name || 'unknown'})`, 4500); }
  },

  async setAsync(key, value) {
    _cache.set(key, value);
    try {
      localStorage.setItem(key, JSON.stringify(value));
    } catch (e) {
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
