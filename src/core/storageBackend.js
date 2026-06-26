// Storage backend — Solo tier only uses TauriBackend (SQLite on disk).
// The RemoteHttpBackend and HybridRouter are Group-tier concerns and
// are never imported here, keeping this module group-free.

import { toast } from '../utils/format.js';

const IS_TAURI = typeof window !== 'undefined' && (
  '__TAURI__' in window || '__TAURI_INTERNALS__' in window
);

const _cache = new Map();

// All note_* key prefixes the warmup phase pre-fetches from SQLite.
export const KEY_PREFIXES = [
  'note_encounters_v1',
  'note_content_v1',
  'note_history_v1',
  'note_templates_v1',
  'note_provider_v1',
  'note_settings_v1',
  'note_audit_v1',
];

// ── Tauri invoke helper ────────────────────────────────────────────────────

function _tauriInvoke(cmd, args) {
  const t = window.__TAURI__;
  if (t?.core?.invoke) return t.core.invoke(cmd, args);
  if (t?.tauri?.invoke) return t.tauri.invoke(cmd, args);
  if (typeof t?.invoke === 'function') return t.invoke(cmd, args);
  return Promise.reject(new Error('Tauri invoke unavailable'));
}

// ── TauriBackend ───────────────────────────────────────────────────────────

const TauriBackend = {
  kind: 'tauri',

  async warmup() {
    await Promise.all(KEY_PREFIXES.map(async prefix => {
      try {
        const rows = await _tauriInvoke('kv_list', { prefix });
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

  getSync(key) {
    return _cache.has(key) ? _cache.get(key) : null;
  },

  setSync(key, value) {
    _cache.set(key, value);
    _tauriInvoke('kv_set', { key, value })
      .catch(e => {
        console.error('Tauri kv_set failed for ' + key, e);
        toast(`Disk write failed — change may not be saved`, 4500);
      });
  },

  removeSync(key) {
    _cache.delete(key);
    _tauriInvoke('kv_remove', { key })
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
    KEY_PREFIXES.forEach(prefix => {
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        if (k && (k === prefix || k.startsWith(prefix + '::'))) {
          try { _cache.set(k, JSON.parse(localStorage.getItem(k))); }
          catch { _cache.set(k, null); }
        }
      }
    });
  },

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

const _backend = IS_TAURI ? TauriBackend : LocalStorageBackend;

export function kvGet(key)          { return _backend.getSync(key); }
export function kvSet(key, value)   { return _backend.setSync(key, value); }
export function kvRemove(key)       { return _backend.removeSync(key); }
export function kvList(prefix)      { return _backend.listKeys(prefix); }
export async function kvWarmup()    { await _backend.warmup(); }

export function kvBackendInfo() {
  return { kind: _backend.kind, isTauri: IS_TAURI };
}

// Direct Tauri IPC for commands beyond KV.
export function tauriInvoke(cmd, args) { return _tauriInvoke(cmd, args); }
