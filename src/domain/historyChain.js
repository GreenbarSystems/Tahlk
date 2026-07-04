// Tamper-evident note history chain (domain logic, transport-agnostic).
//
// The chain is persisted in a proper SQLite table (`note_history`) via two
// Tauri commands: `note_history_list` and `note_history_append`. The old
// `note_history_v1::<id>` KV blob is migrated on first launch (Rust side,
// idempotent) and no longer used.
//
// This module owns three responsibilities that must stay collocated:
//   1. Chain math — deriving prevHash and computing entryHash from the
//      current tail. Doing this per-call site would let one caller subtly
//      diverge from another.
//   2. Cache coherence — the sign-off path reads history synchronously from
//      a Map<encounterId, entries[]> that mirrors the DB. `loadHistory` is
//      the only path that populates that Map from the DB; `appendHistoryEntry`
//      keeps it in sync after each successful insert.
//   3. Non-Tauri (localStorage) fallback — dev builds still go through the
//      KV backend so tests and web preview keep working.

import { kvGet, kvSetAwait } from '../core/storageBackend.js';
import { hashHistoryEntry } from '../utils/contentHash.js';
import { keys } from '../data/keys.js';
import { nowISO } from '../utils/format.js';
import { invoke, isTauri } from '../platform/tauri.js';

// In-memory mirror of note_history rows keyed by encounterId. Populated by
// loadHistory(); mutated on successful appendHistoryEntry(). Without this,
// every appendHistoryEntry would need a round-trip to derive prev_hash.
const _cache = new Map();

// Fetch this encounter's history. Returns [] for a fresh encounter.
// Async: on Tauri this reads from the note_history table; the legacy sync
// signature is gone and callers already sit inside async contexts.
export async function loadHistory(encounterId) {
  if (_cache.has(encounterId)) return _cache.get(encounterId).slice();

  let entries;
  if (isTauri) {
    entries = await invoke('note_history_list', { encounterId });
  } else {
    // Dev / test fallback: read the legacy blob format from the KV backend.
    entries = kvGet(keys.noteHistory(encounterId)) || [];
  }
  _cache.set(encounterId, Array.isArray(entries) ? entries : []);
  return _cache.get(encounterId).slice();
}

// Append one entry to an encounter's chain. The prevHash + entryHash are
// derived here and passed to Rust as opaque data; Rust re-checks that our
// prevHash matches the current tail inside its INSERT transaction, so two
// panels racing an append can't produce a diverged chain.
//
// Fails closed: if the durable insert throws, the cache is NOT updated, so a
// retry sees the true tail and derives the correct prevHash on the next try.
export async function appendHistoryEntry(encounterId, { action, actor, contentHash, notes = '' }) {
  // Prime the cache so we can derive prevHash without a round-trip when we
  // already have it locally.
  if (!_cache.has(encounterId)) await loadHistory(encounterId);

  const tail = _cache.get(encounterId);
  const prevHash = tail.length ? (tail[tail.length - 1].entryHash ?? null) : null;

  const entry = { action, actor, timestamp: nowISO(), contentHash, notes, prevHash };
  entry.entryHash = await hashHistoryEntry(entry, prevHash);

  if (isTauri) {
    // Rust command re-verifies prevHash == current tail's entry_hash inside a
    // transaction and rejects on mismatch, so the chain stays consistent even
    // if two windows race.
    await invoke('note_history_append', { encounterId, entry });
  } else {
    // Non-Tauri fallback: rewrite the whole KV blob (legacy semantics).
    const persisted = tail.concat(entry);
    await kvSetAwait(keys.noteHistory(encounterId), persisted);
  }

  // Only mutate the cache after a successful durable write.
  tail.push(entry);
  return entry;
}
