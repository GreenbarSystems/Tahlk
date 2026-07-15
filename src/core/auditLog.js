// Append-only, hash-chained audit-log helper. Stamps actor + timestamp,
// chains each entry to the previous one (tamper-evident, same construction
// as note_history.rs/historyChain.js — see hashAuditEntry/verifyAuditChain
// in utils/contentHash.js), and archives (never silently discards) entries
// evicted once the log exceeds maxEntries.
//
// Persisted in a proper SQLite table (`note_audit`) via three Tauri
// commands — `audit_list`, `audit_archive_list`, `audit_append` — see
// src-tauri/src/note_audit.rs. The old `note_audit_v1::<id>` /
// `note_audit_archive_v1::<id>` KV blobs are migrated on first launch (Rust
// side, idempotent) and are no longer read or written by this module once
// Tauri is available. This closes audit finding H1 ("JS-side audit log ...
// fully deletable/overwritable via generic kv_remove/kv_set"): unlike the
// old KV storage, no delete/remove command is exposed for note_audit rows
// — a compromised WebView can append or read, never erase.
//
// Cap/archive policy (which entries get archived, and when) stays here in
// JS — Rust just executes "insert this entry, then archive the oldest N
// still-live rows" as one atomic transaction, mirroring note_history.rs's
// "dumb append-only log" design principle.
//
// Async because the hash chain requires crypto.subtle.digest (SHA-256) and
// the durable write must fail closed: every one of appendAudit's six call
// sites already sits inside an async function (noteEditor.js,
// pdfExport.js, exportFormatter.js), so adding `await` at each site is the
// only caller-side change this required.
//
// Returns the appended entry so callers can mirror it server-side (Group tier).

import { kvGet, kvSetAwait } from './storageBackend.js';
import { currentUser } from './capabilities.js';
import { nowISO } from '../utils/format.js';
import { hashAuditEntry } from '../utils/contentHash.js';
import { invoke, isTauri } from '../platform/tauri.js';

export const MAX_AUDIT_ENTRIES = 5000;

// Derives the archive key for a live audit-log key. Both keys are plain
// strings (see data/keys.js: noteAudit / noteAuditArchive) — used only by
// the non-Tauri (dev/browser-preview) fallback path below; the Tauri path
// has no separate archive key, just an `archived` flag on the same table.
function archiveKeyFor(key) {
  return key.replace('note_audit_v1::', 'note_audit_archive_v1::');
}

function encounterIdFromKey(key) {
  return key.startsWith('note_audit_v1::') ? key.slice('note_audit_v1::'.length) : key;
}

// In-memory mirror of each encounter's live (non-archived) entries, keyed
// by the same `note_audit_v1::<id>` string every call site already passes
// — avoids re-fetching the whole live log on every append within a
// session. Same purpose and lifecycle as domain/historyChain.js's _cache.
const _liveCache = new Map();

async function loadLive(key) {
  if (_liveCache.has(key)) return _liveCache.get(key);
  let entries;
  if (isTauri) {
    entries = await invoke('audit_list', { encounterId: encounterIdFromKey(key) });
  } else {
    entries = kvGet(key) || [];
  }
  const list = Array.isArray(entries) ? entries : [];
  _liveCache.set(key, list);
  return list;
}

export async function appendAudit(key, action, details = {}, maxEntries = MAX_AUDIT_ENTRIES) {
  // Work on a local copy; the cache is only updated after a successful
  // durable write, so a failed append doesn't leave the cache diverged
  // from what's actually persisted.
  const log = (await loadLive(key)).slice();
  const u = currentUser();

  const prevHash = log.length ? (log[log.length - 1].entryHash ?? null) : null;
  const entry = {
    actor: u?.name || 'provider',
    actorId: u?.id || null,
    action,
    timestamp: nowISO(),
    ...details,
    prevHash,
  };
  entry.entryHash = await hashAuditEntry(entry, prevHash);
  log.push(entry);

  // Evict oldest-first once over cap, but archive rather than discard (HIPAA
  // risk assessment §4, remediation item 3: "remove silent truncation; if a
  // cap is retained, archive discarded entries ... and log the truncation
  // event itself"). The evicted slice keeps its original entryHash/prevHash
  // values untouched — the archive is an append-only tail of exactly what
  // was cut, in original chain order, so verifyAuditChain can still walk it
  // (as its own independent chain starting from the first archived entry's
  // prevHash, which was null or a still-live entry's hash at eviction time).
  //
  // The truncation marker (appended below, once, only if eviction actually
  // happens) counts toward the cap like any other entry — it is free to be
  // evicted itself on some future overflow, and the archive is where it
  // ends up, same as any other entry. Deliberately NOT exempting markers
  // from eviction: an earlier version of this function did, and that made
  // every marker permanently inflate the live log by one, so each later
  // append re-triggered eviction even without new content exceeding the
  // cap, degenerating the live log into all-markers after a few cycles.
  // Counting markers normally means eviction math is exactly one pass: as
  // soon as we know a marker will be appended (i.e. log is over cap right
  // now, before the marker exists), reserve its slot up front by evicting
  // down to maxEntries-1, so the marker push lands the log at exactly
  // maxEntries with no second eviction needed.
  let evicted = [];
  if (log.length > maxEntries) {
    evicted = log.splice(0, log.length - (maxEntries - 1));
  }

  let truncationEntry = null;
  if (evicted.length) {
    // Log the truncation event itself into the now-eviction-triggering
    // entry's own log, chained after the entry that caused the eviction, so
    // the live log carries a permanent, tamper-evident record that a
    // truncation happened (count + where the evicted entries went) even
    // though the evicted entries themselves no longer live there.
    const truncationPrevHash = entry.entryHash;
    truncationEntry = {
      actor: 'system',
      actorId: null,
      action: 'audit_log_truncated',
      timestamp: nowISO(),
      evictedCount: evicted.length,
      // archivedTo names a legacy KV key and only means anything on the
      // fallback path — the Tauri path archives in-table via a flag, not a
      // separate key, so it's omitted there rather than left stale.
      ...(isTauri ? {} : { archivedTo: archiveKeyFor(key) }),
      prevHash: truncationPrevHash,
    };
    truncationEntry.entryHash = await hashAuditEntry(truncationEntry, truncationPrevHash);
    log.push(truncationEntry);
  }

  if (isTauri) {
    const encounterId = encounterIdFromKey(key);
    // Rust re-checks prevHash against the current tail inside the INSERT
    // transaction and rejects on mismatch (two panels racing an append),
    // then archives the oldest evicted.length still-live rows in the same
    // call — see note_audit.rs::append_audit_row. No delete/remove path is
    // exposed for this table (audit finding H1).
    await invoke('audit_append', { encounterId, entry, evictedCount: evicted.length });
    if (truncationEntry) {
      await invoke('audit_append', { encounterId, entry: truncationEntry, evictedCount: 0 });
    }
  } else {
    // Non-Tauri fallback (dev/browser-preview): legacy KV-blob semantics,
    // unchanged from before this migration.
    if (evicted.length) {
      const archiveKey = archiveKeyFor(key);
      const archive = kvGet(archiveKey) || [];
      await kvSetAwait(archiveKey, archive.concat(evicted));
    }
    // Durable (fails closed): callers whose correctness depends on the
    // chain being persisted before they proceed must not silently diverge
    // from the on-disk log on a write failure. Mirrors storageBackend.js's
    // setAsync contract, already used by historyChain.js for the same
    // reason.
    await kvSetAwait(key, log);
  }

  _liveCache.set(key, log);
  return entry;
}
