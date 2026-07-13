// Append-only, hash-chained audit-log helper. Stamps actor + timestamp,
// chains each entry to the previous one (tamper-evident, same construction
// as note_history.rs/historyChain.js — see hashAuditEntry/verifyAuditChain
// in utils/contentHash.js), and archives (never silently discards) entries
// evicted once the log exceeds maxEntries.
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

export const MAX_AUDIT_ENTRIES = 5000;

// Derives the archive key for a live audit-log key. Both keys are plain
// strings (see data/keys.js: noteAudit / noteAuditArchive) — this helper
// exists only so a future storage-key-format change has one place to stay
// in sync, mirroring keys.js's own stated purpose.
function archiveKeyFor(key) {
  return key.replace('note_audit_v1::', 'note_audit_archive_v1::');
}

export async function appendAudit(key, action, details = {}, maxEntries = MAX_AUDIT_ENTRIES) {
  const log = kvGet(key) || [];
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
  // maxEntries with no second eviction needed. A second pass would have to
  // report its own count on a truncationEntry object already constructed
  // (and hashed) with the first pass's count baked into evictedCount —
  // silently under-reporting exactly how many entries were evicted, which
  // is the one number this compliance record exists to get right.
  let evicted = [];
  if (log.length > maxEntries) {
    evicted = log.splice(0, log.length - (maxEntries - 1));
  }

  if (evicted.length) {
    // Log the truncation event itself into the now-eviction-triggering
    // entry's own log, chained after the entry that caused the eviction, so
    // the live log carries a permanent, tamper-evident record that a
    // truncation happened (count + where the evicted entries went) even
    // though the evicted entries themselves no longer live there.
    const truncationPrevHash = entry.entryHash;
    const truncationEntry = {
      actor: 'system',
      actorId: null,
      action: 'audit_log_truncated',
      timestamp: nowISO(),
      evictedCount: evicted.length,
      archivedTo: archiveKeyFor(key),
      prevHash: truncationPrevHash,
    };
    truncationEntry.entryHash = await hashAuditEntry(truncationEntry, truncationPrevHash);
    log.push(truncationEntry);

    const archiveKey = archiveKeyFor(key);
    const archive = kvGet(archiveKey) || [];
    const newArchiveTail = archive.concat(evicted);

    // Persist archive before the (now-shorter, plus truncation-marker) live
    // log, so a crash between the two writes leaves the evicted entries
    // durably archived rather than lost — the live log's next append would
    // simply re-derive prevHash from whatever the last successfully-written
    // live entry was.
    await kvSetAwait(archiveKey, newArchiveTail);
  }

  // Durable (fails closed): callers whose correctness depends on the chain
  // being persisted before they proceed must not silently diverge from the
  // on-disk log on a write failure. Mirrors storageBackend.js's setAsync
  // contract, already used by historyChain.js's appendHistoryEntry for the
  // same reason.
  await kvSetAwait(key, log);

  return entry;
}
