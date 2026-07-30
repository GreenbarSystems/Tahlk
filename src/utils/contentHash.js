// Content hash — SHA-256 attestation for clinical note sign-off.
//
// computeNoteHash binds a physician's signature to the exact transcript
// and note text at the moment of sign-off. Any post-sign edit produces
// a different hash, making silent modifications detectable.
//
// hashHistoryEntry + verifyHistoryChain implement a tamper-evident audit chain.

// SHA-256 of a UTF-8 string, returned as a 64-char hex digest.
// Async because SubtleCrypto is async.
async function sha256Hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// Compute SHA-256 fingerprint of a signed note.
export async function computeNoteHash({ transcript, noteContent, signedBy, encounterId }) {
  return sha256Hex(JSON.stringify({
    encounterId: encounterId || '',
    signedBy:    signedBy    || '',
    transcript:  transcript  || '',
    noteContent: noteContent || '',
  }));
}

// ── History chain ─────────────────────────────────────────────────────────
// Each note_history entry carries:
//   prevHash  — SHA-256 of the previous entry (null for genesis)
//   entryHash — SHA-256 of this entry's fields + prevHash
//
// Actions recorded: 'generated' | 'edited' | 'signed' | 'exported'

export async function hashHistoryEntry(entry, prevHash) {
  const payload = {
    prevHash:    prevHash              || null,
    action:      entry.action          || '',
    actor:       entry.actor           || '',
    timestamp:   entry.timestamp       || '',
    contentHash: entry.contentHash     || '',
    notes:       entry.notes           || '',
  };
  return sha256Hex(JSON.stringify(payload, Object.keys(payload).sort()));
}

export async function verifyHistoryChain(history) {
  if (!Array.isArray(history) || !history.length) return { ok: true, legacySkipped: 0 };
  let prevHash = null;
  let chainStarted = false;
  let legacySkipped = 0;
  for (let i = 0; i < history.length; i++) {
    const e = history[i];
    // Same removal as verifyAuditChain's, for the same reason and with the
    // same evidence. This verifier carried an identical "legacy" hatch, so
    // stripping entryHash from every history row also downgraded the whole
    // chain to a clean pass. Hardening one verifier and leaving its twin open
    // would have been worse than fixing neither, because it would look done.
    if (!e.entryHash) {
      return { ok: false, brokenAt: i, reason: 'missing entryHash', legacySkipped };
    }
    const expected = await hashHistoryEntry(e, e.prevHash ?? null);
    if (expected !== e.entryHash) {
      return { ok: false, brokenAt: i, reason: 'entryHash mismatch', legacySkipped };
    }
    if (chainStarted) {
      if ((e.prevHash ?? null) !== prevHash) {
        return { ok: false, brokenAt: i, reason: 'prevHash does not chain to prior entry', legacySkipped };
      }
    } else if ((e.prevHash ?? null) !== null) {
      return { ok: false, brokenAt: i, reason: 'first chained entry has non-null prevHash', legacySkipped };
    }
    chainStarted = true;
    prevHash = e.entryHash;
  }
  return { ok: true, legacySkipped };
}

// ── Audit-log chain (generic, arbitrary-shape entries) ────────────────────────────
// auditLog.js entries don't have note_history's fixed 5-field shape — they
// carry a variable `details` spread (encounterId, contentHash, removed,
// reason, error, format, method, ...) that differs per action type. Hashing
// only a fixed subset (like hashHistoryEntry does) would let those detail
// fields be tampered with invisibly, so hashAuditEntry instead hashes the
// entry's OWN keys (sorted, whatever they are) plus prevHash — every field
// the entry actually carries is covered, with no fixed schema to drift out
// of sync with appendAudit's callers.
//
// entryHash/prevHash themselves are excluded from the hashed payload (an
// entry can't hash over its own output field), matching hashHistoryEntry's
// convention of computing the hash before entryHash is attached.
// Canonical JSON: object keys sorted at EVERY level, matching how Rust's
// serde_json serializes a BTreeMap so the two sides agree byte for byte.
//
// Replaces `JSON.stringify(payload, Object.keys(payload).sort())`. That
// array-replacer form applies its key list recursively to every nested object,
// not just the top level — so any `details` value that was itself an object
// had ITS keys stripped from the hashed payload, and two entries differing
// only in a nested field hashed identically. Latent rather than live today,
// since every call site passes scalars, but Rust's `extra_fields` is
// `Vec<(String, Value)>` and accepts `Value::Object`, so the first structured
// detail field would silently open the hole on both sides.
function canonicalJson(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v) ?? 'null';
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(v).sort();
  return `{${keys.map(k => `${JSON.stringify(k)}:${canonicalJson(v[k])}`).join(',')}}`;
}

export async function hashAuditEntry(entry, prevHash) {
  const { entryHash, prevHash: _ignoredPrevHash, ...rest } = entry || {};
  const payload = { ...rest, prevHash: prevHash || null };
  return sha256Hex(canonicalJson(payload));
}

// Same legacy-skip semantics as verifyHistoryChain: pre-hash-chaining
// auditLog.js entries (written before this fix shipped) have no entryHash
// at all. Those are counted as legacySkipped, not failures, as long as they
// appear only as an unbroken prefix before the chain starts — an entryHash
// gap AFTER the chain has started is real tampering (or a rollback to a
// pre-upgrade binary that wrote un-hashed entries into an already-chained
// log), so that case is still reported as broken.
//
// options.allowPartial (default false): unlike note_history.rs's history,
// which is never trimmed, auditLog.js's live log CAN be truncated (oldest
// entries evicted into note_audit_archive_v1::<id>, see core/auditLog.js).
// After a truncation, the live log's own first entry legitimately carries
// a non-null prevHash that points at an entry now living only in the
// archive — verifying the live log in isolation can't resolve that link,
// so by default this would be reported as broken even though nothing was
// tampered with. Callers who know they're checking a possibly-truncated
// live tail (rather than a from-genesis full chain) should pass
// { allowPartial: true } to trust the first entry's stated prevHash as an
// external anchor instead of requiring it to be null. Full end-to-end
// verification (detecting whether that external anchor is itself correct)
// requires walking archive+live together, e.g. verifyAuditChain([...archive, ...live]).
// options.expectedCount / options.expectedHead: the anchor. A hash chain
// cannot detect its own truncation — a valid prefix of a valid chain is itself
// a valid chain, so dropping the newest entries leaves something that verifies
// clean, and an emptied log verifies cleanest of all. Detecting removal needs
// a value recorded OUTSIDE the log: how many entries there should be, and what
// the head should hash to. Callers holding those (persisted on the encounter
// row) should pass them; the check degrades to linkage-only without them,
// which is what every pre-anchor caller already got.
//
// This matters for accidental loss as much as for tampering — a partial write,
// a failed restore, a truncated backup. Without the anchor a short history is
// indistinguishable from a complete one, and nothing surfaces the discrepancy.
export async function verifyAuditChain(log, options = {}) {
  const allowPartial = options.allowPartial ?? false;
  const expectedCount = options.expectedCount ?? null;
  const expectedHead = options.expectedHead ?? null;

  if (!Array.isArray(log)) {
    return { ok: false, brokenAt: 0, reason: 'audit log is not an array', legacySkipped: 0, scrubbedSkipped: 0 };
  }
  // Anchor check first: an emptied or shortened log must fail before the loop
  // gets a chance to find nothing wrong with it.
  if (expectedCount !== null && log.length !== expectedCount) {
    return {
      ok: false,
      brokenAt: Math.min(log.length, expectedCount),
      reason: `entry count ${log.length} does not match the recorded ${expectedCount}`,
      legacySkipped: 0,
      scrubbedSkipped: 0,
    };
  }
  if (!log.length) return { ok: true, legacySkipped: 0, scrubbedSkipped: 0 };
  let prevHash = null;
  let chainStarted = false;
  let legacySkipped = 0;
  // Rows whose content was lawfully destroyed and so cannot be content-
  // verified. Reported so a caller can distinguish "fully verified" from
  // "linkage verified, some content unverifiable by design".
  let scrubbedSkipped = 0;
  for (let i = 0; i < log.length; i++) {
    const e = log[i];
    // A missing entryHash is a broken chain, wherever it appears.
    //
    // This used to be a "legacy" escape hatch: an unhashed entry before the
    // chain started was skipped, on the theory that pre-upgrade rows predate
    // hashing. That made removing integrity metadata a way to SATISFY the
    // integrity check — strip entryHash from every entry and the loop never
    // starts, so every row is skipped and the whole log verifies clean. An
    // attacker did not have to forge the chain or hold any key; they deleted
    // it and the hatch waved the remains through. The same trick prepended
    // fabricated rows in front of a genuine chain.
    //
    // The hatch is gone. Legacy rows, if any are ever found, must be migrated
    // explicitly with a recorded migration event rather than silently excused
    // at verification time — an exemption that cannot be distinguished from an
    // attack is not an exemption worth having.
    if (!e.entryHash) {
      return { ok: false, brokenAt: i, reason: 'missing entryHash', legacySkipped, scrubbedSkipped };
    }
    // A scrubbed row's entry_json is the destruction tombstone: the content
    // the hash covers was lawfully wiped, so it CANNOT be recomputed and a
    // mismatch here carries no information. Its chain fields survive in the
    // DB columns and are re-attached on read, so linkage is still checked
    // below — the row is an explicit, expected content discontinuity rather
    // than a verification failure.
    //
    // Note the honest limit: an attacker with direct database access could
    // set this flag to exempt a rewritten row from content verification. That
    // is not a new weakness — the same access already permits recomputing the
    // whole chain, since entryHash is a plain SHA-256 over public fields with
    // no signing key. This chain detects accidental corruption and casual
    // tampering, not a deliberate rewrite by someone holding the DEK.
    // The exemption is limited to rows that actually look like destruction
    // tombstones. `scrubbed` alone was a blanket waiver: setting it on a
    // REWRITTEN row exempted that rewrite from content verification while its
    // linkage still checked out, so the result read as a clean pass. Requiring
    // the destruction marker means the flag can only excuse a row that claims
    // to be what the exemption exists for. A row wearing `scrubbed` without it
    // is content-verified like any other, and fails if it was altered.
    if (e.scrubbed && e.destroyed === true) {
      scrubbedSkipped++;
    } else {
      const expected = await hashAuditEntry(e, e.prevHash ?? null);
      if (expected !== e.entryHash) {
        return { ok: false, brokenAt: i, reason: 'entryHash mismatch', legacySkipped, scrubbedSkipped };
      }
    }
    if (chainStarted) {
      if ((e.prevHash ?? null) !== prevHash) {
        return { ok: false, brokenAt: i, reason: 'prevHash does not chain to prior entry', legacySkipped, scrubbedSkipped };
      }
    } else if ((e.prevHash ?? null) !== null && !allowPartial) {
      return { ok: false, brokenAt: i, reason: 'first chained entry has non-null prevHash', legacySkipped, scrubbedSkipped };
    }
    chainStarted = true;
    prevHash = e.entryHash;
  }
  // The head must match the recorded anchor. Count alone is not sufficient:
  // removing one entry and appending a fabricated one preserves the count.
  if (expectedHead !== null && prevHash !== expectedHead) {
    return {
      ok: false,
      brokenAt: log.length - 1,
      reason: 'chain head does not match the recorded head',
      legacySkipped,
      scrubbedSkipped,
    };
  }
  return { ok: true, legacySkipped, scrubbedSkipped };
}
