// Content hash — SHA-256 attestation for clinical note sign-off.
//
// computeNoteHash binds a physician's signature to the exact transcript
// and note text at the moment of sign-off. Any post-sign edit produces
// a different hash, making silent modifications detectable.
//
// hashHistoryEntry + verifyHistoryChain are carried verbatim from
// Greenbar Clearing — the tamper-evident audit-chain logic is domain-agnostic.

// Compute SHA-256 fingerprint of a signed note.
// Returns a 64-char hex string. Async because SubtleCrypto is async.
export async function computeNoteHash({ transcript, noteContent, signedBy, encounterId }) {
  const payload = JSON.stringify({
    encounterId: encounterId || '',
    signedBy:    signedBy    || '',
    transcript:  transcript  || '',
    noteContent: noteContent || '',
  });
  const enc = new TextEncoder().encode(payload);
  const buf = await crypto.subtle.digest('SHA-256', enc);
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
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
  const json = JSON.stringify(payload, Object.keys(payload).sort());
  const enc = new TextEncoder().encode(json);
  const buf = await crypto.subtle.digest('SHA-256', enc);
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

export async function verifyHistoryChain(history) {
  if (!Array.isArray(history) || !history.length) return { ok: true, legacySkipped: 0 };
  let prevHash = null;
  let chainStarted = false;
  let legacySkipped = 0;
  for (let i = 0; i < history.length; i++) {
    const e = history[i];
    if (!e.entryHash) {
      if (chainStarted) {
        return { ok: false, brokenAt: i, reason: 'missing entryHash after chain start', legacySkipped };
      }
      legacySkipped++;
      continue;
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
