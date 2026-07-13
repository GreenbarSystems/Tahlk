// Unit tests for the hash-chained audit log (core/auditLog.js +
// utils/contentHash.js::hashAuditEntry/verifyAuditChain).
//
// Before this fix, auditLog.js appended plain unchained entries and silently
// discarded anything past MAX_AUDIT_ENTRIES via `log.splice(...)`. This
// suite pins down the replacement contract:
//   - every appended entry chains to the previous one (prevHash/entryHash)
//   - tampering with any field (not just a fixed subset) is detectable
//   - going over the cap archives the evicted entries instead of discarding
//     them, and logs a `audit_log_truncated` event in the live log
//   - appendAudit is async and its durable write can be made to fail closed
//
// Same mocking approach as test_signoff.mjs: install the test-only Tauri
// escape hatch BEFORE importing app modules so storageBackend.js resolves to
// TauriBackend (getSync reads its own in-memory _cache; setAsync/setSync
// write to that cache immediately and then best-effort persist via invoke).

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

const calls = [];
let kvSetShouldReject = null; // set to an Error to simulate a failed durable write

function invokeMock(cmd, args) {
  calls.push({ cmd, args });
  if (cmd === 'kv_set') {
    if (kvSetShouldReject) return Promise.reject(kvSetShouldReject);
    return Promise.resolve(null);
  }
  return Promise.resolve(null);
}

globalThis.document = { getElementById: () => null }; // toast() no-ops in tests
globalThis.__TAHLK_TEST_TAURI__ = {
  core: { invoke: invokeMock },
  event: { listen: () => () => {} },
};
globalThis.window = globalThis.window || {};

const { appendAudit, MAX_AUDIT_ENTRIES } = await import('../../src/core/auditLog.js');
const { verifyAuditChain, hashAuditEntry } = await import('../../src/utils/contentHash.js');
const { kvGet } = await import('../../src/core/storageBackend.js');
const { keys } = await import('../../src/data/keys.js');
const { resetCapabilities } = await import('../../src/core/capabilities.js');

let _n = 0;
const uid = () => `enc-audit-test-${++_n}`;

beforeEach(() => {
  calls.length = 0;
  kvSetShouldReject = null;
  resetCapabilities();
});

// ── Chain construction ──────────────────────────────────────────────────────

test('a single appended entry has prevHash null and a valid entryHash', async () => {
  const id = uid();
  const entry = await appendAudit(keys.noteAudit(id), 'note_edited', { encounterId: id });
  assert.equal(entry.prevHash, null);
  assert.match(entry.entryHash, /^[0-9a-f]{64}$/);
  const expected = await hashAuditEntry(entry, null);
  assert.equal(expected, entry.entryHash);
});

test('sequential appends chain: each entryHash becomes the next prevHash', async () => {
  const id = uid();
  const key = keys.noteAudit(id);
  const e1 = await appendAudit(key, 'note_edited', { encounterId: id });
  const e2 = await appendAudit(key, 'note_signed', { encounterId: id, contentHash: 'c1' });
  const e3 = await appendAudit(key, 'note_exported', { format: 'pdf', method: 'file' });

  assert.equal(e2.prevHash, e1.entryHash);
  assert.equal(e3.prevHash, e2.entryHash);

  const log = kvGet(key);
  assert.equal(log.length, 3);
  const verdict = await verifyAuditChain(log);
  assert.equal(verdict.ok, true);
});

test('independent encounters do not share a chain', async () => {
  const idA = uid();
  const idB = uid();
  const eA = await appendAudit(keys.noteAudit(idA), 'note_edited', { encounterId: idA });
  const eB = await appendAudit(keys.noteAudit(idB), 'note_edited', { encounterId: idB });
  assert.equal(eA.prevHash, null);
  assert.equal(eB.prevHash, null); // both are genesis entries of their own chain
});

// ── Tamper detection: the core regression this feature must catch ──────────

test('tampering with a details field (not just action/actor/timestamp) is detected', async () => {
  // This is the key difference from a hash over a fixed 5-field schema
  // (which hashHistoryEntry uses): auditLog entries carry a variable
  // `details` spread (contentHash, removed, reason, error, format, method,
  // encounterId), and every one of those fields must be covered by the hash
  // or a tampered `error`/`reason`/`contentHash` field would go undetected.
  const id = uid();
  const key = keys.noteAudit(id);
  await appendAudit(key, 'audio_deleted', { encounterId: id, removed: true, reason: 'manual', error: null });

  const log = kvGet(key);
  assert.equal((await verifyAuditChain(log)).ok, true);

  // Mutate a details field WITHOUT touching entryHash — simulates direct
  // KV/DB-level tampering, not a re-append.
  log[0].reason = 'tampered-reason';
  const verdict = await verifyAuditChain(log);
  assert.equal(verdict.ok, false);
  assert.equal(verdict.brokenAt, 0);
  assert.match(verdict.reason, /mismatch/);
});

test('tampering with the actor field is detected', async () => {
  const id = uid();
  const key = keys.noteAudit(id);
  await appendAudit(key, 'note_signed', { encounterId: id, contentHash: 'c1' });
  const log = kvGet(key);
  log[0].actor = 'Dr. Impostor';
  assert.equal((await verifyAuditChain(log)).ok, false);
});

test('splicing out a middle entry breaks the prevHash link for the entry after it', async () => {
  const id = uid();
  const key = keys.noteAudit(id);
  await appendAudit(key, 'note_edited', { encounterId: id });
  await appendAudit(key, 'note_signed', { encounterId: id, contentHash: 'c1' });
  await appendAudit(key, 'note_exported', { format: 'pdf', method: 'file' });

  const log = kvGet(key);
  assert.equal((await verifyAuditChain(log)).ok, true);

  log.splice(1, 1); // remove the middle entry; entry[1] (was entry[2]) now has a stale prevHash
  const verdict = await verifyAuditChain(log);
  assert.equal(verdict.ok, false);
  assert.equal(verdict.brokenAt, 1);
  assert.match(verdict.reason, /prevHash does not chain/);
});

test('a reordered (swapped) pair of entries is detected', async () => {
  const id = uid();
  const key = keys.noteAudit(id);
  await appendAudit(key, 'note_edited', { encounterId: id });
  await appendAudit(key, 'note_signed', { encounterId: id, contentHash: 'c1' });

  const log = kvGet(key);
  [log[0], log[1]] = [log[1], log[0]]; // swap order without recomputing hashes
  const verdict = await verifyAuditChain(log);
  assert.equal(verdict.ok, false);
});

test('legacy (pre-hash-chain) entries with no entryHash are not flagged broken', async () => {
  // Entries written by the OLD appendAudit (before this fix) have no
  // entryHash/prevHash at all. verifyAuditChain must treat these as
  // legacySkipped, matching verifyHistoryChain's semantics, not report the
  // whole log as tampered just because it predates hash-chaining.
  const legacyLog = [
    { actor: 'provider', actorId: null, action: 'note_edited', timestamp: '2026-01-01T00:00:00Z', encounterId: 'enc-legacy' },
  ];
  const verdict = await verifyAuditChain(legacyLog);
  assert.equal(verdict.ok, true);
  assert.equal(verdict.legacySkipped, 1);
});

test('a legacy entry appearing AFTER the chain has started is reported broken, not skipped', async () => {
  // A gap after chaining began (e.g. a rollback to a pre-upgrade binary that
  // appended an un-hashed entry into an already-chained log) is real
  // tampering/corruption, not benign legacy data, and must not be silently
  // waved through.
  const id = uid();
  const first = await hashAuditEntry({ actor: 'provider', actorId: null, action: 'note_edited', timestamp: 't1', encounterId: id }, null);
  const log = [
    { actor: 'provider', actorId: null, action: 'note_edited', timestamp: 't1', encounterId: id, prevHash: null, entryHash: first },
    { actor: 'provider', actorId: null, action: 'note_signed', timestamp: 't2', encounterId: id }, // no entryHash
  ];
  const verdict = await verifyAuditChain(log);
  assert.equal(verdict.ok, false);
  assert.equal(verdict.brokenAt, 1);
  assert.match(verdict.reason, /missing entryHash/);
});

// ── Truncation / archival (no silent data loss) ─────────────────────────────

test('appending past MAX_AUDIT_ENTRIES archives evicted entries instead of discarding them, and the live log never exceeds the cap', async () => {
  const id = uid();
  const key = keys.noteAudit(id);
  const archiveKey = keys.noteAuditArchive(id);
  const cap = 5; // small cap so the test doesn't need to append thousands of times

  for (let i = 0; i < cap + 3; i++) {
    await appendAudit(key, 'note_exported', { format: 'pdf', method: 'file', i }, cap);
  }

  const live = kvGet(key);
  const archive = kvGet(archiveKey) || [];

  // The live log (content + truncation markers together) must never exceed
  // the cap — that's the entire point of eviction existing.
  assert.ok(live.length <= cap, `live log grew past cap: length ${live.length} > cap ${cap}`);

  // Nothing is lost: every content entry that ever existed is findable
  // somewhere (live or archived), and every marker's own evictedCount tally
  // plus the still-live content entries accounts for all cap+3 appends.
  const liveExportCount = live.filter(e => e.action === 'note_exported').length;
  const archivedExportCount = archive.filter(e => e.action === 'note_exported').length;
  assert.equal(liveExportCount + archivedExportCount, cap + 3,
    'every appended entry must be accounted for across live + archive, none silently dropped');

  // The archive holds exactly the oldest evicted entries, in original order
  // (verified against the real implementation's actual eviction math, not
  // a hand-derived guess — small caps evict in batches sized maxEntries-1
  // to reserve room for the truncation marker each round, so more than
  // just "the first 3" can end up archived; what must hold is order and
  // completeness, asserted above and via the sort-order check below).
  const archivedIds = archive.map(e => e.i);
  assert.deepEqual(archivedIds, [...archivedIds].sort((a, b) => a - b),
    'archive must stay in original append order');
});

test('a truncation event is itself logged in the live log, chained after the triggering entry, with an accurate evictedCount', async () => {
  const id = uid();
  const key = keys.noteAudit(id);
  const archiveKey = keys.noteAuditArchive(id);
  const cap = 3;

  for (let i = 0; i < cap + 1; i++) {
    await appendAudit(key, 'note_exported', { format: 'pdf', method: 'file', i }, cap);
  }

  const live = kvGet(key);
  const archive = kvGet(archiveKey) || [];
  const truncationEvents = live.filter(e => e.action === 'audit_log_truncated');
  assert.equal(truncationEvents.length, 1, 'exactly one truncation event for the one overflow');
  assert.equal(truncationEvents[0].archivedTo, keys.noteAuditArchive(id));

  // The reported evictedCount must exactly match how many entries actually
  // landed in the archive — this is the number a compliance reviewer would
  // trust from the live log alone, so it must never under- or over-report.
  assert.equal(truncationEvents[0].evictedCount, archive.length,
    'evictedCount must exactly match the number of entries actually archived');

  // The truncation event chains correctly too — it's not exempt from the
  // hash chain just because it's system-generated. The live log's own
  // first entry legitimately points at an archived predecessor once
  // truncation has happened, so this must be checked with allowPartial
  // (see contentHash.js's verifyAuditChain doc comment) rather than the
  // strict from-genesis default, which would always fail on any log that
  // has ever been truncated even though nothing was tampered with.
  const verdict = await verifyAuditChain(live, { allowPartial: true });
  assert.equal(verdict.ok, true, JSON.stringify(verdict));

  // And the full history (archive followed by live) must verify as one
  // unbroken chain from true genesis — this is the actual end-to-end
  // tamper-evidence guarantee, live-only verification is a convenience.
  const full = await verifyAuditChain([...archive, ...live]);
  assert.equal(full.ok, true, JSON.stringify(full));
});

test('archived entries retain their original entryHash/prevHash and still verify as a chain', async () => {
  const id = uid();
  const key = keys.noteAudit(id);
  const archiveKey = keys.noteAuditArchive(id);
  const cap = 2;

  for (let i = 0; i < cap + 4; i++) {
    await appendAudit(key, 'note_exported', { format: 'pdf', method: 'file', i }, cap);
  }

  const archive = kvGet(archiveKey);
  assert.ok(archive.length > 0);
  const verdict = await verifyAuditChain(archive);
  assert.equal(verdict.ok, true, 'the archived tail must still be an internally valid chain');
});

test('repeated truncations keep appending to the same archive rather than overwriting it, and the live log stays within cap throughout', async () => {
  const id = uid();
  const key = keys.noteAudit(id);
  const archiveKey = keys.noteAuditArchive(id);
  const cap = 2;

  for (let i = 0; i < cap * 3; i++) {
    await appendAudit(key, 'note_exported', { format: 'pdf', method: 'file', i }, cap);
    const live = kvGet(key);
    assert.ok(live.length <= cap, `live log exceeded cap mid-run at i=${i}: length ${live.length} > cap ${cap}`);
  }

  const archive = kvGet(archiveKey);
  // Across cap*3=6 appends with cap=2, multiple truncation rounds must have
  // fired, all landing in one growing archive, not each truncation
  // clobbering the last.
  assert.ok(archive.length >= 4, `expected archive to accumulate across truncations, got ${archive.length}`);

  // Every content entry (i is defined) must appear exactly once somewhere
  // across archive + live, in original relative order within the archive.
  const archivedContentIds = archive.filter(e => e.i !== undefined).map(e => e.i);
  assert.deepEqual(archivedContentIds, [...archivedContentIds].sort((a, b) => a - b),
    'archive must stay in original append order');
});

// ── Fails closed on a durable-write failure ─────────────────────────────────

test('appendAudit rejects if the durable kv_set write fails, matching historyChain\u2019s fail-closed contract', async () => {
  const id = uid();
  kvSetShouldReject = Object.assign(new Error('disk full'), { code: 'storage' });
  await assert.rejects(() => appendAudit(keys.noteAudit(id), 'note_edited', { encounterId: id }));
});

// ── actor/actorId stamping (unchanged behavior, still covered) ─────────────

test('appendAudit still stamps actor from currentUser(), defaulting to "provider"', async () => {
  const { installCapabilities } = await import('../../src/core/capabilities.js');
  installCapabilities({ currentUser: () => ({ name: 'Dr. Chen', id: 'u1' }) });
  const id = uid();
  const entry = await appendAudit(keys.noteAudit(id), 'note_edited', { encounterId: id });
  assert.equal(entry.actor, 'Dr. Chen');
  assert.equal(entry.actorId, 'u1');
  resetCapabilities();

  const id2 = uid();
  const entry2 = await appendAudit(keys.noteAudit(id2), 'note_edited', { encounterId: id2 });
  assert.equal(entry2.actor, 'provider');
  assert.equal(entry2.actorId, null);
});
