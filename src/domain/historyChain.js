// Tamper-evident note history chain (domain logic, transport-agnostic).
//
// The assemble → hash → link → durably-persist sequence used to be copy-pasted
// across saveDraftGenerated / saveDraftEdited / signNote. Centralizing it here
// makes the chaining invariant (each entry's prevHash == prior entry's
// entryHash) impossible to get subtly wrong in one call site but not another.

import { kvGet, kvSetAwait } from '../core/storageBackend.js';
import { hashHistoryEntry } from '../utils/contentHash.js';
import { keys } from '../data/keys.js';
import { nowISO } from '../utils/format.js';

export function loadHistory(encounterId) {
  return kvGet(keys.noteHistory(encounterId)) || [];
}

// Append one entry to an encounter's chain and persist the whole chain durably
// (kvSetAwait throws on failure, so callers can fail closed). Returns the entry.
export async function appendHistoryEntry(encounterId, { action, actor, contentHash, notes = '' }) {
  const history = loadHistory(encounterId);
  const prevHash = history.length ? history[history.length - 1].entryHash ?? null : null;

  const entry = { action, actor, timestamp: nowISO(), contentHash, notes, prevHash };
  entry.entryHash = await hashHistoryEntry(entry, prevHash);

  history.push(entry);
  await kvSetAwait(keys.noteHistory(encounterId), history);
  return entry;
}
