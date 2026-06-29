// Note editor use-cases — draft lifecycle and sign-off. Chain assembly lives in
// domain/historyChain; encounter persistence goes through encountersRepo. This
// module orchestrates: write content, append a chain entry, emit, audit.

import { kvGet, kvSetAwait } from '../core/storageBackend.js';
import { appendAudit } from '../core/auditLog.js';
import { emit } from '../core/eventBus.js';
import { computeNoteHash } from '../utils/contentHash.js';
import { appendHistoryEntry, loadHistory } from '../domain/historyChain.js';
import { encountersRepo } from '../data/encountersRepo.js';
import { keys } from '../data/keys.js';
import { nowISO } from '../utils/format.js';

// loadHistory is re-exported so existing consumers keep their import surface.
export { loadHistory };

export function loadDraft(encounterId) {
  return kvGet(keys.noteContent(encounterId)) || null;
}

// Store AI-generated draft and append a 'generated' history entry.
export async function saveDraftGenerated(encounterId, noteContent, transcript) {
  await kvSetAwait(keys.noteContent(encounterId), noteContent);
  const contentHash = await computeNoteHash({ transcript, noteContent, signedBy: '', encounterId });
  const entry = await appendHistoryEntry(encounterId, { action: 'generated', actor: 'AI (Tahlk)', contentHash });
  emit('scribe:draft_saved', { encounterId });
  return entry;
}

// Save a physician edit and append an 'edited' history entry.
export async function saveDraftEdited(encounterId, noteContent, transcript) {
  await kvSetAwait(keys.noteContent(encounterId), noteContent);
  const contentHash = await computeNoteHash({ transcript, noteContent, signedBy: '', encounterId });
  await appendHistoryEntry(encounterId, { action: 'edited', actor: 'provider', contentHash });
  appendAudit(keys.noteAudit(encounterId), 'note_edited', { encounterId });
  emit('scribe:draft_saved', { encounterId });
}

// Sign the note — chains a durable 'signed' entry, THEN flips the encounter via
// a targeted update (markSigned can't clobber alias/audio the way a full upsert
// would). The chain is persisted first so a failure never marks an unsigned
// encounter as signed.
export async function signNote(encounterId, noteContent, transcript, providerName) {
  const contentHash = await computeNoteHash({ transcript, noteContent, signedBy: providerName, encounterId });

  await appendHistoryEntry(encounterId, {
    action: 'signed',
    actor: providerName || 'provider',
    contentHash,
    notes: `Attested by ${providerName || 'provider'}`,
  });

  await encountersRepo.markSigned(encounterId, nowISO(), contentHash);

  appendAudit(keys.noteAudit(encounterId), 'note_signed', { encounterId, contentHash });
  emit('scribe:note_signed', { encounterId, hash: contentHash });
  return contentHash;
}
