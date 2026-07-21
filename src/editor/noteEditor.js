// Note editor use-cases — draft lifecycle and sign-off. Chain assembly lives in
// domain/historyChain; encounter persistence goes through encountersRepo. This
// module orchestrates: write content, append a chain entry, emit, audit.

import { kvGet, kvSetAwait } from '../core/storageBackend.js';
import { logNoteEdited, logNoteSigned, logAudioDeleted } from '../core/auditLog.js';
import { emit } from '../core/eventBus.js';
import { computeNoteHash } from '../utils/contentHash.js';
import { appendHistoryEntry, loadHistory, invalidateHistoryCache } from '../domain/historyChain.js';
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
  await logNoteEdited(encounterId);
  emit('scribe:draft_saved', { encounterId });
}

// Sign the note — flips the encounter to signed via markSigned, which on the
// Tauri path atomically appends the `signed` history row inside the same Rust
// transaction. The JS side never calls appendHistoryEntry for the signed
// action; it invalidates the history cache so the next loadHistory() reads
// the DB-written row.
export async function signNote(encounterId, noteContent, transcript, providerName) {
  const contentHash = await computeNoteHash({ transcript, noteContent, signedBy: providerName, encounterId });

  await encountersRepo.markSigned(encounterId, nowISO(), contentHash);
  invalidateHistoryCache(encounterId);

  await logNoteSigned(encounterId, contentHash);
  emit('scribe:note_signed', { encounterId, hash: contentHash });
  return contentHash;
}

// Best-effort audio purge. Removes the .wav on disk (idempotent), then nulls
// the encounter's audio_path column. Records an `audio_deleted` audit entry
// with the outcome. Never throws: a purge failure must not surface as a
// blocking error to the caller — the signed note is the source of truth.
//
// Returns { removed: boolean, error: string | null }. `removed` is true when a
// .wav actually existed and was deleted; `false` if the file was already gone.
export async function purgeAudio(encounterId, { reason = 'manual' } = {}) {
  let removed = false;
  let error = null;
  try {
    removed = await encountersRepo.deleteAudio(encounterId);
    await encountersRepo.clearAudioPath(encounterId);
  } catch (e) {
    error = e?.message || String(e);
  }
  await logAudioDeleted(encounterId, removed, reason, error);
  emit('scribe:audio_deleted', { encounterId, removed, reason, error });
  return { removed, error };
}
