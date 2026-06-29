// Note editor — manages draft lifecycle, edit history chain, and sign-off.
// All state lives in SQLite via kvGet/kvSet. The audit chain uses SHA-256
// linking so post-sign edits are detectable.

import { kvGet, kvSetAwait, tauriInvoke } from '../core/storageBackend.js';
import { appendAudit } from '../core/auditLog.js';
import { emit } from '../core/eventBus.js';
import { computeNoteHash, hashHistoryEntry } from '../utils/contentHash.js';
import { nowISO, genId } from '../utils/format.js';

const CONTENT_KEY = id => `note_content_v1::${id}`;
const HISTORY_KEY = id => `note_history_v1::${id}`;

export function loadDraft(encounterId) {
  return kvGet(CONTENT_KEY(encounterId)) || null;
}

export function loadHistory(encounterId) {
  return kvGet(HISTORY_KEY(encounterId)) || [];
}

// Store AI-generated draft and append a 'generated' history entry.
export async function saveDraftGenerated(encounterId, noteContent, transcript) {
  await kvSetAwait(CONTENT_KEY(encounterId), noteContent);

  const history = loadHistory(encounterId);
  const prevHash = history.length ? history[history.length - 1].entryHash ?? null : null;
  const contentHash = await computeNoteHash({ transcript, noteContent, signedBy: '', encounterId });

  const entry = {
    action: 'generated',
    actor: 'AI (Tahlk)',
    timestamp: nowISO(),
    contentHash,
    notes: '',
  };
  entry.prevHash = prevHash;
  entry.entryHash = await hashHistoryEntry(entry, prevHash);

  history.push(entry);
  await kvSetAwait(HISTORY_KEY(encounterId), history);

  emit('scribe:draft_saved', { encounterId });
  return entry;
}

// Save a physician edit and append an 'edited' history entry.
export async function saveDraftEdited(encounterId, noteContent, transcript) {
  await kvSetAwait(CONTENT_KEY(encounterId), noteContent);

  const history = loadHistory(encounterId);
  const prevHash = history.length ? history[history.length - 1].entryHash ?? null : null;
  const contentHash = await computeNoteHash({ transcript, noteContent, signedBy: '', encounterId });

  const entry = {
    action: 'edited',
    actor: 'provider',
    timestamp: nowISO(),
    contentHash,
    notes: '',
  };
  entry.prevHash = prevHash;
  entry.entryHash = await hashHistoryEntry(entry, prevHash);

  history.push(entry);
  await kvSetAwait(HISTORY_KEY(encounterId), history);

  appendAudit(`note_audit_v1::${encounterId}`, 'note_edited', { encounterId });
  emit('scribe:draft_saved', { encounterId });
}

// Sign the note — computes final hash, chains a 'signed' entry, marks encounter.
export async function signNote(encounterId, noteContent, transcript, providerName) {
  const contentHash = await computeNoteHash({ transcript, noteContent, signedBy: providerName, encounterId });

  const history = loadHistory(encounterId);
  const prevHash = history.length ? history[history.length - 1].entryHash ?? null : null;

  const entry = {
    action: 'signed',
    actor: providerName || 'provider',
    timestamp: nowISO(),
    contentHash,
    notes: `Attested by ${providerName || 'provider'}`,
  };
  entry.prevHash = prevHash;
  entry.entryHash = await hashHistoryEntry(entry, prevHash);

  // Persist the signed chain entry durably BEFORE flipping the encounter
  // status. If the disk write fails this throws and the encounter is never
  // marked signed — the tamper-evidence and the status stay consistent.
  history.push(entry);
  await kvSetAwait(HISTORY_KEY(encounterId), history);

  // Update encounter in DB.
  await tauriInvoke('upsert_encounter', {
    encounter: {
      id: encounterId,
      provider_id: 'solo',
      encounter_date: new Date().toISOString().slice(0, 10),
      status: 'signed',
      created_at: nowISO(),
      signed_at: nowISO(),
      signed_hash: contentHash,
    },
  });

  appendAudit(`note_audit_v1::${encounterId}`, 'note_signed', { encounterId, contentHash });
  emit('scribe:note_signed', { encounterId, hash: contentHash });
  return contentHash;
}
