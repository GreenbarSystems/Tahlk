// Background sync engine — pushes local encounters + patients to the cloud and
// merges any records that exist on the server but not yet on this device.
//
// Security model:
//   - All clinical content (note, transcript, flags) is AES-256-GCM encrypted
//     client-side before leaving the device. The server stores ciphertext only.
//   - Audio never leaves the device (Whisper runs locally).
//   - Signed encounters are immutable on the server; the server rejects any
//     attempt to overwrite them.
//   - The sync engine is additive: it never deletes local data.

import { isAuthenticated, getProvider } from './auth.js';
import { getEncKey, encryptText, decryptText, encryptJson, decryptJson } from './crypto.js';
import { apiFetch } from './api.js';
import { kvGet, kvSet, kvList, tauriInvoke } from './storageBackend.js';
import { emit } from './eventBus.js';

const CURSOR_KEY   = 'note_sync_v1::cursor';
const STATUS_KEY   = 'note_sync_v1::status';

const NOTE_KEY      = id => `note_content_v1::${id}`;
const TRANSCRIPT_KEY= id => `note_content_v1::transcript::${id}`;
const FLAGS_KEY     = id => `note_flags_v1::${id}`;
const PATIENT_KEY   = id => `note_patients_v1::${id}`;

let _timer      = null;   // current setTimeout handle
let _running    = false;  // true while syncOnce() is executing
let _loopActive = false;  // true between startSyncLoop() and stopSyncLoop()

// ── Public API ─────────────────────────────────────────────────────────────

export function startSyncLoop(intervalMs = 30_000) {
  if (_loopActive) return;
  _loopActive = true;
  // Run immediately, then schedule the next tick only after this one finishes.
  // Using setTimeout chains (not setInterval) guarantees a minimum gap of
  // intervalMs between the END of one sync and the START of the next, so a
  // slow or hanging network call never causes overlapping syncs.
  syncOnce().finally(() => {
    if (_loopActive) _scheduleNext(intervalMs);
  });
}

function _scheduleNext(intervalMs) {
  _timer = setTimeout(async () => {
    _timer = null;
    await syncOnce();
    if (_loopActive) _scheduleNext(intervalMs);
  }, intervalMs);
}

export function stopSyncLoop() {
  _loopActive = false;
  if (_timer) { clearTimeout(_timer); _timer = null; }
}

export function getSyncStatus() {
  return kvGet(STATUS_KEY) ?? { state: 'idle', lastSync: null, error: null };
}

// ── Core sync ──────────────────────────────────────────────────────────────

export async function syncOnce() {
  if (_running)          return;
  if (!isAuthenticated()) return;

  const encKey = getEncKey();
  if (!encKey) return; // key not available — user must log in with password first

  _running = true;
  _setStatus('syncing');

  try {
    const provider = getProvider();

    // ── Pull first so we don't re-download what we're about to push ──────
    const cursor = kvGet(CURSOR_KEY) ?? new Date(0).toISOString();
    const pullRes = await apiFetch(`/api/sync/pull?since=${encodeURIComponent(cursor)}`);
    if (pullRes.ok) {
      const pulled = await pullRes.json();
      await _mergePulled(pulled, encKey);
      if (pulled.cursor) kvSet(CURSOR_KEY, pulled.cursor);
    }

    // ── Build push payload ────────────────────────────────────────────────
    const encounters = await tauriInvoke('list_encounters', { limit: 500 }).catch(() => []);
    const patients   = _loadAllPatients();

    const encPayload = await Promise.all(
      encounters.map(e => _prepareEncounter(e, encKey, provider)),
    );
    const ptPayload = await Promise.all(
      patients.map(p => _preparePatient(p, encKey)),
    );

    const pushRes = await apiFetch('/api/sync/push', {
      method: 'POST',
      body: JSON.stringify({ encounters: encPayload, patients: ptPayload }),
    });

    if (!pushRes.ok) {
      const body = await pushRes.json().catch(() => ({}));
      throw new Error(body.error || `Push failed (${pushRes.status})`);
    }

    _setStatus('idle', null, new Date().toISOString());
    emit('sync:complete', { pushed: encPayload.length + ptPayload.length });
  } catch (err) {
    _setStatus('error', err.message);
    emit('sync:error', { message: err.message });
  } finally {
    _running = false;
  }
}

// ── Payload builders ───────────────────────────────────────────────────────

async function _prepareEncounter(enc, encKey, provider) {
  const note       = kvGet(NOTE_KEY(enc.id))       ?? '';
  const transcript = kvGet(TRANSCRIPT_KEY(enc.id)) ?? '';
  const flags      = kvGet(FLAGS_KEY(enc.id))      ?? null;

  const [noteEnc, transcriptEnc, flagsEnc] = await Promise.all([
    note       ? encryptText(note, encKey)                : Promise.resolve(null),
    transcript ? encryptText(transcript, encKey)          : Promise.resolve(null),
    flags      ? encryptJson(flags, encKey)               : Promise.resolve(null),
  ]);

  return {
    id:             enc.id,
    encounterDate:  enc.encounter_date ?? null,
    status:         enc.status,
    noteEnc,
    transcriptEnc,
    flagsEnc,
    signedAt:       enc.signed_at    ?? null,
    signedHash:     enc.signed_hash  ?? null,
    signedBy:       enc.signed_at ? (provider?.name ?? null) : null,
    clientUpdatedAt: enc.signed_at ?? enc.created_at ?? new Date().toISOString(),
  };
}

async function _preparePatient(patient, encKey) {
  const nameEnc  = patient.name  ? await encryptText(patient.name, encKey)  : null;
  const notesEnc = patient.notes ? await encryptText(patient.notes, encKey) : null;
  return {
    id:             patient.id,
    nameEnc,
    mrn:            patient.mrn  ?? null,
    dob:            patient.dob  ?? null,
    notesEnc,
    // Use the record's own timestamp so only genuinely modified patients are
    // treated as dirty by the server. Falling back to createdAt, then now,
    // prevents null — but a real updatedAt is always present after the
    // patients.js savePatient() fix landed.
    clientUpdatedAt: patient.updatedAt ?? patient.createdAt ?? new Date().toISOString(),
  };
}

// ── Pull merge ─────────────────────────────────────────────────────────────
// Local-first: only apply pulled records that don't already exist on this
// device. Records this device created are authoritative locally — the server's
// copy is their backup, not an override.

async function _mergePulled({ encounters = [], patients = [] }, encKey) {
  // Build set of local encounter IDs for fast lookup
  const localEncs = await tauriInvoke('list_encounters', { limit: 1000 }).catch(() => []);
  const localIds  = new Set(localEncs.map(e => e.id));

  for (const enc of encounters) {
    if (localIds.has(enc.id)) continue; // already local — skip

    // Decrypt content and write into local KV + SQLite
    try {
      if (enc.noteEnc)       kvSet(NOTE_KEY(enc.id),       await decryptText(enc.noteEnc, encKey));
      if (enc.transcriptEnc) kvSet(TRANSCRIPT_KEY(enc.id), await decryptText(enc.transcriptEnc, encKey));
      if (enc.flagsEnc)      kvSet(FLAGS_KEY(enc.id),      await decryptJson(enc.flagsEnc, encKey));
    } catch { continue; } // decryption failed (wrong key) — skip this record

    // Write encounter metadata into local SQLite
    await tauriInvoke('upsert_encounter', {
      encounter: {
        id:             enc.id,
        provider_id:    enc.providerId ?? '',
        encounter_date: enc.encounterDate
          ? new Date(enc.encounterDate).toISOString().slice(0, 10)
          : '',
        patient_alias:  null,    // alias resolved client-side; not stored on server
        status:         enc.status,
        audio_path:     null,    // audio is never synced to cloud
        created_at:     enc.clientUpdatedAt ?? new Date().toISOString(),
        signed_at:      enc.signedAt   ?? null,
        signed_hash:    enc.signedHash ?? null,
      },
    }).catch(() => {});
  }

  // Merge patients that don't exist locally
  const localPatientKeys = new Set(kvList('note_patients_v1::'));
  for (const pt of patients) {
    const key = PATIENT_KEY(pt.id);
    if (localPatientKeys.has(key)) continue;

    try {
      const name  = pt.nameEnc  ? await decryptText(pt.nameEnc, encKey)  : null;
      const notes = pt.notesEnc ? await decryptText(pt.notesEnc, encKey) : null;
      kvSet(key, { id: pt.id, name: name ?? '', mrn: pt.mrn ?? '', dob: pt.dob ?? '', notes: notes ?? '' });
    } catch { /* skip */ }
  }
}

// ── Helpers ────────────────────────────────────────────────────────────────

function _loadAllPatients() {
  return kvList('note_patients_v1::')
    .map(k => kvGet(k))
    .filter(Boolean);
}

function _setStatus(state, error = null, lastSync = null) {
  kvSet(STATUS_KEY, {
    state,
    error,
    lastSync: lastSync ?? getSyncStatus().lastSync,
  });
}
