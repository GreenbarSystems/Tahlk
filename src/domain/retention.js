// Audio retention policy — single source of truth for what happens to a
// session's .wav file after the note is signed.
//
// Values:
//   'keep'            — leave the audio file in place (default; preserves the
//                       source-of-truth recording for later re-transcription).
//   'delete_on_sign'  — best-effort delete the .wav and null the encounter's
//                       audio_path column immediately after a successful sign.
//                       Intended for providers who want minimal at-rest audio.
//
// The delete is best-effort: a filesystem error must never roll back a
// successful sign. Callers audit-log the outcome so a purge failure is
// visible to the provider without corrupting the signed-note record.

import { kvGet, kvSet } from '../core/storageBackend.js';
import { keys } from '../data/keys.js';

export const AUDIO_RETENTION_POLICIES = ['keep', 'delete_on_sign'];
export const AUDIO_RETENTION_DEFAULT = 'keep';

export function getAudioRetention() {
  const v = kvGet(keys.audioRetention());
  return AUDIO_RETENTION_POLICIES.includes(v) ? v : AUDIO_RETENTION_DEFAULT;
}

export function setAudioRetention(policy) {
  if (!AUDIO_RETENTION_POLICIES.includes(policy)) {
    throw new Error(`Invalid audio retention policy: ${policy}`);
  }
  kvSet(keys.audioRetention(), policy);
}
