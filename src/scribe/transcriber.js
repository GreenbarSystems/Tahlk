// Transcription pipeline.
// Calls the Tauri transcribe_audio command which shells to the whisper.cpp
// sidecar binary. Audio stays on-device; no network call is made.
//
// Error surface contract: on failure we (1) record a diagnostic locally
// via telemetry.recordError and (2) re-throw the AppError from `invoke`.
// We do NOT emit `scribe:transcription_error` — the caller (the UI catch
// site) toasts once. Emitting an event on top of throwing led to two
// user-visible surfaces for a single failure.
//
// Finding #2 (transcription confidence/duration sanity check): the Rust
// command now returns `{ transcript, quality }` instead of a bare string —
// `quality` is an advisory signal (per-token confidence averaged from
// whisper.cpp's own `-ojf` output, plus implied words-per-minute) that
// `transcriptionQualityGate.js` turns into a plain-language warning.
//
// `transcribe()` now returns `{ transcript, quality }` too, mirroring how
// `generateNote()` / noteSection.js hands the caller its result directly
// for an immediate, synchronous quality check right after the await —
// finding #1's exact pattern. The alternative (leave `transcribe()`
// returning a bare string, surface `quality` only via the event bus) was
// considered and rejected: this codebase's convention for "advisory check
// right after an async generation step" is a direct return value read by
// the one caller, not a global event-bus side-channel, and there both is
// and should be only one real caller (`transcriptSection.js`).

import { emit } from '../core/eventBus.js';
import { invoke } from '../platform/tauri.js';
import { recordError } from '../core/telemetry.js';

export async function transcribe(audioPath, encounterId) {
  emit('scribe:transcription_started', { encounterId });
  try {
    const result = await invoke('transcribe_audio', { audioPath });
    // Tolerate a bare-string result too, so any stale mock/fixture still
    // using the pre-Finding-#2 shape (a plain transcript string) keeps
    // working rather than reading `undefined.transcript` and throwing.
    const transcript = typeof result === 'string' ? result : result?.transcript ?? '';
    const quality = typeof result === 'string' ? null : result?.quality ?? null;
    emit('scribe:transcription_complete', { transcript, quality, encounterId });
    return { transcript, quality };
  } catch (e) {
    recordError('transcription', e);
    throw e;
  }
}
