// Transcription pipeline.
// Calls the Tauri transcribe_audio command which shells to the whisper.cpp
// sidecar binary. Audio stays on-device; no network call is made.
//
// Error surface contract: on failure we (1) record a diagnostic locally
// via telemetry.recordError and (2) re-throw the AppError from `invoke`.
// We do NOT emit `scribe:transcription_error` — the caller (the UI catch
// site) toasts once. Emitting an event on top of throwing led to two
// user-visible surfaces for a single failure.

import { emit } from '../core/eventBus.js';
import { invoke, listen } from '../platform/tauri.js';
import { recordError } from '../core/telemetry.js';

export async function checkModelDownloaded() {
  return invoke('model_downloaded', {});
}

export async function downloadModel(onProgress) {
  // Subscribe to backend progress events while the download runs.
  let unlisten;
  if (onProgress) {
    unlisten = await listen('whisper:download_progress', e => {
      const { downloaded, total } = e.payload;
      onProgress(total > 0 ? downloaded / total : 0);
    });
  }
  try {
    await invoke('download_whisper_model', {});
  } finally {
    if (unlisten) unlisten();
  }
}

export async function transcribe(audioPath, encounterId) {
  emit('scribe:transcription_started', { encounterId });
  try {
    const transcript = await invoke('transcribe_audio', { audioPath });
    emit('scribe:transcription_complete', { transcript, encounterId });
    return transcript;
  } catch (e) {
    recordError('transcription', e);
    throw e;
  }
}
