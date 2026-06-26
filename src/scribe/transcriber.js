// Transcription pipeline.
// Calls the Tauri transcribe_audio command which shells to the whisper.cpp
// sidecar binary. Audio stays on-device; no network call is made.

import { emit } from '../core/eventBus.js';
import { tauriInvoke } from '../core/storageBackend.js';

export async function checkModelDownloaded() {
  return tauriInvoke('model_downloaded', {});
}

export async function downloadModel(onProgress) {
  // Subscribe to Tauri events for progress reporting.
  const { listen } = window.__TAURI__?.event || {};
  let unlisten;
  if (listen && onProgress) {
    unlisten = await listen('whisper:download_progress', e => {
      const { downloaded, total } = e.payload;
      onProgress(total > 0 ? downloaded / total : 0);
    });
  }
  try {
    await tauriInvoke('download_whisper_model', {});
  } finally {
    if (unlisten) unlisten();
  }
}

export async function transcribe(audioPath, encounterId) {
  emit('scribe:transcription_started', { encounterId });
  try {
    const transcript = await tauriInvoke('transcribe_audio', { audioPath });
    emit('scribe:transcription_complete', { transcript, encounterId });
    return transcript;
  } catch (e) {
    emit('scribe:transcription_error', { error: e.message || String(e), encounterId });
    throw e;
  }
}
