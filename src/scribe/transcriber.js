// Transcription pipeline.
// Calls the Tauri transcribe_audio command which shells to the whisper.cpp
// sidecar binary. Audio stays on-device; no network call is made.

import { emit } from '../core/eventBus.js';
import { invoke, listen } from '../platform/tauri.js';

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
    emit('scribe:transcription_error', { error: e.message || String(e), encounterId });
    throw e;
  }
}
