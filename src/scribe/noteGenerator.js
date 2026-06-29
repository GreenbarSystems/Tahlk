// Note generation — sends the session transcript to Anthropic claude-haiku
// via the Rust generate_note command. The API key lives in SQLite (LOCAL_ONLY)
// and is never accessible from JS. Returns the full note text.

import { emit } from '../core/eventBus.js';
import { invoke, listen } from '../platform/tauri.js';
import { getTemplate } from '../templates/templateLibrary.js';

export async function generateNote(transcript, templateId, encounterId) {
  const template = getTemplate(templateId);
  if (!template) throw new Error(`Unknown template: ${templateId}`);

  emit('scribe:generation_started', { encounterId, templateId });

  // Rust emits a `scribe:note_chunk` Tauri event per token as it streams from
  // Anthropic. Bridge those onto the internal bus for live display, then
  // unlisten once generation settles. If the event API is unavailable the
  // command still returns the full assembled note (no progressive rendering).
  const unlisten = await listen('scribe:note_chunk', e => {
    emit('scribe:note_chunk', { text: e.payload, encounterId });
  });

  try {
    const note = await invoke('generate_note', {
      transcript,
      systemPrompt: template.systemPrompt,
    });
    emit('scribe:generation_complete', { note, encounterId });
    return note;
  } catch (e) {
    const msg = e.message || String(e);
    emit('scribe:generation_error', { error: msg, encounterId });
    throw new Error(msg);
  } finally {
    if (unlisten) unlisten();
  }
}
