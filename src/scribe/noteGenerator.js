// Note generation — sends the session transcript to Anthropic claude-haiku
// via the Rust generate_note command. The API key lives in SQLite (LOCAL_ONLY)
// and is never accessible from JS. Returns the full note text.

import { emit } from '../core/eventBus.js';
import { tauriInvoke } from '../core/storageBackend.js';
import { getTemplate } from '../templates/templateLibrary.js';

export async function generateNote(transcript, templateId, encounterId) {
  const template = getTemplate(templateId);
  if (!template) throw new Error(`Unknown template: ${templateId}`);

  emit('scribe:generation_started', { encounterId, templateId });

  try {
    const note = await tauriInvoke('generate_note', {
      transcript,
      systemPrompt: template.systemPrompt,
    });
    emit('scribe:generation_complete', { note, encounterId });
    return note;
  } catch (e) {
    const msg = e.message || String(e);
    emit('scribe:transcription_error', { error: msg, encounterId });
    throw new Error(msg);
  }
}
