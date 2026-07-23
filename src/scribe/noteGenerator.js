// Note generation — sends the session transcript to Anthropic claude-haiku
// via the Rust generate_note command. In managed mode the transcript goes
// through Greenbar's secure proxy authenticated by a per-device token (see
// src-tauri/src/device.rs); there is no user API key anywhere in JS. Returns
// the full note text.
//
// Error surface contract: on failure we (1) record a diagnostic locally
// via telemetry.recordError and (2) re-throw the AppError from `invoke`
// (preserving `code` for branch logic like `secure_service_unreachable` or
// `baa_required`). We do NOT emit `scribe:generation_error` — the caller
// toasts once. Emitting an event on top of throwing led to two user-visible
// surfaces for a single failure.
//
// `encounterId` is forwarded to Rust so the on-device LLM audit row can be
// attached to the encounter that triggered the call (see src-tauri/src/
// llm_audit.rs). It is metadata only — never the transcript or note text.

import { emit } from '../core/eventBus.js';
import { invoke, listen } from '../platform/tauri.js';
import { recordError } from '../core/telemetry.js';
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
      encounterId: encounterId ?? null,
    });
    emit('scribe:generation_complete', { note, encounterId });
    return note;
  } catch (e) {
    recordError('generation', e);
    throw e;
  } finally {
    if (unlisten) unlisten();
  }
}
