// Transcribe button + transcript textarea persistence.
//
// Transcript is stored under keys.noteTranscript(encounterId) so it
// survives panel close/reopen and can be manually edited. The generate
// button enables as soon as any transcript text is present.

import { kvSet } from '../../core/storageBackend.js';
import { transcribe } from '../../scribe/transcriber.js';
import { toast } from '../../utils/format.js';
import { userMessage } from '../../platform/appError.js';
import { TRANSCRIPT_KEY, setStatus, clearStatus } from './template.js';

export function wireTranscriptSection(ctx) {
  // Run transcription. Returns true on success, false on failure or when there
  // is no audio to transcribe. `chain` is set when called as part of the
  // auto-chain: on success the status banner is left in place so the caller
  // (note generation) can update it to "Writing note…" without a flicker; on
  // the manual path the banner is cleared here.
  async function transcribeNow({ chain = false } = {}) {
    if (!ctx.currentEncounter.audio_path) return false;
    setStatus('Transcribing… this may take 20–40 seconds.');
    const btn = document.getElementById('btn-transcribe');
    if (btn) btn.disabled = true;
    try {
      const transcript = await transcribe(ctx.currentEncounter.audio_path, ctx.currentEncounter.id);
      ctx.setTranscript(transcript);
      kvSet(TRANSCRIPT_KEY(ctx.currentEncounter.id), transcript);
      const ta = document.getElementById('transcript-area');
      if (ta) ta.value = transcript;
      document.getElementById('btn-generate')?.removeAttribute('disabled');
      if (!chain) clearStatus();
      return true;
    } catch (e) {
      clearStatus();
      toast(userMessage(e, 'Transcription failed.'));
      return false;
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  document.getElementById('btn-transcribe')?.addEventListener('click', () => transcribeNow());

  // Allow manual transcript edits.
  document.getElementById('transcript-area')?.addEventListener('input', e => {
    ctx.setTranscript(e.target.value);
    kvSet(TRANSCRIPT_KEY(ctx.currentEncounter.id), e.target.value);
    if (e.target.value.trim()) {
      document.getElementById('btn-generate')?.removeAttribute('disabled');
    }
  });

  return { transcribeNow };
}
