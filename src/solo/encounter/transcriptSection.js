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
  document.getElementById('btn-transcribe')?.addEventListener('click', async () => {
    if (!ctx.currentEncounter.audio_path) return;
    setStatus('Transcribing… this may take 20–40 seconds.');
    try {
      const transcript = await transcribe(ctx.currentEncounter.audio_path, ctx.currentEncounter.id);
      ctx.setTranscript(transcript);
      kvSet(TRANSCRIPT_KEY(ctx.currentEncounter.id), transcript);
      document.getElementById('transcript-area').value = transcript;
      document.getElementById('btn-generate')?.removeAttribute('disabled');
      clearStatus();
      toast('Transcription complete.');
    } catch (e) {
      clearStatus();
      toast(userMessage(e, 'Transcription failed.'));
    }
  });

  // Allow manual transcript edits.
  document.getElementById('transcript-area')?.addEventListener('input', e => {
    ctx.setTranscript(e.target.value);
    kvSet(TRANSCRIPT_KEY(ctx.currentEncounter.id), e.target.value);
    if (e.target.value.trim()) {
      document.getElementById('btn-generate')?.removeAttribute('disabled');
    }
  });
}
