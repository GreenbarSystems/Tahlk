// Clinical note area: streaming generation, debounced edit-save, sign-off,
// and (post-sign) manual audio purge.
//
// Two buffers live here because they both touch #note-area:
//   • _chunkBuf: coalesces scribe:note_chunk deltas into one textarea write
//     per animation frame (avoids O(n^2) string growth + a reflow per token).
//   • _pendingNote: debounced local-edit value; flushed on dispose AND
//     before signing so an in-flight edit can never be dropped or omitted
//     from the note history chain.

import { encountersRepo } from '../../data/encountersRepo.js';
import { generateNote } from '../../scribe/noteGenerator.js';
import { saveDraftGenerated, saveDraftEdited, signNote, purgeAudio } from '../../editor/noteEditor.js';
import { getAudioRetention } from '../../domain/retention.js';
import { toast } from '../../utils/format.js';
import { userMessage, fromInvoke } from '../../platform/appError.js';
import { setStatus, clearStatus } from './template.js';

export function wireNoteSection(ctx) {
  let _pendingNote = null;
  let _saveTimer;
  let _chunkBuf = '';
  let _chunkRaf = 0;

  function _setIndicator(state) {
    const el = document.getElementById('note-save-indicator');
    if (!el) return;
    el.className = 'note-save-indicator' + (state ? ` ${state}` : '');
    el.textContent = state === 'saving' ? 'Saving…' : state === 'saved' ? 'Saved' : '';
  }

  async function flushPendingEdit() {
    if (_pendingNote == null) return;
    clearTimeout(_saveTimer);
    const v = _pendingNote;
    _pendingNote = null;
    try {
      await saveDraftEdited(ctx.currentEncounter.id, v, ctx.currentTranscript());
      _setIndicator('saved');
      setTimeout(() => _setIndicator(''), 2000);
    } catch {
      _setIndicator('');
      toast('Could not save your last edit.');
    }
  }

  function cleanup() {
    if (_chunkRaf) { cancelAnimationFrame(_chunkRaf); _chunkRaf = 0; }
    _chunkBuf = '';
  }

  // Live note streaming — buffer deltas and flush once per frame to avoid a
  // reflow per token (and the O(n^2) string growth of value += per delta).
  ctx.sub('scribe:note_chunk', ({ text, encounterId }) => {
    if (encounterId !== ctx.currentEncounter.id) return;
    _chunkBuf += text;
    if (_chunkRaf) return;
    _chunkRaf = requestAnimationFrame(() => {
      _chunkRaf = 0;
      if (!_chunkBuf) return;
      const ta = document.getElementById('note-area');
      if (ta) ta.value += _chunkBuf;
      _chunkBuf = '';
    });
  });

  // Note generation.
  document.getElementById('btn-generate')?.addEventListener('click', async () => {
    const transcript = ctx.currentTranscript();
    if (!transcript.trim()) return;
    const templateId = document.getElementById('template-select')?.value || 'soap-generic';
    setStatus('Generating clinical note…');
    const noteArea = document.getElementById('note-area');
    if (noteArea) {
      noteArea.value = '';
      noteArea.placeholder = 'Generating…';
      noteArea.classList.add('generating');
    }
    try {
      const note = await generateNote(transcript, templateId, ctx.currentEncounter.id);
      // Streaming finished: cancel any pending frame and drop the buffered tail
      // so the rAF flush can't append leftovers after the authoritative set.
      cleanup();
      if (noteArea) {
        noteArea.value = note; // reconcile with the full assembled note
        noteArea.placeholder = 'Clinical note will appear here after generation. Review and edit before signing.';
        noteArea.classList.remove('generating');
      }
      await saveDraftGenerated(ctx.currentEncounter.id, note, transcript);
      document.getElementById('btn-sign')?.removeAttribute('disabled');
      document.getElementById('btn-copy')?.removeAttribute('disabled');
      document.getElementById('btn-save-file')?.removeAttribute('disabled');
      ctx.currentEncounter.status = 'draft';
      await encountersRepo.save(ctx.currentEncounter);
      ctx.onEncounterUpdated(ctx.currentEncounter);
      clearStatus();
    } catch (e) {
      if (noteArea) {
        noteArea.placeholder = 'Clinical note will appear here after generation. Review and edit before signing.';
        noteArea.classList.remove('generating');
      }
      clearStatus();
      // If Anthropic isn't configured, point the user at the fix.
      const err = fromInvoke(e);
      if (err.code === 'no_api_key') {
        toast('No Anthropic API key. Open Settings to add one.');
      } else {
        toast(userMessage(err, 'Note generation failed.'));
      }
    }
  });

  // Note edits — buffer the value and debounce the durable save. The buffer
  // is also flushed on dispose and before signing (see flushPendingEdit).
  document.getElementById('note-area')?.addEventListener('input', e => {
    _pendingNote = e.target.value;
    _setIndicator('saving');
    clearTimeout(_saveTimer);
    _saveTimer = setTimeout(flushPendingEdit, 1500);
  });

  // Sign.
  document.getElementById('btn-sign')?.addEventListener('click', async () => {
    const noteContent = document.getElementById('note-area')?.value || '';
    if (!noteContent.trim()) { toast('Note is empty — cannot sign.'); return; }
    if (!confirm('Sign and attest this note? The signed version will be locked.')) return;

    // Persist any in-flight edit before sealing the chain.
    await flushPendingEdit();

    const signBtn = document.getElementById('btn-sign');
    if (signBtn) { signBtn.disabled = true; signBtn.innerHTML = '<span class="btn-spinner"></span>Signing…'; }

    try {
      await signNote(
        ctx.currentEncounter.id,
        noteContent,
        ctx.currentTranscript(),
        ctx.providerProfile.name || 'Provider'
      );
      ctx.currentEncounter.status = 'signed';

      // Best-effort audio purge if the provider opted into delete-on-sign.
      // Runs AFTER the successful sign so a purge failure cannot roll back
      // attestation; purgeAudio itself never throws.
      if (getAudioRetention() === 'delete_on_sign' && ctx.currentEncounter.audio_path) {
        const { removed, error } = await purgeAudio(ctx.currentEncounter.id, { reason: 'delete_on_sign' });
        if (error) {
          toast(`Note signed. Audio purge failed: ${error}`);
        } else if (removed) {
          toast('Note signed. Audio deleted from device.');
        } else {
          toast('Note signed. Audio was already gone.');
        }
        ctx.currentEncounter.audio_path = null;
      } else {
        toast('Note signed and attested.');
      }

      ctx.onEncounterUpdated(ctx.currentEncounter);
      // Re-render panel as signed.
      document.getElementById('btn-sign')?.remove();
      document.getElementById('note-area').readOnly = true;
      document.getElementById('transcript-area').readOnly = true;
      document.querySelector('.recording-section')?.remove();
    } catch (e) {
      if (signBtn) { signBtn.disabled = false; signBtn.textContent = 'Sign & Attest Note'; }
      toast(userMessage(e, 'Sign failed.'));
    }
  });

  // Manual audio purge — available on signed encounters that still have a .wav.
  document.getElementById('btn-purge-audio')?.addEventListener('click', async () => {
    if (!confirm('Delete the recorded audio for this encounter? The signed note and transcript are unaffected. This cannot be undone.')) return;
    const purgeBtn = document.getElementById('btn-purge-audio');
    if (purgeBtn) purgeBtn.disabled = true;
    const { removed, error } = await purgeAudio(ctx.currentEncounter.id, { reason: 'manual' });
    if (error) {
      toast(`Delete failed: ${error}`);
      if (purgeBtn) purgeBtn.disabled = false;
      return;
    }
    ctx.currentEncounter.audio_path = null;
    ctx.onEncounterUpdated(ctx.currentEncounter);
    purgeBtn?.remove();
    toast(removed ? 'Audio deleted from device.' : 'Audio was already gone.');
  });

  // Expose the flush + cleanup handles so panel.dispose() can drain them
  // before tearing down subscriptions.
  return { flushPendingEdit, cleanup };
}
