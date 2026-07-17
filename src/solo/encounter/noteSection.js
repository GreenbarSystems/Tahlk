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
import { confirmModal } from '../confirmModal.js';
import { appendAudit } from '../../core/auditLog.js';
import { keys } from '../../data/keys.js';
import { getTemplate } from '../../templates/templateLibrary.js';
import { checkSectionCoverage, describeMissingSections } from '../../domain/sectionCoverage.js';
import { checkNoteQuality, describeQualityIssues, qualityIssuesCallToAction } from '../../domain/noteQualityGate.js';
import { checkClaimGrounding, describeGroundingIssues, groundingIssuesCallToAction } from '../../domain/noteClaimGroundingGate.js';

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

  // Note generation. Returns true on success, false on failure/no-op. Used by
  // both the manual "Generate Note" button and the post-transcription
  // auto-chain; `chain` only documents the call site (the shared status banner
  // is set the same way either way, so the auto-chain reads as one continuous
  // "Transcribing… → Writing note…" flow).
  async function generateNow(_opts = {}) {
    const transcript = ctx.currentTranscript();
    if (!transcript.trim()) return false;
    const templateId = document.getElementById('template-select')?.value || 'soap-generic';
    setStatus('Writing note…');
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

      // Advisory only — never blocks the flow. Flags the common drift case
      // where the LLM (or a truncated response) omits a section the
      // template requires, e.g. a psych eval missing "Risk Assessment".
      // Fires after clearStatus() so it doesn't get stomped by the status
      // banner, and after the note is already saved as a draft so a missing
      // section is never mistaken for a save failure.
      const template = getTemplate(templateId);
      const { missing } = checkSectionCoverage(note, template);

      // Content-quality heuristics (separate from section coverage above):
      // catches a refusal/disclaimer instead of a note, a response that
      // looks cut off mid-stream, or a note suspiciously short relative to
      // the transcript it came from — none of which "outcome: ok" in the
      // llm_audit table would ever reveal, since the API call itself
      // succeeded in all three cases.
      const { issues } = checkNoteQuality(note, transcript);

      // Claim-grounding check (compliance audit finding, Medium: no
      // output-side check for hallucinated/unsupported clinical claims).
      // Flags numeric clinical values (vitals, dosages) the model wrote
      // that don't appear to have a matching value anywhere in the
      // transcript — a grounding check, not a fact-checker; see
      // noteClaimGroundingGate.js's module doc for exactly what this can
      // and can't catch, and why it's scoped that way.
      const { issues: groundingIssues } = checkClaimGrounding(note, transcript);

      // Combined into ONE toast call, not two sequential ones. toast() is a
      // single-slot, last-write-wins mechanism (see utils/format.js) — two
      // toast() calls back-to-back with no await between them mean the
      // FIRST message is overwritten before it's ever rendered, silently
      // dropping it. A refusal/truncated note (caught by checkNoteQuality)
      // is also very likely to be missing every required section (caught
      // by checkSectionCoverage), so this isn't a rare edge case — it's the
      // exact high-stakes scenario these two checks exist for. Mirrors the
      // sign-button handler below, which already combines its own
      // coverage + quality warnings into one message for the same reason.
      const advisories = [];
      if (missing.length > 0) advisories.push(describeMissingSections(missing));
      if (issues.length > 0) advisories.push(`${describeQualityIssues(issues)}${qualityIssuesCallToAction(issues)}`);
      if (groundingIssues.length > 0) advisories.push(`${describeGroundingIssues(groundingIssues)}${groundingIssuesCallToAction(groundingIssues)}`);
      if (advisories.length > 0) toast(advisories.join(' '), 6000);

      return true;
    } catch (e) {
      if (noteArea) {
        noteArea.placeholder = 'Clinical note will appear here after generation. Review and edit before signing.';
        noteArea.classList.remove('generating');
      }
      clearStatus();
      // If Anthropic isn't configured OR the BAA hasn't been affirmed, point
      // the user at Settings. These two cases share the same fix (“open
      // Settings”) but are distinguished so the toast can name the reason.
      const err = fromInvoke(e);
      if (err.code === 'no_api_key') {
        toast('No Anthropic API key. Open Settings to add one.');
      } else if (err.code === 'baa_required') {
        toast('Confirm your agreements in Settings before generating notes.');
      } else {
        toast(userMessage(err, 'Note generation failed.'));
      }
      return false;
    }
  }

  document.getElementById('btn-generate')?.addEventListener('click', () => generateNow());

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

    // Last-chance advisory before locking: re-check coverage against the
    // CURRENT textarea content, not the originally generated note — a
    // provider's manual edit after generation can just as easily drop a
    // required section as the LLM can. Folded into the existing sign
    // confirmation message rather than a second dialog, so signing a note
    // Tahlk flagged still takes exactly one provider decision, same as today.
    const templateId = document.getElementById('template-select')?.value || 'soap-generic';
    const template = getTemplate(templateId);
    const { missing } = checkSectionCoverage(noteContent, template);
    const { issues: qualityIssues } = checkNoteQuality(noteContent, ctx.currentTranscript());
    const { issues: groundingIssues } = checkClaimGrounding(noteContent, ctx.currentTranscript());
    const warnings = [];
    if (missing.length > 0) warnings.push(describeMissingSections(missing));
    if (qualityIssues.length > 0) warnings.push(describeQualityIssues(qualityIssues));
    if (groundingIssues.length > 0) warnings.push(describeGroundingIssues(groundingIssues));
    const warning = warnings.length > 0 ? `\n\n${warnings.join(' ')} Review before signing.` : '';

    const confirmed = await confirmModal({
      title: 'Sign & lock this note?',
      message: `Signing attests to this clinical note. The signed version will be locked and can no longer be edited.${warning}`,
      confirmLabel: 'Sign & Lock',
      cancelLabel: 'Cancel',
      confirmClass: 'btn-sign',
    });
    if (!confirmed) return;

    // Persist any in-flight edit before sealing the chain.
    await flushPendingEdit();

    const signBtn = document.getElementById('btn-sign');
    if (signBtn) { signBtn.disabled = true; signBtn.innerHTML = '<span class="btn-spinner"></span>Signing…'; }

    // The DB write (signNote) is the only step that can legitimately fail
    // and warrant a "Sign failed" toast + re-enabled button. Everything
    // after a successful signNote() -- the audio purge, the DOM refresh --
    // must live OUTSIDE this try/catch. Previously the DOM refresh below
    // (readOnly toggles, node removal) ran inside the same try block as
    // signNote(); if the panel had been disposed mid-await (e.g. the user
    // switched tabs while purgeAudio was in flight) those unguarded
    // document.getElementById(...).readOnly writes would throw on a null
    // element, and that throw was caught here and reported as "Sign
    // failed." even though the note was already durably signed --
    // re-enabling a stale Sign button for an encounter that no longer
    // needs signing.
    try {
      await signNote(
        ctx.currentEncounter.id,
        noteContent,
        ctx.currentTranscript(),
        ctx.providerProfile.name || 'Provider'
      );
    } catch (e) {
      if (signBtn) { signBtn.disabled = false; signBtn.textContent = 'Sign & Attest Note'; }
      toast(userMessage(e, 'Sign failed.'));
      return;
    }

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
    // Re-render panel as signed. The note is already durably signed at this
    // point regardless of whether these DOM nodes still exist, so every
    // lookup here is optionally-chained -- a disposed/torn-down panel must
    // never surface a "Sign failed" error for a sign that already succeeded.
    document.getElementById('btn-sign')?.remove();
    const noteArea = document.getElementById('note-area');
    if (noteArea) noteArea.readOnly = true;
    const transcriptArea = document.getElementById('transcript-area');
    if (transcriptArea) transcriptArea.readOnly = true;
    document.querySelector('.recording-section')?.remove();
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

  // Permanently delete the whole encounter (audit finding: no capability
  // exists to delete a signed note, transcript, or entire encounter record).
  // Available regardless of status — a signed note must be deletable too,
  // since that's the exact case the finding names. The audit trail
  // (note_history/note_audit/llm_audit) is deliberately preserved by the
  // Rust command; this appends a final 'encounter_deleted' entry to that
  // same trail so it records who deleted the record and when, even though
  // the clinical content itself is now gone.
  document.getElementById('btn-delete-encounter')?.addEventListener('click', async () => {
    const id = ctx.currentEncounter.id;
    const ok = await confirmModal({
      title: 'Delete encounter',
      message: 'This permanently deletes this encounter’s note, transcript, and record. This cannot be undone.',
      confirmLabel: 'Delete',
      confirmClass: 'btn-danger',
    });
    if (!ok) return;
    const deleteBtn = document.getElementById('btn-delete-encounter');
    if (deleteBtn) deleteBtn.disabled = true;
    try {
      await encountersRepo.delete(id);
      await appendAudit(keys.noteAudit(id), 'encounter_deleted', {
        encounterId: id,
        status: ctx.currentEncounter.status,
      });
      toast('Encounter deleted.');
      await ctx.closePanel();
    } catch (e) {
      toast(`Delete failed: ${userMessage(e, 'unknown error')}`);
      if (deleteBtn) deleteBtn.disabled = false;
    }
  });

  // Expose the flush + cleanup handles so panel.dispose() can drain them
  // before tearing down subscriptions, plus generateNow for the auto-chain.
  return { flushPendingEdit, cleanup, generateNow };
}
