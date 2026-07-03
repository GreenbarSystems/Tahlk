// Encounter panel — recording controls, transcription status, note editor, sign-off.

import { kvGet, kvSet } from '../core/storageBackend.js';
import { encountersRepo } from '../data/encountersRepo.js';
import { keys } from '../data/keys.js';
import { on, emit } from '../core/eventBus.js';
import { startRecording, stopRecording, isRecording, recordingDuration } from '../scribe/recorder.js';
import { transcribe } from '../scribe/transcriber.js';
import { generateNote } from '../scribe/noteGenerator.js';
import { loadDraft, loadHistory, saveDraftGenerated, saveDraftEdited, signNote } from '../editor/noteEditor.js';
import { listTemplates } from '../templates/templateLibrary.js';
import {
  toPlainText, toSimplePractice, toTherapyNotes,
  copyToClipboard, saveToFile,
} from '../export/exportFormatter.js';
import { toast, fmtDuration, displayDate, escapeHtml, statusLabel } from '../utils/format.js';

const TRANSCRIPT_KEY = keys.noteTranscript;

export function renderEncounterPanel(encounter) {
  const isSigned = encounter.status === 'signed';
  const draft = loadDraft(encounter.id) || '';
  const transcript = kvGet(TRANSCRIPT_KEY(encounter.id)) || '';
  const templates = listTemplates();

  return `
    <div class="panel encounter-panel" data-encounter-id="${encounter.id}">

      <!-- Header: date · alias (always editable) · status · close -->
      <div class="panel-header">
        <div class="panel-header-left">
          <span class="panel-date">${escapeHtml(encounter.encounter_date || '')}</span>
          <input type="text" id="patient-alias" class="panel-alias-input"
                 value="${escapeHtml(encounter.patient_alias || '')}"
                 placeholder="Add alias…" maxlength="40" />
          <span class="status-chip status-chip--${escapeHtml(encounter.status)}">${statusLabel(encounter.status)}</span>
        </div>
        <button class="btn btn-ghost btn-sm" id="btn-close-panel">✕ Close</button>
      </div>

      <!-- Two-column workspace -->
      <div class="enc-workspace">

        <!-- Left: recording + transcript -->
        <div class="enc-col">

          <section class="section recording-section" ${isSigned ? 'style="display:none"' : ''}>
            <div class="recording-controls">
              <button class="btn btn-record" id="btn-record" ${isSigned ? 'disabled' : ''}>
                <span class="record-icon"></span>
                <span id="record-label">Start Recording</span>
              </button>
              <span class="record-timer" id="record-timer"></span>
              ${encounter.audio_path ? '<span class="audio-saved">✓ Audio saved</span>' : ''}
            </div>
          </section>

          <section class="section transcript-section">
            <div class="section-header">
              <h3 class="section-title">Transcript</h3>
              <div class="section-actions" ${isSigned ? 'style="display:none"' : ''}>
                <button class="btn btn-secondary btn-sm" id="btn-transcribe"
                        ${!encounter.audio_path ? 'disabled title="Record audio first"' : ''}>
                  Transcribe
                </button>
                <div class="generate-group">
                  <select id="template-select">
                    ${templates.map(t => `<option value="${escapeHtml(t.id)}">${escapeHtml(t.name)}</option>`).join('')}
                  </select>
                  <button class="btn btn-primary btn-sm" id="btn-generate"
                          ${!transcript ? 'disabled title="Transcribe first"' : ''}>
                    Generate Note
                  </button>
                </div>
              </div>
            </div>
            <div class="status-banner" id="status-banner" style="display:none"></div>
            <textarea class="transcript-area" id="transcript-area"
                      placeholder="Transcript will appear here after transcription…"
                      ${isSigned ? 'readonly' : ''}>${escapeHtml(transcript)}</textarea>
          </section>

        </div>

        <!-- Right: clinical note + sign/export (one unified card) -->
        <div class="enc-col">

          <section class="section note-sign-section">
            <div class="section-header">
              <h3 class="section-title">Clinical Note</h3>
              ${isSigned
                ? '<span class="signed-badge">✓ Signed</span>'
                : '<span class="note-save-indicator" id="note-save-indicator"></span>'}
            </div>

            <textarea class="note-area" id="note-area"
                      placeholder="Clinical note will appear here after generation. Review and edit before signing."
                      ${isSigned ? 'readonly' : ''}>${escapeHtml(draft)}</textarea>

            <div class="note-card-footer">
              ${!isSigned ? `
                <button class="btn btn-sign btn-sign-full" id="btn-sign" ${!draft ? 'disabled' : ''}>
                  Sign &amp; Attest Note
                </button>
                <div class="export-controls">
                  <select id="export-format">
                    <option value="plain">Plain text</option>
                    <option value="simplepractice">SimplePractice</option>
                    <option value="therapynotes">TherapyNotes</option>
                  </select>
                  <button class="btn btn-secondary btn-sm" id="btn-copy" ${!draft ? 'disabled' : ''}>Copy</button>
                  <button class="btn btn-secondary btn-sm" id="btn-save-file" ${!draft ? 'disabled' : ''}>Save File</button>
                </div>
              ` : `
                <div class="signed-export-row">
                  <span class="signed-at">Signed ${displayDate(encounter.signed_at)}</span>
                  <div class="export-controls">
                    <select id="export-format">
                      <option value="plain">Plain text</option>
                      <option value="simplepractice">SimplePractice</option>
                      <option value="therapynotes">TherapyNotes</option>
                    </select>
                    <button class="btn btn-secondary btn-sm" id="btn-copy">Copy</button>
                    <button class="btn btn-secondary btn-sm" id="btn-save-file">Save File</button>
                  </div>
                </div>
                ${encounter.signed_hash ? `
                  <p class="hash-display">SHA-256: <code>${escapeHtml(encounter.signed_hash)}</code></p>
                ` : ''}
              `}
            </div>
          </section>

        </div>
      </div>
    </div>
  `;
}

export function wireEncounterPanel(encounter, onClose, onEncounterUpdated) {
  let currentEncounter = { ...encounter };
  let currentTranscript = kvGet(TRANSCRIPT_KEY(encounter.id)) || '';

  const providerProfile = kvGet(keys.provider()) || {};

  // Collect event-bus subscriptions so they can be torn down when the panel
  // closes. Without this, every panel open leaks handlers that fire against
  // detached DOM nodes from prior encounters.
  const _disposers = [];
  const sub = (evt, fn) => { _disposers.push(on(evt, fn)); };

  // Debounced note-edit buffer — flushed on close and before signing so an
  // in-flight edit (and its history entry) is never dropped.
  let _pendingNote = null;
  let _saveTimer;

  function _setIndicator(state) {
    const el = document.getElementById('note-save-indicator');
    if (!el) return;
    el.className = 'note-save-indicator' + (state ? ` ${state}` : '');
    el.textContent = state === 'saving' ? 'Saving…' : state === 'saved' ? 'Saved' : '';
  }

  // Streaming-token buffer — coalesce note_chunk deltas into one textarea write
  // per animation frame instead of one (reflow-forcing) write per token.
  let _chunkBuf = '';
  let _chunkRaf = 0;
  async function flushPendingEdit() {
    if (_pendingNote == null) return;
    clearTimeout(_saveTimer);
    const v = _pendingNote;
    _pendingNote = null;
    try {
      await saveDraftEdited(currentEncounter.id, v, currentTranscript);
      _setIndicator('saved');
      setTimeout(() => _setIndicator(''), 2000);
    } catch {
      _setIndicator('');
      toast('Could not save your last edit.');
    }
  }

  // Unmount: flush a pending edit, then drop every bus subscription. Safe to
  // call more than once. Returned to the caller so the router can dispose the
  // panel on ANY unmount path (close button, tab navigation, re-render).
  let _disposed = false;
  async function dispose() {
    if (_disposed) return;
    _disposed = true;
    if (_chunkRaf) { cancelAnimationFrame(_chunkRaf); _chunkRaf = 0; }
    _chunkBuf = '';
    await flushPendingEdit();
    _disposers.forEach(d => d());
    _disposers.length = 0;
  }

  // Close — dispose, then hand control back to the router.
  document.getElementById('btn-close-panel')?.addEventListener('click', async () => {
    await dispose();
    onClose();
  });

  // Patient alias save on blur
  document.getElementById('patient-alias')?.addEventListener('change', async e => {
    currentEncounter.patient_alias = e.target.value.trim() || null;
    await encountersRepo.save(currentEncounter);
    onEncounterUpdated(currentEncounter);
  });

  // Recording
  const recordBtn = document.getElementById('btn-record');
  const recordLabel = document.getElementById('record-label');
  const recordTimer = document.getElementById('record-timer');

  sub('scribe:recording_tick', ({ duration }) => {
    if (recordTimer) recordTimer.textContent = fmtDuration(duration);
  });

  sub('scribe:audio_saved', async ({ path }) => {
    currentEncounter.audio_path = path;
    currentEncounter.status = 'recording_done';
    await encountersRepo.save(currentEncounter);
    onEncounterUpdated(currentEncounter);
    document.getElementById('btn-transcribe')?.removeAttribute('disabled');
    toast('Recording saved to device.');
  });

  recordBtn?.addEventListener('click', async () => {
    if (isRecording()) {
      recordBtn.disabled = true;
      recordLabel.textContent = 'Saving…';
      try {
        await stopRecording(currentEncounter.id);
      } catch (e) {
        toast(e.message);
        recordBtn.disabled = false;
        recordLabel.textContent = 'Start Recording';
      }
    } else {
      try {
        await startRecording();
        recordBtn.classList.add('btn-record--active');
        recordLabel.textContent = 'Stop Recording';
      } catch (e) {
        toast(e.message);
      }
    }
  });

  sub('scribe:recording_stopped', () => {
    recordBtn?.classList.remove('btn-record--active');
    recordLabel.textContent = 'Re-record';
    recordBtn.disabled = false;
  });

  // Live note streaming — buffer deltas and flush once per frame to avoid a
  // reflow per token (and the O(n^2) string growth of value += per delta).
  sub('scribe:note_chunk', ({ text, encounterId }) => {
    if (encounterId !== currentEncounter.id) return;
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

  // Transcription
  document.getElementById('btn-transcribe')?.addEventListener('click', async () => {
    if (!currentEncounter.audio_path) return;
    setStatus('Transcribing… this may take 20–40 seconds.');
    try {
      const transcript = await transcribe(currentEncounter.audio_path, currentEncounter.id);
      currentTranscript = transcript;
      kvSet(TRANSCRIPT_KEY(currentEncounter.id), transcript);
      document.getElementById('transcript-area').value = transcript;
      document.getElementById('btn-generate')?.removeAttribute('disabled');
      clearStatus();
      toast('Transcription complete.');
    } catch (e) {
      clearStatus();
      toast(e.message || 'Transcription failed.');
    }
  });

  // Allow manual transcript edits
  document.getElementById('transcript-area')?.addEventListener('input', e => {
    currentTranscript = e.target.value;
    kvSet(TRANSCRIPT_KEY(currentEncounter.id), currentTranscript);
    if (currentTranscript.trim()) {
      document.getElementById('btn-generate')?.removeAttribute('disabled');
    }
  });

  // Note generation
  document.getElementById('btn-generate')?.addEventListener('click', async () => {
    if (!currentTranscript.trim()) return;
    const templateId = document.getElementById('template-select')?.value || 'soap-generic';
    setStatus('Generating clinical note…');
    const noteArea = document.getElementById('note-area');
    if (noteArea) {
      noteArea.value = '';
      noteArea.placeholder = 'Generating…';
      noteArea.classList.add('generating');
    }
    try {
      const note = await generateNote(currentTranscript, templateId, currentEncounter.id);
      // Streaming finished: cancel any pending frame and drop the buffered tail
      // so the rAF flush can't append leftovers after the authoritative set.
      if (_chunkRaf) { cancelAnimationFrame(_chunkRaf); _chunkRaf = 0; }
      _chunkBuf = '';
      if (noteArea) {
        noteArea.value = note; // reconcile with the full assembled note
        noteArea.placeholder = 'Clinical note will appear here after generation. Review and edit before signing.';
        noteArea.classList.remove('generating');
      }
      await saveDraftGenerated(currentEncounter.id, note, currentTranscript);
      document.getElementById('btn-sign')?.removeAttribute('disabled');
      document.getElementById('btn-copy')?.removeAttribute('disabled');
      document.getElementById('btn-save-file')?.removeAttribute('disabled');
      currentEncounter.status = 'draft';
      await encountersRepo.save(currentEncounter);
      onEncounterUpdated(currentEncounter);
      clearStatus();
    } catch (e) {
      if (noteArea) {
        noteArea.placeholder = 'Clinical note will appear here after generation. Review and edit before signing.';
        noteArea.classList.remove('generating');
      }
      clearStatus();
      toast(e.message || 'Note generation failed.');
    }
  });

  // Note edits — buffer the value and debounce the durable save. The buffer
  // is also flushed on close and before signing (see flushPendingEdit).
  document.getElementById('note-area')?.addEventListener('input', e => {
    _pendingNote = e.target.value;
    _setIndicator('saving');
    clearTimeout(_saveTimer);
    _saveTimer = setTimeout(flushPendingEdit, 1500);
  });

  // Sign
  document.getElementById('btn-sign')?.addEventListener('click', async () => {
    const noteContent = document.getElementById('note-area')?.value || '';
    if (!noteContent.trim()) { toast('Note is empty — cannot sign.'); return; }
    if (!confirm('Sign and attest this note? The signed version will be locked.')) return;

    // Persist any in-flight edit before sealing the chain.
    await flushPendingEdit();

    const signBtn = document.getElementById('btn-sign');
    if (signBtn) { signBtn.disabled = true; signBtn.innerHTML = '<span class="btn-spinner"></span>Signing…'; }

    try {
      await signNote(currentEncounter.id, noteContent, currentTranscript, providerProfile.name || 'Provider');
      currentEncounter.status = 'signed';
      onEncounterUpdated(currentEncounter);
      toast('Note signed and attested.');
      // Re-render panel as signed
      document.getElementById('btn-sign')?.remove();
      document.getElementById('note-area').readOnly = true;
      document.getElementById('transcript-area').readOnly = true;
      document.querySelector('.recording-section')?.remove();
    } catch (e) {
      if (signBtn) { signBtn.disabled = false; signBtn.textContent = 'Sign & Attest Note'; }
      toast(e.message || 'Sign failed.');
    }
  });

  // Export
  function getFormattedNote() {
    const note = document.getElementById('note-area')?.value || '';
    const fmt = document.getElementById('export-format')?.value || 'plain';
    if (fmt === 'simplepractice') return toSimplePractice(note, currentEncounter);
    if (fmt === 'therapynotes')   return toTherapyNotes(note, currentEncounter);
    return toPlainText(note, currentEncounter);
  }

  document.getElementById('btn-copy')?.addEventListener('click', async () => {
    const fmt = document.getElementById('export-format')?.value || 'plain';
    await copyToClipboard(getFormattedNote(), currentEncounter.id, fmt);
    toast('Note copied to clipboard.');
  });

  document.getElementById('btn-save-file')?.addEventListener('click', async () => {
    const fmt = document.getElementById('export-format')?.value || 'plain';
    await saveToFile(getFormattedNote(), currentEncounter, fmt);
    toast('Note saved to file.');
  });

  return dispose;
}

function setStatus(msg) {
  const el = document.getElementById('status-banner');
  if (!el) return;
  el.textContent = msg;
  el.style.display = 'block';
}

function clearStatus() {
  const el = document.getElementById('status-banner');
  if (el) el.style.display = 'none';
}
