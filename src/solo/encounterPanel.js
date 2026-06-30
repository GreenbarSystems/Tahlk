// Encounter panel — recording controls, transcription status, note editor, sign-off.

import { kvGet, kvSet, tauriInvoke } from '../core/storageBackend.js';
import { on, emit } from '../core/eventBus.js';
import { startRecording, stopRecording, isRecording, recordingDuration } from '../scribe/recorder.js';
import { transcribe } from '../scribe/transcriber.js';
import { generateNote } from '../scribe/noteGenerator.js';
import { extractCodingFlags, loadCodingFlags, renderFlagsCard, wireFlagsCard } from '../scribe/codingFlags.js';
import { loadDraft, loadHistory, saveDraftGenerated, saveDraftEdited, signNote } from '../editor/noteEditor.js';
import { listTemplates } from '../templates/templateLibrary.js';
import {
  exportFormatsFor, formatNote,
  copyToClipboard, saveToFile,
} from '../export/exportFormatter.js';
import {
  saveToPdf, archiveToCloud, getCloudPdfUrl, getLocalArchiveStatus,
} from '../export/pdfExport.js';
import { isAuthenticated } from '../core/auth.js';
import { toast, fmtDuration, genId, nowISO, displayDate } from '../utils/format.js';

const TRANSCRIPT_KEY = id => `note_content_v1::transcript::${id}`;

export function renderEncounterPanel(encounter) {
  const isSigned = encounter.status === 'signed';
  const draft = loadDraft(encounter.id) || '';
  const transcript = kvGet(TRANSCRIPT_KEY(encounter.id)) || '';
  const provider = kvGet('note_provider_v1::profile') || {};
  const templates = listTemplates(provider.specialty);
  const archiveStatus = getLocalArchiveStatus(encounter.id);

  return `
    <div class="panel encounter-panel" data-encounter-id="${encounter.id}">
      <div class="panel-header">
        <div class="panel-header-left">
          <span class="panel-date">${encounter.encounter_date || ''}</span>
          ${encounter.patient_alias ? `<span class="panel-alias">${encounter.patient_alias}</span>` : ''}
          <span class="status-chip status-chip--${encounter.status}">${statusLabel(encounter.status)}</span>
        </div>
        <button class="btn btn-ghost btn-sm" id="btn-close-panel">✕ Close</button>
      </div>

      <!-- Recording controls -->
      <section class="section recording-section" ${isSigned ? 'style="display:none"' : ''}>
        <h3 class="section-title">Session Recording</h3>
        <div class="recording-controls">
          <button class="btn btn-record" id="btn-record" ${isSigned ? 'disabled' : ''}>
            <span class="record-icon"></span>
            <span id="record-label">Start Recording</span>
          </button>
          <span class="record-timer" id="record-timer"></span>
          ${encounter.audio_path ? '<span class="audio-saved">✓ Audio saved</span>' : ''}
        </div>
        <div class="patient-alias-row">
          <label>Patient alias (optional)</label>
          <input type="text" id="patient-alias" value="${encounter.patient_alias || ''}"
                 placeholder="e.g. P-001 or first name only" maxlength="40" />
        </div>
      </section>

      <!-- Transcription -->
      <section class="section transcript-section">
        <div class="section-header">
          <h3 class="section-title">Transcript</h3>
          <div class="section-actions" ${isSigned ? 'style="display:none"' : ''}>
            <select id="template-select">
              ${templates.map(t => `<option value="${t.id}">${t.name}</option>`).join('')}
            </select>
            <button class="btn btn-secondary btn-sm" id="btn-transcribe"
                    ${!encounter.audio_path ? 'disabled title="Record audio first"' : ''}>
              Transcribe
            </button>
            <button class="btn btn-primary btn-sm" id="btn-generate"
                    ${!transcript ? 'disabled title="Transcribe first"' : ''}>
              Generate Note
            </button>
          </div>
        </div>
        <div class="status-banner" id="status-banner" style="display:none"></div>
        <textarea class="transcript-area" id="transcript-area"
                  placeholder="Transcript will appear here after transcription…"
                  ${isSigned ? 'readonly' : ''}>${transcript}</textarea>
      </section>

      <!-- Note editor -->
      <section class="section note-section">
        <div class="section-header">
          <h3 class="section-title">Clinical Note</h3>
          ${isSigned ? '<span class="signed-badge">✓ Signed</span>' : ''}
        </div>
        <textarea class="note-area" id="note-area"
                  placeholder="Clinical note will appear here after generation. Review and edit before signing."
                  ${isSigned ? 'readonly' : ''}>${draft}</textarea>
      </section>

      <!-- Coding flags -->
      <section class="section flags-section" id="flags-section" ${!draft ? 'style="display:none"' : ''}>
        <div class="section-header">
          <h3 class="section-title">Coding Suggestions</h3>
          <span class="flags-beta-badge">AI</span>
        </div>
        <div id="flags-content">${draft ? renderFlagsCard(loadCodingFlags(encounter.id)) : ''}</div>
      </section>

      <!-- Sign-off and export -->
      <section class="section actions-section">
        <div class="actions-row">
          ${!isSigned ? `
            <button class="btn btn-sign" id="btn-sign" ${!draft ? 'disabled' : ''}>
              Sign &amp; Attest Note
            </button>
          ` : `
            <span class="signed-at">Signed ${displayDate(encounter.signed_at)}</span>
          `}
          <div class="export-controls">
            <select id="export-format">
              ${exportFormatsFor(provider.specialty).map(f => `<option value="${f.id}">${f.label}</option>`).join('')}
            </select>
            <button class="btn btn-secondary" id="btn-copy" ${!draft ? 'disabled' : ''}>Copy</button>
            <button class="btn btn-secondary" id="btn-save-file" ${!draft ? 'disabled' : ''}>Save .txt</button>
            <button class="btn btn-secondary btn-pdf" id="btn-export-pdf" ${!draft ? 'disabled' : ''}>Export PDF</button>
          </div>
        </div>
        ${isSigned && encounter.signed_hash ? `
          <p class="hash-display">SHA-256: <code>${encounter.signed_hash}</code></p>
        ` : ''}
        ${isSigned && isAuthenticated() ? `
          <div class="cloud-archive-row" id="cloud-archive-row">
            ${archiveStatus.s3Key ? `
              <div class="archive-meta">
                <span class="archive-status archive-status--done">☁ Archived to Cloud</span>
                ${archiveStatus.archivedAt
                  ? `<span class="archive-date">${new Date(archiveStatus.archivedAt).toLocaleString()}</span>`
                  : ''}
              </div>
              <button class="btn btn-ghost btn-sm" id="btn-view-cloud-pdf">View →</button>
            ` : `
              <button class="btn btn-secondary btn-sm" id="btn-archive-cloud">☁ Archive to Cloud</button>
            `}
          </div>
        ` : ''}
      </section>
    </div>
  `;
}

export function wireEncounterPanel(encounter, onClose, onEncounterUpdated) {
  let currentEncounter = { ...encounter };
  let currentTranscript = kvGet(TRANSCRIPT_KEY(encounter.id)) || '';

  const providerProfile = kvGet('note_provider_v1::profile') || {};

  // Wire any flags already rendered (draft/signed encounter reopened)
  wireFlagsCard();

  // Close
  document.getElementById('btn-close-panel')?.addEventListener('click', onClose);

  // Patient alias save on blur
  document.getElementById('patient-alias')?.addEventListener('change', async e => {
    currentEncounter.patient_alias = e.target.value.trim() || null;
    await tauriInvoke('upsert_encounter', { encounter: currentEncounter });
    onEncounterUpdated(currentEncounter);
  });

  // Recording
  const recordBtn = document.getElementById('btn-record');
  const recordLabel = document.getElementById('record-label');
  const recordTimer = document.getElementById('record-timer');

  on('scribe:recording_tick', ({ duration }) => {
    if (recordTimer) recordTimer.textContent = fmtDuration(duration);
  });

  on('scribe:audio_saved', async ({ path }) => {
    currentEncounter.audio_path = path;
    currentEncounter.status = 'recording_done';
    await tauriInvoke('upsert_encounter', { encounter: currentEncounter });
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
        if (currentEncounter.status === 'new') {
          currentEncounter.status = 'recording';
          await tauriInvoke('upsert_encounter', { encounter: currentEncounter });
          onEncounterUpdated(currentEncounter);
        }
      } catch (e) {
        toast(e.message);
      }
    }
  });

  on('scribe:recording_stopped', () => {
    recordBtn?.classList.remove('btn-record--active');
    recordLabel.textContent = 'Re-record';
    recordBtn.disabled = false;
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
    try {
      const note = await generateNote(currentTranscript, templateId, currentEncounter.id);
      document.getElementById('note-area').value = note;
      await saveDraftGenerated(currentEncounter.id, note, currentTranscript);
      document.getElementById('btn-sign')?.removeAttribute('disabled');
      document.getElementById('btn-copy')?.removeAttribute('disabled');
      document.getElementById('btn-save-file')?.removeAttribute('disabled');
      document.getElementById('btn-export-pdf')?.removeAttribute('disabled');
      currentEncounter.status = 'draft';
      await tauriInvoke('upsert_encounter', { encounter: currentEncounter });
      onEncounterUpdated(currentEncounter);
      clearStatus();

      // Extract coding flags asynchronously — non-blocking
      setStatus('Extracting coding suggestions…');
      const flags = await extractCodingFlags(
        note, currentTranscript, providerProfile.specialty, currentEncounter.id
      );
      clearStatus();
      if (flags) {
        const section = document.getElementById('flags-section');
        const content = document.getElementById('flags-content');
        if (section && content) {
          content.innerHTML = renderFlagsCard(flags);
          section.style.display = '';
          wireFlagsCard();
        }
      }
    } catch (e) {
      clearStatus();
      toast(e.message || 'Note generation failed.');
    }
  });

  // Note edits
  let _saveTimer;
  document.getElementById('note-area')?.addEventListener('input', e => {
    clearTimeout(_saveTimer);
    _saveTimer = setTimeout(async () => {
      await saveDraftEdited(currentEncounter.id, e.target.value, currentTranscript);
    }, 1500);
  });

  // Sign
  document.getElementById('btn-sign')?.addEventListener('click', async () => {
    const noteContent = document.getElementById('note-area')?.value || '';
    if (!noteContent.trim()) { toast('Note is empty — cannot sign.'); return; }
    if (!confirm('Sign and attest this note? The signed version will be locked.')) return;

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
      toast(e.message || 'Sign failed.');
    }
  });

  // Export
  function getFormattedNote() {
    const note = document.getElementById('note-area')?.value || '';
    const fmt = document.getElementById('export-format')?.value || 'plain';
    return formatNote(fmt, note, currentEncounter);
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

  document.getElementById('btn-export-pdf')?.addEventListener('click', async () => {
    const note = document.getElementById('note-area')?.value || '';
    if (!note.trim()) { toast('No note to export.'); return; }
    try {
      await saveToPdf(note, currentEncounter, providerProfile);
      toast('PDF saved.');
    } catch (e) {
      toast(e.message || 'PDF export failed.');
    }
  });

  // ── Cloud archive (signed notes only, cloud account required) ──────────────

  async function _openCloudPdf() {
    try {
      const url = await getCloudPdfUrl(currentEncounter.id);
      await tauriInvoke('open_url', { url });
    } catch (e) {
      toast(e.message || 'Could not open archived PDF.');
    }
  }

  document.getElementById('btn-view-cloud-pdf')?.addEventListener('click', _openCloudPdf);

  document.getElementById('btn-archive-cloud')?.addEventListener('click', async () => {
    const note = document.getElementById('note-area')?.value || '';
    if (!note.trim()) { toast('No note content to archive.'); return; }
    const btn = document.getElementById('btn-archive-cloud');
    btn.disabled = true;
    btn.textContent = '☁ Archiving…';
    try {
      await archiveToCloud(note, currentEncounter, providerProfile);
      const row = document.getElementById('cloud-archive-row');
      if (row) {
        const status = getLocalArchiveStatus(currentEncounter.id);
        row.innerHTML = `
          <div class="archive-meta">
            <span class="archive-status archive-status--done">☁ Archived to Cloud</span>
            ${status.archivedAt
              ? `<span class="archive-date">${new Date(status.archivedAt).toLocaleString()}</span>`
              : ''}
          </div>
          <button class="btn btn-ghost btn-sm" id="btn-view-cloud-pdf">View →</button>
        `;
        document.getElementById('btn-view-cloud-pdf')?.addEventListener('click', _openCloudPdf);
      }
      toast('PDF archived to Tahlk Cloud.');
    } catch (e) {
      toast(e.message || 'Archive failed.');
      btn.disabled = false;
      btn.textContent = '☁ Archive to Cloud';
    }
  });
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

function statusLabel(status) {
  return { new: 'New', recording: 'Recording', recording_done: 'Recorded', transcribing: 'Transcribing',
           draft: 'Draft', signed: 'Signed', exported: 'Exported' }[status] || status;
}
