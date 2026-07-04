// Encounter-panel HTML template + status-banner helpers.
//
// Kept as one contiguous template because the two-column layout has no
// meaningful reuse to extract. Behavior lives in the sibling *Section.js
// modules; this file is DOM-string generation only.

import { kvGet } from '../../core/storageBackend.js';
import { keys } from '../../data/keys.js';
import { loadDraft } from '../../editor/noteEditor.js';
import { listTemplates } from '../../templates/templateLibrary.js';
import { displayDate, escapeHtml, statusLabel } from '../../utils/format.js';

export const TRANSCRIPT_KEY = keys.noteTranscript;

export function renderEncounterPanel(encounter) {
  const isSigned = encounter.status === 'signed';
  const draft = loadDraft(encounter.id) || '';
  const transcript = kvGet(TRANSCRIPT_KEY(encounter.id)) || '';
  const templates = listTemplates();

  return `
    <div class="panel encounter-panel" data-encounter-id="${escapeHtml(encounter.id)}">

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
                  <span class="signed-at">Signed ${escapeHtml(displayDate(encounter.signed_at))}</span>
                  <div class="export-controls">
                    <select id="export-format">
                      <option value="plain">Plain text</option>
                      <option value="simplepractice">SimplePractice</option>
                      <option value="therapynotes">TherapyNotes</option>
                    </select>
                    <button class="btn btn-secondary btn-sm" id="btn-copy">Copy</button>
                    <button class="btn btn-secondary btn-sm" id="btn-save-file">Save File</button>
                    ${encounter.audio_path
                      ? '<button class="btn btn-ghost btn-danger btn-sm" id="btn-purge-audio" title="Delete the recorded audio from this device">Delete Audio</button>'
                      : ''}
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

export function setStatus(msg) {
  const el = document.getElementById('status-banner');
  if (!el) return;
  el.textContent = msg;
  el.style.display = 'block';
}

export function clearStatus() {
  const el = document.getElementById('status-banner');
  if (el) el.style.display = 'none';
}
