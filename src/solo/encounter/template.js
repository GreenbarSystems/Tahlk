// Encounter-panel HTML template + status-banner helpers.
//
// Kept as one contiguous template because the two-column layout has no
// meaningful reuse to extract. Behavior lives in the sibling *Section.js
// modules; this file is DOM-string generation only.

import { kvGet } from '../../core/storageBackend.js';
import { keys } from '../../data/keys.js';
import { loadDraft } from '../../editor/noteEditor.js';
import { listTemplates, defaultTemplateId } from '../../templates/templateLibrary.js';
import { specialtyFamily } from '../../domain/specialties.js';
import { displayDate, escapeHtml, statusLabel } from '../../utils/format.js';
import { iconCheck, iconClose } from '../icons.js';

export const TRANSCRIPT_KEY = keys.noteTranscript;

// Export presets whose brand names only make sense to behavioral-health
// providers. Plain text is specialty-agnostic and always offered. The
// underlying formatters (exportFormatter.js) stay available regardless — this
// only governs which presets are SHOWN, so a podiatrist isn't offered two EHR
// brand names ("SimplePractice"/"TherapyNotes") that mean nothing to them.
const BEHAVIORAL_HEALTH_EXPORTS = [
  { value: 'simplepractice', label: 'SimplePractice' },
  { value: 'therapynotes',   label: 'TherapyNotes' },
];

// Disclosure copy for file-based note export (Save File / Save as PDF).
// export_note_to_file / export_note_pdf_to_file (src-tauri/src/export.rs)
// write plaintext to a location the provider picks via the OS Save-As
// dialog — outside Tahlk's own encrypted storage (SQLCipher DB, AES-256-GCM
// audio) and outside the app's control from that point on. This is
// documented and accepted in AUDIT-RESIDUAL-RISK.md "Item 1" on the
// condition that this disclosure stays visible; do not remove or silence it
// without updating that document. Shown as persistent helper text (not a
// dismissible one-time modal) because the risk applies to every export, not
// just the first one.
const EXPORT_DISCLOSURE_TEXT =
  'Exported files are not encrypted by Tahlk. Save only to an encrypted device or secure location — you are responsible for protecting this file once it leaves the app.';
const EXPORT_DISCLOSURE_TITLE =
  'Exported files are not encrypted by Tahlk — save only to an encrypted device or secure location.';

// Build the <option> list for the export-format selector, filtered to the
// provider's specialty. Behavioral-health-specific presets appear only for
// behavioral-health-family specialties; everyone always gets Plain text.
export function exportFormatOptions(providerSpecialty) {
  const options = [{ value: 'plain', label: 'Plain text' }];
  if (specialtyFamily(providerSpecialty) === 'behavioral-health') {
    options.push(...BEHAVIORAL_HEALTH_EXPORTS);
  }
  return options
    .map(o => `<option value="${escapeHtml(o.value)}">${escapeHtml(o.label)}</option>`)
    .join('');
}

export function renderEncounterPanel(encounter) {
  const isSigned = encounter.status === 'signed';
  const draft = loadDraft(encounter.id) || '';
  const transcript = kvGet(TRANSCRIPT_KEY(encounter.id)) || '';
  const providerSpecialty = (kvGet(keys.provider()) || {}).specialty;
  const templates = listTemplates(providerSpecialty);
  const defaultId = defaultTemplateId(providerSpecialty);
  const exportOptions = exportFormatOptions(providerSpecialty);

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
        <button class="btn btn-ghost btn-sm" id="btn-close-panel">${iconClose()} Close</button>
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
              ${encounter.audio_path ? `<span class="audio-saved">${iconCheck()} Audio saved</span>` : ''}
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
                    ${templates.map(t => `<option value="${escapeHtml(t.id)}"${t.id === defaultId ? ' selected' : ''}>${escapeHtml(t.name)}</option>`).join('')}
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
                ? `<span class="signed-badge">${iconCheck()} Signed</span>`
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
                    ${exportOptions}
                  </select>
                  <button class="btn btn-secondary btn-sm" id="btn-copy" ${!draft ? 'disabled' : ''}>Copy</button>
                  <button class="btn btn-secondary btn-sm" id="btn-save-file" ${!draft ? 'disabled' : ''} title="${EXPORT_DISCLOSURE_TITLE}">Save File</button>
                  <button class="btn btn-secondary btn-sm" id="btn-save-pdf" ${!draft ? 'disabled' : ''} title="${EXPORT_DISCLOSURE_TITLE}">Save as PDF</button>
                </div>
                <p class="settings-desc export-disclosure">${EXPORT_DISCLOSURE_TEXT}</p>
              ` : `
                <div class="signed-export-row">
                  <span class="signed-at">Signed ${escapeHtml(displayDate(encounter.signed_at))}</span>
                  <div class="export-controls">
                    <select id="export-format">
                      ${exportOptions}
                    </select>
                    <button class="btn btn-secondary btn-sm" id="btn-copy">Copy</button>
                    <button class="btn btn-secondary btn-sm" id="btn-save-file" title="${EXPORT_DISCLOSURE_TITLE}">Save File</button>
                    <button class="btn btn-secondary btn-sm" id="btn-save-pdf" title="${EXPORT_DISCLOSURE_TITLE}">Save as PDF</button>
                    ${encounter.audio_path
                      ? '<button class="btn btn-ghost btn-danger btn-sm" id="btn-purge-audio" title="Delete the recorded audio from this device">Delete Audio</button>'
                      : ''}
                  </div>
                  <p class="settings-desc export-disclosure">${EXPORT_DISCLOSURE_TEXT}</p>
                </div>
                ${encounter.signed_hash ? `
                  <div class="integrity-block">
                    <span class="trust-indicator">${iconCheck()} Tamper-evident record</span>
                    <details class="integrity-details">
                      <summary>View integrity details</summary>
                      <p class="hash-display">SHA-256: <code>${escapeHtml(encounter.signed_hash)}</code></p>
                    </details>
                  </div>
                ` : ''}
              `}
              <div class="danger-zone">
                <button class="btn btn-ghost btn-danger btn-sm" id="btn-delete-encounter"
                        title="Permanently delete this encounter, its note, and its transcript">Delete Encounter</button>
              </div>
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
