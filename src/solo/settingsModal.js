// Settings modal — provider profile, API key, Whisper model management.

import { kvGet, kvSetCacheOnly, kvEnsure } from '../core/storageBackend.js';
import { invoke } from '../platform/tauri.js';
import { secretsRepo } from '../data/secretsRepo.js';
import { baaRepo } from '../data/baa.js';
import { keys } from '../data/keys.js';
import * as telemetry from '../core/telemetry.js';
import { toast, escapeHtml } from '../utils/format.js';
import { userMessage } from '../platform/appError.js';
import { PICKER_SPECIALTIES } from '../domain/specialties.js';
import { getAudioRetention, setAudioRetention } from '../domain/retention.js';
import { retentionRepo } from '../data/retentionRepo.js';
import { verifyAllChains } from '../domain/historyChain.js';
import { checkLlmAuditDrift, describeDrift } from '../domain/llmAuditDrift.js';
import { iconCheck } from './icons.js';
// In-app dialogs, not the browser-native confirm()/prompt(). Those block the
// WebView's event loop and are not implemented in every configuration Tauri
// ships on — where prompt() is stubbed it returns null unconditionally, which
// made the typed-name confirmation below impossible to satisfy.
import { confirmModal, promptModal } from './confirmModal.js';
import { lockRepo } from '../data/lockRepo.js';
import { authRepo } from '../data/authRepo.js';
import { showRegenCodesFlow } from './authScreen.js';
import {
  DEFAULT_TIMEOUT_MINUTES,
  isLockEnabled,
  setLockEnabled,
  getLockTimeoutMinutes,
  setLockTimeoutMinutes,
} from '../core/idleLock.js';

const PROVIDER_KEY = keys.provider();

// Disclosure for the diagnostics log export button. NOTE this is narrower
// than the note-export disclosure in src/solo/encounter/template.js: the
// diagnostics log itself contains no PHI by design (telemetry.js's
// scrubProps() allowlists only numbers/booleans/6 non-PHI string keys, and
// recordError() truncates through already-hardened Rust error paths — see
// AUDIT-RESIDUAL-RISK.md Item 1 verification notes). So this only needs to
// disclose that the exported FILE is unencrypted at rest — it must NOT imply
// the log contains patient data, which would contradict the "No patient
// data...are ever recorded" copy directly above it.
const DIAG_EXPORT_DISCLOSURE =
  'This log contains no patient data, but the exported file itself is not encrypted — save it only to a secure location.';

export async function renderSettings() {
  const provider = kvGet(PROVIDER_KEY) || {};
  const hasKey = await secretsRepo.hasApiKey().catch(() => false);
  await kvEnsure([keys.diagEvents()]);          // load any persisted diagnostics for the count
  const diagOn = telemetry.isEnabled();
  const diagCount = telemetry.getEvents().length;
  const retention = getAudioRetention();
  // BAA status may be `null` (never acknowledged) or a row for the current
  // attestation version. `.catch` swallows transport errors so the pane still
  // renders — the section then shows as “not acknowledged”, which is the
  // fail-closed default and matches what the Rust gate would enforce anyway.
  const baaAck = await baaRepo.getStatus().catch(() => null);
  const baaAcked = !!(baaAck && baaAck.acknowledged);
  const pinSet = await lockRepo.isPinSet().catch(() => false);
  const lockOn = isLockEnabled();
  const lockTimeout = getLockTimeoutMinutes();
  const retentionYears = await retentionRepo.getYears().catch(() => 7);
  const retentionHold = await retentionRepo.getHold().catch(() => false);
  return `
    <div class="settings-page">
      <h2 class="settings-title">Settings</h2>

      <section class="settings-section">
        <h3>Your profile</h3>
        <p class="settings-desc">Your name appears as the signer on every note.</p>
        <div class="field-row">
          <label>Full name</label>
          <input type="text" id="s-name" value="${escapeHtml(provider.name || '')}" placeholder="Dr. Jane Smith" />
        </div>
        <div class="field-row">
          <label>Credentials</label>
          <input type="text" id="s-creds" value="${escapeHtml(provider.credentials || '')}" placeholder="MD, PMHNP-BC…" />
        </div>
        <div class="field-row">
          <label>Specialty</label>
          <select id="s-specialty">
            ${PICKER_SPECIALTIES.map(s =>
              `<option value="${s.value}" ${provider.specialty === s.value ? 'selected' : ''}>${escapeHtml(s.label)}</option>`
            ).join('')}
          </select>
        </div>
        <button class="btn btn-primary" id="s-save-provider">Save profile</button>
      </section>

      <section class="settings-section">
        <h3>Screen lock</h3>
        <p class="settings-desc">
          Automatically locks the screen after a period of inactivity, so a laptop left unattended
          between patients doesn't sit open with a note or transcript on screen. Set a PIN here — separate
          from your computer's password — to unlock it. Pauses while you're recording.
        </p>
        <div class="baa-status-row">
          <span class="baa-status-pill ${pinSet ? 'baa-status-pill--ok' : 'baa-status-pill--danger'}" id="s-lock-status-pill">
            ${pinSet ? 'PIN set' : 'No PIN set'}
          </span>
        </div>

        <div class="field-row">
          <label id="s-lock-pin-label">${pinSet ? 'New PIN' : 'Set PIN'}</label>
          <input type="password" id="s-lock-pin" inputmode="numeric" autocomplete="off"
                 placeholder="At least 4 digits" />
        </div>
        <div class="field-row">
          <label>Confirm PIN</label>
          <input type="password" id="s-lock-pin-confirm" inputmode="numeric" autocomplete="off" />
        </div>
        <button class="btn btn-primary" id="s-lock-save-pin">${pinSet ? 'Change PIN' : 'Set PIN'}</button>
        ${pinSet ? '<button class="btn btn-ghost btn-danger" id="s-lock-remove-pin">Remove PIN</button>' : ''}

        <label class="diag-toggle" style="margin-top:16px">
          <input type="checkbox" id="s-lock-enabled" ${lockOn ? 'checked' : ''} ${pinSet ? '' : 'disabled'} />
          <span id="s-lock-toggle-text">Lock automatically after inactivity${pinSet ? '' : ' (set a PIN first)'}</span>
        </label>
        <div class="field-row">
          <label>Lock after (minutes)</label>
          <input type="number" id="s-lock-timeout" min="1" max="60" value="${Number(lockTimeout)}"
                 ${pinSet ? '' : 'disabled'} />
        </div>
        <p class="settings-desc">Default: ${DEFAULT_TIMEOUT_MINUTES} minutes.</p>
      </section>

      <section class="settings-section">
        <h3>Account security</h3>
        <p class="settings-desc">
          Your Tahlk password protects access to this device's patient records.
          <span class="baa-status-pill baa-status-pill--ok" style="margin-left:8px">Password set</span>
        </p>

        <div class="settings-subsection">
          <h4 class="settings-sub-h">Change password</h4>
          <div class="field-row">
            <label for="s-auth-old-pw">Current password</label>
            <input id="s-auth-old-pw" type="password" autocomplete="current-password" />
          </div>
          <div class="field-row">
            <label for="s-auth-new-pw">New password</label>
            <input id="s-auth-new-pw" type="password" autocomplete="new-password" />
            <div class="auth-strength-row" id="s-auth-strength-row" hidden>
              <div class="auth-strength-bar">
                <div class="auth-strength-fill" id="s-auth-strength-fill"></div>
              </div>
              <span class="auth-strength-label" id="s-auth-strength-label"></span>
            </div>
          </div>
          <div class="field-row">
            <label for="s-auth-new-pw2">Confirm new password</label>
            <input id="s-auth-new-pw2" type="password" autocomplete="new-password" />
          </div>
          <p class="auth-error" id="s-auth-pw-error" hidden></p>
          <button class="btn btn-secondary" id="s-auth-change-pw">Change password</button>
        </div>

        <div class="settings-subsection" style="margin-top:16px">
          <h4 class="settings-sub-h">Recovery codes</h4>
          <p class="settings-desc">
            Any of your three recovery codes restores access to your records if you forget
            your password. Regenerating replaces all three immediately — old codes stop working.
          </p>
          <button class="btn btn-secondary" id="s-auth-regen-codes">
            Regenerate recovery codes…
          </button>
        </div>
      </section>

      <section class="settings-section">
        <h3>AI note generation</h3>
        <p class="settings-desc">
          When you finish recording a visit, Tahlk turns the transcript into a structured clinical note in
          the template you choose — a SOAP note, a psychiatric evaluation, a medication-management
          follow-up, and more. You review and edit every note, then sign it yourself; nothing is finalized
          automatically. This is powered by Anthropic's Claude; the key that connects to it is set up under
          <strong>Advanced &amp; troubleshooting</strong> below.
        </p>
      </section>

      <section class="settings-section">
        <h3>Agreements (BAA &amp; EULA)</h3>
        <p class="settings-desc">
          Using Tahlk with real patient information is covered by two agreements between your organization
          and <strong>Greenbar Systems</strong>, the maker of Tahlk: a <strong>Business Associate Agreement
          (BAA)</strong> setting out how protected health information is handled under HIPAA, and an
          <strong>End User License Agreement (EULA)</strong> covering your use of the app. Confirm below
          once both are in place. During the current beta (test data only), this is optional.
        </p>
        <div class="baa-status-row">
          <span class="baa-status-pill ${baaAcked ? 'baa-status-pill--ok' : 'baa-status-pill--danger'}">
            ${baaAcked ? 'Confirmed' : 'Not confirmed'}
          </span>
          ${baaAcked && baaAck.acknowledged_at
            ? `<span class="settings-desc">on ${escapeHtml(baaAck.acknowledged_at)}${baaAck.provider_id ? ` by ${escapeHtml(baaAck.provider_id)}` : ''}</span>`
            : ''}
        </div>
        <label class="baa-toggle">
          <input type="checkbox" id="s-baa-ack" ${baaAcked ? 'checked' : ''} />
          <span>My organization has accepted Greenbar Systems' BAA and EULA.</span>
        </label>
      </section>

      <section class="settings-section">
        <h3>Audio recordings</h3>
        <p class="settings-desc">
          Choose what happens to the audio recording after you sign a note. Your note, transcript, and
          history are always kept either way.
        </p>
        <label class="retention-option">
          <input type="radio" name="s-audio-retention" value="keep" ${retention === 'keep' ? 'checked' : ''} />
          <span><strong>Keep recordings</strong> — audio stays on this device so you can re-transcribe later. (Default.)</span>
        </label>
        <label class="retention-option">
          <input type="radio" name="s-audio-retention" value="delete_on_sign" ${retention === 'delete_on_sign' ? 'checked' : ''} />
          <span><strong>Delete after signing</strong> — remove the audio recording as soon as you sign each note.</span>
        </label>
      </section>

      <section class="settings-section">
        <h3>Privacy &amp; data retention</h3>
        <p class="settings-desc">
          HIPAA requires covered entities to retain records for at least 6 years; many state laws require
          7 or 10. Set your practice's retention window here. Tahlk can identify encounter records that have
          aged past that window so you can permanently destroy them. A <strong>litigation hold</strong>
          suspends all retention-based deletion when legal matters require preserving records beyond the
          normal window.
        </p>
        <div class="field-row">
          <label for="s-retention-years">Keep records for at least</label>
          <select id="s-retention-years">
            ${[5, 6, 7, 10, 15].map(y =>
              `<option value="${y}" ${retentionYears === y ? 'selected' : ''}>${y} year${y === 7 ? ' (default)' : ''}</option>`
            ).join('')}
          </select>
        </div>
        <label class="diag-toggle">
          <input type="checkbox" id="s-retention-hold" ${retentionHold ? 'checked' : ''} />
          <span>Litigation hold — suspend all retention-based deletion</span>
        </label>
        <button class="btn btn-secondary" id="s-retention-check" style="margin-top:12px">
          Check for records due for deletion
        </button>
        <div id="s-retention-result" class="settings-desc" style="margin-top:8px"></div>
      </section>

      <section class="settings-section settings-section--muted">
        <h3>Where your data is stored</h3>
        <p class="settings-desc">
          Your recordings, transcripts, and notes all stay on this device — nothing is sent to Tahlk, ever.
          The one thing that leaves your computer is a visit transcript sent to Anthropic to generate a note.
        </p>
      </section>

      <details class="settings-advanced">
        <summary>Advanced &amp; troubleshooting</summary>

        <section class="settings-section">
          <h3>Speech recognition</h3>
          <p class="settings-desc">Turns your recordings into text right on this device — your audio never leaves your computer to be transcribed.</p>
          <div class="model-status-row">
            <span class="model-status-icon">${iconCheck()}</span>
            <span>Included with Tahlk — ready to use</span>
          </div>
        </section>

        <section class="settings-section">
          <h3>Anthropic API key</h3>
          <p class="settings-desc">
            The key that connects Tahlk to Anthropic's Claude for note generation. Paste it here — it's
            stored securely on this device and never sent to Tahlk.
            <br>Status: ${hasKey ? '<strong>Key added</strong>' : '<strong style="color:var(--danger)">No key yet</strong>'}
          </p>
          <div class="field-row">
            <label>Anthropic API key</label>
            <input type="password" id="s-apikey" value="${hasKey ? '••••••••••••' : ''}"
                   placeholder="sk-ant-…" autocomplete="off" />
          </div>
          <button class="btn btn-primary" id="s-save-apikey">Save key</button>
          ${hasKey ? '<button class="btn btn-ghost btn-danger" id="s-clear-apikey">Remove key</button>' : ''}
          <p class="step-hint"><a href="https://console.anthropic.com" target="_blank" rel="noreferrer noopener">Get a key at console.anthropic.com →</a></p>
        </section>

        <section class="settings-section">
          <h3>Usage &amp; error reporting</h3>
          <p class="settings-desc">
            Off by default. When on, Tahlk keeps basic app activity and error information
            <strong>on this device only</strong> to help diagnose problems.
            <strong>No patient data, transcripts, notes, or audio</strong> is ever included, and nothing is
            sent anywhere automatically. You can export it to share with support.
          </p>
          <label class="diag-toggle">
            <input type="checkbox" id="s-diag-enabled" ${diagOn ? 'checked' : ''} />
            <span>Keep usage &amp; error reporting on this device</span>
          </label>
          <div class="diag-actions">
            <span class="settings-desc" id="s-diag-count">${diagCount} event${diagCount === 1 ? '' : 's'} stored</span>
            <button class="btn btn-secondary btn-sm" id="s-diag-export" ${diagCount === 0 ? 'disabled' : ''} title="${DIAG_EXPORT_DISCLOSURE}">Export</button>
            <button class="btn btn-ghost btn-sm" id="s-diag-clear" ${diagCount === 0 ? 'disabled' : ''}>Clear</button>
          </div>
          <p class="settings-desc export-disclosure">${DIAG_EXPORT_DISCLOSURE}</p>
        </section>

        <section class="settings-section">
          <h3>Note history</h3>
          <p class="settings-desc">
            Tahlk keeps a secure, tamper-evident record of every change to a note. Run a check to confirm
            none of your saved notes have been altered. It only reads your data — it can't change or repair
            anything.
          </p>
          <button class="btn btn-secondary" id="s-verify-chains">Check note records</button>
          <div id="s-verify-chains-result" class="settings-desc"></div>
        </section>

        <section class="settings-section">
          <h3>AI performance</h3>
          <p class="settings-desc">
            Tahlk keeps an eye on how the AI is performing. Run a check to compare your recent notes for
            changes like slower responses or more failures, so you can catch a problem early. It only reads
            your own recent activity.
          </p>
          <button class="btn btn-secondary" id="s-check-drift">Check AI performance</button>
          <div id="s-check-drift-result" class="settings-desc"></div>
        </section>

        <section class="settings-section">
          <h3>Destruction log</h3>
          <p class="settings-desc">
            A permanent, append-only record of every PHI deletion — required by HIPAA §164.530(j).
            Includes patient-record cascades, individual encounter deletes, and retention-based
            purges. This log cannot be cleared or modified.
          </p>
          <div class="diag-actions">
            <button class="btn btn-secondary btn-sm" id="s-destlog-load">View log</button>
            <button class="btn btn-secondary btn-sm" id="s-destlog-export" hidden>Export CSV</button>
          </div>
          <div id="s-destlog-result" style="margin-top:8px"></div>
        </section>
      </details>
    </div>
  `;
}

// Reflects PIN-set vs PIN-unset across the Screen Lock section's static
// controls, so the two states can't drift apart. Both the set-PIN and
// remove-PIN handlers previously carried their own mirror-image ladder over
// these same six elements, which meant every copy had to be kept in sync by
// hand — add a control to one branch, forget the other, and the pane silently
// lies about whether a PIN exists.
//
// Deliberately does NOT own the Remove-PIN button: that one is mounted and
// unmounted (not just relabelled), and its handler has to be wired at mount
// time, so it stays with the callers that own that lifecycle.
function setLockPinUiState(hasPin) {
  const pill = document.getElementById('s-lock-status-pill');
  if (pill) {
    pill.textContent = hasPin ? 'PIN set' : 'No PIN set';
    pill.classList.toggle('baa-status-pill--ok', hasPin);
    pill.classList.toggle('baa-status-pill--danger', !hasPin);
  }

  const saveBtn = document.getElementById('s-lock-save-pin');
  if (saveBtn) saveBtn.textContent = hasPin ? 'Change PIN' : 'Set PIN';

  const pinLabel = document.getElementById('s-lock-pin-label');
  if (pinLabel) pinLabel.textContent = hasPin ? 'New PIN' : 'Set PIN';

  const toggleText = document.getElementById('s-lock-toggle-text');
  if (toggleText) {
    toggleText.textContent = hasPin
      ? 'Lock automatically after inactivity'
      : 'Lock automatically after inactivity (set a PIN first)';
  }

  // The enable toggle and timeout are meaningless without a PIN to unlock
  // with, so they follow the PIN's presence.
  for (const id of ['s-lock-enabled', 's-lock-timeout']) {
    const el = document.getElementById(id);
    if (!el) continue;
    if (hasPin) el.removeAttribute('disabled');
    else el.setAttribute('disabled', '');
  }

  // Losing the PIN also turns the feature off, not just greys it out — a
  // checked-but-disabled box would misrepresent whether locking is active.
  if (!hasPin) {
    const enabledCheckbox = document.getElementById('s-lock-enabled');
    if (enabledCheckbox) enabledCheckbox.checked = false;
  }
}

// Wires a button that runs one async check and renders its outcome into a
// result element: disable + busy label, clear the last result, run, restore on
// the way out whether it threw or not.
//
// `run` receives the result element and owns everything specific to its check —
// what to await and how to describe the outcome. Everything around it (the
// busy/restore dance, the failure toast) was previously duplicated verbatim
// between the two diagnostics buttons below.
function wireAsyncActionButton({ id, resultId, busyLabel, idleLabel, failPrefix, run }) {
  document.getElementById(id)?.addEventListener('click', async e => {
    const btn = e.currentTarget;
    const resultEl = document.getElementById(resultId);
    btn.setAttribute('disabled', '');
    btn.textContent = busyLabel;
    if (resultEl) resultEl.textContent = '';
    try {
      await run(resultEl);
    } catch (err) {
      if (resultEl) resultEl.textContent = '';
      toast(`${failPrefix}: ${userMessage(err, 'unknown error')}`);
    } finally {
      // Always restore, even if the panel was torn down mid-run — the button
      // must never be left stuck on its busy label.
      btn.removeAttribute('disabled');
      btn.textContent = idleLabel;
    }
  });
}

function renderDestructionLogTable(rows) {
  // Static header written inline (not via a variable) so the HTML-escape build
  // guard can see it is a literal, not an interpolated value to escape.
  const body = rows.map(r => `<tr>
    <td>${escapeHtml(r.created_at.slice(0, 10))}</td>
    <td>${escapeHtml(r.provider_id)}</td>
    <td>${escapeHtml(r.entity_type)}</td>
    <td>${escapeHtml(r.patient_alias || r.entity_id)}</td>
    <td>${escapeHtml(r.legal_basis)}</td>
    <td>${Number(r.records_scrubbed)}</td>
  </tr>`).join('');
  return `<div class="destlog-table-wrap"><table class="destlog-table"><tr>
    <th>Date</th><th>Provider</th><th>Type</th><th>Patient</th><th>Basis</th><th>Records</th>
  </tr>${body}</table></div>`;
}

// Quote a CSV cell, neutralising spreadsheet formula injection.
//
// Quote-doubling alone only makes the file parse correctly; it does nothing
// about Excel, LibreOffice and Sheets treating a leading =, +, - or @ as the
// start of a formula. provider_id and patient_alias are provider-entered free
// text, so a value like `=HYPERLINK("http://evil","click")` executes when the
// compliance export is opened — and this is the destruction log, the file an
// auditor is most likely to open. Prefixing an apostrophe forces the cell to
// text in every major spreadsheet without altering the value a CSV parser
// reads back after unquoting... except the apostrophe itself, which is why it
// is applied only to cells that would otherwise be interpreted.
//
// Tab and carriage return are included because both can lead a formula once a
// spreadsheet trims leading whitespace.
function csvCell(v) {
  const s = String(v ?? '');
  const needsGuard = /^[=+\-@\t\r]/.test(s);
  const guarded = needsGuard ? `'${s}` : s;
  return `"${guarded.replace(/"/g, '""')}"`;
}

function destructionLogToCsv(rows) {
  const header = 'date,provider_id,entity_type,entity_id,patient_alias,legal_basis,records_scrubbed';
  const body = rows.map(r => [
    r.created_at.slice(0, 10),
    r.provider_id,
    r.entity_type,
    r.entity_id,
    r.patient_alias || '',
    r.legal_basis,
    r.records_scrubbed,
  ].map(csvCell).join(',')).join('\n');
  return `${header}\n${body}`;
}

const STRENGTH_LABELS = ['', 'Weak', 'Fair', 'Good', 'Strong'];
const STRENGTH_COLORS = ['', 'var(--danger)', 'var(--warn)', 'var(--teal)', 'var(--green)'];
const AUTH_PASSWORD_MIN_LEN = 12;

function settingsPasswordStrength(pw) {
  if (!pw || pw.length < 4) return 0;
  let s = 0;
  if (pw.length >= AUTH_PASSWORD_MIN_LEN) s++;
  if (pw.length >= 20) s++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) s++;
  if (/\d/.test(pw)) s++;
  if (/[^A-Za-z0-9]/.test(pw)) s++;
  return Math.min(s, 4);
}

export function wireSettings() {
  // ── Account security ────────────────────────────────────────────────────────

  const newPwInput = document.getElementById('s-auth-new-pw');
  if (newPwInput) {
    newPwInput.addEventListener('input', () => {
      const s = settingsPasswordStrength(newPwInput.value);
      const row = document.getElementById('s-auth-strength-row');
      const fill = document.getElementById('s-auth-strength-fill');
      const label = document.getElementById('s-auth-strength-label');
      if (row) row.hidden = !newPwInput.value;
      if (fill) { fill.style.width = `${s * 25}%`; fill.style.background = STRENGTH_COLORS[s] || ''; }
      if (label) { label.textContent = STRENGTH_LABELS[s] || ''; label.style.color = STRENGTH_COLORS[s] || ''; }
    });
  }

  document.getElementById('s-auth-change-pw')?.addEventListener('click', async () => {
    const oldPw = document.getElementById('s-auth-old-pw')?.value || '';
    const newPw = document.getElementById('s-auth-new-pw')?.value || '';
    const newPw2 = document.getElementById('s-auth-new-pw2')?.value || '';
    const errorEl = document.getElementById('s-auth-pw-error');
    const btn = document.getElementById('s-auth-change-pw');

    function showErr(msg) { if (errorEl) { errorEl.textContent = msg; errorEl.hidden = false; } }
    if (errorEl) errorEl.hidden = true;

    if (!oldPw) { showErr('Enter your current password.'); return; }
    if (!newPw) { showErr('Enter a new password.'); return; }
    if (newPw.length < AUTH_PASSWORD_MIN_LEN) {
      showErr(`New password must be at least ${AUTH_PASSWORD_MIN_LEN} characters.`); return;
    }
    if (newPw !== newPw2) { showErr('New passwords do not match.'); return; }

    btn.disabled = true;
    try {
      await authRepo.changePassword(oldPw, newPw);
      for (const id of ['s-auth-old-pw', 's-auth-new-pw', 's-auth-new-pw2']) {
        const el = document.getElementById(id);
        if (el) el.value = '';
      }
      const row = document.getElementById('s-auth-strength-row');
      if (row) row.hidden = true;
      toast('Password changed.');
    } catch (err) {
      showErr(userMessage(err, 'Could not change password. Check your current password and try again.'));
    } finally {
      btn.disabled = false;
    }
  });

  document.getElementById('s-auth-regen-codes')?.addEventListener('click', () => {
    showRegenCodesFlow();
  });

  // ── Provider profile ────────────────────────────────────────────────────────

  document.getElementById('s-save-provider')?.addEventListener('click', async () => {
    const profile = {
      name:        document.getElementById('s-name')?.value.trim() || '',
      credentials: document.getElementById('s-creds')?.value.trim() || '',
      specialty:   document.getElementById('s-specialty')?.value || 'psychiatry',
    };
    // Use the dedicated set_provider_profile command (C3 fix). Generic kv_set
    // is write-blocked for this key to prevent audit-identity forgery.
    // After the Rust write succeeds, sync the in-memory cache so subsequent
    // synchronous kvGet(keys.provider()) reads reflect the new value.
    try {
      await invoke('set_provider_profile', { profile });
      kvSetCacheOnly(PROVIDER_KEY, profile);
      toast('Profile saved.');
    } catch (e) {
      toast(`Could not save profile: ${userMessage(e, 'unknown error')}`);
    }
  });

  const apiKeyInput = document.getElementById('s-apikey');
  if (apiKeyInput) {
    apiKeyInput.addEventListener('focus', () => {
      if (apiKeyInput.value === '••••••••••••') apiKeyInput.value = '';
    });
    apiKeyInput.addEventListener('blur', async () => {
      if (!apiKeyInput.value.trim()) {
        const hasKey = await secretsRepo.hasApiKey().catch(() => false);
        if (hasKey) apiKeyInput.value = '••••••••••••';
      }
    });
  }

  document.getElementById('s-save-apikey')?.addEventListener('click', async () => {
    const val = document.getElementById('s-apikey')?.value.trim();
    if (!val || val === '••••••••••••') return;
    try {
      await secretsRepo.setApiKey(val);
      toast('API key saved.');
    } catch (e) {
      toast(`Could not save API key: ${userMessage(e, 'unknown error')}`);
    }
  });

  document.getElementById('s-clear-apikey')?.addEventListener('click', async () => {
    if (!await confirmModal({
    title: 'Remove API key?',
    message: 'Note generation will stop working until you add a key again.',
    confirmLabel: 'Remove key',
    confirmClass: 'btn-danger',
  })) return;
    try {
      await secretsRepo.clearApiKey();
      toast('API key removed.');
    } catch (e) {
      toast(`Could not remove API key: ${userMessage(e, 'unknown error')}`);
    }
  });

  // BAA toggle. Setting = write ack row with a fresh timestamp; unsetting =
  // clear the row. Copy is deliberately silent on whether this currently
  // blocks note generation — that's a Rust-side flag (baa::GATE_ENABLED,
  // see ADR 0003) this module can't see, and hardcoding "enabled/disabled"
  // language here is exactly what went stale when the beta gate was
  // soft-disabled. When the gate IS enforced, the Rust side still rejects
  // note generation the instant the row is missing, so a user can revoke and
  // immediately verify the app refuses to send further transcripts — no
  // restart or refresh required.
  document.getElementById('s-baa-ack')?.addEventListener('change', async e => {
    const checked = !!e.target.checked;
    try {
      if (checked) {
        const providerName =
          document.getElementById('s-name')?.value.trim() ||
          (kvGet(PROVIDER_KEY) || {}).name || '';
        await baaRepo.setAck({
          acknowledgedAt: new Date().toISOString(),
          providerId: providerName,
        });
        toast('Agreements confirmed.');
      } else {
        if (!await confirmModal({
          title: 'Remove your agreement confirmation?',
          message: 'Note generation is blocked until the BAA and EULA are confirmed again.',
          confirmLabel: 'Remove confirmation',
          confirmClass: 'btn-danger',
        })) {
          e.target.checked = true;
          return;
        }
        await baaRepo.clear();
        toast('Confirmation removed.');
      }
    } catch (err) {
      // Revert the checkbox visually since the write did not land.
      e.target.checked = !checked;
      toast(`Could not update: ${userMessage(err, 'unknown error')}`);
    }
  });

  document.getElementById('s-diag-enabled')?.addEventListener('change', e => {
    telemetry.setEnabled(e.target.checked);
    toast(e.target.checked ? 'Usage reporting on (this device only).' : 'Usage reporting off.');
  });

  document.getElementById('s-diag-export')?.addEventListener('click', async () => {
    try {
      await telemetry.exportLog();
      toast('Exported.');
    } catch (err) {
      toast(`Export failed: ${userMessage(err, 'unknown error')}`);
    }
  });

  document.getElementById('s-diag-clear')?.addEventListener('click', async () => {
    const ok = await confirmModal({
      title: 'Clear diagnostics?',
      message: 'Removes the usage and error reporting stored on this device. Clinical records are unaffected.',
      confirmLabel: 'Clear',
      confirmClass: 'btn-danger',
    });
    if (!ok) return;
    telemetry.clear();
    const count = document.getElementById('s-diag-count');
    if (count) count.textContent = '0 events stored';
    document.getElementById('s-diag-export')?.setAttribute('disabled', '');
    document.getElementById('s-diag-clear')?.setAttribute('disabled', '');
    toast('Cleared.');
  });

  document.querySelectorAll('input[name="s-audio-retention"]').forEach(el => {
    el.addEventListener('change', e => {
      if (!e.target.checked) return;
      try {
        setAudioRetention(e.target.value);
        toast(e.target.value === 'delete_on_sign'
          ? 'Audio will be deleted immediately after each sign-off.'
          : 'Audio will be kept on this device.');
      } catch (err) {
        toast(`Could not update retention: ${userMessage(err, 'unknown error')}`);
      }
    });
  });

  // Privacy & data retention.
  document.getElementById('s-retention-years')?.addEventListener('change', async e => {
    const years = Number(e.target.value);
    try {
      await retentionRepo.setYears(years);
      toast(`Retention window set to ${years} years.`);
    } catch (err) {
      toast(`Could not update retention window: ${userMessage(err, 'unknown error')}`);
    }
  });

  document.getElementById('s-retention-hold')?.addEventListener('change', async e => {
    const active = !!e.target.checked;
    try {
      await retentionRepo.setHold(active);
      toast(active
        ? 'Litigation hold active — retention-based deletion suspended.'
        : 'Litigation hold cleared.');
    } catch (err) {
      e.target.checked = !active;
      toast(`Could not update hold: ${userMessage(err, 'unknown error')}`);
    }
  });

  wireAsyncActionButton({
    id: 's-retention-check',
    resultId: 's-retention-result',
    busyLabel: 'Checking…',
    idleLabel: 'Check for records due for deletion',
    failPrefix: 'Could not check retention',
    run: async resultEl => {
      // Cutoff date is now server-side — no today argument needed.
      const candidates = await retentionRepo.listCandidates();
      if (!resultEl) return;
      if (candidates.length === 0) {
        resultEl.textContent = 'No signed records are past their retention window.';
        return;
      }
      const n = candidates.length;
      resultEl.innerHTML = `
        <strong>${escapeHtml(n)} signed encounter record${n === 1 ? '' : 's'} ${n === 1 ? 'is' : 'are'} past the retention window.</strong>
        <br>Oldest: ${escapeHtml(candidates[0].encounter_date)}
        ${candidates[0].patient_alias ? ` — ${escapeHtml(candidates[0].patient_alias)}` : ''}.
        <br><button class="btn btn-danger btn-sm" id="s-retention-destroy" style="margin-top:8px">
          Permanently delete ${escapeHtml(n)} record${n === 1 ? '' : 's'}…
        </button>
      `;
      document.getElementById('s-retention-destroy')?.addEventListener('click', async () => {
        // Require provider name confirmation before bulk destruction (Low finding L2).
        const providerName = (kvGet(PROVIDER_KEY) || {}).name || '';
        if (providerName) {
          const typed = await promptModal({
            title: `Permanently delete ${n} record${n === 1 ? '' : 's'}?`,
            message: 'Type your name to confirm. This is irreversible and will be recorded in the destruction log.',
            expected: providerName,
            placeholder: 'Your name',
            confirmLabel: 'Delete permanently',
            confirmClass: 'btn-danger',
          });
          // null means cancelled; a mismatch is a distinct outcome worth
          // naming, so the provider knows the click registered.
          if (typed === null) return;
          if (typed.trim() !== providerName.trim()) {
            toast('Name did not match — deletion cancelled.');
            return;
          }
        } else if (!await confirmModal({
          title: `Permanently delete ${n} record${n === 1 ? '' : 's'}?`,
          message: 'These encounters are past the retention window. This is irreversible and will be recorded in the destruction log.',
          confirmLabel: 'Delete permanently',
          confirmClass: 'btn-danger',
        })) {
          return;
        }
        const btn = document.getElementById('s-retention-destroy');
        if (btn) { btn.disabled = true; btn.textContent = 'Deleting…'; }
        try {
          const { destroyed } = await retentionRepo.destroyEligible();
          if (resultEl) resultEl.textContent = `${destroyed} record${destroyed === 1 ? '' : 's'} permanently deleted.`;
          toast(`${destroyed} record${destroyed === 1 ? '' : 's'} deleted.`);
        } catch (err) {
          if (btn) { btn.disabled = false; btn.textContent = `Permanently delete ${n} record${n === 1 ? '' : 's'}…`; }
          toast(`Deletion failed: ${userMessage(err, 'unknown error')}`);
        }
      });
    },
  });

  // Screen Lock. Setting/changing a PIN and removing it both flip several
  // dependent bits of UI — updated in place via setLockPinUiState rather than
  // re-rendering the whole settings pane, matching the diag-clear pattern
  // above.
  document.getElementById('s-lock-save-pin')?.addEventListener('click', async () => {
    const pinInput = document.getElementById('s-lock-pin');
    const confirmInput = document.getElementById('s-lock-pin-confirm');
    const pin = pinInput?.value || '';
    const confirmPin = confirmInput?.value || '';
    if (!pin || pin.length < 4) {
      toast('PIN must be at least 4 digits.');
      return;
    }
    if (pin !== confirmPin) {
      toast('PINs do not match.');
      return;
    }
    try {
      await lockRepo.setPin(pin);
      if (pinInput) pinInput.value = '';
      if (confirmInput) confirmInput.value = '';
      toast('Lock PIN saved.');
      setLockPinUiState(true);

      // Mount the Remove-PIN action if this was a first-time set.
      const saveBtn = document.getElementById('s-lock-save-pin');
      if (!document.getElementById('s-lock-remove-pin') && saveBtn) {
        const removeBtn = document.createElement('button');
        removeBtn.className = 'btn btn-ghost btn-danger';
        removeBtn.id = 's-lock-remove-pin';
        removeBtn.textContent = 'Remove PIN';
        saveBtn.insertAdjacentElement('afterend', removeBtn);
        wireLockRemoveButton(removeBtn);
      }
    } catch (err) {
      toast(`Could not save PIN: ${userMessage(err, 'unknown error')}`);
    }
  });

  function wireLockRemoveButton(btn) {
    btn.addEventListener('click', async () => {
      if (!await confirmModal({
    title: 'Remove your lock PIN?',
    message: 'Screen lock will be turned off, so the app will no longer lock itself when idle.',
    confirmLabel: 'Remove PIN',
    confirmClass: 'btn-danger',
  })) return;
      try {
        await lockRepo.clearPin();
        setLockEnabled(false);
        toast('Lock PIN removed.');
        setLockPinUiState(false);
        btn.remove();
      } catch (err) {
        toast(`Could not remove PIN: ${userMessage(err, 'unknown error')}`);
      }
    });
  }
  const existingRemoveBtn = document.getElementById('s-lock-remove-pin');
  if (existingRemoveBtn) wireLockRemoveButton(existingRemoveBtn);

  document.getElementById('s-lock-enabled')?.addEventListener('change', e => {
    setLockEnabled(e.target.checked);
    toast(e.target.checked ? 'Screen lock enabled.' : 'Screen lock disabled.');
  });

  document.getElementById('s-lock-timeout')?.addEventListener('change', e => {
    const n = Number(e.target.value);
    setLockTimeoutMinutes(n);
    e.target.value = getLockTimeoutMinutes();
    toast(`Lock timeout set to ${getLockTimeoutMinutes()} minute${getLockTimeoutMinutes() === 1 ? '' : 's'}.`);
  });

  wireAsyncActionButton({
    id: 's-verify-chains',
    resultId: 's-verify-chains-result',
    busyLabel: 'Checking…',
    idleLabel: 'Check note records',
    failPrefix: 'Could not check note records',
    run: async resultEl => {
      const { ok, checked, broken } = await verifyAllChains();
      if (checked === 0) {
        if (resultEl) resultEl.textContent = 'No saved notes yet — nothing to check.';
      } else if (ok) {
        if (resultEl) resultEl.textContent = `All ${checked} note record${checked === 1 ? '' : 's'} checked — no changes found.`;
        toast('Note records check passed.');
      } else {
        const detail = broken
          .map(b => `${escapeHtml(b.encounterId)} (${escapeHtml(b.reason || 'unknown')}${b.brokenAt != null ? `, entry #${Number(b.brokenAt)}` : ''})`)
          .join('; ');
        if (resultEl) {
          resultEl.innerHTML = `<strong style="color:var(--danger)">${broken.length} of ${checked} note record${checked === 1 ? '' : 's'} show a change:</strong> ${detail}`;
        }
        toast(`Note records check found ${broken.length} issue${broken.length === 1 ? '' : 's'} — see Settings.`);
      }
    },
  });

  wireAsyncActionButton({
    id: 's-check-drift',
    resultId: 's-check-drift-result',
    busyLabel: 'Checking…',
    idleLabel: 'Check AI performance',
    failPrefix: 'Could not check AI performance',
    run: async resultEl => {
      const { insufficientData, checked, findings } = await checkLlmAuditDrift();
      if (insufficientData) {
        if (resultEl) resultEl.textContent = `Not enough recent activity to compare yet (${checked} note${checked === 1 ? '' : 's'} so far).`;
      } else if (findings.length === 0) {
        if (resultEl) resultEl.textContent = `Checked your last ${checked} notes — nothing unusual.`;
        toast('AI performance check passed.');
      } else {
        const summary = describeDrift(findings);
        if (resultEl) resultEl.innerHTML = `<strong style="color:var(--danger)">${escapeHtml(summary)}</strong>`;
        toast('AI performance check flagged something — see Settings.', 6000);
      }
    },
  });

  // Destruction log — lazy-loaded on demand; never blocks settings render.
  let _destructionLogRows = null;

  document.getElementById('s-destlog-load')?.addEventListener('click', async () => {
    const loadBtn   = document.getElementById('s-destlog-load');
    const exportBtn = document.getElementById('s-destlog-export');
    const resultEl  = document.getElementById('s-destlog-result');
    if (loadBtn) { loadBtn.disabled = true; loadBtn.textContent = 'Loading…'; }
    try {
      _destructionLogRows = await invoke('destruction_log_list', { limit: 200 });
      if (resultEl) {
        if (_destructionLogRows.length === 0) {
          resultEl.textContent = 'No destruction events recorded yet.';
          if (exportBtn) exportBtn.hidden = true;
        } else {
          resultEl.innerHTML = renderDestructionLogTable(_destructionLogRows);
          if (exportBtn) exportBtn.hidden = false;
        }
      }
    } catch (err) {
      toast(`Could not load destruction log: ${userMessage(err, 'unknown error')}`);
    } finally {
      if (loadBtn) { loadBtn.disabled = false; loadBtn.textContent = 'Refresh'; }
    }
  });

  document.getElementById('s-destlog-export')?.addEventListener('click', async () => {
    if (!_destructionLogRows || _destructionLogRows.length === 0) return;
    const csv  = destructionLogToCsv(_destructionLogRows);
    const blob = new Blob([csv], { type: 'text/csv' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `destruction-log-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    // Audit the export event — records who exported the log and how many rows
    // were included (Low finding L4 closed).
    invoke('destruction_log_note_exported', { rowCount: _destructionLogRows.length }).catch(() => {});
  });
}

