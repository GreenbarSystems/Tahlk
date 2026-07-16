// Settings modal — provider profile, API key, Whisper model management.

import { kvGet, kvSet, kvEnsure } from '../core/storageBackend.js';
import { secretsRepo } from '../data/secretsRepo.js';
import { baaRepo } from '../data/baa.js';
import { keys } from '../data/keys.js';
import * as telemetry from '../core/telemetry.js';
import { toast, escapeHtml } from '../utils/format.js';
import { userMessage } from '../platform/appError.js';
import { PICKER_SPECIALTIES } from '../domain/specialties.js';
import { getAudioRetention, setAudioRetention } from '../domain/retention.js';
import { verifyAllChains } from '../domain/historyChain.js';
import { checkLlmAuditDrift, describeDrift } from '../domain/llmAuditDrift.js';
import { iconCheck } from './icons.js';
import { lockRepo } from '../data/lockRepo.js';
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

  return `
    <div class="settings-page">
      <h2 class="settings-title">Settings</h2>

      <section class="settings-section">
        <h3>Provider Profile</h3>
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
        <button class="btn btn-primary" id="s-save-provider">Save Profile</button>
      </section>

      <section class="settings-section">
        <h3>Transcription Model (Whisper)</h3>
        <p class="settings-desc">Local speech recognition — runs on this device. No audio sent to any server.</p>
        <div class="model-status-row">
          <span class="model-status-icon">${iconCheck()}</span>
          <span>Whisper base.en — included with Tahlk</span>
        </div>
      </section>

      <section class="settings-section">
        <h3>BAA acknowledgment</h3>
        <p class="settings-desc">
          During the current test-data-only beta, note generation does <strong>not</strong> require
          this acknowledgment (see ADR 0003) — this checkbox is optional. Before sending any real
          patient information, your organization needs an executed
          <strong>Business Associate Agreement (BAA)</strong> with Anthropic covering the API key
          configured below; recording it here now gives you an accurate local audit trail once that's
          in place.
        </p>
        <p class="settings-desc">
          This is <strong>your own organization's</strong> agreement with Anthropic for the API
          key entered in Settings below — not an agreement Greenbar Systems has with Anthropic on
          your behalf, and not a substitute for one. Tahlk cannot verify that a real, signed BAA
          exists; checking this box is your organization's own compliance record, and you remain
          responsible for keeping it accurate.
        </p>
        <div class="baa-status-row">
          <span class="baa-status-pill ${baaAcked ? 'baa-status-pill--ok' : 'baa-status-pill--danger'}">
            ${baaAcked ? 'Acknowledged' : 'Not acknowledged'}
          </span>
          ${baaAcked && baaAck.acknowledged_at
            ? `<span class="settings-desc">on ${escapeHtml(baaAck.acknowledged_at)}${baaAck.provider_id ? ` by ${escapeHtml(baaAck.provider_id)}` : ''}</span>`
            : ''}
        </div>
        <label class="baa-toggle">
          <input type="checkbox" id="s-baa-ack" ${baaAcked ? 'checked' : ''} />
          <span>I confirm my organization has an executed BAA with Anthropic covering the API key below.</span>
        </label>
        <p class="step-hint"><a href="https://support.anthropic.com/en/articles/8555474-i-need-a-business-associate-agreement-baa-with-anthropic-for-hipaa-compliance-what-do-i-do" target="_blank" rel="noreferrer noopener">How to request a BAA from Anthropic →</a></p>
      </section>

      <section class="settings-section">
        <h3>Note Generation (Anthropic API)</h3>
        <p class="settings-desc">
          Your API key is stored in your operating system's secure credential store (Keychain / Credential Manager) — not in Tahlk's database — and is used to call Anthropic's Claude model to generate clinical notes from transcripts.
          <br>Status: ${hasKey ? '<strong>Key configured</strong>' : '<strong style="color:var(--danger)">No key set</strong>'}
        </p>
        <div class="field-row">
          <label>Anthropic API key</label>
          <input type="password" id="s-apikey" value="${hasKey ? '••••••••••••' : ''}"
                 placeholder="sk-ant-…" autocomplete="off" />
        </div>
        <button class="btn btn-primary" id="s-save-apikey">Save Key</button>
        ${hasKey ? '<button class="btn btn-ghost btn-danger" id="s-clear-apikey">Remove Key</button>' : ''}
      </section>

      <section class="settings-section">
        <h3>Diagnostics</h3>
        <p class="settings-desc">
          Off by default. When on, Tahlk records app diagnostics <strong>on this device only</strong>
          — counts, durations, and error types. <strong>No patient data, transcripts, notes, or audio</strong>
          are ever recorded, and nothing is sent anywhere automatically. You can export the log to share with support.
        </p>
        <label class="diag-toggle">
          <input type="checkbox" id="s-diag-enabled" ${diagOn ? 'checked' : ''} />
          <span>Record diagnostics on this device</span>
        </label>
        <div class="diag-actions">
          <span class="settings-desc" id="s-diag-count">${diagCount} event${diagCount === 1 ? '' : 's'} stored</span>
          <button class="btn btn-secondary btn-sm" id="s-diag-export" ${diagCount === 0 ? 'disabled' : ''} title="${DIAG_EXPORT_DISCLOSURE}">Export Log</button>
          <button class="btn btn-ghost btn-sm" id="s-diag-clear" ${diagCount === 0 ? 'disabled' : ''}>Clear Log</button>
        </div>
        <p class="settings-desc export-disclosure">${DIAG_EXPORT_DISCLOSURE}</p>
      </section>

      <section class="settings-section">
        <h3>Audio Retention</h3>
        <p class="settings-desc">
          Choose what happens to session recordings after you sign a note. The signed note, transcript,
          and audit trail are kept in both modes — only the raw .wav file is affected.
        </p>
        <label class="retention-option">
          <input type="radio" name="s-audio-retention" value="keep" ${retention === 'keep' ? 'checked' : ''} />
          <span><strong>Keep recordings</strong> — audio stays on this device so you can re-transcribe later. (Default.)</span>
        </label>
        <label class="retention-option">
          <input type="radio" name="s-audio-retention" value="delete_on_sign" ${retention === 'delete_on_sign' ? 'checked' : ''} />
          <span><strong>Delete on sign</strong> — immediately delete the .wav from disk after each sign-off. Minimizes at-rest audio.</span>
        </label>
      </section>

      <section class="settings-section">
        <h3>Screen Lock</h3>
        <p class="settings-desc">
          Automatically locks the screen after a period of inactivity so a laptop left unattended
          between patients doesn't sit open with note or transcript content visible. Requires a
          PIN set here — not your operating system password — to resume. Suspended while a
          recording is in progress.
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
        <h3>Note History Chain Integrity</h3>
        <p class="settings-desc">
          Every note edit, sign-off, and export is recorded in a tamper-evident hash chain per encounter.
          The chain is checked automatically whenever a new entry is appended, but an encounter that hasn't
          been touched since it was signed never gets re-checked on its own. Run this to independently
          re-verify every stored chain right now — it only reads data and cannot modify or repair anything.
        </p>
        <button class="btn btn-secondary" id="s-verify-chains">Verify All Chains</button>
        <div id="s-verify-chains-result" class="settings-desc"></div>
      </section>

      <section class="settings-section">
        <h3>AI Call Health Check</h3>
        <p class="settings-desc">
          Every note-generation call to Anthropic is logged on this device (timing, size, success/failure —
          never the note content itself). Each call looking fine on its own can still hide a pattern, like a
          silent slowdown or a rise in failures. Run this to compare your most recent calls against your
          own recent history — it only reads the log and never changes anything.
        </p>
        <button class="btn btn-secondary" id="s-check-drift">Check for AI Drift</button>
        <div id="s-check-drift-result" class="settings-desc"></div>
      </section>

      <section class="settings-section settings-section--muted">
        <h3>Privacy</h3>
        <p class="settings-desc">Audio recordings are stored in your OS app data directory and never leave this device. Transcripts and notes are stored in a local SQLite database. Nothing is sent to Tahlk servers.</p>
      </section>
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

export function wireSettings() {
  document.getElementById('s-save-provider')?.addEventListener('click', () => {
    const profile = {
      name:        document.getElementById('s-name')?.value.trim() || '',
      credentials: document.getElementById('s-creds')?.value.trim() || '',
      specialty:   document.getElementById('s-specialty')?.value || 'psychiatry',
    };
    kvSet(PROVIDER_KEY, profile);
    toast('Profile saved.');
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
    if (!confirm('Remove the stored API key?')) return;
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
        toast('BAA acknowledgment recorded.');
      } else {
        if (!confirm('Remove your BAA acknowledgment record?')) {
          e.target.checked = true;
          return;
        }
        await baaRepo.clear();
        toast('BAA acknowledgment cleared.');
      }
    } catch (err) {
      // Revert the checkbox visually since the write did not land.
      e.target.checked = !checked;
      toast(`Could not update BAA: ${userMessage(err, 'unknown error')}`);
    }
  });

  document.getElementById('s-diag-enabled')?.addEventListener('change', e => {
    telemetry.setEnabled(e.target.checked);
    toast(e.target.checked ? 'Diagnostics on (this device only).' : 'Diagnostics off.');
  });

  document.getElementById('s-diag-export')?.addEventListener('click', async () => {
    try {
      await telemetry.exportLog();
      toast('Diagnostics log exported.');
    } catch (err) {
      toast(`Export failed: ${userMessage(err, 'unknown error')}`);
    }
  });

  document.getElementById('s-diag-clear')?.addEventListener('click', () => {
    if (!confirm('Clear the on-device diagnostics log?')) return;
    telemetry.clear();
    const count = document.getElementById('s-diag-count');
    if (count) count.textContent = '0 events stored';
    document.getElementById('s-diag-export')?.setAttribute('disabled', '');
    document.getElementById('s-diag-clear')?.setAttribute('disabled', '');
    toast('Diagnostics log cleared.');
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
      if (!confirm('Remove your lock PIN? Screen lock will be turned off.')) return;
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
    busyLabel: 'Verifying…',
    idleLabel: 'Verify All Chains',
    failPrefix: 'Could not verify chains',
    run: async resultEl => {
      const { ok, checked, broken } = await verifyAllChains();
      if (checked === 0) {
        if (resultEl) resultEl.textContent = 'No note history found yet — nothing to verify.';
      } else if (ok) {
        if (resultEl) resultEl.textContent = `All ${checked} encounter chain${checked === 1 ? '' : 's'} verified intact.`;
        toast('Chain integrity check passed.');
      } else {
        const detail = broken
          .map(b => `${escapeHtml(b.encounterId)} (${escapeHtml(b.reason || 'unknown')}${b.brokenAt != null ? `, entry #${Number(b.brokenAt)}` : ''})`)
          .join('; ');
        if (resultEl) {
          resultEl.innerHTML = `<strong style="color:var(--danger)">${broken.length} of ${checked} chain${checked === 1 ? '' : 's'} failed verification:</strong> ${detail}`;
        }
        toast(`Chain integrity check found ${broken.length} problem${broken.length === 1 ? '' : 's'} — see Settings for details.`);
      }
    },
  });

  wireAsyncActionButton({
    id: 's-check-drift',
    resultId: 's-check-drift-result',
    busyLabel: 'Checking…',
    idleLabel: 'Check for AI Drift',
    failPrefix: 'Could not check AI call health',
    run: async resultEl => {
      const { insufficientData, checked, findings } = await checkLlmAuditDrift();
      if (insufficientData) {
        if (resultEl) resultEl.textContent = `Not enough call history yet to compare (${checked} call${checked === 1 ? '' : 's'} logged so far).`;
      } else if (findings.length === 0) {
        if (resultEl) resultEl.textContent = `Checked your last ${checked} calls — nothing unusual found.`;
        toast('AI call health check passed.');
      } else {
        const summary = describeDrift(findings);
        if (resultEl) resultEl.innerHTML = `<strong style="color:var(--danger)">${escapeHtml(summary)}</strong>`;
        toast('AI call health check found something worth a look — see Settings for details.', 6000);
      }
    },
  });
}

