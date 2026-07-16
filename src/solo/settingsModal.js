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
          Note generation is disabled until you confirm your organization has an executed
          <strong>Business Associate Agreement (BAA)</strong> with Anthropic covering the API key
          configured below. Revoking this immediately disables note generation on this device.
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
  // clear the row. The Rust gate rejects note generation the instant the row
  // is missing, so a user can revoke and immediately verify the app refuses
  // to send further transcripts — no restart or refresh required.
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
        toast('BAA acknowledged. Note generation is enabled.');
      } else {
        if (!confirm('Revoke your BAA acknowledgment? Note generation will stop working until you re-acknowledge.')) {
          e.target.checked = true;
          return;
        }
        await baaRepo.clear();
        toast('BAA acknowledgment cleared. Note generation is disabled.');
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

  document.getElementById('s-verify-chains')?.addEventListener('click', async e => {
    const btn = e.currentTarget;
    const resultEl = document.getElementById('s-verify-chains-result');
    btn.setAttribute('disabled', '');
    btn.textContent = 'Verifying…';
    if (resultEl) resultEl.textContent = '';
    try {
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
    } catch (err) {
      if (resultEl) resultEl.textContent = '';
      toast(`Could not verify chains: ${userMessage(err, 'unknown error')}`);
    } finally {
      btn.removeAttribute('disabled');
      btn.textContent = 'Verify All Chains';
    }
  });

  document.getElementById('s-check-drift')?.addEventListener('click', async e => {
    const btn = e.currentTarget;
    const resultEl = document.getElementById('s-check-drift-result');
    btn.setAttribute('disabled', '');
    btn.textContent = 'Checking…';
    if (resultEl) resultEl.textContent = '';
    try {
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
    } catch (err) {
      if (resultEl) resultEl.textContent = '';
      toast(`Could not check AI call health: ${userMessage(err, 'unknown error')}`);
    } finally {
      btn.removeAttribute('disabled');
      btn.textContent = 'Check for AI Drift';
    }
  });
}

