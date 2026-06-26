// Settings modal — provider profile, API key, Whisper model management.

import { kvGet, kvSet } from '../core/storageBackend.js';
import { checkModelDownloaded, downloadModel } from '../scribe/transcriber.js';
import { toast } from '../utils/format.js';

const PROVIDER_KEY = 'note_provider_v1::profile';

export async function renderSettings() {
  const provider = kvGet(PROVIDER_KEY) || {};
  const modelOk = await checkModelDownloaded().catch(() => false);
  const hasKey = !!(kvGet('note_settings_v1::anthropic_api_key'));

  return `
    <div class="settings-page">
      <h2 class="settings-title">Settings</h2>

      <section class="settings-section">
        <h3>Provider Profile</h3>
        <div class="field-row">
          <label>Full name</label>
          <input type="text" id="s-name" value="${esc(provider.name || '')}" placeholder="Dr. Jane Smith" />
        </div>
        <div class="field-row">
          <label>Credentials</label>
          <input type="text" id="s-creds" value="${esc(provider.credentials || '')}" placeholder="MD, PMHNP-BC…" />
        </div>
        <div class="field-row">
          <label>Specialty</label>
          <select id="s-specialty">
            ${['psychiatry','behavioral-health','psychology','other'].map(v =>
              `<option value="${v}" ${provider.specialty === v ? 'selected' : ''}>${specialtyLabel(v)}</option>`
            ).join('')}
          </select>
        </div>
        <button class="btn btn-primary" id="s-save-provider">Save Profile</button>
      </section>

      <section class="settings-section">
        <h3>Transcription Model (Whisper)</h3>
        <p class="settings-desc">Local speech recognition — runs on this device. No audio sent to any server.</p>
        <div class="model-status-row">
          <span class="model-status-icon">${modelOk ? '✓' : '✗'}</span>
          <span>${modelOk ? 'Whisper base.en model ready' : 'Model not downloaded'}</span>
        </div>
        <button class="btn btn-secondary" id="s-download-model" ${modelOk ? 'disabled' : ''}>
          ${modelOk ? 'Model Downloaded' : 'Download Model (142 MB)'}
        </button>
        <div class="progress-bar" id="s-model-progress" style="display:none">
          <div class="progress-fill" id="s-model-fill"></div>
        </div>
      </section>

      <section class="settings-section">
        <h3>Note Generation (Anthropic API)</h3>
        <p class="settings-desc">
          Your API key is stored on this device only and used to call Anthropic's Claude model to generate clinical notes from transcripts.
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

      <section class="settings-section settings-section--danger">
        <h3>Privacy</h3>
        <p class="settings-desc">Audio recordings are stored in your OS app data directory and never leave this device. Transcripts and notes are stored in a local SQLite database. Nothing is sent to Greenbar servers.</p>
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

  document.getElementById('s-download-model')?.addEventListener('click', async () => {
    const bar  = document.getElementById('s-model-progress');
    const fill = document.getElementById('s-model-fill');
    if (bar) bar.style.display = 'block';
    try {
      await downloadModel(pct => { if (fill) fill.style.width = `${Math.round(pct * 100)}%`; });
      toast('Model downloaded.');
      document.getElementById('s-download-model').disabled = true;
      document.getElementById('s-download-model').textContent = 'Model Downloaded';
    } catch (e) {
      toast(`Download failed: ${e.message || e}`);
    }
  });

  document.getElementById('s-save-apikey')?.addEventListener('click', () => {
    const val = document.getElementById('s-apikey')?.value.trim();
    if (!val || val === '••••••••••••') return;
    kvSet('note_settings_v1::anthropic_api_key', val);
    toast('API key saved.');
  });

  document.getElementById('s-clear-apikey')?.addEventListener('click', () => {
    if (!confirm('Remove the stored API key?')) return;
    kvSet('note_settings_v1::anthropic_api_key', null);
    toast('API key removed.');
  });
}

function specialtyLabel(v) {
  return { psychiatry: 'Psychiatry', 'behavioral-health': 'Behavioral Health / Therapy',
           psychology: 'Psychology', other: 'Other' }[v] || v;
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;');
}
