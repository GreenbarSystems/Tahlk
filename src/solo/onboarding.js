// First-run onboarding — collect provider info, trigger model download, enter API key.

import { kvGet, kvSet, tauriInvoke } from '../core/storageBackend.js';
import { downloadModel, checkModelDownloaded } from '../scribe/transcriber.js';
import { toast } from '../utils/format.js';

const PROVIDER_KEY = 'note_provider_v1::profile';
const ONBOARDED_KEY = 'note_settings_v1::onboarded';

export function isOnboarded() {
  return !!kvGet(ONBOARDED_KEY);
}

export function renderOnboarding() {
  return `
    <div class="onboarding-backdrop">
      <div class="onboarding-card">
        <div class="onboarding-logo">✦ Greenbar Note</div>
        <h1 class="onboarding-title">Welcome. Let's get you set up.</h1>
        <p class="onboarding-sub">Takes about 3 minutes. Your data stays on this device.</p>

        <div class="onboarding-steps">

          <!-- Step 1: Provider info -->
          <div class="onboarding-step" id="step-provider">
            <div class="step-num">1</div>
            <div class="step-body">
              <h3>Your provider profile</h3>
              <div class="field-row">
                <label>Full name <span class="req">*</span></label>
                <input id="ob-name" type="text" placeholder="Dr. Jane Smith" autocomplete="name" />
              </div>
              <div class="field-row">
                <label>Credentials</label>
                <input id="ob-creds" type="text" placeholder="MD, PMHNP-BC, LCSW…" />
              </div>
              <div class="field-row">
                <label>Specialty</label>
                <select id="ob-specialty">
                  <option value="psychiatry">Psychiatry</option>
                  <option value="behavioral-health">Behavioral Health / Therapy</option>
                  <option value="psychology">Psychology</option>
                  <option value="other">Other</option>
                </select>
              </div>
            </div>
          </div>

          <!-- Step 2: Whisper model -->
          <div class="onboarding-step" id="step-model">
            <div class="step-num">2</div>
            <div class="step-body">
              <h3>Download transcription model</h3>
              <p class="step-desc">A 142 MB local speech model (Whisper base.en). Downloads once; runs entirely on this device. No audio leaves your computer.</p>
              <div id="model-status" class="model-status"></div>
              <button class="btn btn-secondary" id="ob-download-model">Download Model</button>
              <div class="progress-bar" id="model-progress" style="display:none">
                <div class="progress-fill" id="model-progress-fill"></div>
              </div>
            </div>
          </div>

          <!-- Step 3: Anthropic API key -->
          <div class="onboarding-step" id="step-apikey">
            <div class="step-num">3</div>
            <div class="step-body">
              <h3>Note generation API key</h3>
              <p class="step-desc">Greenbar Note uses Claude (Anthropic) to turn transcripts into clinical notes. Enter your Anthropic API key — stored locally on this device only, never sent to Greenbar servers.</p>
              <div class="field-row">
                <label>Anthropic API key <span class="req">*</span></label>
                <input id="ob-apikey" type="password" placeholder="sk-ant-…" autocomplete="off" />
              </div>
              <p class="step-hint"><a href="#" id="ob-apikey-link">Get a key at console.anthropic.com →</a></p>
            </div>
          </div>

        </div>

        <div class="onboarding-footer">
          <button class="btn btn-primary btn-lg" id="ob-finish">Start using Greenbar Note</button>
        </div>
      </div>
    </div>
  `;
}

export async function wireOnboarding(onComplete) {
  // Check model status on load.
  const modelOk = await checkModelDownloaded().catch(() => false);
  const statusEl = document.getElementById('model-status');
  if (statusEl) statusEl.textContent = modelOk ? '✓ Model ready' : 'Not downloaded yet';

  document.getElementById('ob-download-model')?.addEventListener('click', async () => {
    const bar = document.getElementById('model-progress');
    const fill = document.getElementById('model-progress-fill');
    if (bar) bar.style.display = 'block';

    try {
      await downloadModel(pct => {
        if (fill) fill.style.width = `${Math.round(pct * 100)}%`;
      });
      if (statusEl) statusEl.textContent = '✓ Model ready';
      toast('Transcription model downloaded successfully.');
    } catch (e) {
      toast(`Download failed: ${e.message || e}`);
    }
  });

  document.getElementById('ob-finish')?.addEventListener('click', async () => {
    const name = document.getElementById('ob-name')?.value.trim();
    if (!name) { toast('Provider name is required.'); return; }

    const apiKey = document.getElementById('ob-apikey')?.value.trim();
    if (!apiKey) { toast('Anthropic API key is required.'); return; }

    kvSet(PROVIDER_KEY, {
      name,
      credentials: document.getElementById('ob-creds')?.value.trim() || '',
      specialty:   document.getElementById('ob-specialty')?.value || 'psychiatry',
    });
    kvSet('note_settings_v1::anthropic_api_key', apiKey);
    kvSet(ONBOARDED_KEY, true);

    onComplete();
  });
}
