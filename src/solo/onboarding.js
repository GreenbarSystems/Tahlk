// First-run onboarding — collect provider info and API key.

import { kvGet, kvSet } from '../core/storageBackend.js';
import { secretsRepo } from '../data/secretsRepo.js';
import { keys } from '../data/keys.js';
import { toast, escapeHtml } from '../utils/format.js';
import { PICKER_SPECIALTIES } from '../domain/specialties.js';
import { LOGO_SVG_LG } from './logoSvg.js';

const PROVIDER_KEY = keys.provider();
const ONBOARDED_KEY = keys.onboarded();

export function isOnboarded() {
  return !!kvGet(ONBOARDED_KEY);
}

export function renderOnboarding() {
  return `
    <div class="onboarding-backdrop">
      <div class="onboarding-card">
        <div class="onboarding-logo">${LOGO_SVG_LG}<span>Tahlk</span></div>
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
                  ${PICKER_SPECIALTIES.map(s =>
                    `<option value="${s.value}">${escapeHtml(s.label)}</option>`
                  ).join('')}
                </select>
              </div>
            </div>
          </div>

          <!-- Step 2: Anthropic API key -->
          <div class="onboarding-step" id="step-apikey">
            <div class="step-num">2</div>
            <div class="step-body">
              <h3>Note generation API key</h3>
              <p class="step-desc">Tahlk uses Claude (Anthropic) to turn transcripts into clinical notes. Enter your Anthropic API key — stored locally on this device only, never sent to Tahlk servers.</p>
              <div class="field-row">
                <label>Anthropic API key <span class="req">*</span></label>
                <input id="ob-apikey" type="password" placeholder="sk-ant-…" autocomplete="off" />
              </div>
              <p class="step-hint"><a href="#" id="ob-apikey-link">Get a key at console.anthropic.com →</a></p>
            </div>
          </div>

        </div>

        <div class="onboarding-footer">
          <button class="btn btn-primary btn-lg" id="ob-finish">Start using Tahlk</button>
        </div>
      </div>
    </div>
  `;
}

export async function wireOnboarding(onComplete) {
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
    // Store the API key write-only — it never round-trips back to JS.
    try {
      await secretsRepo.setApiKey(apiKey);
    } catch (e) {
      toast(`Could not save API key: ${e.message || e}`);
      return;
    }
    kvSet(ONBOARDED_KEY, true);

    onComplete();
  });
}
