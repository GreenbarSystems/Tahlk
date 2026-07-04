// First-run onboarding — collect provider info and API key.

import { kvGet, kvSet } from '../core/storageBackend.js';
import { secretsRepo } from '../data/secretsRepo.js';
import { baaRepo } from '../data/baa.js';
import { keys } from '../data/keys.js';
import { toast, escapeHtml } from '../utils/format.js';
import { userMessage } from '../platform/appError.js';
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

          <!-- Step 3: BAA acknowledgment. HIPAA-covered use of the Anthropic
               API requires an executed Business Associate Agreement. Tahlk
               refuses to send transcripts upstream until the provider affirms
               they have one in place — the gate lives in Rust (baa.rs) so a
               WebView compromise cannot bypass it. -->
          <div class="onboarding-step" id="step-baa">
            <div class="step-num">3</div>
            <div class="step-body">
              <h3>Anthropic BAA acknowledgment</h3>
              <p class="step-desc">Under HIPAA, any protected health information (PHI) sent to Anthropic
              requires an executed Business Associate Agreement (BAA) between your organization and Anthropic.
              Tahlk will not generate notes until you confirm this is in place. You can revoke this in Settings at any time.</p>
              <label class="baa-consent">
                <input id="ob-baa" type="checkbox" />
                <span>I confirm my organization has an executed BAA with Anthropic covering the API key entered above.</span>
              </label>
              <p class="step-hint"><a href="https://support.anthropic.com/en/articles/8555474-i-need-a-business-associate-agreement-baa-with-anthropic-for-hipaa-compliance-what-do-i-do" target="_blank" rel="noreferrer noopener">How to request a BAA from Anthropic →</a></p>
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

    // BAA affirmation is required at first-run — the underlying Rust gate
    // will refuse to call Anthropic without an ack, so gating the button
    // here is a UX courtesy that avoids a confusing generation failure on
    // the very first encounter.
    const baaChecked = !!document.getElementById('ob-baa')?.checked;
    if (!baaChecked) {
      toast('Please confirm the Anthropic BAA to continue.');
      return;
    }

    kvSet(PROVIDER_KEY, {
      name,
      credentials: document.getElementById('ob-creds')?.value.trim() || '',
      specialty:   document.getElementById('ob-specialty')?.value || 'psychiatry',
    });
    // Store the API key write-only — it never round-trips back to JS.
    try {
      await secretsRepo.setApiKey(apiKey);
    } catch (e) {
      toast(`Could not save API key: ${userMessage(e, 'unknown error')}`);
      return;
    }

    // Record the BAA ack AFTER the API key lands, so we never have an
    // acknowledged-but-unusable state (ack row present, key missing).
    // The Rust command stamps `attestation_version` server-side.
    try {
      await baaRepo.setAck({
        acknowledgedAt: new Date().toISOString(),
        providerId: name,
      });
    } catch (e) {
      toast(`Could not save BAA acknowledgment: ${userMessage(e, 'unknown error')}`);
      return;
    }

    kvSet(ONBOARDED_KEY, true);

    onComplete();
  });
}
