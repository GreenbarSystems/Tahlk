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
        <div class="onboarding-logo">${LOGO_SVG_LG}<span>Tahlk</span><span class="onboarding-badge">Beta</span></div>
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
              <p class="step-desc">Tahlk uses Anthropic's AI (Claude) to turn what you say into clinical notes.
              You'll need your own Anthropic account and API key so your data goes directly to Anthropic under
              your own agreement with them — Tahlk itself never sees or stores your key on any server. The key
              is saved in your operating system's secure credential store (the same place your computer keeps
              other app passwords), not in Tahlk's database.</p>
              <details class="onboarding-help" id="ob-apikey-help">
                <summary>How do I get one?</summary>
                <div class="onboarding-help-body">
                  <p>An API key is a private password that lets Tahlk send transcripts to Anthropic on your behalf. To create one:</p>
                  <ol>
                    <li>Go to <a href="https://console.anthropic.com" target="_blank" rel="noreferrer noopener">console.anthropic.com</a> and sign in (or create a free account).</li>
                    <li>Open <strong>API Keys</strong> and choose <strong>Create Key</strong>.</li>
                    <li>Copy the key (it starts with <code>sk-ant-</code>) and paste it in the box below.</li>
                  </ol>
                  <p class="onboarding-help-note">Anthropic bills you directly for usage. You can revoke or rotate the key from the same page at any time.</p>
                </div>
              </details>
              <div class="field-row">
                <label>Anthropic API key <span class="req">*</span></label>
                <input id="ob-apikey" type="password" placeholder="sk-ant-…" autocomplete="off" />
              </div>
              <p class="step-hint"><a href="https://console.anthropic.com" target="_blank" rel="noreferrer noopener" id="ob-apikey-link">Get a key at console.anthropic.com →</a></p>
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
              <details class="onboarding-help" id="ob-baa-help">
                <summary>What is this?</summary>
                <div class="onboarding-help-body">
                  <p>A <strong>Business Associate Agreement (BAA)</strong> is a contract HIPAA requires whenever a
                  vendor like Anthropic processes patient health information on your behalf. It commits Anthropic to
                  safeguarding that data. You must have a BAA in place with Anthropic before sending any patient
                  information through Tahlk.</p>
                  <p>To request one:</p>
                  <ol>
                    <li>Sign in at <a href="https://console.anthropic.com" target="_blank" rel="noreferrer noopener">console.anthropic.com</a> with the same account as your API key.</li>
                    <li>Follow Anthropic's HIPAA / BAA request process (see the link below) and execute the agreement.</li>
                    <li>Once it's in place, tick the box below to confirm.</li>
                  </ol>
                  <p class="onboarding-help-note">Tahlk can't verify the BAA for you — this checkbox is your attestation
                  that one exists. The block on note generation stays in effect until you confirm.</p>
                </div>
              </details>
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
      <div class="toast" id="toast"><span id="toast-msg"></span></div>
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
