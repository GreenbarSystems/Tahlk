// First-run onboarding — collect provider info and API key.

import { kvGet, kvSet, kvSetCacheOnly } from '../core/storageBackend.js';
import { invoke } from '../platform/tauri.js';
import { secretsRepo } from '../data/secretsRepo.js';
import { baaRepo } from '../data/baa.js';
import { keys } from '../data/keys.js';
import { toast, escapeHtml, nowISO } from '../utils/format.js';
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

          <!-- Step 3: Agreements. Required, because baa::GATE_ENABLED is true
               and generate_note refuses until an ack is stored. Collecting it
               here is what makes the gate satisfiable: without this step a new
               install hits a baa_required error on its first Generate with no
               path forward except a checkbox buried in Settings.
               (No backticks in here — this block sits inside a template
               literal, and one would terminate the string.) -->
          <div class="onboarding-step" id="step-agreements">
            <div class="step-num">3</div>
            <div class="step-body">
              <h3>Agreements (BAA &amp; EULA)</h3>
              <p class="step-desc">Using Tahlk with real patient information is covered by two agreements
              between your organization and <strong>Greenbar Systems</strong>, the maker of Tahlk: a
              <strong>Business Associate Agreement (BAA)</strong> setting out how protected health
              information is handled under HIPAA, and an <strong>End User License Agreement (EULA)</strong>
              covering your use of the app.</p>
              <p class="step-desc">Confirm below once both are in place. Tahlk will not generate notes
              until you do.</p>
              <label class="baa-toggle">
                <input type="checkbox" id="ob-baa" />
                <span>My organization has accepted Greenbar Systems' BAA and EULA.</span>
              </label>
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

    // Checked BEFORE anything is written, so a provider who has not confirmed
    // the agreements is not left half-onboarded with a profile and API key
    // stored and no way to generate a note.
    const baaChecked = !!document.getElementById('ob-baa')?.checked;
    if (!baaChecked) {
      toast('Confirm the BAA and EULA to finish setup.');
      return;
    }

    // Use the dedicated set_provider_profile command (C3 fix). Generic kv_set
    // is write-blocked for this key; sync the in-memory cache afterwards so
    // synchronous kvGet(keys.provider()) reads work for the rest of this session.
    const profile = {
      name,
      credentials: document.getElementById('ob-creds')?.value.trim() || '',
      specialty:   document.getElementById('ob-specialty')?.value || 'psychiatry',
    };
    try {
      await invoke('set_provider_profile', { profile });
      kvSetCacheOnly(PROVIDER_KEY, profile);
    } catch (e) {
      toast(`Could not save profile: ${userMessage(e, 'unknown error')}`);
      return;
    }
    // Store the API key write-only — it never round-trips back to JS.
    try {
      await secretsRepo.setApiKey(apiKey);
    } catch (e) {
      toast(`Could not save API key: ${userMessage(e, 'unknown error')}`);
      return;
    }

    // Record the attestation LAST, so onboarding is only marked complete once
    // every prerequisite for generating a note is actually in place. Failing
    // here leaves the provider on this screen with a message rather than
    // dropping them into an app that cannot do its job.
    try {
      await baaRepo.setAck({ acknowledgedAt: nowISO(), providerId: name });
    } catch (e) {
      toast(`Could not record your confirmation: ${userMessage(e, 'unknown error')}`);
      return;
    }

    kvSet(ONBOARDED_KEY, true);

    onComplete();
  });
}
