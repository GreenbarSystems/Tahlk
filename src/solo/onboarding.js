// First-run onboarding — collect the provider profile and the BAA/EULA
// acknowledgment.
//
// Note generation runs through Greenbar's managed proxy using a per-device
// token minted transparently on first use (see src-tauri/src/device.rs), so
// there is deliberately no API-key step here and no user-visible sign of the
// device registration.
//
// The BAA/EULA acknowledgment step is BLOCKING: the Rust-side gate
// (baa::require_ack, GATE_ENABLED = true) rejects the very first note
// generation with AppError::BaaRequired unless an ack row exists. Onboarding
// therefore records the ack via the same baaRepo/baa_ack_set command the
// Settings pane uses, so there is a single source of truth for "has this been
// acknowledged" and a fresh install can generate a note immediately after
// finishing onboarding.

import { kvGet, kvSet, kvSetCacheOnly } from '../core/storageBackend.js';
import { invoke } from '../platform/tauri.js';
import { keys } from '../data/keys.js';
import { toast, escapeHtml } from '../utils/format.js';
import { userMessage } from '../platform/appError.js';
import { PICKER_SPECIALTIES } from '../domain/specialties.js';
import { baaRepo } from '../data/baa.js';
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

          <!-- Step 2: BAA / EULA acknowledgment (blocking) -->
          <div class="onboarding-step" id="step-baa">
            <div class="step-num">2</div>
            <div class="step-body">
              <h3>Agreements (BAA &amp; EULA)</h3>
              <p class="step-desc">
                Tahlk generates your notes through <strong>Greenbar Systems'</strong> managed,
                HIPAA-covered infrastructure. Every transcript is processed under a
                <strong>Business Associate Agreement (BAA)</strong> between your practice and
                Greenbar, with Greenbar acting as your business associate and Anthropic operating
                as Greenbar's zero-data-retention (ZDR) subcontractor. No data is used to train
                models, and no third-party account of your own is involved. Your use of the app is
                also governed by Greenbar's <strong>End User License Agreement (EULA)</strong>.
              </p>
              <label class="baa-toggle">
                <input type="checkbox" id="ob-baa" />
                <span>I have read and accept Greenbar Systems' BAA and EULA governing this processing of protected health information.</span>
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

    // The BAA/EULA acknowledgment is a hard gate: onboarding cannot complete
    // without it, because the Rust gate (baa::require_ack) would otherwise
    // reject the user's first note generation with an opaque BaaRequired error.
    const baaChecked = !!document.getElementById('ob-baa')?.checked;
    if (!baaChecked) { toast('Please accept the BAA and EULA to continue.'); return; }

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

    // Record the BAA/EULA acknowledgment via the same command Settings uses
    // (baaRepo.setAck -> baa_ack_set), so the Rust gate is satisfied before the
    // first note generation. Onboarding is not marked complete if this write
    // fails — otherwise the user would land in the app but still hit
    // BaaRequired on their first note.
    try {
      await baaRepo.setAck({ acknowledgedAt: new Date().toISOString(), providerId: name });
    } catch (e) {
      toast(`Could not record your agreement: ${userMessage(e, 'unknown error')}`);
      return;
    }

    kvSet(ONBOARDED_KEY, true);

    onComplete();
  });
}
