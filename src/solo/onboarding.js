// First-run onboarding — collect the provider profile.
//
// Note generation runs through Greenbar's managed proxy using a per-device
// token minted transparently on first use (see src-tauri/src/device.rs), so
// there is deliberately no API-key step here and no user-visible sign of the
// device registration.

import { kvGet, kvSet, kvSetCacheOnly } from '../core/storageBackend.js';
import { invoke } from '../platform/tauri.js';
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

    // BAA acknowledgment is not collected here during the current beta
    // (ADR 0003 — test data only, Rust-side gate soft-disabled). Anyone with
    // a real BAA already in place can still record it in Settings.
    kvSet(ONBOARDED_KEY, true);

    onComplete();
  });
}
