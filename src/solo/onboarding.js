// First-run onboarding wizard — guides a new user from profile setup to
// (optionally) cloud account creation, HIPAA BAA acceptance, and subscription.
//
// Steps:  profile → terms → cloud-choice → cloud-account → baa → subscribe → finish
// Cloud steps are skipped when the user chooses "use locally for now".

import { kvGet, kvSet, tauriInvoke } from '../core/storageBackend.js';
import { toast } from '../utils/format.js';
import {
  register as cloudRegister,
  login    as cloudLogin,
  acceptBaa,
  isAuthenticated,
  getProvider as getCloudProvider,
} from '../core/auth.js';
import { apiFetch } from '../core/api.js';

const PROVIDER_KEY  = 'note_provider_v1::profile';
const ONBOARDED_KEY = 'note_settings_v1::onboarded';

const STEPS = ['profile', 'terms', 'cloud-choice', 'cloud-account', 'baa', 'subscribe', 'finish'];
const TIERS = [
  { id: 'SOLO', label: 'Solo',  price: '$599',   period: '/mo', desc: '1 provider, unlimited sessions' },
  { id: 'PRO',  label: 'Pro',   price: '$1,699', period: '/mo', desc: '2–3 providers' },
  { id: 'FIRM', label: 'Firm',  price: '$3,499', period: '/mo', desc: '4–5 providers' },
];

// ── Module state ────────────────────────────────────────────────────────────

let _step       = 'profile';
let _cloudPath  = false;       // true if user chose cloud setup
let _orgName    = '';          // captured during cloud-account step
let _onComplete = null;

export function isOnboarded() {
  return !!kvGet(ONBOARDED_KEY);
}

// ── Entry point ─────────────────────────────────────────────────────────────

export function renderOnboarding() {
  _step      = 'profile';
  _cloudPath = false;
  _orgName   = '';
  return _shell(_renderStep('profile'));
}

export async function wireOnboarding(onComplete) {
  _onComplete = onComplete;
  _wire();
}

// ── Shell ────────────────────────────────────────────────────────────────────

function _shell(inner) {
  return `
    <div class="onboarding-backdrop">
      <div class="onboarding-card" id="ob-card">
        <img class="onboarding-logo-img" src="/tahlk-logo.png" alt="Tahlk" />
        <div id="ob-step">${inner}</div>
      </div>
      <div class="toast" id="toast"><span id="toast-msg"></span></div>
    </div>`;
}

// ── Step renderer ────────────────────────────────────────────────────────────

function _renderStep(step) {
  switch (step) {
    case 'profile':       return _stepProfile();
    case 'terms':         return _stepTerms();
    case 'cloud-choice':  return _stepCloudChoice();
    case 'cloud-account': return _stepCloudAccount();
    case 'baa':           return _stepBaa();
    case 'subscribe':     return _stepSubscribe();
    case 'finish':        return _stepFinish();
    default:              return _stepProfile();
  }
}

// ── Individual steps ─────────────────────────────────────────────────────────

function _stepProfile() {
  const saved = kvGet(PROVIDER_KEY) || {};
  return `
    <h1 class="ob-title">Set up your profile</h1>
    <p class="ob-subtitle">This stays on your device and never leaves without your permission.</p>
    <div class="ob-fields">
      <div class="field-row">
        <label>Full name <span class="req">*</span></label>
        <input id="ob-name" type="text" placeholder="Dr. Jane Smith"
               value="${esc(saved.name || '')}" autocomplete="name" />
      </div>
      <div class="field-row">
        <label>Credentials</label>
        <input id="ob-creds" type="text" placeholder="MD, PMHNP-BC, LCSW…"
               value="${esc(saved.credentials || '')}" />
      </div>
      <div class="field-row">
        <label>Specialty</label>
        <select id="ob-specialty">
          ${['psychiatry','behavioral-health','psychology','podiatry','other'].map(v =>
            `<option value="${v}" ${saved.specialty === v ? 'selected' : ''}>${_specialtyLabel(v)}</option>`
          ).join('')}
        </select>
      </div>
    </div>
    <div class="ob-actions">
      <button class="btn btn-primary btn-lg" id="ob-next">Continue →</button>
    </div>`;
}

function _stepTerms() {
  return `
    <h1 class="ob-title">Before you start</h1>
    <div class="ob-terms-box">
      <p><strong>Tahlk is pre-release beta software.</strong> By continuing you acknowledge:</p>
      <ul>
        <li>This software is provided as-is for evaluation purposes.</li>
        <li>Transcript text is sent to Anthropic's API (using your own key) to generate notes.</li>
        <li>Audio recordings are transcribed locally and never leave this device.</li>
        <li>Notes are stored in a local encrypted database on this device.</li>
      </ul>
      <a href="https://www.tahlkscribe.com/beta-terms" class="ob-link">Read full Beta Terms →</a>
    </div>
    <label class="ob-checkbox-row">
      <input type="checkbox" id="ob-baa-check" />
      <span>I understand and agree to the Tahlk Beta Terms</span>
    </label>
    <div class="ob-actions ob-actions--split">
      <button class="btn btn-ghost btn-sm" id="ob-back">← Back</button>
      <button class="btn btn-primary btn-lg" id="ob-next" disabled>Continue →</button>
    </div>`;
}

function _stepCloudChoice() {
  return `
    <h1 class="ob-title">Secure cloud backup</h1>
    <p class="ob-subtitle">
      Tahlk can back up your notes to the cloud with zero-knowledge encryption —
      all content is encrypted on this device before upload. Tahlk servers never see your notes.
    </p>
    <div class="ob-choice-cards">
      <button class="ob-choice-card ob-choice-card--recommended" id="ob-choose-cloud">
        <span class="ob-choice-badge">Recommended</span>
        <strong>Set up cloud backup</strong>
        <span>Protect against device failure. Sync across devices.</span>
        <span class="ob-choice-cta">Get started →</span>
      </button>
      <button class="ob-choice-card" id="ob-choose-local">
        <strong>Use locally for now</strong>
        <span>Notes stay on this device only. You can enable cloud later in Settings.</span>
        <span class="ob-choice-cta">Skip →</span>
      </button>
    </div>
    <div class="ob-actions">
      <button class="btn btn-ghost btn-sm" id="ob-back">← Back</button>
    </div>`;
}

function _stepCloudAccount(mode = 'register', error = '') {
  if (mode === 'login') {
    return `
      <h1 class="ob-title">Log in to Tahlk Cloud</h1>
      <div class="ob-fields">
        <div class="field-row">
          <label>Email</label>
          <input id="ob-email" type="email" placeholder="you@practice.com" autocomplete="email" />
        </div>
        <div class="field-row">
          <label>Password</label>
          <input id="ob-password" type="password" autocomplete="current-password" />
        </div>
        ${error ? `<p class="ob-error">${esc(error)}</p>` : ''}
      </div>
      <div class="ob-actions ob-actions--split">
        <button class="btn btn-ghost btn-sm" id="ob-back">← Back</button>
        <button class="btn btn-primary btn-lg" id="ob-do-login">Log In</button>
      </div>
      <p class="ob-switch-row">No account? <button class="btn-inline" id="ob-switch-mode">Create one →</button></p>`;
  }

  return `
    <h1 class="ob-title">Create your cloud account</h1>
    <div class="ob-fields">
      <div class="field-row">
        <label>Practice name <span class="req">*</span></label>
        <input id="ob-org-name" type="text" placeholder="Sunrise Behavioral Health" />
      </div>
      <div class="field-row">
        <label>Email <span class="req">*</span></label>
        <input id="ob-email" type="email" placeholder="you@practice.com" autocomplete="email" />
      </div>
      <div class="field-row">
        <label>Password <span class="req">*</span></label>
        <input id="ob-password" type="password" placeholder="12+ characters" autocomplete="new-password" />
      </div>
      <div class="field-row">
        <label>Beta invite code</label>
        <input id="ob-beta-code" type="text" placeholder="Leave blank if not required" autocomplete="off" />
      </div>
      ${error ? `<p class="ob-error">${esc(error)}</p>` : ''}
    </div>
    <div class="ob-actions ob-actions--split">
      <button class="btn btn-ghost btn-sm" id="ob-back">← Back</button>
      <button class="btn btn-primary btn-lg" id="ob-do-register">Create Account</button>
    </div>
    <p class="ob-switch-row">Already have an account? <button class="btn-inline" id="ob-switch-mode">Log in →</button></p>`;
}

function _stepBaa() {
  const cloudProvider = getCloudProvider();
  const signerName = kvGet(PROVIDER_KEY)?.name || cloudProvider?.name || 'Provider';
  return `
    <h1 class="ob-title">HIPAA Business Associate Agreement</h1>
    <div class="ob-baa-box">
      <p>
        To store clinical content in Tahlk Cloud, your practice must enter into a
        HIPAA Business Associate Agreement (BAA) with Tahlk Health, Inc.
      </p>
      <p>The BAA covers:</p>
      <ul>
        <li>Tahlk's obligations as a Business Associate handling Protected Health Information (PHI)</li>
        <li>End-to-end encryption of all clinical content before it leaves your device</li>
        <li>Data retention, breach notification, and access controls under 45 CFR § 164</li>
      </ul>
      <a href="https://www.tahlkscribe.com/baa" class="ob-link" id="ob-baa-link">Read the full BAA document →</a>
    </div>
    <label class="ob-checkbox-row">
      <input type="checkbox" id="ob-baa-cloud-check" />
      <span>
        I, <strong>${esc(signerName)}</strong>, am authorized to enter into agreements on behalf
        of <strong>${esc(_orgName)}</strong>, and I accept the Tahlk HIPAA Business Associate Agreement.
      </span>
    </label>
    <p class="ob-baa-note">Acceptance is recorded with a timestamp and associated with your account.</p>
    <div class="ob-actions ob-actions--split">
      <button class="btn btn-ghost btn-sm" id="ob-back">← Back</button>
      <button class="btn btn-primary btn-lg" id="ob-next" disabled>Accept &amp; Continue →</button>
    </div>`;
}

function _stepSubscribe(checkoutPending = false) {
  return `
    <h1 class="ob-title">Activate your plan</h1>
    <p class="ob-subtitle">Your cloud backup is enabled. Choose a plan to keep access after the trial.</p>
    <div class="ob-tier-cards">
      ${TIERS.map(t => `
        <div class="ob-tier-card">
          <div class="ob-tier-name">${t.label}</div>
          <div class="ob-tier-price">${t.price}<span>${t.period}</span></div>
          <div class="ob-tier-desc">${t.desc}</div>
          <button class="btn btn-primary btn-sm ob-subscribe-btn" data-tier="${t.id}">Subscribe</button>
        </div>`).join('')}
    </div>
    ${checkoutPending ? `
      <div class="ob-checkout-pending">
        <p>Checkout opened in your browser. Complete payment there, then click Continue.</p>
      </div>` : ''}
    <div class="ob-actions ob-actions--split">
      <button class="btn btn-ghost btn-sm" id="ob-back">← Back</button>
      <button class="btn btn-ghost" id="ob-skip-subscribe">I'll subscribe later →</button>
    </div>`;
}

function _stepFinish() {
  const hasCloud = isAuthenticated();
  return `
    <h1 class="ob-title">You're all set!</h1>
    <div class="ob-finish-items">
      <div class="ob-finish-item">
        <span class="ob-finish-check">✓</span>
        <span>Provider profile configured</span>
      </div>
      <div class="ob-finish-item">
        <span class="ob-finish-check">✓</span>
        <span>Local transcription ready — no audio ever leaves this device</span>
      </div>
      ${hasCloud ? `
        <div class="ob-finish-item">
          <span class="ob-finish-check">✓</span>
          <span>Cloud backup active — notes encrypted before upload</span>
        </div>` : `
        <div class="ob-finish-item">
          <span class="ob-finish-check ob-finish-check--skip">○</span>
          <span>Cloud backup not configured — you can set it up in Settings any time</span>
        </div>`}
    </div>
    <p class="ob-subtitle" style="margin-top:16px">Add your Anthropic API key in Settings to enable AI note generation.</p>
    <div class="ob-actions">
      <button class="btn btn-primary btn-lg" id="ob-finish-btn">Start Using Tahlk</button>
    </div>`;
}

// ── Step navigation ──────────────────────────────────────────────────────────

function _goTo(step) {
  _step = step;
  const container = document.getElementById('ob-step');
  if (container) {
    container.innerHTML = _renderStep(step);
    _wire();
  }
}

function _nextFrom(current) {
  if (current === 'profile')      return 'terms';
  if (current === 'terms')        return 'cloud-choice';
  if (current === 'cloud-choice') return _cloudPath ? 'cloud-account' : 'finish';
  if (current === 'cloud-account')return 'baa';
  if (current === 'baa')          return 'subscribe';
  if (current === 'subscribe')    return 'finish';
  return 'finish';
}

function _backFrom(current) {
  if (current === 'terms')        return 'profile';
  if (current === 'cloud-choice') return 'terms';
  if (current === 'cloud-account')return 'cloud-choice';
  if (current === 'baa')          return 'cloud-account';
  if (current === 'subscribe')    return 'baa';
  return 'profile';
}

// ── Wiring ───────────────────────────────────────────────────────────────────

function _wire() {
  // Generic back
  document.getElementById('ob-back')?.addEventListener('click', () => _goTo(_backFrom(_step)));

  // Generic next (steps that use a plain Next button)
  const nextBtn = document.getElementById('ob-next');

  // ── profile ──
  if (_step === 'profile' && nextBtn) {
    nextBtn.addEventListener('click', () => {
      const name = document.getElementById('ob-name')?.value.trim();
      if (!name) { toast('Provider name is required.'); return; }
      kvSet(PROVIDER_KEY, {
        name,
        credentials: document.getElementById('ob-creds')?.value.trim() || '',
        specialty:   document.getElementById('ob-specialty')?.value || 'psychiatry',
      });
      _goTo(_nextFrom('profile'));
    });
  }

  // ── terms ──
  if (_step === 'terms') {
    document.getElementById('ob-baa-check')?.addEventListener('change', e => {
      if (nextBtn) nextBtn.disabled = !e.target.checked;
    });
    nextBtn?.addEventListener('click', () => {
      if (!document.getElementById('ob-baa-check')?.checked) return;
      kvSet('note_settings_v1::baa_accepted', { accepted: true, date: new Date().toISOString() });
      _goTo(_nextFrom('terms'));
    });
  }

  // ── cloud-choice ──
  if (_step === 'cloud-choice') {
    document.getElementById('ob-choose-cloud')?.addEventListener('click', () => {
      _cloudPath = true;
      _goTo(_nextFrom('cloud-choice'));
    });
    document.getElementById('ob-choose-local')?.addEventListener('click', () => {
      _cloudPath = false;
      _goTo('finish');
    });
  }

  // ── cloud-account ──
  if (_step === 'cloud-account') {
    let _mode = 'register';

    document.getElementById('ob-switch-mode')?.addEventListener('click', () => {
      _mode = _mode === 'register' ? 'login' : 'register';
      const container = document.getElementById('ob-step');
      if (container) { container.innerHTML = _stepCloudAccount(_mode); _wire(); }
    });

    document.getElementById('ob-do-register')?.addEventListener('click', async () => {
      const orgName  = document.getElementById('ob-org-name')?.value.trim();
      const email    = document.getElementById('ob-email')?.value.trim();
      const password = document.getElementById('ob-password')?.value;
      const betaCode = document.getElementById('ob-beta-code')?.value.trim();
      if (!orgName || !email || !password) {
        const container = document.getElementById('ob-step');
        if (container) { container.innerHTML = _stepCloudAccount('register', 'All fields are required.'); _wire(); }
        return;
      }
      const btn = document.getElementById('ob-do-register');
      btn.disabled = true; btn.textContent = 'Creating account…';
      try {
        const providerName = kvGet(PROVIDER_KEY)?.name || '';
        await cloudRegister(orgName, email, password, providerName, betaCode);
        await cloudLogin(email, password);
        _orgName = orgName;
        _goTo(_nextFrom('cloud-account'));
      } catch (e) {
        const container = document.getElementById('ob-step');
        if (container) { container.innerHTML = _stepCloudAccount('register', e.message || 'Registration failed.'); _wire(); }
      }
    });

    document.getElementById('ob-do-login')?.addEventListener('click', async () => {
      const email    = document.getElementById('ob-email')?.value.trim();
      const password = document.getElementById('ob-password')?.value;
      if (!email || !password) {
        const container = document.getElementById('ob-step');
        if (container) { container.innerHTML = _stepCloudAccount('login', 'Email and password are required.'); _wire(); }
        return;
      }
      const btn = document.getElementById('ob-do-login');
      btn.disabled = true; btn.textContent = 'Logging in…';
      try {
        await cloudLogin(email, password);
        // For login path, fetch org name from server
        const res = await apiFetch('/api/account/me');
        if (res.ok) { const d = await res.json(); _orgName = d.org?.name || ''; }
        _goTo(_nextFrom('cloud-account'));
      } catch (e) {
        const container = document.getElementById('ob-step');
        if (container) { container.innerHTML = _stepCloudAccount('login', e.message || 'Login failed.'); _wire(); }
      }
    });
  }

  // ── baa ──
  if (_step === 'baa') {
    document.getElementById('ob-baa-cloud-check')?.addEventListener('change', e => {
      if (nextBtn) nextBtn.disabled = !e.target.checked;
    });
    document.getElementById('ob-baa-link')?.addEventListener('click', e => {
      e.preventDefault();
      tauriInvoke('open_url', { url: 'https://www.tahlkscribe.com/baa' }).catch(() => {});
    });
    nextBtn?.addEventListener('click', async () => {
      if (!document.getElementById('ob-baa-cloud-check')?.checked) return;
      nextBtn.disabled = true; nextBtn.textContent = 'Recording…';
      try {
        const signerName = kvGet(PROVIDER_KEY)?.name || 'Provider';
        await acceptBaa(signerName);
        _goTo(_nextFrom('baa'));
      } catch (e) {
        toast(e.message || 'Could not record BAA acceptance. Check your connection.');
        nextBtn.disabled = false; nextBtn.textContent = 'Accept & Continue →';
      }
    });
  }

  // ── subscribe ──
  if (_step === 'subscribe') {
    document.querySelectorAll('.ob-subscribe-btn').forEach(btn => {
      btn.addEventListener('click', async () => {
        const tier = btn.dataset.tier;
        btn.disabled = true; btn.textContent = 'Opening…';
        try {
          const res = await apiFetch('/api/billing/checkout', {
            method: 'POST',
            body: JSON.stringify({ tier }),
          });
          if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || `Error ${res.status}`);
          const { url } = await res.json();
          await tauriInvoke('open_url', { url });
          // Re-render with "pending" banner
          const container = document.getElementById('ob-step');
          if (container) { container.innerHTML = _stepSubscribe(true); _wire(); }
        } catch (e) {
          toast(e.message || 'Could not open checkout.');
          btn.disabled = false; btn.textContent = 'Subscribe';
        }
      });
    });

    document.getElementById('ob-skip-subscribe')?.addEventListener('click', () => _goTo('finish'));
  }

  // ── finish ──
  if (_step === 'finish') {
    document.getElementById('ob-finish-btn')?.addEventListener('click', () => {
      kvSet(ONBOARDED_KEY, true);
      _onComplete?.();
    });
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function _specialtyLabel(v) {
  return { psychiatry: 'Psychiatry', 'behavioral-health': 'Behavioral Health / Therapy',
           psychology: 'Psychology', podiatry: 'Podiatry', other: 'Other' }[v] || v;
}

function esc(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/"/g,'&quot;')
    .replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
