// Settings modal — provider profile, API key, Whisper model, cloud auth, billing.

import { kvGet, kvSet, tauriInvoke } from '../core/storageBackend.js';
import { checkModelDownloaded, downloadModel } from '../scribe/transcriber.js';
import { toast } from '../utils/format.js';
import { specialtyLabel } from '../core/specialties.js';
import { isAuthenticated, getProvider, login, logout, register, forgotPassword, inviteProvider } from '../core/auth.js';
import { apiFetch } from '../core/api.js';

const PROVIDER_KEY = 'note_provider_v1::profile';

const TIERS = [
  { id: 'SOLO', label: 'Solo',  price: '$599',   desc: '1 provider' },
  { id: 'PRO',  label: 'Pro',   price: '$1,699',  desc: '2–3 providers' },
  { id: 'FIRM', label: 'Firm',  price: '$3,499',  desc: '4–5 providers' },
];

// ── Render ─────────────────────────────────────────────────────────────────

export async function renderSettings() {
  const provider = kvGet(PROVIDER_KEY) || {};
  const modelOk  = await checkModelDownloaded().catch(() => false);
  const hasKey   = !!(kvGet('note_settings_v1::anthropic_api_key'));
  const keepAudio = !!(kvGet('note_settings_v1::keep_audio_after_transcription'));
  const baa      = kvGet('note_settings_v1::baa_accepted') || null;

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
            ${['psychiatry','behavioral-health','psychology','podiatry','other'].map(v =>
              `<option value="${v}" ${provider.specialty === v ? 'selected' : ''}>${specialtyLabel(v)}</option>`
            ).join('')}
          </select>
        </div>
        <button class="btn btn-primary" id="s-save-provider">Save Profile</button>
      </section>

      <section class="settings-section">
        <h3>Transcription Model (Whisper)</h3>
        <p class="settings-desc">Local speech recognition — runs entirely on this device. No audio is sent to any server.</p>
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
          Your API key is stored on this device only and used to call Claude to generate clinical notes.
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

      ${await _renderCloudSection()}

      <section class="settings-section settings-section--danger">
        <h3>Privacy</h3>
        <p class="settings-desc">
          <strong>Audio never leaves this device.</strong> Recordings are transcribed locally.
          Transcript text is sent to Anthropic (Claude) using your own API key — audio is never transmitted.
          Notes are stored in a local SQLite database.
          ${isAuthenticated() ? ' Cloud backup encrypts all note content client-side before upload — Tahlk servers cannot read your notes.' : ''}
        </p>
        <div class="setting-toggle-row">
          <div class="setting-toggle-label">
            <strong>Delete audio after transcription</strong>
            <span class="settings-desc" style="margin:0">Removes recordings once transcribed. Recommended for HIPAA compliance.</span>
          </div>
          <label class="toggle-switch">
            <input type="checkbox" id="s-keep-audio" ${keepAudio ? '' : 'checked'} />
            <span class="toggle-track"></span>
          </label>
        </div>
      </section>

      <section class="settings-section">
        <h3>Legal</h3>
        ${baa
          ? `<p class="settings-desc">Beta agreement acknowledged on <strong>${new Date(baa.date).toLocaleDateString()}</strong>.</p>`
          : `<p class="settings-desc" style="color:var(--danger)">Beta agreement not yet acknowledged.</p>`
        }
        <a href="https://www.tahlkscribe.com/beta-terms" target="_blank" class="settings-link">View Beta Terms →</a>
      </section>
    </div>
  `;
}

async function _renderCloudSection() {
  if (!isAuthenticated()) {
    return `
      <section class="settings-section" id="cloud-section">
        <h3>Cloud Backup &amp; Sync</h3>
        <p class="settings-desc">
          Securely back up your notes to the cloud. All clinical content is
          encrypted on this device before upload — Tahlk cannot read your notes.
        </p>
        <div id="cloud-auth-panel">
          ${_renderLoginForm()}
        </div>
      </section>`;
  }

  // Authenticated — show billing status
  const cloudProvider = getProvider();
  let billingHtml = '<p class="settings-desc">Checking subscription…</p>';
  try {
    const res  = await apiFetch('/api/billing/status');
    if (res.ok) {
      const sub = await res.json();
      billingHtml = _renderBillingStatus(sub);
    }
  } catch { /* server unreachable — show tier cards anyway */ }

  return `
    <section class="settings-section" id="cloud-section">
      <h3>Cloud Backup &amp; Sync</h3>
      <div class="cloud-account-row">
        <span class="cloud-account-email">${esc(cloudProvider?.email ?? '')}</span>
        <button class="btn btn-ghost btn-sm" id="s-logout-cloud">Log out</button>
      </div>
      <div id="billing-panel">${billingHtml}</div>
    </section>`;
}

function _renderLoginForm(showRegister = false) {
  if (showRegister) {
    return `
      <div class="cloud-form" id="register-form">
        <div class="field-row"><label>Practice name</label>
          <input type="text" id="s-org-name" placeholder="Sunrise Behavioral Health" /></div>
        <div class="field-row"><label>Your name</label>
          <input type="text" id="s-reg-name" placeholder="Dr. Jane Smith" /></div>
        <div class="field-row"><label>Email</label>
          <input type="email" id="s-reg-email" placeholder="you@practice.com" autocomplete="off" /></div>
        <div class="field-row"><label>Password <span class="req">*</span></label>
          <input type="password" id="s-reg-password" placeholder="12+ characters" autocomplete="new-password" /></div>
        <div class="field-row"><label>Beta invite code</label>
          <input type="text" id="s-beta-code" placeholder="Leave blank if not required" autocomplete="off" /></div>
        <div class="form-actions">
          <button class="btn btn-primary" id="s-do-register">Create Account</button>
          <button class="btn btn-ghost btn-sm" id="s-show-login">Back to Log In</button>
        </div>
        <p id="s-auth-error" class="auth-error" style="display:none"></p>
      </div>`;
  }
  return `
    <div class="cloud-form" id="login-form">
      <div class="field-row"><label>Email</label>
        <input type="email" id="s-login-email" placeholder="you@practice.com" autocomplete="off" /></div>
      <div class="field-row"><label>Password</label>
        <input type="password" id="s-login-password" autocomplete="current-password" /></div>
      <div class="form-actions">
        <button class="btn btn-primary" id="s-do-login">Log In</button>
        <button class="btn btn-ghost btn-sm" id="s-show-register">New account →</button>
      </div>
      <p class="s-forgot-row"><button class="btn-inline" id="s-show-forgot">Forgot password?</button></p>
      <p id="s-auth-error" class="auth-error" style="display:none"></p>
    </div>`;
}

function _renderBillingStatus(sub) {
  const tierLabel = { SOLO: 'Solo', PRO: 'Pro', FIRM: 'Firm' }[sub.tier] ?? sub.tier;
  const statusLabel = {
    active:   '<span class="billing-badge billing-badge--active">Active</span>',
    past_due: '<span class="billing-badge billing-badge--warn">Past due</span>',
    canceled: '<span class="billing-badge billing-badge--error">Canceled</span>',
    free:     '<span class="billing-badge">Free</span>',
  }[sub.status] ?? `<span class="billing-badge">${sub.status}</span>`;

  const isSubscribed = sub.status === 'active' || sub.status === 'past_due';

  if (isSubscribed) {
    const renewDate = sub.currentPeriodEnd
      ? new Date(sub.currentPeriodEnd).toLocaleDateString()
      : '—';
    const cancelNote = sub.cancelAtPeriodEnd
      ? `<p class="settings-desc" style="color:var(--danger)">Cancels at end of period (${renewDate}).</p>`
      : `<p class="settings-desc">Renews ${renewDate}</p>`;
    return `
      <div class="billing-status-row">
        <span class="billing-tier">${tierLabel} plan</span>${statusLabel}
      </div>
      ${cancelNote}
      <button class="btn btn-secondary btn-sm" id="s-manage-billing">Manage Billing →</button>
      <button class="btn btn-ghost btn-sm" id="s-refresh-billing">↻ Refresh</button>`;
  }

  // No active subscription — show tier cards
  return `
    <p class="settings-desc">No active subscription. Choose a plan to enable cloud backup and sync.</p>
    <div class="tier-cards">
      ${TIERS.map(t => `
        <div class="tier-card">
          <div class="tier-card-name">${t.label}</div>
          <div class="tier-card-price">${t.price}<span>/mo</span></div>
          <div class="tier-card-desc">${t.desc}</div>
          <button class="btn btn-primary btn-sm tier-subscribe" data-tier="${t.id}">Subscribe</button>
        </div>`).join('')}
    </div>
    <button class="btn btn-ghost btn-sm" id="s-refresh-billing" style="margin-top:.5rem">↻ Refresh after checkout</button>`;
}

// ── Wire ───────────────────────────────────────────────────────────────────

export function wireSettings() {
  // Provider profile
  document.getElementById('s-save-provider')?.addEventListener('click', () => {
    const profile = {
      name:        document.getElementById('s-name')?.value.trim() || '',
      credentials: document.getElementById('s-creds')?.value.trim() || '',
      specialty:   document.getElementById('s-specialty')?.value || 'psychiatry',
    };
    kvSet(PROVIDER_KEY, profile);
    toast('Profile saved.');
  });

  // Whisper model
  document.getElementById('s-download-model')?.addEventListener('click', async () => {
    const bar  = document.getElementById('s-model-progress');
    const fill = document.getElementById('s-model-fill');
    if (bar) bar.style.display = 'block';
    try {
      await downloadModel(pct => { if (fill) fill.style.width = `${Math.round(pct * 100)}%`; });
      toast('Model downloaded.');
      document.getElementById('s-download-model').disabled = true;
      document.getElementById('s-download-model').textContent = 'Model Downloaded';
    } catch (e) { toast(`Download failed: ${e.message || e}`); }
  });

  // API key
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

  // Audio toggle
  document.getElementById('s-keep-audio')?.addEventListener('change', e => {
    kvSet('note_settings_v1::keep_audio_after_transcription', !e.target.checked);
    toast(e.target.checked ? 'Audio will be deleted after transcription.' : 'Audio will be kept after transcription.');
  });

  // Cloud auth
  _wireCloudAuth();
}

function _wireCloudAuth() {
  // Toggle between login and register forms
  document.getElementById('s-show-register')?.addEventListener('click', () => {
    const panel = document.getElementById('cloud-auth-panel');
    if (panel) panel.innerHTML = _renderLoginForm(true);
    _wireCloudAuth();
  });
  document.getElementById('s-show-login')?.addEventListener('click', () => {
    const panel = document.getElementById('cloud-auth-panel');
    if (panel) panel.innerHTML = _renderLoginForm(false);
    _wireCloudAuth();
  });

  // Log in
  document.getElementById('s-do-login')?.addEventListener('click', async () => {
    const email    = document.getElementById('s-login-email')?.value.trim();
    const password = document.getElementById('s-login-password')?.value;
    const errEl    = document.getElementById('s-auth-error');
    if (!email || !password) { _showAuthError('Email and password are required.'); return; }
    const btn = document.getElementById('s-do-login');
    btn.disabled = true; btn.textContent = 'Logging in…';
    try {
      await login(email, password);
      // Reload the settings page to show the billing panel
      const main = document.getElementById('main-content');
      if (main) { main.innerHTML = await renderSettings(); wireSettings(); }
    } catch (e) {
      _showAuthError(e.message || 'Login failed.');
      btn.disabled = false; btn.textContent = 'Log In';
    }
  });

  // Register
  document.getElementById('s-do-register')?.addEventListener('click', async () => {
    const orgName  = document.getElementById('s-org-name')?.value.trim();
    const name     = document.getElementById('s-reg-name')?.value.trim();
    const email    = document.getElementById('s-reg-email')?.value.trim();
    const password = document.getElementById('s-reg-password')?.value;
    const betaCode = document.getElementById('s-beta-code')?.value.trim();
    if (!orgName || !email || !password) { _showAuthError('Practice name, email, and password are required.'); return; }
    const btn = document.getElementById('s-do-register');
    btn.disabled = true; btn.textContent = 'Creating account…';
    try {
      await register(orgName, email, password, name, betaCode);
      await login(email, password);
      const main = document.getElementById('main-content');
      if (main) { main.innerHTML = await renderSettings(); wireSettings(); }
    } catch (e) {
      _showAuthError(e.message || 'Registration failed.');
      btn.disabled = false; btn.textContent = 'Create Account';
    }
  });

  // Forgot password — shows an inline email form; server sends reset email
  document.getElementById('s-show-forgot')?.addEventListener('click', () => {
    const panel = document.getElementById('cloud-auth-panel');
    if (!panel) return;
    panel.innerHTML = `
      <div class="cloud-form" id="forgot-form">
        <p style="margin-top:0;color:var(--gray-600);font-size:13px">
          Enter your email and we'll send a reset link.
        </p>
        <div class="field-row">
          <label>Email</label>
          <input type="email" id="s-forgot-email" placeholder="you@practice.com" autocomplete="off" />
        </div>
        <div class="form-actions">
          <button class="btn btn-primary" id="s-do-forgot">Send Reset Link</button>
          <button class="btn btn-ghost btn-sm" id="s-back-to-login">Cancel</button>
        </div>
        <p id="s-auth-error" class="auth-error" style="display:none"></p>
        <p id="s-forgot-ok" class="s-forgot-ok" style="display:none">
          Check your email — a reset link is on its way.
        </p>
      </div>`;

    document.getElementById('s-back-to-login')?.addEventListener('click', () => {
      panel.innerHTML = _renderLoginForm(false);
      _wireCloudAuth();
    });

    document.getElementById('s-do-forgot')?.addEventListener('click', async () => {
      const email = document.getElementById('s-forgot-email')?.value.trim();
      if (!email) { _showAuthError('Email is required.'); return; }
      const btn = document.getElementById('s-do-forgot');
      btn.disabled = true; btn.textContent = 'Sending…';
      await forgotPassword(email);
      document.getElementById('s-forgot-form') && (document.getElementById('s-forgot-form').style.display = 'none');
      const okEl = document.getElementById('s-forgot-ok');
      if (okEl) okEl.style.display = 'block';
    });
  });

  // Log out
  document.getElementById('s-logout-cloud')?.addEventListener('click', async () => {
    if (!confirm('Log out of Tahlk Cloud? Background sync will stop until you log in again.')) return;
    await logout();
    const main = document.getElementById('main-content');
    if (main) { main.innerHTML = await renderSettings(); wireSettings(); }
  });

  // Billing actions
  _wireBilling();
}

function _wireBilling() {
  // Subscribe button(s)
  document.querySelectorAll('.tier-subscribe').forEach(btn => {
    btn.addEventListener('click', async () => {
      const tier = btn.dataset.tier;
      btn.disabled = true; btn.textContent = 'Opening…';
      try {
        const res  = await apiFetch('/api/billing/checkout', {
          method: 'POST',
          body: JSON.stringify({ tier }),
        });
        if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || `Error ${res.status}`);
        const { url } = await res.json();
        await tauriInvoke('open_url', { url });
        toast('Checkout opened in your browser. Return here after payment.');
      } catch (e) {
        toast(e.message || 'Could not open checkout.');
      } finally {
        btn.disabled = false;
        btn.textContent = 'Subscribe';
      }
    });
  });

  // Manage billing (Stripe portal)
  document.getElementById('s-manage-billing')?.addEventListener('click', async () => {
    const btn = document.getElementById('s-manage-billing');
    btn.disabled = true; btn.textContent = 'Opening…';
    try {
      const res = await apiFetch('/api/billing/portal', { method: 'POST', body: '{}' });
      if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || `Error ${res.status}`);
      const { url } = await res.json();
      await tauriInvoke('open_url', { url });
    } catch (e) {
      toast(e.message || 'Could not open billing portal.');
    } finally {
      btn.disabled = false; btn.textContent = 'Manage Billing →';
    }
  });

  // Refresh billing status
  document.getElementById('s-refresh-billing')?.addEventListener('click', async () => {
    const panel = document.getElementById('billing-panel');
    if (!panel) return;
    panel.innerHTML = '<p class="settings-desc">Refreshing…</p>';
    try {
      const res = await apiFetch('/api/billing/status');
      panel.innerHTML = res.ok ? _renderBillingStatus(await res.json()) : '<p class="settings-desc">Could not fetch status.</p>';
      _wireBilling();
    } catch { panel.innerHTML = '<p class="settings-desc">Could not reach server.</p>'; }
  });
}

// ── Helpers ────────────────────────────────────────────────────────────────

function _showAuthError(msg) {
  const el = document.getElementById('s-auth-error');
  if (el) { el.textContent = msg; el.style.display = 'block'; }
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;');
}
