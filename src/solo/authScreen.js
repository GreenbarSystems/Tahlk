// ADR 0004 auth screens — shown before the app shell renders at every process start.
//
// Exports:
//   showSignInScreen(onUnlocked)       — subsequent opens: password prompt + lockout.
//   runFirstOpenAuth(appEl, onComplete) — first-open: Screens A → C → D.
//
// Both render into a caller-supplied element (typically #app). The screen is
// cleared and replaced by the normal app flow once auth passes.
//
// Failed-attempt lockout mirrors lockScreen.js: 5 tries → 30s cooldown,
// doubling each time the threshold is crossed again.

import { authRepo } from '../data/authRepo.js';
import { createModal } from '../platform/modal.js';
import { kvGet } from '../core/storageBackend.js';
import { keys } from '../data/keys.js';
import { userMessage } from '../platform/appError.js';
import { escapeHtml } from '../utils/format.js';
import { clipboardWriteText } from '../platform/tauri.js';

const BASE_LOCKOUT_MS = 30_000;
const ATTEMPTS_BEFORE_LOCKOUT = 5;
const PASSWORD_MIN_LEN = 12;

// ─── helpers ─────────────────────────────────────────────────────────────────

function providerDisplayName() {
  const p = kvGet(keys.provider());
  return p && p.name ? p.name : '';
}

// UX-only strength hint: 0–4. Not a security control.
function passwordStrength(pw) {
  if (!pw || pw.length < 4) return 0;
  let s = 0;
  if (pw.length >= PASSWORD_MIN_LEN) s++;
  if (pw.length >= 20) s++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) s++;
  if (/\d/.test(pw)) s++;
  if (/[^A-Za-z0-9]/.test(pw)) s++;
  return Math.min(s, 4);
}

const STRENGTH_LABELS = ['', 'Weak', 'Fair', 'Good', 'Strong'];
const STRENGTH_COLORS = ['', 'var(--danger)', 'var(--warn)', 'var(--teal)', 'var(--green)'];

// ─── sign-in screen (subsequent opens) ───────────────────────────────────────

// Renders the sign-in form into `#app` and calls `onUnlocked` after a
// successful password verification. Does not return a value; the caller must
// await `onUnlocked` firing (e.g. via a wrapping Promise).
export function showSignInScreen(onUnlocked) {
  const app = document.getElementById('app');
  const name = providerDisplayName();

  app.innerHTML = `
    <div class="auth-signin-backdrop">
      <div class="auth-signin-card">
        <div class="auth-icon" aria-hidden="true">🔐</div>
        <h1 class="auth-title">Welcome back${name ? ', ' + escapeHtml(name) : ''}.</h1>
        <p class="auth-sub">Enter your Tahlk password to continue.</p>
        <form id="auth-signin-form" autocomplete="off">
          <div class="field-row">
            <label for="auth-signin-pw">Password</label>
            <input id="auth-signin-pw" type="password" autocomplete="current-password" />
          </div>
          <p class="auth-error" id="auth-signin-error" hidden></p>
          <button type="submit" class="btn btn-primary btn-lg auth-full-btn" id="auth-signin-btn">
            Sign in
          </button>
        </form>
        <p class="auth-forgot-row">
          <button type="button" class="btn btn-ghost btn-sm" id="auth-forgot-btn">
            Forgot password?
          </button>
        </p>
      </div>
    </div>
  `;

  const form = app.querySelector('#auth-signin-form');
  const input = app.querySelector('#auth-signin-pw');
  const errorEl = app.querySelector('#auth-signin-error');
  const submitBtn = app.querySelector('#auth-signin-btn');
  const forgotBtn = app.querySelector('#auth-forgot-btn');

  let failedAttempts = 0;
  let lockedUntil = 0;

  function showError(msg) { errorEl.textContent = msg; errorEl.hidden = false; }
  function clearError()   { errorEl.hidden = true; }
  function remainingMs()  { return Math.max(0, lockedUntil - Date.now()); }

  form.addEventListener('submit', async e => {
    e.preventDefault?.();
    const remaining = remainingMs();
    if (remaining > 0) {
      showError(`Too many attempts. Try again in ${Math.ceil(remaining / 1000)}s.`);
      return;
    }
    const pw = input.value;
    if (!pw) { showError('Enter your password.'); return; }

    submitBtn.disabled = true;
    clearError();
    try {
      await authRepo.unlockWithPassword(pw);
      app.innerHTML = '';
      onUnlocked();
    } catch (err) {
      failedAttempts++;
      if (failedAttempts >= ATTEMPTS_BEFORE_LOCKOUT) {
        const cooldown = BASE_LOCKOUT_MS * 2 ** (failedAttempts - ATTEMPTS_BEFORE_LOCKOUT);
        lockedUntil = Date.now() + cooldown;
        showError(`Too many attempts. Try again in ${Math.ceil(cooldown / 1000)}s.`);
      } else {
        showError('Incorrect password.');
      }
      input.value = '';
      input.focus?.();
    } finally {
      submitBtn.disabled = false;
    }
  });

  forgotBtn.addEventListener('click', () => {
    showForgotPasswordModal(() => {
      app.innerHTML = '';
      onUnlocked();
    });
  });

  input.focus?.();
}

// ─── forgot-password modal ────────────────────────────────────────────────────

function showForgotPasswordModal(onUnlocked) {
  const modal = createModal({
    backdropId: 'auth-forgot-modal',
    closeOnEscape: false,
    closeOnBackdrop: false,
  });
  const { card } = modal;
  card.className = 'auth-modal-card';

  function renderView(viewFn) {
    card.innerHTML = '';
    viewFn(card, modal, onUnlocked);
  }

  renderView(renderForgotOptions);
  modal.open();
}

function renderForgotOptions(card, modal, onUnlocked) {
  card.innerHTML = `
    <h2 class="auth-modal-title">Forgot your password?</h2>
    <p class="auth-sub">Choose how you want to recover access to your records.</p>
    <div class="auth-option-list">
      <button class="auth-option-btn" id="auth-opt-recovery">
        <span class="auth-option-icon" aria-hidden="true">🔑</span>
        <span>
          <strong>Enter a recovery code</strong>
          <span class="auth-option-desc">Use one of the three codes you saved at setup.</span>
        </span>
      </button>
      <button class="auth-option-btn auth-option-btn--danger" id="auth-opt-nuke">
        <span class="auth-option-icon" aria-hidden="true">⚠️</span>
        <span>
          <strong>Reinstall and start fresh</strong>
          <span class="auth-option-desc">Permanently deletes all records. Cannot be undone.</span>
        </span>
      </button>
    </div>
    <button class="btn btn-ghost btn-sm" id="auth-forgot-cancel">Cancel — go back</button>
  `;

  card.querySelector('#auth-opt-recovery').addEventListener('click', () => {
    card.innerHTML = '';
    renderRecoveryEntry(card, modal, onUnlocked);
  });

  card.querySelector('#auth-opt-nuke').addEventListener('click', () => {
    card.innerHTML = '';
    renderNukeConfirmation(card, modal);
  });

  card.querySelector('#auth-forgot-cancel').addEventListener('click', () => modal.close());
}

function renderRecoveryEntry(card, modal, onUnlocked) {
  card.innerHTML = `
    <h2 class="auth-modal-title">Enter a recovery code</h2>
    <p class="auth-sub">Any of your three recovery codes will work. Hyphens are optional.</p>
    <form id="auth-recovery-form" autocomplete="off">
      <div class="field-row">
        <label for="auth-rec-code">Recovery code</label>
        <input id="auth-rec-code" type="text" autocomplete="off"
               placeholder="XXXXXX-XXXXXX-XXXXXX-XXXXXX-X"
               style="font-family:monospace;letter-spacing:1px" />
      </div>
      <div class="field-row">
        <label for="auth-rec-pw">New password <span class="req">*</span></label>
        <input id="auth-rec-pw" type="password" autocomplete="new-password" />
        <div class="auth-strength-row" id="auth-rec-strength-row" hidden>
          <div class="auth-strength-bar">
            <div class="auth-strength-fill" id="auth-rec-strength-fill"></div>
          </div>
          <span class="auth-strength-label" id="auth-rec-strength-label"></span>
        </div>
      </div>
      <div class="field-row">
        <label for="auth-rec-pw2">Confirm new password <span class="req">*</span></label>
        <input id="auth-rec-pw2" type="password" autocomplete="new-password" />
      </div>
      <p class="auth-error" id="auth-rec-error" hidden></p>
      <div class="auth-modal-actions">
        <button type="button" class="btn btn-secondary" id="auth-rec-back">Back</button>
        <button type="submit" class="btn btn-primary" id="auth-rec-submit">Reset password</button>
      </div>
    </form>
  `;

  const form = card.querySelector('#auth-recovery-form');
  const codeInput = card.querySelector('#auth-rec-code');
  const pwInput = card.querySelector('#auth-rec-pw');
  const pw2Input = card.querySelector('#auth-rec-pw2');
  const errorEl = card.querySelector('#auth-rec-error');
  const submitBtn = card.querySelector('#auth-rec-submit');
  const strengthRow = card.querySelector('#auth-rec-strength-row');
  const strengthFill = card.querySelector('#auth-rec-strength-fill');
  const strengthLabel = card.querySelector('#auth-rec-strength-label');

  pwInput.addEventListener('input', () => {
    const s = passwordStrength(pwInput.value);
    strengthRow.hidden = !pwInput.value;
    strengthFill.style.width = `${s * 25}%`;
    strengthFill.style.background = STRENGTH_COLORS[s] || '';
    strengthLabel.textContent = STRENGTH_LABELS[s] || '';
    strengthLabel.style.color = STRENGTH_COLORS[s] || '';
  });

  function showError(msg) { errorEl.textContent = msg; errorEl.hidden = false; }

  card.querySelector('#auth-rec-back').addEventListener('click', () => {
    card.innerHTML = '';
    renderForgotOptions(card, modal, onUnlocked);
  });

  form.addEventListener('submit', async e => {
    e.preventDefault?.();
    const code = codeInput.value.trim();
    const pw = pwInput.value;
    const pw2 = pw2Input.value;

    if (!code) { showError('Enter a recovery code.'); return; }
    if (!pw) { showError('Enter a new password.'); return; }
    if (pw.length < PASSWORD_MIN_LEN) {
      showError(`Password must be at least ${PASSWORD_MIN_LEN} characters.`); return;
    }
    if (pw !== pw2) { showError('Passwords do not match.'); return; }

    submitBtn.disabled = true;
    errorEl.hidden = true;
    try {
      const newCodes = await authRepo.resetWithRecoveryCode(code, pw);
      modal.close();
      // Show the new recovery codes before unlocking (Screen C re-run).
      const appEl = document.getElementById('app');
      runRecoveryCodeScreen(appEl, newCodes, onUnlocked);
    } catch (err) {
      showError(userMessage(err, 'Recovery code was not accepted. Please try again.'));
      submitBtn.disabled = false;
    }
  });

  codeInput.focus?.();
}

function renderNukeConfirmation(card, modal) {
  card.innerHTML = `
    <h2 class="auth-modal-title auth-title-danger">Delete everything?</h2>
    <p class="auth-sub">
      This permanently deletes <strong>every note, recording, and patient record</strong>
      on this computer. There is no undo. Your next launch will be a fresh install.
    </p>
    <div class="field-row" style="margin-top:16px">
      <label for="auth-nuke-confirm">Type <code>DELETE</code> to confirm</label>
      <input id="auth-nuke-confirm" type="text" autocomplete="off" spellcheck="false" />
    </div>
    <p class="auth-error" id="auth-nuke-error" hidden></p>
    <div class="auth-modal-actions">
      <button type="button" class="btn btn-secondary" id="auth-nuke-back">Cancel</button>
      <button type="button" class="btn btn-primary btn-danger" id="auth-nuke-go" disabled>
        Delete everything
      </button>
    </div>
  `;

  const confirmInput = card.querySelector('#auth-nuke-confirm');
  const nukeBtn = card.querySelector('#auth-nuke-go');
  const errorEl = card.querySelector('#auth-nuke-error');

  confirmInput.addEventListener('input', () => {
    nukeBtn.disabled = confirmInput.value.trim() !== 'DELETE';
  });

  card.querySelector('#auth-nuke-back').addEventListener('click', () => {
    card.innerHTML = '';
    renderForgotOptions(card, modal, () => {});
  });

  nukeBtn.addEventListener('click', async () => {
    nukeBtn.disabled = true;
    errorEl.hidden = true;
    try {
      await authRepo.nukeAndReinstall();
      // Hard reload so next launch starts fresh.
      window.location.reload();
    } catch (err) {
      errorEl.textContent = userMessage(err, 'Could not complete reinstall. Please try again.');
      errorEl.hidden = false;
      nukeBtn.disabled = confirmInput.value.trim() !== 'DELETE';
    }
  });

  confirmInput.focus?.();
}

// ─── first-open auth setup (Screens A → C → D) ───────────────────────────────

// Runs the full first-open flow, rendering each screen into `appEl` (#app).
// `onComplete` is called when the flow finishes; the caller then continues
// with the normal onboarding / app-render flow.
export async function runFirstOpenAuth(appEl, onComplete) {
  // Screen A: set password → Rust returns 3 recovery codes
  const codes = await new Promise((resolve, reject) => {
    renderSetPasswordScreen(appEl, resolve, reject);
  });

  // Screen C: save recovery codes (one at a time)
  await new Promise(resolve => runRecoveryCodeScreen(appEl, codes, resolve));

  // Screen D: optional email reminder
  await new Promise(resolve => renderEmailReminderScreen(appEl, codes, resolve));

  onComplete();
}

// ─── Screen A: set password ───────────────────────────────────────────────────

function renderSetPasswordScreen(appEl, onCodes) {
  appEl.innerHTML = `
    <div class="onboarding-backdrop">
      <div class="onboarding-card">
        <div class="auth-step-badge">Step 1 of 3 — Set your password</div>
        <h1 class="onboarding-title">Protect your patient records.</h1>
        <p class="onboarding-sub">
          Your password stays on this device — Greenbar never sees it and cannot reset it.
          Recovery codes (shown next) are your only fallback if you forget it.
        </p>
        <div class="field-row">
          <label for="auth-pw">Password <span class="req">*</span></label>
          <input id="auth-pw" type="password" autocomplete="new-password"
                 placeholder="At least ${PASSWORD_MIN_LEN} characters" />
          <div class="auth-strength-row" id="auth-strength-row" hidden>
            <div class="auth-strength-bar">
              <div class="auth-strength-fill" id="auth-strength-fill"></div>
            </div>
            <span class="auth-strength-label" id="auth-strength-label"></span>
          </div>
        </div>
        <div class="field-row">
          <label for="auth-pw2">Confirm password <span class="req">*</span></label>
          <input id="auth-pw2" type="password" autocomplete="new-password" />
        </div>
        <p class="auth-error" id="auth-pw-error" hidden></p>
        <div class="onboarding-footer">
          <button class="btn btn-primary btn-lg" id="auth-pw-submit">
            Create password &amp; continue →
          </button>
        </div>
      </div>
    </div>
  `;

  const pwInput = appEl.querySelector('#auth-pw');
  const pw2Input = appEl.querySelector('#auth-pw2');
  const errorEl = appEl.querySelector('#auth-pw-error');
  const submitBtn = appEl.querySelector('#auth-pw-submit');
  const strengthRow = appEl.querySelector('#auth-strength-row');
  const strengthFill = appEl.querySelector('#auth-strength-fill');
  const strengthLabelEl = appEl.querySelector('#auth-strength-label');

  pwInput.addEventListener('input', () => {
    const s = passwordStrength(pwInput.value);
    strengthRow.hidden = !pwInput.value;
    strengthFill.style.width = `${s * 25}%`;
    strengthFill.style.background = STRENGTH_COLORS[s] || '';
    strengthLabelEl.textContent = STRENGTH_LABELS[s] || '';
    strengthLabelEl.style.color = STRENGTH_COLORS[s] || '';
  });

  function showError(msg) { errorEl.textContent = msg; errorEl.hidden = false; }

  submitBtn.addEventListener('click', async () => {
    errorEl.hidden = true;
    const pw = pwInput.value;
    const pw2 = pw2Input.value;

    if (!pw) { showError('Password is required.'); return; }
    if (pw.length < PASSWORD_MIN_LEN) {
      showError(`Password must be at least ${PASSWORD_MIN_LEN} characters.`); return;
    }
    if (pw !== pw2) { showError('Passwords do not match.'); return; }

    submitBtn.disabled = true;
    submitBtn.textContent = 'Setting up…';
    try {
      const codes = await authRepo.setPassword(pw);
      onCodes(codes);
    } catch (err) {
      showError(userMessage(err, 'Could not set password. Please try again.'));
      submitBtn.disabled = false;
      submitBtn.textContent = 'Create password & continue →';
    }
  });

  pwInput.focus?.();
}

// ─── Screen C: save recovery codes ───────────────────────────────────────────

// `codes` is string[] of display-formatted codes (e.g. "XXXXXX-XXXXXX-XXXXXX-XXXXXX-X").
// Shows each code one at a time; user must use a save affordance before advancing.
// Calls `onComplete` after the confirmation summary is acknowledged.
function runRecoveryCodeScreen(appEl, codes, onComplete) {
  let idx = 0;
  const saved = codes.map(() => false);

  function renderCode() {
    if (idx >= codes.length) {
      renderCodeSummary();
      return;
    }

    const code = codes[idx];
    const isLast = idx === codes.length - 1;

    appEl.innerHTML = `
      <div class="onboarding-backdrop">
        <div class="onboarding-card">
          <div class="auth-step-badge">
            Step 2 of 3 — Recovery code ${idx + 1} of ${codes.length}
          </div>
          <h1 class="onboarding-title">Save this recovery code.</h1>
          <p class="onboarding-sub">
            Any one of your three codes can restore access if you forget your password.
            Store each one somewhere safe.
          </p>
          <div class="auth-code-box">
            <code class="auth-code-display" id="auth-code-text" aria-label="Recovery code ${idx + 1}">
              ${escapeHtml(code)}
            </code>
          </div>
          <div class="auth-code-actions">
            <button class="btn btn-secondary" id="auth-code-copy">Copy to clipboard</button>
            <button class="btn btn-secondary" id="auth-code-dl">Download as text</button>
          </div>
          <p class="auth-code-hint" id="auth-code-hint" hidden>✓ Saved — you can continue.</p>
          <p class="auth-error" id="auth-code-error" hidden></p>
          <div class="onboarding-footer">
            <button class="btn btn-primary btn-lg" id="auth-code-next" disabled>
              ${isLast ? 'I’ve saved all three codes →' : 'Next code →'}
            </button>
          </div>
        </div>
      </div>
    `;

    const nextBtn = appEl.querySelector('#auth-code-next');
    const hintEl = appEl.querySelector('#auth-code-hint');
    const errorEl = appEl.querySelector('#auth-code-error');

    function markSaved() {
      saved[idx] = true;
      nextBtn.disabled = false;
      hintEl.hidden = false;
    }

    appEl.querySelector('#auth-code-copy').addEventListener('click', async () => {
      try {
        await clipboardWriteText(code);
      } catch {
        errorEl.textContent = 'Could not copy — select the code above and copy it manually.';
        errorEl.hidden = false;
      }
      markSaved();
    });

    appEl.querySelector('#auth-code-dl').addEventListener('click', () => {
      const text = [
        `Tahlk Recovery Code ${idx + 1} of ${codes.length}`,
        '',
        code,
        '',
        'Keep this code somewhere safe. Any one of your three codes recovers access',
        'to your Tahlk records if you forget your password.',
      ].join('\n');
      const blob = new Blob([text], { type: 'text/plain' });
      const a = Object.assign(document.createElement('a'), {
        href: URL.createObjectURL(blob),
        download: `tahlk-recovery-code-${idx + 1}.txt`,
      });
      a.click();
      URL.revokeObjectURL(a.href);
      markSaved();
    });

    nextBtn.addEventListener('click', () => {
      idx++;
      renderCode();
    });
  }

  function renderCodeSummary() {
    const rows = codes.map((_, i) =>
      `<li>Recovery code ${i + 1} — saved ✓</li>`
    ).join('');

    appEl.innerHTML = `
      <div class="onboarding-backdrop">
        <div class="onboarding-card">
          <div class="auth-step-badge">Step 2 of 3 — All codes saved</div>
          <h1 class="onboarding-title">All three codes saved.</h1>
          <p class="onboarding-sub">
            Keep your codes in at least two different locations. Any one of them
            restores access to your records if you forget your password.
          </p>
          <ul class="auth-summary-list">${rows}</ul>
          <div class="onboarding-footer">
            <button class="btn btn-primary btn-lg" id="auth-codes-done">
              Continue →
            </button>
          </div>
        </div>
      </div>
    `;

    appEl.querySelector('#auth-codes-done').addEventListener('click', onComplete);
  }

  renderCode();
}

// ─── Screen D: optional email reminder ───────────────────────────────────────

function renderEmailReminderScreen(appEl, codes, onComplete) {
  const fields = codes.map((_, i) => `
    <div class="field-row">
      <label for="auth-loc-${i}">Code ${i + 1} saved to</label>
      <input id="auth-loc-${i}" type="text"
             placeholder='e.g. "1Password vault Work", "printed card, top drawer"' />
    </div>
  `).join('');

  appEl.innerHTML = `
    <div class="onboarding-backdrop">
      <div class="onboarding-card">
        <div class="auth-step-badge">Step 3 of 3 — Optional reminder</div>
        <h1 class="onboarding-title">Where did you put your codes?</h1>
        <p class="onboarding-sub">
          Tahlk will open your mail app with a draft you send to yourself as a search-findable
          reminder. Your codes are <em>not</em> included in the email — only the location hints.
          Tahlk never sends or sees this email.
        </p>
        ${fields}
        <div class="onboarding-footer auth-reminder-footer">
          <button class="btn btn-secondary" id="auth-reminder-skip">Skip this step</button>
          <button class="btn btn-primary" id="auth-reminder-mail">Open in mail →</button>
        </div>
      </div>
    </div>
  `;

  appEl.querySelector('#auth-reminder-skip').addEventListener('click', onComplete);

  appEl.querySelector('#auth-reminder-mail').addEventListener('click', () => {
    const locs = codes.map((_, i) => {
      const v = appEl.querySelector(`#auth-loc-${i}`)?.value.trim() || '(not specified)';
      return `Code ${i + 1}: ${v}`;
    });
    const subject = encodeURIComponent('Where I saved my Tahlk recovery codes');
    const body = encodeURIComponent(
      'I saved my Tahlk recovery codes in the following locations:\n\n' +
      locs.join('\n') +
      '\n\n(This is a personal reminder. The codes themselves are NOT in this email.)\n'
    );
    const a = Object.assign(document.createElement('a'), {
      href: `mailto:?subject=${subject}&body=${body}`,
    });
    a.click();
    onComplete();
  });
}
