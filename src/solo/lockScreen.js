// Idle-lock overlay — rendered as a standalone element appended to
// document.body (not swapped into #app), so locking never disturbs
// whatever the rest of the app is mid-doing underneath (an in-progress
// recording, a streaming note generation, unsaved form state). Being
// position:fixed and covering the full viewport, it naturally intercepts
// every click/keypress without needing any pointer-events trickery.
//
// Built on the shared modal shell (platform/modal.js) with dismissal
// disabled — Escape and backdrop clicks must NOT close this overlay, since
// it IS the security control; only a correct PIN may remove it. Nodes are
// built explicitly (no innerHTML), matching confirmModal.js's convention,
// so this stays drivable in the fake-DOM tests without an HTML parser.
//
// A small, in-memory failed-attempt lockout (5 tries -> 30s cooldown,
// doubling each time it's hit again) is included as cheap defense in
// depth against someone with physical access trying to brute-force a
// short PIN. Deliberately NOT persisted across app restarts — this
// control's actual threat model is a passerby at an already-running,
// unattended laptop, not a sustained offline attack, and OS login + full-
// disk encryption (recommended elsewhere in this app's documentation) are
// the real boundary against the latter.

import { createModal } from '../platform/modal.js';
import { lockRepo } from '../data/lockRepo.js';
import { userMessage } from '../platform/appError.js';

const OVERLAY_ID = 'lock-overlay';
const BASE_LOCKOUT_MS = 30_000;
const ATTEMPTS_BEFORE_LOCKOUT = 5;

let _activeModal = null; // so hideLockScreen() can tear down the keydown listener too

// Shows the overlay and wires PIN verification. `onUnlock` fires once a
// correct PIN is entered; the overlay removes itself before calling it.
// Idempotent: calling this while the overlay is already showing is a
// harmless no-op (guards against a double-fire race between the idle
// timer and, e.g., a manual "Lock now" button).
export function showLockScreen(onUnlock) {
  if (document.getElementById(OVERLAY_ID)) return;

  const modal = createModal({
    backdropClass: 'lock-overlay',
    backdropId: OVERLAY_ID,
    cardClass: 'lock-card',
    closeOnEscape: false,
    closeOnBackdrop: false,
  });
  _activeModal = modal;
  const { card } = modal;

  const icon = document.createElement('div');
  icon.className = 'lock-icon';
  icon.setAttribute('aria-hidden', 'true');
  icon.textContent = '\u{1F512}';

  const heading = document.createElement('h2');
  heading.className = 'lock-title';
  heading.textContent = 'Tahlk is locked';

  const sub = document.createElement('p');
  sub.className = 'settings-desc';
  sub.textContent = 'You stepped away — enter your PIN to continue.';

  const form = document.createElement('form');
  form.id = 'lock-form';
  form.setAttribute('autocomplete', 'off');

  const fieldRow = document.createElement('div');
  fieldRow.className = 'field-row';
  const label = document.createElement('label');
  label.setAttribute('for', 'lock-pin-input');
  label.textContent = 'PIN';
  const input = document.createElement('input');
  input.type = 'password';
  input.id = 'lock-pin-input';
  input.setAttribute('autocomplete', 'off');
  input.setAttribute('inputmode', 'numeric');
  fieldRow.appendChild(label);
  fieldRow.appendChild(input);

  const errorEl = document.createElement('p');
  errorEl.className = 'lock-error';
  errorEl.id = 'lock-error';
  errorEl.hidden = true;

  const unlockBtn = document.createElement('button');
  unlockBtn.type = 'submit';
  unlockBtn.className = 'btn btn-primary btn-lg';
  unlockBtn.id = 'lock-unlock-btn';
  unlockBtn.textContent = 'Unlock';

  form.appendChild(fieldRow);
  form.appendChild(errorEl);
  form.appendChild(unlockBtn);
  card.appendChild(icon);
  card.appendChild(heading);
  card.appendChild(sub);
  card.appendChild(form);

  let failedAttempts = 0;
  let lockedUntil = 0;

  function showError(msg) {
    errorEl.textContent = msg;
    errorEl.hidden = false;
  }

  function remainingLockoutMs() {
    return Math.max(0, lockedUntil - Date.now());
  }

  form.addEventListener('submit', async e => {
    e.preventDefault?.();
    const remaining = remainingLockoutMs();
    if (remaining > 0) {
      showError(`Too many attempts. Try again in ${Math.ceil(remaining / 1000)}s.`);
      return;
    }

    const pin = input.value || '';
    if (!pin) { showError('Enter your PIN.'); return; }

    unlockBtn.disabled = true;
    try {
      const ok = await lockRepo.verifyPin(pin);
      if (ok) {
        modal.close();
        if (_activeModal === modal) _activeModal = null;
        onUnlock();
        return;
      }
      failedAttempts++;
      if (failedAttempts >= ATTEMPTS_BEFORE_LOCKOUT) {
        const cooldown = BASE_LOCKOUT_MS * 2 ** (failedAttempts - ATTEMPTS_BEFORE_LOCKOUT);
        lockedUntil = Date.now() + cooldown;
        showError(`Too many attempts. Try again in ${Math.ceil(cooldown / 1000)}s.`);
      } else {
        showError('Incorrect PIN.');
      }
      input.value = '';
      input.focus?.();
    } catch (err) {
      showError(`Could not verify PIN: ${userMessage(err, 'unknown error')}`);
    } finally {
      unlockBtn.disabled = false;
    }
  });

  modal.open();
  input.focus?.();
}

export function hideLockScreen() {
  _activeModal?.close();
  _activeModal = null;
}

export function isLockScreenShowing() {
  return !!document.getElementById(OVERLAY_ID);
}
