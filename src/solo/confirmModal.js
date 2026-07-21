// In-app confirmation dialog — a styled replacement for the browser-native
// confirm(). Used for deliberate, meaningful actions (e.g. sign-off) so the
// prompt matches the rest of the app's chrome instead of breaking out to
// browser UI. Returns a Promise<boolean>: true if confirmed, false if cancelled
// (via the Cancel button, backdrop click, or Escape).

// The backdrop+card shell and the Escape / backdrop-click / mount-unmount
// lifecycle are shared scaffolding (src/platform/modal.js). This file keeps
// only the confirm-specific content and semantics: title/message, the
// confirm/cancel buttons, Enter-to-confirm, and resolving the promise.

// Nodes are built explicitly (no innerHTML) so untrusted callers can't inject
// markup through the title/message and so the dialog is drivable in the
// fake-DOM tests without an HTML parser.
import { createModal } from '../platform/modal.js';

export function confirmModal({
  title,
  message,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  confirmClass = 'btn-primary',
} = {}) {
  return new Promise(resolve => {
    let settled = false;
    const settle = result => {
      if (settled) return;
      settled = true;
      modal.close();
      resolve(result);
    };

    // Escape and backdrop click cancel; Enter confirms — matching the native
    // confirm() the app's patterns already trained users on.
    const modal = createModal({
      backdropId: 'modal-backdrop',
      onRequestClose: () => settle(false),
      onKeyDown: e => {
        if (e.key === 'Enter') { e.preventDefault?.(); settle(true); }
      },
    });
    const { card } = modal;

    const heading = document.createElement('h2');
    heading.className = 'modal-title';
    heading.id = 'modal-title';
    heading.textContent = title;

    const body = document.createElement('p');
    body.className = 'modal-message';
    body.id = 'modal-message';
    body.textContent = message;

    const actions = document.createElement('div');
    actions.className = 'modal-actions';

    const cancelBtn = document.createElement('button');
    cancelBtn.className = 'btn btn-ghost';
    cancelBtn.id = 'modal-cancel';
    cancelBtn.textContent = cancelLabel;

    const confirmBtn = document.createElement('button');
    confirmBtn.className = `btn ${confirmClass}`;
    confirmBtn.id = 'modal-confirm';
    confirmBtn.textContent = confirmLabel;

    actions.appendChild(cancelBtn);
    actions.appendChild(confirmBtn);
    card.appendChild(heading);
    card.appendChild(body);
    card.appendChild(actions);

    confirmBtn.addEventListener('click', () => settle(true));
    cancelBtn.addEventListener('click', () => settle(false));

    modal.open();
    confirmBtn.focus?.();
  });
}

// Text-entry confirmation — the in-app replacement for the browser-native
// prompt(). Resolves the typed string, or null if cancelled.
//
// prompt() is not implemented in every WebView configuration Tauri ships on;
// where it is stubbed it returns null unconditionally, which made the
// typed-name confirmation for bulk retention destruction impossible to
// satisfy — the feature was unreachable rather than merely ugly. confirm()
// has the same portability problem and additionally blocks the WebView's
// event loop, which is why the app already had confirmModal.
//
// `expected` renders as a read-only hint above the field so the provider can
// see exactly what they must type; matching is left to the caller.
export function promptModal({
  title,
  message,
  expected = '',
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  confirmClass = 'btn-primary',
  placeholder = '',
} = {}) {
  return new Promise(resolve => {
    let settled = false;
    const settle = result => {
      if (settled) return;
      settled = true;
      modal.close();
      resolve(result);
    };

    const modal = createModal({
      backdropId: 'modal-backdrop',
      onRequestClose: () => settle(null),
      onKeyDown: e => {
        if (e.key === 'Enter') { e.preventDefault?.(); settle(input.value ?? ''); }
      },
    });
    const { card } = modal;

    const heading = document.createElement('h2');
    heading.className = 'modal-title';
    heading.id = 'modal-title';
    heading.textContent = title;

    const body = document.createElement('p');
    body.className = 'modal-message';
    body.id = 'modal-message';
    body.textContent = message;

    const input = document.createElement('input');
    input.type = 'text';
    input.className = 'modal-input';
    input.id = 'modal-input';
    input.placeholder = placeholder;
    input.autocomplete = 'off';

    const actions = document.createElement('div');
    actions.className = 'modal-actions';

    const cancelBtn = document.createElement('button');
    cancelBtn.className = 'btn btn-ghost';
    cancelBtn.id = 'modal-cancel';
    cancelBtn.textContent = cancelLabel;

    const confirmBtn = document.createElement('button');
    confirmBtn.className = `btn ${confirmClass}`;
    confirmBtn.id = 'modal-confirm';
    confirmBtn.textContent = confirmLabel;

    actions.appendChild(cancelBtn);
    actions.appendChild(confirmBtn);
    card.appendChild(heading);
    card.appendChild(body);
    if (expected) {
      const hint = document.createElement('p');
      hint.className = 'modal-hint';
      hint.id = 'modal-hint';
      // textContent, not innerHTML — `expected` is the provider's own name.
      hint.textContent = expected;
      card.appendChild(hint);
    }
    card.appendChild(input);
    card.appendChild(actions);

    confirmBtn.addEventListener('click', () => settle(input.value ?? ''));
    cancelBtn.addEventListener('click', () => settle(null));

    modal.open();
    input.focus?.();
  });
}
