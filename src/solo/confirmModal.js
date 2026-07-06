// In-app confirmation dialog — a styled replacement for the browser-native
// confirm(). Used for deliberate, meaningful actions (e.g. sign-off) so the
// prompt matches the rest of the app's chrome instead of breaking out to
// browser UI. Returns a Promise<boolean>: true if confirmed, false if cancelled
// (via the Cancel button, backdrop click, or Escape).

// Nodes are built explicitly (no innerHTML) so untrusted callers can't inject
// markup through the title/message and so the dialog is drivable in the
// fake-DOM tests without an HTML parser.
export function confirmModal({
  title,
  message,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  confirmClass = 'btn-primary',
} = {}) {
  return new Promise(resolve => {
    const backdrop = document.createElement('div');
    backdrop.className = 'modal-backdrop';
    backdrop.id = 'modal-backdrop';

    const card = document.createElement('div');
    card.className = 'modal-card';
    card.setAttribute('role', 'dialog');
    card.setAttribute('aria-modal', 'true');

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
    backdrop.appendChild(card);

    let settled = false;
    const close = result => {
      if (settled) return;
      settled = true;
      document.removeEventListener('keydown', onKey);
      backdrop.remove();
      resolve(result);
    };

    // Escape cancels, Enter confirms — matching the native confirm() the app
    // patterns already trained users on.
    const onKey = e => {
      if (e.key === 'Escape') { e.preventDefault?.(); close(false); }
      else if (e.key === 'Enter') { e.preventDefault?.(); close(true); }
    };

    confirmBtn.addEventListener('click', () => close(true));
    cancelBtn.addEventListener('click', () => close(false));
    // Click on the dimmed backdrop (but not the card) cancels.
    backdrop.addEventListener('click', e => { if (e.target === backdrop) close(false); });
    document.addEventListener('keydown', onKey);

    document.body.appendChild(backdrop);
    confirmBtn.focus?.();
  });
}
