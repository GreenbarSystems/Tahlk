// Shared modal scaffolding — the dimmed backdrop + centered card shell, plus
// the close-on-Escape / close-on-backdrop-click / mount-unmount lifecycle that
// every in-app overlay dialog needs. Callers fill `card` with their own content
// and own their result semantics; this module only owns the generic chrome.
//
// Deliberately minimal: no theming, sizes, animations, or variants beyond what
// the app's real modals use today. Add options here only when a real call site
// needs them.

// Build the backdrop+card shell and wire the dismissal behavior. Returns the
// nodes plus `open()` (mount to <body> and start listening) and `close()`
// (unmount and stop listening; idempotent). Nodes are created explicitly (no
// innerHTML) so callers can't inject markup and so it stays drivable in the
// fake-DOM tests without an HTML parser.
export function createModal({
  backdropClass = 'modal-backdrop',
  backdropId,
  cardClass = 'modal-card',
  onRequestClose,
  onKeyDown,
  closeOnEscape = true,
  closeOnBackdrop = true,
} = {}) {
  const backdrop = document.createElement('div');
  backdrop.className = backdropClass;
  if (backdropId) backdrop.id = backdropId;

  const card = document.createElement('div');
  card.className = cardClass;
  card.setAttribute('role', 'dialog');
  card.setAttribute('aria-modal', 'true');
  backdrop.appendChild(card);

  let closed = false;
  let _triggerEl = null;

  function getFocusable() {
    return [...card.querySelectorAll(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    )].filter(el => !el.disabled && !el.hidden);
  }

  // A single document-level keydown listener: Escape requests close, Tab is
  // trapped inside the card, everything else is forwarded to the caller.
  const onKey = e => {
    if (closeOnEscape && e.key === 'Escape') {
      e.preventDefault?.();
      onRequestClose?.('escape');
      return;
    }
    if (e.key === 'Tab') {
      const focusable = getFocusable();
      if (!focusable.length) { e.preventDefault(); return; }
      const first = focusable[0];
      const last  = focusable[focusable.length - 1];
      if (e.shiftKey) {
        if (document.activeElement === first) { e.preventDefault(); last.focus(); }
      } else {
        if (document.activeElement === last)  { e.preventDefault(); first.focus(); }
      }
      return;
    }
    onKeyDown?.(e);
  };

  // Click on the dimmed backdrop (but not the card) requests close.
  const onBackdropClick = e => {
    if (closeOnBackdrop && e.target === backdrop) onRequestClose?.('backdrop');
  };

  function open() {
    _triggerEl = document.activeElement;
    document.addEventListener('keydown', onKey);
    backdrop.addEventListener('click', onBackdropClick);
    document.body.appendChild(backdrop);
    const focusable = getFocusable();
    if (focusable.length) focusable[0].focus();
    return { backdrop, card };
  }

  function close() {
    if (closed) return;
    closed = true;
    document.removeEventListener('keydown', onKey);
    backdrop.remove();
    _triggerEl?.focus();
  }

  return { backdrop, card, open, close };
}
