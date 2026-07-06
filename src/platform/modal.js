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

  // A single document-level keydown listener: Escape requests close, everything
  // else is forwarded to the caller (e.g. confirmModal maps Enter to confirm).
  const onKey = e => {
    if (closeOnEscape && e.key === 'Escape') {
      e.preventDefault?.();
      onRequestClose?.('escape');
      return;
    }
    onKeyDown?.(e);
  };

  // Click on the dimmed backdrop (but not the card) requests close.
  const onBackdropClick = e => {
    if (closeOnBackdrop && e.target === backdrop) onRequestClose?.('backdrop');
  };

  function open() {
    document.addEventListener('keydown', onKey);
    backdrop.addEventListener('click', onBackdropClick);
    document.body.appendChild(backdrop);
    return { backdrop, card };
  }

  function close() {
    if (closed) return;
    closed = true;
    document.removeEventListener('keydown', onKey);
    backdrop.remove();
  }

  return { backdrop, card, open, close };
}
