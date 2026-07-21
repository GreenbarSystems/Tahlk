// Shared formatting, ID generation, and UI utilities.

export const nowISO = () => new Date().toISOString();

export const genId = prefix =>
  `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;

// Escape a value for safe interpolation into innerHTML / attribute contexts.
// All dynamic strings (patient input, AI output, custom template names) must
// pass through this before being templated into the DOM.
export const escapeHtml = v =>
  String(v ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

export const displayDate = v => {
  if (v == null || v === '') return '';
  const s = String(v);
  if (/^\d{4}-\d{2}-\d{2}T/.test(s)) {
    const d = new Date(s);
    return isNaN(d) ? s : d.toLocaleString('en-US', {
      month: 'short', day: 'numeric', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  }
  return s;
};

export const displayDateShort = v => {
  if (v == null || v === '') return '';
  const s = String(v);
  if (/^\d{4}-\d{2}-\d{2}/.test(s)) {
    const [year, month, day] = s.slice(0, 10).split('-');
    return `${Number(month)}/${Number(day)}/${year}`;
  }
  return s;
};

export const todayISO = () => new Date().toISOString().slice(0, 10);

export const fmtDuration = secs => {
  const m = Math.floor(secs / 60);
  const s = Math.floor(secs % 60);
  return `${m}:${String(s).padStart(2, '0')}`;
};

// Human label for an encounter status. Single source of truth — both the
// home list and the encounter panel render through this.
const STATUS_LABELS = {
  recording:       'Recording',
  recording_done:  'Recorded',
  transcribing:    'Transcribing',
  draft:           'Draft',
  signed:          'Signed',
  exported:        'Exported',
};
// Returns a fixed literal for every input. The `|| status` fall-through this
// replaces echoed unrecognised input straight back — while the interpolation
// build guard allowlists statusLabel as a sanitizer on the stated grounds that
// it "returns a fixed literal per known status", and three sinks render its
// result unescaped on that basis. Rust's status allowlist means an unknown
// value should be unreachable, so this is defence in depth rather than a live
// hole, but a sanitizer that is only conditionally a sanitizer is not one.
export const statusLabel = status => STATUS_LABELS[status] || 'Unknown';

let _toastTimer;
let _toastHovered = false;
export function toast(msg, dur = 3800) {
  clearTimeout(_toastTimer);
  const el = document.getElementById('toast');
  const msgEl = document.getElementById('toast-msg');
  if (!el || !msgEl) { console.warn('toast:', msg); return; }
  msgEl.textContent = msg;
  el.setAttribute('role', 'status');
  el.classList.add('show');

  const dismiss = () => el.classList.remove('show');

  // Pause dismiss on hover so users can finish reading longer messages.
  el.onmouseenter = () => { _toastHovered = true; clearTimeout(_toastTimer); };
  el.onmouseleave = () => { _toastHovered = false; _toastTimer = setTimeout(dismiss, 1200); };

  _toastTimer = setTimeout(() => { if (!_toastHovered) dismiss(); }, dur);
}
