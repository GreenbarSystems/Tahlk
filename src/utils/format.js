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

let _toastTimer;
export function toast(msg, dur = 3200) {
  clearTimeout(_toastTimer);
  const el = document.getElementById('toast');
  const msgEl = document.getElementById('toast-msg');
  if (!el || !msgEl) { console.warn('toast:', msg); return; }
  msgEl.textContent = msg;
  el.classList.add('show');
  _toastTimer = setTimeout(() => el.classList.remove('show'), dur);
}
