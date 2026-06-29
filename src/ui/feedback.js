// Feedback & loading primitives.

import { cx, escapeHtml } from './html.js';

// Indeterminate spinner. Announced via role=status; honors reduced-motion (CSS).
export function Spinner({ size = 'md', label = 'Loading' } = {}) {
  return `<span class="ui-spinner ui-spinner--${size}" role="status" ` +
    `aria-label="${escapeHtml(label)}"></span>`;
}

// Skeleton placeholder for content that is loading. Decorative (aria-hidden);
// put aria-busy="true" on the live region that contains it.
export function Skeleton({ lines = 3, className } = {}) {
  const rows = Array.from({ length: Math.max(1, lines) })
    .map(() => '<div class="ui-skeleton__line"></div>')
    .join('');
  return `<div class="${cx('ui-skeleton', className)}" aria-hidden="true">${rows}</div>`;
}

// Determinate progress bar. `value` is 0..1; clamped.
export function ProgressBar({ value = 0, label, id } = {}) {
  const pct = Math.max(0, Math.min(100, Math.round((Number(value) || 0) * 100)));
  return (
    `<div class="ui-progress"${id ? ` id="${escapeHtml(id)}"` : ''} role="progressbar" ` +
    `aria-valuenow="${pct}" aria-valuemin="0" aria-valuemax="100"` +
    (label ? ` aria-label="${escapeHtml(label)}"` : '') + '>' +
    `<div class="ui-progress__fill" style="width:${pct}%"></div>` +
    `</div>`
  );
}

const BANNER_ICON = { info: 'ℹ️', success: '✓', warning: '⚠️', error: '⛔' };

// Inline status/alert banner. Errors and warnings use role=alert (assertive);
// info/success use role=status (polite).
export function Banner({ kind = 'info', message = '', id } = {}) {
  const role = kind === 'error' || kind === 'warning' ? 'alert' : 'status';
  return (
    `<div class="ui-banner ui-banner--${kind}"${id ? ` id="${escapeHtml(id)}"` : ''} role="${role}">` +
    `<span class="ui-banner__icon" aria-hidden="true">${BANNER_ICON[kind] || BANNER_ICON.info}</span>` +
    `<span class="ui-banner__msg">${escapeHtml(message)}</span>` +
    `</div>`
  );
}
