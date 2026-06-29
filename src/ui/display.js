// Data-display components.

import { cx, escapeHtml } from './html.js';
import { statusLabel } from '../utils/format.js';
import { Button } from './Button.js';

// Maps an encounter status to a visual tone (color), decoupling color from the
// status vocabulary so new statuses don't require CSS changes everywhere.
const STATUS_TONE = {
  recording: 'active',
  recording_done: 'info',
  transcribing: 'active',
  draft: 'neutral',
  signed: 'success',
  exported: 'info',
};

export function StatusChip({ status, label } = {}) {
  const tone = STATUS_TONE[status] || 'neutral';
  const text = label || statusLabel(status);
  return (
    `<span class="ui-chip ui-chip--${tone}" data-status="${escapeHtml(status || '')}">` +
    `${escapeHtml(text)}</span>`
  );
}

// A single metric. Labeled as a group so screen readers read "12 Signed".
export function StatCard({ value, label = '', id, tone = 'default' } = {}) {
  const shown = value == null ? '—' : value;
  return (
    `<div class="${cx('ui-stat', `ui-stat--${tone}`)}"${id ? ` id="${escapeHtml(id)}"` : ''} ` +
    `role="group" aria-label="${escapeHtml(`${shown} ${label}`.trim())}">` +
    `<div class="ui-stat__value">${escapeHtml(shown)}</div>` +
    `<div class="ui-stat__label">${escapeHtml(label)}</div>` +
    `</div>`
  );
}

// Empty state with optional call-to-action.
//   action?: Button props ({ id, label, variant, ... })
export function EmptyState({ icon = '📋', title = '', description, action } = {}) {
  return (
    `<div class="ui-empty" role="status">` +
    `<div class="ui-empty__icon" aria-hidden="true">${icon}</div>` +
    `<h3 class="ui-empty__title">${escapeHtml(title)}</h3>` +
    (description ? `<p class="ui-empty__desc">${escapeHtml(description)}</p>` : '') +
    (action ? `<div class="ui-empty__action">${Button({ variant: 'primary', ...action })}</div>` : '') +
    `</div>`
  );
}
