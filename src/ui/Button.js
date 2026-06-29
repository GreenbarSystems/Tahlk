// Button — the primary action primitive.
//
// Props:
//   label?       string   visible text (escaped). Omit for icon-only.
//   variant?     'primary'|'secondary'|'ghost'|'danger'|'record'|'sign'  (default 'secondary')
//   size?        'sm'|'md'|'lg'  (default 'md')
//   id?          string
//   type?        'button'|'submit'|'reset'  (default 'button')
//   disabled?    boolean
//   loading?     boolean  shows a spinner, disables, sets aria-busy
//   iconLeft?    string   trusted markup/emoji, decorative (aria-hidden)
//   iconRight?   string
//   fullWidth?   boolean
//   ariaLabel?   string   REQUIRED for icon-only buttons
//   title?       string
//   dataset?     object   -> data-* attributes
//   className?   string   extra classes (migration / one-offs)

import { cx, dataAttrs, escapeHtml } from './html.js';

export function Button({
  label = '',
  variant = 'secondary',
  size = 'md',
  id,
  type = 'button',
  disabled = false,
  loading = false,
  iconLeft,
  iconRight,
  fullWidth = false,
  ariaLabel,
  title,
  dataset,
  className,
} = {}) {
  if (!label && !ariaLabel) {
    console.warn('Button: icon-only button needs `ariaLabel` for screen readers.');
  }

  const isDisabled = disabled || loading;
  const classes = cx(
    'ui-btn',
    `ui-btn--${variant}`,
    `ui-btn--${size}`,
    fullWidth && 'ui-btn--block',
    loading && 'is-loading',
    className,
  );

  const attrs = [
    `type="${escapeHtml(type)}"`,
    `class="${classes}"`,
    id && `id="${escapeHtml(id)}"`,
    isDisabled && 'disabled',
    loading && 'aria-busy="true"',
    ariaLabel && `aria-label="${escapeHtml(ariaLabel)}"`,
    title && `title="${escapeHtml(title)}"`,
    dataset && dataAttrs(dataset),
  ].filter(Boolean).join(' ');

  return (
    `<button ${attrs}>` +
    (loading ? '<span class="ui-btn__spinner" aria-hidden="true"></span>' : '') +
    (iconLeft ? `<span class="ui-btn__icon" aria-hidden="true">${iconLeft}</span>` : '') +
    (label ? `<span class="ui-btn__label">${escapeHtml(label)}</span>` : '') +
    (iconRight ? `<span class="ui-btn__icon" aria-hidden="true">${iconRight}</span>` : '') +
    `</button>`
  );
}
