// UI primitives — the foundation every component builds on.
//
// Components render to HTML strings (the app's idiom, zero runtime/bundle cost).
// Safety is in the foundation: the `html` tag auto-escapes every interpolation,
// and each component additionally escapes its own dynamic props, so untrusted
// data (patient input, AI output) can never break out of markup.

import { escapeHtml } from '../utils/format.js';

export { escapeHtml };

// Marker wrapping pre-rendered, trusted markup (e.g. nested component output)
// so the `html` tag does not double-escape it.
export const raw = value => ({ __raw: String(value ?? '') });

function renderValue(value) {
  if (value == null || value === false || value === true) return '';
  if (Array.isArray(value)) return value.map(renderValue).join('');
  if (typeof value === 'object' && '__raw' in value) return value.__raw;
  return escapeHtml(value);
}

// Auto-escaping tagged template:
//   html`<p>${userText}</p>`                  // escaped
//   html`<div>${raw(Button({ label }))}</div>` // trusted nested markup
export function html(strings, ...values) {
  let out = strings[0];
  for (let i = 0; i < values.length; i++) {
    out += renderValue(values[i]) + strings[i + 1];
  }
  return out;
}

// classnames: cx('a', cond && 'b', { c: isC }) -> "a c"
export function cx(...args) {
  const out = [];
  for (const arg of args) {
    if (!arg) continue;
    if (typeof arg === 'string') out.push(arg);
    else if (typeof arg === 'object') {
      for (const [key, on] of Object.entries(arg)) if (on) out.push(key);
    }
  }
  return out.join(' ');
}

// Serialize a { key: value } map to escaped data-* attributes.
export function dataAttrs(data) {
  if (!data) return '';
  return Object.entries(data)
    .map(([k, v]) => `data-${escapeHtml(k)}="${escapeHtml(v)}"`)
    .join(' ');
}
