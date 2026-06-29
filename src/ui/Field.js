// Field — labeled form control with built-in accessibility.
//
// Guarantees a programmatic label↔control association, wires hint/error text via
// aria-describedby, and flags invalid/required state for assistive tech.
//
// Props:
//   label        string
//   id?          string   auto-generated if omitted (label stays associated)
//   type?        'text'|'password'|'email'|'select'|...  (default 'text')
//   name?, value?, placeholder?, autocomplete?
//   hint?        string   helper text (aria-describedby)
//   error?       string   error text (role=alert, aria-invalid, aria-describedby)
//   required?    boolean
//   disabled?    boolean
//   options?     [{ value, label }]   for type='select'

import { cx, escapeHtml } from './html.js';

let _seq = 0;
const nextId = () => `ui-field-${++_seq}`;

export function Field({
  label = '',
  id,
  type = 'text',
  name,
  value = '',
  placeholder = '',
  hint,
  error,
  required = false,
  disabled = false,
  autocomplete,
  options,
} = {}) {
  const fid = id || nextId();
  const hintId = hint ? `${fid}-hint` : '';
  const errId = error ? `${fid}-err` : '';
  const describedBy = cx(hintId, errId);

  const shared = [
    `id="${escapeHtml(fid)}"`,
    name && `name="${escapeHtml(name)}"`,
    required && 'required aria-required="true"',
    disabled && 'disabled',
    error && 'aria-invalid="true"',
    describedBy && `aria-describedby="${describedBy}"`,
  ].filter(Boolean).join(' ');

  let control;
  if (type === 'select') {
    const opts = (options || [])
      .map(o =>
        `<option value="${escapeHtml(o.value)}"${o.value === value ? ' selected' : ''}>` +
        `${escapeHtml(o.label)}</option>`)
      .join('');
    control = `<select class="ui-field__control" ${shared}>${opts}</select>`;
  } else {
    control =
      `<input class="ui-field__control" type="${escapeHtml(type)}" ` +
      `value="${escapeHtml(value)}" placeholder="${escapeHtml(placeholder)}"` +
      (autocomplete ? ` autocomplete="${escapeHtml(autocomplete)}"` : '') +
      ` ${shared} />`;
  }

  return (
    `<div class="${cx('ui-field', error && 'ui-field--error')}">` +
    `<label class="ui-field__label" for="${escapeHtml(fid)}">${escapeHtml(label)}` +
    (required ? '<span class="ui-field__req" aria-hidden="true">*</span>' : '') +
    `</label>` +
    control +
    (hint ? `<p class="ui-field__hint" id="${hintId}">${escapeHtml(hint)}</p>` : '') +
    (error ? `<p class="ui-field__error" id="${errId}" role="alert">${escapeHtml(error)}</p>` : '') +
    `</div>`
  );
}
