// Small inline icon set — stroke-based SVGs sized to sit inline with text,
// using currentColor so each icon inherits whatever color context it's placed
// in (a status chip, a button, a badge) automatically.
//
// Replaces bare Unicode glyphs (✓ ✕) that were used as ad-hoc icons: those
// render inconsistently across platform/font (different weight, baseline, and
// on some systems ✓/✕ pull in emoji-style presentation), which reads as
// unpolished in a clinical product. A single consistent icon language mirrors
// the treatment already used for the brand mark (see logoSvg.js).

const ICON_ATTRS = 'width="13" height="13" viewBox="0 0 16 16" fill="none" ' +
  'xmlns="http://www.w3.org/2000/svg" aria-hidden="true" class="icon-inline"';

// Exported as zero-arg functions (not bare constants) so call sites read as
// `${iconCheck()}` — the shape the template-interpolation-escaping build
// guard (tests/build/test_template_interpolation_escaped.mjs) already
// recognizes as a trusted helper call via SAFE_CALL_HELPERS, the same
// convention statusLabel() uses there.
export const iconCheck = () =>
  `<svg ${ICON_ATTRS}><path d="M3 8.5L6.5 12L13 4.5" stroke="currentColor" ` +
  `stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>`;

export const iconClose = () =>
  `<svg ${ICON_ATTRS}><path d="M4 4L12 12M12 4L4 12" stroke="currentColor" ` +
  `stroke-width="1.6" stroke-linecap="round"/></svg>`;
