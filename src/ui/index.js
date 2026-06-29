// Tahlk UI kit — dependency-free, accessible, string-rendering components.
//
//   import { Button, Field, EmptyState } from '../ui/index.js';
//
// Every component is a pure function (props -> HTML string), escapes its own
// dynamic props, and bakes in ARIA/keyboard/state handling. Styles live in
// styles/ui.css (design tokens + component styles + responsive + reduced-motion).

export { html, raw, cx, dataAttrs, escapeHtml } from './html.js';
export { Button } from './Button.js';
export { Field } from './Field.js';
export { Spinner, Skeleton, ProgressBar, Banner } from './feedback.js';
export { StatusChip, StatCard, EmptyState } from './display.js';
