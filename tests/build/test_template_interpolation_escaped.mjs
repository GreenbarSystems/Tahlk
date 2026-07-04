// Build guard: any template-literal interpolation `${ ... }` sitting inside an
// HTML attribute value or as raw text between tags in the audited encounter
// panel template must run through `escapeHtml` (or another explicitly-safe
// helper). Audit L5 flagged two attribute interpolations in
// `src/solo/encounter/template.js` that skipped escaping and called for a
// lint rule so the next one gets caught at CI time.
//
// Scope: this rule is intentionally limited to the file L5 named. Broadening
// to the full codebase would surface many similar patterns whose safety
// depends on locally-escaped variables the linter can't reason about
// (e.g. `homeScreen.js` where `dateStr = escapeHtml(...)` before the
// template runs). Widening the sweep is worth a follow-up audit finding of
// its own; folding it into an L-tier PR would balloon scope past the audit's
// original ask.
//
// We don't run a full ESLint (no ESLint in the repo — adding a whole toolchain
// for one rule is overkill for a low-severity finding). Instead a small AST-
// free regex sweep flags the anti-pattern: interpolations that appear right
// after `="`, `='`, or `>` and whose expression is a bare identifier / member
// access rather than an escape helper call.

import { readFileSync } from 'fs';
import { resolve, dirname, join, relative } from 'path';
import { fileURLToPath } from 'url';
import { test } from 'node:test';
import assert from 'node:assert/strict';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '../..');
// Files the rule scans. Add here when you want the guard to protect a new
// template module — and audit the file's existing interpolations first.
const SCANNED_FILES = [
  join(ROOT, 'src', 'solo', 'encounter', 'template.js'),
];

// Helpers whose call sites are trusted to produce already-escaped HTML or a
// safe HTML literal. Add here (with justification in the PR) only when the
// helper's implementation obviously runs escapeHtml on all string leaves.
const SAFE_CALL_HELPERS = new Set([
  'escapeHtml',
  'statusLabel', // src/utils/format.js: returns fixed literal per known status
]);

// Pull the expression text out of a `${ ... }` in a way that tolerates one
// level of nested braces (enough for `foo({ a: 1 })` and ternaries).
function expressionsIn(src) {
  const out = [];
  for (let i = 0; i < src.length - 1; i++) {
    if (src[i] === '$' && src[i + 1] === '{') {
      let depth = 1;
      let j = i + 2;
      while (j < src.length && depth > 0) {
        const c = src[j];
        if (c === '{') depth++;
        else if (c === '}') depth--;
        if (depth === 0) break;
        j++;
      }
      if (depth === 0) {
        out.push({ start: i, end: j, expr: src.slice(i + 2, j).trim() });
        i = j;
      }
    }
  }
  return out;
}

// Return true when the character immediately preceding `pos` (skipping any
// contiguous whitespace) is one of the HTML-context sentinels: `="`, `='`,
// or `>`. That's the classic "user-controlled string interpolated as HTML"
// shape — the exact pattern L5 flagged.
function isHtmlContext(src, pos) {
  let i = pos - 1;
  while (i >= 0 && /\s/.test(src[i])) i--;
  if (i < 0) return false;
  const c = src[i];
  if (c === '>') return true;
  if (c === '"' || c === "'") {
    // Look further back for a `=` immediately before the quote (with possible
    // whitespace). `="${x}"` and `='${x}'` are attribute-value positions.
    let k = i - 1;
    while (k >= 0 && /\s/.test(src[k])) k--;
    return k >= 0 && src[k] === '=';
  }
  return false;
}

// Given the expression text of an interpolation, return true when it obviously
// invokes a known-safe helper (top-level call to one of SAFE_CALL_HELPERS).
function callsSafeHelper(expr) {
  const m = expr.match(/^([A-Za-z_$][\w$]*)\s*\(/);
  return !!m && SAFE_CALL_HELPERS.has(m[1]);
}

// The rule targets the exact anti-pattern L5 flagged: a *bare* identifier or
// member access sitting inside an HTML context — `${encounter.id}` inside
// `="..."`, or `${someRawString}` after `>`. Interpolations that call a
// function, invoke .map()/.join(), branch through a ternary, or otherwise
// wrap the value are out of scope: they either delegate to a helper we can
// audit separately, or produce HTML literals the reviewer already inspected.
//
// A "bare value" is a chain of identifiers and dots plus optional `?.` and
// `|| ''` fallbacks. Anything containing `(`, `?`, `:` (outside `?.`), `` ` ``,
// or `=>` is not bare and thus not flagged by this cheap sweep.
function isBareValue(expr) {
  // Reject expressions with call/arrow/ternary/template-literal syntax.
  if (/[(`]/.test(expr)) return false;
  if (/=>/.test(expr)) return false;
  // Allow `a?.b` but reject standalone `?` (ternary).
  const withoutOptChain = expr.replace(/\?\./g, '.');
  if (/[?:]/.test(withoutOptChain)) return false;
  // Allow `x || ''` / `x || ""` as an idiomatic fallback that keeps the value
  // a string; strip it before the shape check.
  const withoutFallback = expr.replace(/\|\|\s*(?:''|"")\s*$/, '').trim();
  // Whatever remains must be identifier(.identifier)*.
  return /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*$/.test(withoutFallback);
}

test('template-literal interpolations in HTML context are escaped', () => {
  const violations = [];

  for (const file of SCANNED_FILES) {
    const src = readFileSync(file, 'utf8');
    for (const { start, expr } of expressionsIn(src)) {
      if (!isHtmlContext(src, start)) continue;
      if (callsSafeHelper(expr)) continue;
      // Only flag bare-value interpolations; everything else is out of scope
      // for this cheap regex sweep (see isBareValue for the exact contract).
      if (!isBareValue(expr)) continue;
      // Emit a violation with 1-based line number for easy click-through.
      const line = src.slice(0, start).split('\n').length;
      violations.push({
        file: relative(ROOT, file),
        line,
        expr: expr.length > 80 ? expr.slice(0, 77) + '...' : expr,
      });
    }
  }

  if (violations.length) {
    const detail = violations
      .map(v => `  ${v.file}:${v.line}  \${${v.expr}}`)
      .join('\n');
    assert.fail(
      `Found ${violations.length} unescaped template interpolation(s) in an HTML ` +
        `context. Wrap in escapeHtml() or add the helper to SAFE_CALL_HELPERS ` +
        `with justification.\n${detail}`
    );
  }
});
