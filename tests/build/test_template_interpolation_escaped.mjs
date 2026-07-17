// Build guard: any template-literal interpolation `${ ... }` sitting inside an
// HTML attribute value or as raw text between tags in the audited encounter
// panel template must run through `escapeHtml` (or another explicitly-safe
// helper). Audit L5 flagged two attribute interpolations in
// `src/solo/encounter/template.js` that skipped escaping and called for a
// lint rule so the next one gets caught at CI time.
//
// Scope: originally limited to the file L5 named (template.js). Widened
// per the M6 follow-up finding to also cover the other HTML-template-literal
// modules under src/solo/ (homeScreen.js, patientsView.js, settingsModal.js,
// onboarding.js, templatesView.js) so the same class of unescaped-
// interpolation bug is caught across the whole panel surface, not just one
// file. Still not the full codebase: modules outside src/solo/ that build
// HTML via template literals should be added here deliberately, one at a
// time, with their existing interpolations audited first — see the header
// note above SCANNED_FILES.
//
// We don't run a full ESLint (no ESLint in the repo — adding a whole toolchain
// for one rule is overkill for a low-severity finding). Instead a small AST-
// free regex sweep flags the anti-pattern: interpolations that appear right
// after `="`, `='`, or `>` and whose expression is a bare identifier / member
// access rather than an escape helper call.
//
// False-positive handling: widening the scan surface to the 5 new files
// surfaced bare-identifier and derived-value interpolations that are safe in
// practice but don't match SAFE_CALL_HELPERS' "direct call" shape. Several
// independent mechanisms resolve these without weakening real detection:
//   1. isLocallySafeAlias() traces a single bare identifier back to a
//      `const <name> = <expr>;` in the *same enclosing function* and
//      recursively checks that <expr> is a safe-helper call, a ternary of
//      safe branches, a join() over safe pieces (Case 3), or a
//      `arrayVar.map(param => \`...\`).join(sep)` chain whose map callback's
//      template body is itself all safe pieces (Case 4 — settingsModal.js's
//      chain-verification "detail" message, which joins per-row strings
//      that are each escapeHtml()-wrapped rather than being an array
//      literal). Scoped to the nearest enclosing function (not file-wide)
//      on purpose: patientsView.js reuses the name `alias` for both a
//      safely-escaped render-time value and a raw `.value.trim()` form
//      value in a different function — a file-wide allow would launder the
//      unsafe one. The RHS of the declaration is extracted with paren/
//      bracket/brace-depth and string/template-quote tracking (not a naive
//      `[^;]+` capture), since a join separator like `'; '` contains a
//      literal semicolon that would otherwise truncate the match before any
//      of the cases above even run.
//   2. SAFE_BARE_IDENTIFIERS is a small per-file, per-identifier allowlist
//      for values that are safe by construction rather than by escaping
//      (numeric COUNT(*) results, fixed string/SVG constants, an imported
//      module-level binding) — cases (1) can't and shouldn't try to prove,
//      since that requires knowing the value's origin/type, not just that
//      it was run through escapeHtml().
//   3. A general (not per-identifier) rule: any expression ending in
//      `.length` is unconditionally safe, since array/string length is
//      always a number by JS language semantics regardless of what's being
//      measured (settingsModal.js's `${broken.length}`).
// All mechanisms were verified against real (deliberately injected, then
// reverted) unescaped-interpolation bugs to confirm they don't just launder
// away genuine violations — see tests/build/test_template_interpolation_escaped_unit.mjs
// for the pinned scenarios and the commit message for the manual
// injected-bug verification runs.

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
  join(ROOT, 'src', 'solo', 'homeScreen.js'),
  join(ROOT, 'src', 'solo', 'patientsView.js'),
  join(ROOT, 'src', 'solo', 'settingsModal.js'),
  join(ROOT, 'src', 'solo', 'onboarding.js'),
  join(ROOT, 'src', 'solo', 'templatesView.js'),
];

// Helpers whose call sites are trusted to produce already-escaped HTML or a
// safe HTML literal. Add here (with justification in the PR) only when the
// helper's implementation obviously runs escapeHtml on all string leaves.
const SAFE_CALL_HELPERS = new Set([
  'escapeHtml',
  'statusLabel', // src/utils/format.js: returns fixed literal per known status
  'iconCheck',   // src/solo/icons.js: returns a fixed, hand-authored SVG literal
  'iconClose',   // src/solo/icons.js: returns a fixed, hand-authored SVG literal
  'iconSearch',  // src/solo/icons.js: returns a fixed, hand-authored SVG literal
]);

// Bare identifiers that are safe by construction (never derived from
// unescaped user input) rather than by having been run through
// escapeHtml() at the interpolation site. Scoped PER FILE (relative to
// ROOT) because the same identifier name can hold unsafe raw input in one
// function and a safe value in another (e.g. patientsView.js's `alias`
// inside renderPatientRow vs. inside its form-submit handler) — a file-wide
// or codebase-wide allow would be too coarse to catch that. Add an entry
// here (with justification) only when you've confirmed the identifier is
// never assigned from raw external/user input anywhere in that file.
const SAFE_BARE_IDENTIFIERS = new Map([
  [join(ROOT, 'src', 'solo', 'homeScreen.js'), new Set([
    'stats.today', 'stats.signed', 'stats.total', // encountersRepo.stats() COUNT(*) results — always numbers
  ])],
  [join(ROOT, 'src', 'solo', 'settingsModal.js'), new Set([
    'diagCount',              // telemetry.getEvents().length — always a number
    'DIAG_EXPORT_DISCLOSURE', // module-level fixed string literal, never derived from input
  ])],
  [join(ROOT, 'src', 'solo', 'onboarding.js'), new Set([
    'LOGO_SVG_LG', // imported from src/solo/logoSvg.js — a fixed, hand-authored
                   // SVG string constant with no interpolation of its own
                   // (confirmed by reading logoSvg.js), same class as the
                   // already-trusted iconCheck/iconClose helpers.
  ])],
]);

// Trace a bare identifier back to a `const <name> = <expr>;` declaration
// within the same enclosing function body, and return true if that
// declaration's RHS is itself provably safe: a call to a SAFE_CALL_HELPERS
// helper, a ternary between two such-safe branches (or empty-string
// literal), or an array `.join(...)` over identifiers that are themselves
// each traced safe by this same check. This is intentionally narrow (single
// assignment, no reassignment search beyond the nearest enclosing function)
// so it can't accidentally launder a same-named-but-different variable from
// an unrelated function — see the SAFE_BARE_IDENTIFIERS comment above for a
// concrete example of why that matters.
// Extract the RHS text of `const <name> = <expr>;` starting at `declStart`
// (the index right after the matched `= `), stopping at the statement's
// OWN top-level semicolon rather than the first semicolon anywhere. A naive
// `[^;]+` capture breaks the moment the expression contains a string or
// template literal with a literal `;` in it, e.g. `.join('; ')` -- a real
// gap this closes rather than works around, since it silently truncated
// the RHS for any such call before Case 4 below was even reachable.
// Tracks nesting depth across `(`/`)`/`[`/`]`/`{`/`}` plus string/template
// literal state so semicolons and brackets inside quotes don't confuse it.
function extractStatementRhs(src, declStart) {
  let i = declStart;
  let depth = 0;
  let quote = null; // one of `'`, `"`, "`", or null
  for (; i < src.length; i++) {
    const c = src[i];
    if (quote) {
      if (c === '\\') { i++; continue; } // skip escaped char
      if (c === quote) quote = null;
      continue;
    }
    if (c === "'" || c === '"' || c === '`') { quote = c; continue; }
    if (c === '(' || c === '[' || c === '{') { depth++; continue; }
    if (c === ')' || c === ']' || c === '}') { depth--; continue; }
    if (c === ';' && depth === 0) break;
  }
  return src.slice(declStart, i);
}

function isLocallySafeAlias(name, src, pos, depth = 0) {
  if (depth > 4) return false; // guard against pathological join()-of-join() chains
  // Find the start of the enclosing function body: nearest preceding
  // top-level-ish `function` keyword before pos. Good enough for this
  // codebase's flat render-function style (no nested function literals
  // between the declaration and the template return).
  const before = src.slice(0, pos);
  const fnStart = before.lastIndexOf('function');
  if (fnStart === -1) return false;
  const scope = src.slice(fnStart, pos);

  const declHeadRe = new RegExp('const\\s+' + name + '\\s*=\\s*');
  const headMatch = scope.match(declHeadRe);
  if (!headMatch) return false;
  const declStart = headMatch.index + headMatch[0].length;
  const rhs = extractStatementRhs(scope, declStart).trim();
  // Preserve `m.index` semantics used by callers below (Case 2's recursive
  // lookup needs the position of the START of this declaration, matching
  // the old regex-based `m.index`).
  const m = { index: headMatch.index };

  // Case 1: direct call to a known-safe helper, e.g. `escapeHtml(x)`.
  const callMatch = rhs.match(/^([A-Za-z_$][\w$]*)\s*\(/);
  if (callMatch && SAFE_CALL_HELPERS.has(callMatch[1])) return true;

  // Case 2: ternary whose two branches are each a safe call, the empty
  // string literal, or a recursively-safe identifier, e.g.
  // `cond ? escapeHtml(x) : ''`.
  const ternaryMatch = rhs.match(/^.+\?\s*(.+?)\s*:\s*(.+)$/);
  if (ternaryMatch) {
    const branches = [ternaryMatch[1].trim(), ternaryMatch[2].trim()];
    const branchIsSafe = (b) => {
      if (b === "''" || b === '""') return true;
      const bc = b.match(/^([A-Za-z_$][\w$]*)\s*\(/);
      if (bc && SAFE_CALL_HELPERS.has(bc[1])) return true;
      return /^[A-Za-z_$][\w$]*$/.test(b) && isLocallySafeAlias(b, src, fnStart + m.index, depth + 1);
    };
    if (branches.every(branchIsSafe)) return true;
  }

  // Case 3: `[a, b, c].filter(Boolean).join(sep)` (or plain `.join(sep)`)
  // over identifiers that are each themselves traced safe.
  const joinMatch = rhs.match(/^\[([^\]]+)\]\s*(?:\.filter\([^)]*\))?\s*\.join\(/);
  if (joinMatch) {
    const parts = joinMatch[1].split(',').map(s => s.trim()).filter(Boolean);
    if (parts.every(p => /^[A-Za-z_$][\w$]*$/.test(p) && isLocallySafeAlias(p, src, fnStart + m.index, depth + 1))) {
      return true;
    }
  }

  // Case 4: `arrayVar.map(param => \`...template...\`).join(sep)` -- an array
  // variable (not a literal) mapped through an arrow function whose body is
  // itself a template literal, then joined. Safe when every `${...}`
  // interpolation inside that template body is, itself, a call to a
  // SAFE_CALL_HELPERS helper or a `Number(...)` cast (never raw string
  // concatenation of unescaped input), recursing into nested ternaries the
  // same way the top-level scan below does. This is the exact shape
  // settingsModal.js's chain-verification detail message uses: each row is
  // escapeHtml()-wrapped before the pieces are joined, but the safety lives
  // inside the map callback's template, not in a bare identifier this
  // tracer could otherwise see.
  const mapJoinMatch = rhs.match(/^([A-Za-z_$][\w$]*)\s*\n?\s*\.map\(\s*([A-Za-z_$][\w$]*)\s*=>\s*`([\s\S]*)`\s*\)\s*\n?\s*\.join\(/);
  if (mapJoinMatch) {
    const templateBody = mapJoinMatch[3];
    const innerExprs = expressionsIn('`' + templateBody + '`');
    const innerIsSafe = (expr) => {
      if (callsSafeHelper(expr)) return true;
      // `Number(x)` / a numeric-looking cast is safe regardless of x's
      // provenance -- the result can only ever be a number.
      if (/^Number\(/.test(expr)) return true;
      // A nested template literal branch, e.g. `` `, entry #${Number(x)}` ``
      // -- safe when every interpolation INSIDE that nested template is
      // itself safe by this same rule (recursive: a nested template could
      // in principle nest another ternary-with-template branch, though in
      // practice one level covers every real case seen so far).
      if (/^`[\s\S]*`$/.test(expr)) {
        return expressionsIn(expr).every(({ expr: inner }) => innerIsSafe(inner));
      }
      // A ternary whose two branches are each safe (ie. reuse the same
      // branch-safety rule Case 2 applies, without requiring a full
      // recursive isLocallySafeAlias call since these are expressions,
      // not bare identifiers).
      const t = expr.match(/^.+\?\s*(.+?)\s*:\s*(.+)$/);
      if (t) {
        const branches = [t[1].trim(), t[2].trim()];
        return branches.every(b => {
          if (b === "''" || b === '""') return true;
          if (callsSafeHelper(b)) return true;
          if (/^Number\(/.test(b)) return true;
          if (/^`[\s\S]*`$/.test(b)) {
            return expressionsIn(b).every(({ expr: inner }) => innerIsSafe(inner));
          }
          return false;
        });
      }
      return false;
    };
    if (innerExprs.every(({ expr }) => innerIsSafe(expr))) return true;
  }

  return false;
}

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
    const safeIdentifiers = SAFE_BARE_IDENTIFIERS.get(file) || new Set();
    for (const { start, expr } of expressionsIn(src)) {
      if (!isHtmlContext(src, start)) continue;
      if (callsSafeHelper(expr)) continue;
      // Only flag bare-value interpolations; everything else is out of scope
      // for this cheap regex sweep (see isBareValue for the exact contract).
      if (!isBareValue(expr)) continue;
      // Explicit per-file allowlist for identifiers that are safe by
      // construction (never derived from unescaped input) rather than by
      // having been escaped — e.g. numeric COUNT(*) results, fixed string
      // constants. See SAFE_BARE_IDENTIFIERS above.
      if (safeIdentifiers.has(expr)) continue;
      // A single bare identifier (no dots) whose nearest enclosing
      // function assigns it from a provably-safe expression (an escapeHtml
      // call, a ternary of safe branches, or a join() of safe pieces) is
      // treated as safe. This is what a full AST/taint tracer would give us
      // "for free"; see isLocallySafeAlias for the scoping rationale.
      if (/^[A-Za-z_$][\w$]*$/.test(expr) && isLocallySafeAlias(expr, src, start)) continue;
      // `<anything>.length` is always a number by JS language semantics --
      // safe regardless of what the array/string it's measuring contains,
      // with no need to trace the base expression's provenance at all.
      // General rule (not a per-file/per-identifier allowlist entry) since
      // it holds for any base expression, unlike SAFE_BARE_IDENTIFIERS'
      // per-value justifications above.
      if (/\.length$/.test(expr)) continue;
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
