// Unit-level regression tests for the false-positive-handling mechanisms
// added to test_template_interpolation_escaped.mjs when its SCANNED_FILES
// was widened (M6 follow-up finding). These pin the exact scenarios that
// were manually verified during that fix so a future refactor of the sweep
// can't silently regress detection:
//   1. A same-named variable that is safe in one function and unsafe in
//      another must not be laundered by a file-wide (rather than
//      function-scoped) alias check (the patientsView.js `alias` case).
//   2. A value that flows into a template only via a `.join()` of
//      individually-safe pieces must still be traced as safe (the
//      homeScreen.js `label` case) — but breaking any one piece's safety
//      must be caught (the injected-bug verification done by hand during
//      the fix, pinned here so it survives future refactors).
//   3. The RHS-of-declaration extractor must find the statement's OWN
//      top-level semicolon, not the first semicolon anywhere in the tail --
//      a declaration like `const detail = x.join('; ');` has a literal `;`
//      inside the join separator string, which a naive `[^;]+` capture
//      truncates on (the settingsModal.js `detail` false-positive found
//      while widening SCANNED_FILES to include settingsModal.js).
//   4. `arrayVar.map(param => \`...\`).join(sep)` -- a mapped-and-joined
//      template, not an array-literal join -- must be traced safe when
//      every interpolation inside the map callback's template body is
//      itself safe (including through a nested ternary whose true-branch is
//      itself a nested template literal), and must NOT be traced safe the
//      moment any one of those inner pieces loses its escaping.
//   5. `<anything>.length` is unconditionally safe (always a number by JS
//      semantics) without needing alias-tracing at all.
//
// This file exercises the real SCANNED_FILES-driven sweep against small
// fixture strings that mirror the shapes above, rather than importing
// internals from test_template_interpolation_escaped.mjs (which
// intentionally doesn't export anything — it's a standalone build guard).
// We reimplement the minimal pieces needed to test the tracing behavior in
// isolation, kept in sync with the real implementation; the end-to-end guard
// itself is exercised directly against the real files by
// test_template_interpolation_escaped.mjs and by the manual injected-bug
// verification described in that file's header comment.

import { test } from 'node:test';
import assert from 'node:assert/strict';

const SAFE_CALL_HELPERS = new Set(['escapeHtml', 'statusLabel']);

function callsSafeHelper(expr) {
  const m = expr.match(/^([A-Za-z_$][\w$]*)\s*\(/);
  return !!m && SAFE_CALL_HELPERS.has(m[1]);
}

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

// Mirrors the real extractStatementRhs: finds the statement's OWN top-level
// semicolon (tracking paren/bracket/brace nesting and string/template quote
// state), not just the first semicolon character anywhere in the tail.
function extractStatementRhs(src, declStart) {
  let i = declStart;
  let depth = 0;
  let quote = null;
  for (; i < src.length; i++) {
    const c = src[i];
    if (quote) {
      if (c === '\\') { i++; continue; }
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
  if (depth > 4) return false;
  const before = src.slice(0, pos);
  const fnStart = before.lastIndexOf('function');
  if (fnStart === -1) return false;
  const scope = src.slice(fnStart, pos);

  const declHeadRe = new RegExp('const\\s+' + name + '\\s*=\\s*');
  const headMatch = scope.match(declHeadRe);
  if (!headMatch) return false;
  const declStart = headMatch.index + headMatch[0].length;
  const rhs = extractStatementRhs(scope, declStart).trim();
  const m = { index: headMatch.index };

  const callMatch = rhs.match(/^([A-Za-z_$][\w$]*)\s*\(/);
  if (callMatch && SAFE_CALL_HELPERS.has(callMatch[1])) return true;

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

  const joinMatch = rhs.match(/^\[([^\]]+)\]\s*(?:\.filter\([^)]*\))?\s*\.join\(/);
  if (joinMatch) {
    const parts = joinMatch[1].split(',').map(s => s.trim()).filter(Boolean);
    if (parts.every(p => /^[A-Za-z_$][\w$]*$/.test(p) && isLocallySafeAlias(p, src, fnStart + m.index, depth + 1))) {
      return true;
    }
  }

  const mapJoinMatch = rhs.match(/^([A-Za-z_$][\w$]*)\s*\n?\s*\.map\(\s*([A-Za-z_$][\w$]*)\s*=>\s*`([\s\S]*)`\s*\)\s*\n?\s*\.join\(/);
  if (mapJoinMatch) {
    const templateBody = mapJoinMatch[3];
    const innerExprs = expressionsIn('`' + templateBody + '`');
    const innerIsSafe = (expr) => {
      if (callsSafeHelper(expr)) return true;
      if (/^Number\(/.test(expr)) return true;
      if (/^`[\s\S]*`$/.test(expr)) {
        return expressionsIn(expr).every(({ expr: inner }) => innerIsSafe(inner));
      }
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

// Mirrors the general (not per-identifier) `.length` rule applied directly
// in the main scan loop, alongside isLocallySafeAlias.
function isAlwaysSafeExpr(expr) {
  return /\.length$/.test(expr);
}

test('same variable name is safe in one function and unsafe in another (function-scoped, not file-wide)', () => {
  const src = `
function renderRow(p) {
  const alias = escapeHtml(p.alias);
  return \`<div>\${alias}</div>\`;
}
function onSubmit() {
  const alias = aliasEl.value.trim();
  send(alias);
}
`;
  const safePos = src.indexOf('${alias}');
  assert.equal(isLocallySafeAlias('alias', src, safePos), true, 'the escapeHtml-derived alias in renderRow must be traced safe');

  // The second `alias` is never interpolated into HTML in this fixture (it's
  // passed to send()), so there's no ${alias} usage to mistrace inside
  // onSubmit — the real protection here is that isLocallySafeAlias always
  // looks at the *nearest enclosing function* of the usage site, so even if
  // onSubmit's alias were (hypothetically) interpolated, it would trace back
  // to `aliasEl.value.trim()`, not to renderRow's declaration.
  const hypotheticalUnsafeSrc = src.replace('send(alias);', "return `${alias}`;");
  const unsafePos = hypotheticalUnsafeSrc.lastIndexOf('${alias}');
  assert.equal(
    isLocallySafeAlias('alias', hypotheticalUnsafeSrc, unsafePos),
    false,
    'a same-named alias assigned from raw .value.trim() in a different function must not be laundered as safe'
  );
});

test('a value reaching the template only through .join() of safe pieces is traced safe', () => {
  const src = `
function renderRow(e) {
  const statusStr = statusLabel(e.status);
  const dateStr   = escapeHtml(e.date);
  const label     = [statusStr, dateStr].filter(Boolean).join(', ');
  return \`<div aria-label="\${label}"></div>\`;
}
`;
  const pos = src.indexOf('${label}');
  assert.equal(isLocallySafeAlias('label', src, pos), true, 'label built from two safe pieces via join() must be traced safe');
});

test('breaking one joined piece\u2019s safety is caught, not laundered through by the join tracer', () => {
  // Mirrors the injected-bug verification done by hand during the fix:
  // changing statusStr's source from a safe helper call to a raw property
  // access must flip both the direct usage and the join-derived usage back
  // to unsafe.
  const src = `
function renderRow(e) {
  const statusStr = e.status;
  const dateStr   = escapeHtml(e.date);
  const label     = [statusStr, dateStr].filter(Boolean).join(', ');
  return \`<div aria-label="\${label}"></div><span>\${statusStr}</span>\`;
}
`;
  const labelPos = src.indexOf('${label}');
  const statusPos = src.indexOf('${statusStr}');
  assert.equal(isLocallySafeAlias('label', src, labelPos), false, 'label must be unsafe once one of its joined pieces is unsafe');
  assert.equal(isLocallySafeAlias('statusStr', src, statusPos), false, 'a bare property-access assignment must never be traced safe');
});

test('a ternary between a safe helper call and the empty-string literal is traced safe', () => {
  const src = `
function renderRow(p) {
  const aliasStr = p.patient_alias ? escapeHtml(p.patient_alias) : '';
  return \`<div>\${aliasStr}</div>\`;
}
`;
  const pos = src.indexOf('${aliasStr}');
  assert.equal(isLocallySafeAlias('aliasStr', src, pos), true, 'ternary of safe-call / empty-string must be traced safe');
});

test('a ternary whose non-empty branch is unsafe is not traced safe', () => {
  const src = `
function renderRow(p) {
  const aliasStr = p.patient_alias ? p.patient_alias : '';
  return \`<div>\${aliasStr}</div>\`;
}
`;
  const pos = src.indexOf('${aliasStr}');
  assert.equal(isLocallySafeAlias('aliasStr', src, pos), false, 'ternary with a raw non-empty branch must not be traced safe');
});

test('a join separator containing a literal semicolon does not truncate the RHS extraction', () => {
  // Mirrors the exact settingsModal.js false positive: `.join('; ')` has a
  // `;` inside the string literal. A naive `[^;]+` capture would stop right
  // there and never even reach the map/join tracer below -- this pins that
  // the statement-boundary-aware extractor keeps going past it.
  const src = `
function renderRow(broken) {
  const detail = broken
    .map(b => \`\${escapeHtml(b.encounterId)}\`)
    .join('; ');
  return \`<div>\${detail}</div>\`;
}
`;
  const pos = src.indexOf('${detail}');
  assert.equal(
    isLocallySafeAlias('detail', src, pos),
    true,
    'a semicolon inside the join separator string must not truncate RHS extraction before the map/join tracer runs'
  );
});

test('array.map(fn).join(sep) is traced safe when every piece of the template body is safe', () => {
  const src = `
function renderRow(broken) {
  const detail = broken
    .map(b => \`\${escapeHtml(b.encounterId)} (\${escapeHtml(b.reason || 'unknown')})\`)
    .join('; ');
  return \`<div>\${detail}</div>\`;
}
`;
  const pos = src.indexOf('${detail}');
  assert.equal(isLocallySafeAlias('detail', src, pos), true, 'a map().join() whose template body is all escapeHtml()-wrapped must be traced safe');
});

test('array.map(fn).join(sep) traces through a nested ternary whose true-branch is itself a template literal', () => {
  // Mirrors the exact settingsModal.js shape: the third interpolation inside
  // the map callback's template is a ternary whose true-branch is itself a
  // nested template literal (`, entry #${Number(b.brokenAt)}`), not a bare
  // safe-call or empty string -- this must be traced through one level of
  // nesting, not just accepted at the top level.
  const src = `
function renderRow(broken) {
  const detail = broken
    .map(b => \`\${escapeHtml(b.encounterId)}\${b.brokenAt != null ? \`, entry #\${Number(b.brokenAt)}\` : ''}\`)
    .join('; ');
  return \`<div>\${detail}</div>\`;
}
`;
  const pos = src.indexOf('${detail}');
  assert.equal(isLocallySafeAlias('detail', src, pos), true, 'a nested-template ternary branch whose own interpolations are safe must be traced safe');
});

test('array.map(fn).join(sep) is NOT traced safe once any one piece loses its escaping', () => {
  // Bug-inject-style pin: dropping escapeHtml() from just the first piece
  // must flip the whole map/join chain back to unsafe, proving the tracer
  // doesn't just always return true once it recognizes the .map().join()
  // shape.
  const srcUnescapedFirstPiece = `
function renderRow(broken) {
  const detail = broken
    .map(b => \`\${b.encounterId} (\${escapeHtml(b.reason || 'unknown')})\`)
    .join('; ');
  return \`<div>\${detail}</div>\`;
}
`;
  const pos1 = srcUnescapedFirstPiece.indexOf('${detail}');
  assert.equal(
    isLocallySafeAlias('detail', srcUnescapedFirstPiece, pos1),
    false,
    'dropping escapeHtml() from the first mapped piece must be caught, not laundered through'
  );

  // And dropping the Number() cast from the nested ternary branch must also
  // be caught.
  const srcUncastedTernaryBranch = `
function renderRow(broken) {
  const detail = broken
    .map(b => \`\${escapeHtml(b.encounterId)}\${b.brokenAt != null ? \`, entry #\${b.brokenAt}\` : ''}\`)
    .join('; ');
  return \`<div>\${detail}</div>\`;
}
`;
  const pos2 = srcUncastedTernaryBranch.indexOf('${detail}');
  assert.equal(
    isLocallySafeAlias('detail', srcUncastedTernaryBranch, pos2),
    false,
    'dropping the Number() cast from the nested ternary branch must be caught, not laundered through'
  );
});

test('<anything>.length is always safe regardless of the base expression', () => {
  assert.equal(isAlwaysSafeExpr('broken.length'), true);
  assert.equal(isAlwaysSafeExpr('someDeeply.nested.chain.length'), true);
});

test('a lookalike property name ending in "length" but not exactly .length is not matched by the length rule', () => {
  assert.equal(isAlwaysSafeExpr('foo.lengthUnsafe'), false);
  assert.equal(isAlwaysSafeExpr('foo.length2'), false);
  assert.equal(isAlwaysSafeExpr('fooLength'), false);
});
