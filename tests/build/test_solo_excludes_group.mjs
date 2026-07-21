// Build guard: walk the static import graph from entry-solo.js and fail if
// any src/group/ module is reachable.
//
// The original walker extracted specifiers with a single regex,
//   /^\s*import\s+.*?from\s+['"]([^'"]+)['"]/gm
// which misses four real forms:
//
//   * `export { x } from './y.js'` re-exports — and src/solo/encounter/index.js
//     is exactly that, so the ENTIRE encounter subtree was severed from the
//     walk, along with scribe/, editor/ and four domain/ gate modules
//   * multi-line import blocks (`.` does not match newline)
//   * side-effect imports, `import './x.js'`
//   * dynamic `import('./x.js')`
//
// It reached 54 modules where a complete walk reaches 70, so the guard was
// silently blind to 23% of the graph — including every module an encounter
// panel loads. Not violated today (src/group/ does not exist yet), which is
// the problem: it would not have fired when group code was introduced, which
// is the only moment it exists to catch.
//
// A coverage floor is asserted below so an extraction regression fails loudly
// instead of quietly shrinking the guard again.

import { readFileSync, existsSync } from 'fs';
import { resolve, dirname, join } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '../..');

// Any module reachable from entry-solo.js must be found by at least one of
// these. False positives (e.g. the word `import` inside a comment) only cause
// an extra file to be walked, which is harmless; false negatives are what
// this guard cannot tolerate.
const SPEC_PATTERNS = [
  // `import ... from '...'` and `export ... from '...'`, multi-line safe.
  /(?:^|\n)\s*(?:import|export)\b[\s\S]*?\bfrom\s*['"]([^'"]+)['"]/g,
  // Side-effect import: `import './x.js'`.
  /(?:^|\n)\s*import\s*['"]([^'"]+)['"]/g,
  // Dynamic: `import('./x.js')`.
  /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
];

function specifiersIn(src) {
  const out = new Set();
  for (const re of SPEC_PATTERNS) {
    for (const m of src.matchAll(re)) out.add(m[1]);
  }
  return [...out];
}

function resolveImport(from, spec) {
  if (!spec.startsWith('.')) return null;
  const base = dirname(from);
  for (const ext of ['', '.js', '/index.js']) {
    const p = resolve(base, spec + ext);
    if (existsSync(p)) return p;
  }
  return null;
}

function walk(file, visited = new Set(), violations = []) {
  if (visited.has(file)) return { visited, violations };
  visited.add(file);
  if (!existsSync(file)) return { visited, violations };

  for (const spec of specifiersIn(readFileSync(file, 'utf8'))) {
    const resolved = resolveImport(file, spec);
    if (!resolved) continue;
    const rel = resolved.replace(ROOT + '\\', '').replace(ROOT + '/', '');
    if (rel.startsWith('src/group/') || rel.startsWith('src\\group\\')) {
      violations.push({ from: file.replace(ROOT, ''), import: rel });
    }
    walk(resolved, visited, violations);
  }
  return { visited, violations };
}

const entry = join(ROOT, 'src', 'entry-solo.js');
const { visited, violations } = walk(entry);

// Modules only reachable through the forms the old regex could not see. If
// the extraction breaks again, these disappear from `visited` and this fails
// — rather than the guard silently narrowing to a subset of the app.
const MUST_REACH = [
  'src/solo/encounter/panel.js',        // via `export ... from` in encounter/index.js
  'src/solo/encounter/noteSection.js',
  'src/solo/encounter/recordingSection.js',
  'src/scribe/recorder.js',
  'src/editor/noteEditor.js',
];

const reached = new Set(
  [...visited].map(p => p.replace(ROOT + '\\', '').replace(ROOT + '/', '').replaceAll('\\', '/')),
);
const unreached = MUST_REACH.filter(m => !reached.has(m));

let failed = false;

if (unreached.length > 0) {
  console.error('FAIL: import-graph walk no longer reaches modules it must cover:');
  unreached.forEach(m => console.error(`  ${m}`));
  console.error('  The specifier extraction has regressed — this guard is now blind to part of the app.');
  failed = true;
}

if (violations.length > 0) {
  console.error('FAIL: entry-solo.js reaches group/ modules:');
  violations.forEach(v => console.error(`  ${v.from} → ${v.import}`));
  failed = true;
}

if (failed) {
  process.exit(1);
} else {
  console.log(`PASS: entry-solo.js does not reach any group/ modules (${reached.size} modules walked).`);
}
