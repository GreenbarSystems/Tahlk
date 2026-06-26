// Build guard: walk the static import graph from entry-solo.js and fail if
// any src/group/ module is reachable. Mirrors the pattern from Greenbar Clearing.

import { readFileSync, existsSync } from 'fs';
import { resolve, dirname, join } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '../..');

function resolveImport(from, spec) {
  if (!spec.startsWith('.')) return null;
  const base = dirname(from);
  for (const ext of ['', '.js', '/index.js']) {
    const p = resolve(base, spec + ext);
    if (existsSync(p)) return p;
  }
  return null;
}

function walk(file, visited = new Set()) {
  if (visited.has(file)) return [];
  visited.add(file);
  if (!existsSync(file)) return [];
  const src = readFileSync(file, 'utf8');
  const imports = [...src.matchAll(/^\s*import\s+.*?from\s+['"]([^'"]+)['"]/gm)].map(m => m[1]);
  const violations = [];
  for (const spec of imports) {
    const resolved = resolveImport(file, spec);
    if (!resolved) continue;
    const rel = resolved.replace(ROOT + '\\', '').replace(ROOT + '/', '');
    if (rel.startsWith('src/group/') || rel.startsWith('src\\group\\')) {
      violations.push({ from: file.replace(ROOT, ''), import: rel });
    }
    violations.push(...walk(resolved, visited));
  }
  return violations;
}

const entry = join(ROOT, 'src', 'entry-solo.js');
const violations = walk(entry);

if (violations.length > 0) {
  console.error('FAIL: entry-solo.js reaches group/ modules:');
  violations.forEach(v => console.error(`  ${v.from} → ${v.import}`));
  process.exit(1);
} else {
  console.log('PASS: entry-solo.js does not reach any group/ modules.');
}
