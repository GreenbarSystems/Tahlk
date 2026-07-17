// Build guard: run the PHI-in-logs guardrail (scripts/check_log_phi.sh) as
// part of `npm run test:build`, so a forbidden token on a log line fails
// BEFORE push, not only later in CI.
//
// Why shell out to the bash script instead of re-implementing the scan in
// Node: the script is the single source of truth for the policy — the
// FORBIDDEN token list, the log-macro regex, and the path-prefix-stripping
// logic that a recent fix corrected. A Node re-implementation would be a
// second copy of a security control that could silently drift from the one
// CI actually runs. This test keeps exactly one implementation and simply
// invokes it.
//
// bash discovery: the original incident that motivated this was bash not
// being on PATH on a Windows dev box (git-bash lives under a non-obvious
// prefix), NOT bash being absent — anyone who can build this project has git,
// and git ships bash. So we look on PATH first, then the standard
// git-for-windows locations. If bash genuinely can't be found the test SKIPS
// (loudly, naming where it looked) rather than failing a legitimate no-bash
// environment — CI runs on Linux where bash is always present, so the
// authoritative gate is never skipped. A skip is strictly better than today's
// no-local-check status quo, and never worse.

import { spawnSync } from 'child_process';
import { existsSync } from 'fs';
import { resolve, dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { test } from 'node:test';
import assert from 'node:assert/strict';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '../..');
const SCRIPT = join(ROOT, 'scripts', 'check_log_phi.sh');

// Return a runnable bash path, or null. Order: PATH, then git-for-windows.
function findBash() {
  // On PATH? `bash --version` exits 0 if a usable bash is resolvable.
  const onPath = spawnSync('bash', ['--version'], { encoding: 'utf8' });
  if (!onPath.error && onPath.status === 0) return 'bash';

  if (process.platform === 'win32') {
    const candidates = [
      join(process.env.LOCALAPPDATA || '', 'Programs', 'Git', 'bin', 'bash.exe'),
      join(process.env.ProgramFiles || 'C:\\Program Files', 'Git', 'bin', 'bash.exe'),
      join(process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)', 'Git', 'bin', 'bash.exe'),
    ];
    for (const c of candidates) {
      if (c && existsSync(c)) return c;
    }
  }
  return null;
}

test('log-PHI guardrail (check_log_phi.sh) passes', t => {
  const bash = findBash();
  if (!bash) {
    const msg =
      'SKIPPED: no bash found to run scripts/check_log_phi.sh locally. ' +
      'Looked on PATH and standard git-for-windows locations. ' +
      'This check still runs authoritatively in CI (Linux). Install Git ' +
      '(which ships bash) or add bash to PATH to get the pre-push check.';
    console.warn(`\n[test:build] ${msg}\n`);
    t.skip(msg);
    return;
  }

  const res = spawnSync(bash, [SCRIPT], { cwd: ROOT, encoding: 'utf8' });

  if (res.error) {
    assert.fail(`Could not run ${SCRIPT} via ${bash}: ${res.error.message}`);
  }

  // The script prints the offending file:line list to stderr on failure and
  // exits 1. Surface that verbatim so the pre-push failure is as actionable
  // as the CI one.
  if (res.status !== 0) {
    assert.fail(
      `check_log_phi.sh failed (exit ${res.status}). ` +
      `A log::/eprintln!/println! line references a PHI-named token.\n` +
      `${res.stdout || ''}${res.stderr || ''}`
    );
  }
});
