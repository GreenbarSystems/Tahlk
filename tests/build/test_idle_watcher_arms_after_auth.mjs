// Guards the startup ordering in entry-solo.js's bootstrap(): the idle-lock
// watcher must not arm until the startup auth flow has resolved.
//
// Why this is a source-level guard rather than a runtime one: bootstrap() is
// not exported and runs on import, and importing entry-solo.js pulls the whole
// DOM-heavy render graph. Pinning the ordering in the source is the cheap,
// stable way to keep the regression from coming back.
//
// The regression: startIdleWatcher() used to be called near the top of
// bootstrap(), before the auth block. The idle lock is ON by default with a
// 2-minute timeout, so the timer could fire while first-open setup was still
// on screen and replace it with the sign-in prompt — asking an un-configured
// provider for a password that does not exist yet. In a packaged build
// auth_unlock_password then rejects, so there is no way out but a restart.
//
// Two halves to the invariant, one test each:
//   1. The watcher arms AFTER the auth decision and both of its branches.
//   2. Nothing returns out of bootstrap() before it arms, so every path that
//      finishes auth ends up with the watcher running (notably the onboarding
//      early-return, which sits below the call site).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const ENTRY = fileURLToPath(new URL('../../src/entry-solo.js', import.meta.url));

// Blank out comments and string/template literals, replacing their contents
// with spaces so every index in the result still lines up with the original.
// Without this, a brace inside a comment or a string would throw off the
// brace matching, and a keyword mentioned in prose would read as real code.
function blankNonCode(src) {
  const out = src.split('');
  let i = 0;
  const n = src.length;

  const blank = (from, to) => {
    for (let k = from; k < to && k < n; k++) {
      if (out[k] !== '\n') out[k] = ' ';
    }
  };

  while (i < n) {
    const two = src.slice(i, i + 2);

    if (two === '//') {
      const end = src.indexOf('\n', i);
      const stop = end === -1 ? n : end;
      blank(i, stop);
      i = stop;
      continue;
    }

    if (two === '/*') {
      const end = src.indexOf('*/', i + 2);
      const stop = end === -1 ? n : end + 2;
      blank(i, stop);
      i = stop;
      continue;
    }

    const ch = src[i];
    if (ch === '"' || ch === "'" || ch === '`') {
      let j = i + 1;
      while (j < n) {
        if (src[j] === '\\') { j += 2; continue; }
        if (src[j] === ch) break;
        j++;
      }
      blank(i + 1, j);
      i = j + 1;
      continue;
    }

    i++;
  }

  return out.join('');
}

// Extract the balanced body of `async function bootstrap() { ... }`, as a
// {start, end} index pair into the (already blanked) source.
function bootstrapBodyRange(code) {
  const decl = /async\s+function\s+bootstrap\s*\(\s*\)\s*\{/.exec(code);
  assert.ok(decl, 'expected an `async function bootstrap()` declaration in entry-solo.js');

  const open = decl.index + decl[0].length - 1;
  let depth = 0;
  for (let i = open; i < code.length; i++) {
    if (code[i] === '{') depth++;
    else if (code[i] === '}') {
      depth--;
      if (depth === 0) return { start: open + 1, end: i };
    }
  }
  assert.fail('bootstrap() body is not brace-balanced');
}

const raw = await readFile(ENTRY, 'utf8');
const code = blankNonCode(raw);
const { start, end } = bootstrapBodyRange(code);
const body = code.slice(start, end);

// Offset of the first occurrence of `needle` within the bootstrap body, or -1.
function at(needle) {
  return body.indexOf(needle);
}

test('the idle watcher arms only after the startup auth flow resolves', () => {
  const watcher = at('startIdleWatcher(');
  assert.notEqual(watcher, -1, 'bootstrap() should still start the idle watcher');

  // The auth decision and both of its branches must all precede the call.
  // Listing the branches individually (not just the isConfigured() check)
  // means moving the call into the middle of the if/else is caught too.
  for (const marker of [
    'authRepo.isConfigured(',   // the decision
    'runFirstOpenAuth(',        // first-open setup branch
    'showSignInScreen(',        // returning-user branch
  ]) {
    const idx = at(marker);
    assert.notEqual(idx, -1, `expected bootstrap() to still call ${marker}...)`);
    assert.ok(
      idx < watcher,
      `startIdleWatcher() must come after ${marker}...) in bootstrap() — ` +
      'arming it earlier lets the idle timer replace the first-open setup ' +
      'screen with a sign-in prompt for a password that does not exist yet',
    );
  }
});

test('nothing returns out of bootstrap() before the watcher arms', () => {
  const watcher = at('startIdleWatcher(');
  assert.notEqual(watcher, -1);

  // Walk to the call site tracking brace depth. A `return` at depth 0 is a
  // return from bootstrap() itself; one nested inside a callback or a helper
  // is somebody else's control flow and does not concern us.
  let depth = 0;
  const returns = /\breturn\b/g;
  for (let i = 0; i < watcher; i++) {
    if (body[i] === '{') depth++;
    else if (body[i] === '}') depth--;
  }
  assert.equal(depth, 0, 'startIdleWatcher() should sit at the top level of bootstrap()');

  depth = 0;
  let match;
  while ((match = returns.exec(body)) !== null) {
    if (match.index >= watcher) break;
    let d = 0;
    for (let i = 0; i < match.index; i++) {
      if (body[i] === '{') d++;
      else if (body[i] === '}') d--;
    }
    assert.notEqual(
      d, 0,
      'a top-level `return` before startIdleWatcher() would leave the idle ' +
      'lock un-armed on that path — move the return below the watcher, or ' +
      'arm the watcher before it',
    );
  }
});

test('the watcher is armed from exactly one place', () => {
  // A second call site would re-introduce the bug by another door: an early
  // arm somewhere above the auth flow would still fire during setup, even
  // with the well-placed call below it.
  const callSites = raw.match(/startIdleWatcher\s*\(/g) || [];
  assert.equal(
    callSites.length, 1,
    `expected exactly one startIdleWatcher() call site in entry-solo.js, found ${callSites.length}`,
  );
});
