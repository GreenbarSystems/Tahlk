// Build guard for L8: tauri-plugin-dialog's blocking_save_file() (and its
// sibling blocking_* dialog methods) park the calling thread on a
// sync_channel().recv() until the user closes the native dialog — the
// plugin's own doc comment says these "should NOT be used when running on
// the main thread." Calling one directly inside an async Tauri command body
// blocks a Tokio worker thread for however long the user takes to respond
// to the dialog (seconds to indefinitely), starving the runtime's worker
// pool of a thread for that whole window.
//
// The fix wraps every such call in tauri::async_runtime::spawn_blocking,
// which moves it onto Tokio's dedicated blocking-thread pool. This is a
// source-level structural check (no Rust test harness constructs a mock
// AppHandle/dialog plugin in this codebase) that any `.blocking_*(` call in
// export.rs is textually preceded by `spawn_blocking(` before the next
// closing of that scope — i.e. it's not a bare call sitting directly in an
// async fn body.
//
// This is intentionally narrow (export.rs only, blocking_* dialog calls
// only) — if a future PR adds another blocking_* dialog call elsewhere,
// add that file to SCANNED_FILES here too, after auditing it first.

import { readFileSync } from 'fs';
import { resolve, dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { test } from 'node:test';
import assert from 'node:assert/strict';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '../..');
const SCANNED_FILES = [
  join(ROOT, 'src-tauri', 'src', 'export.rs'),
];

test('blocking_*() dialog calls in export.rs are wrapped in spawn_blocking, not called directly on the async task', () => {
  const violations = [];

  for (const file of SCANNED_FILES) {
    const src = readFileSync(file, 'utf8');
    const callRe = /\.blocking_[A-Za-z_]+\(/g;
    let m;
    while ((m = callRe.exec(src)) !== null) {
      const callStart = m.index;
      // Look backward from the call for the nearest `spawn_blocking(` — and
      // make sure there's no closing `})` of an *earlier* spawn_blocking
      // call in between (which would mean we've already exited that
      // closure by the time we reach this call).
      const before = src.slice(0, callStart);
      const spawnIdx = before.lastIndexOf('spawn_blocking(');
      if (spawnIdx === -1) {
        const line = src.slice(0, callStart).split('\n').length;
        violations.push({ file, line, call: m[0] });
        continue;
      }
      // Crude but adequate brace-balance check between the spawn_blocking(
      // call and our blocking_*( call: if the closure has already been
      // closed (net negative brace balance back to 0 before callStart),
      // this call is not actually inside it.
      const between = src.slice(spawnIdx, callStart);
      let depth = 0;
      let stillOpen = true;
      for (const ch of between) {
        if (ch === '{') depth++;
        else if (ch === '}') {
          depth--;
          if (depth < 0) { stillOpen = false; break; }
        }
      }
      if (!stillOpen) {
        const line = src.slice(0, callStart).split('\n').length;
        violations.push({ file, line, call: m[0] });
      }
    }
  }

  if (violations.length) {
    const detail = violations.map(v => `  ${v.file}:${v.line}  ${v.call}`).join('\n');
    assert.fail(
      `Found ${violations.length} blocking dialog call(s) not wrapped in spawn_blocking:\n${detail}`
    );
  }
});
