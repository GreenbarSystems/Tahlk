// L10 regression: stopRecording() previously had no timeout path. It returns
// a Promise that only resolves/rejects from inside `_mediaRecorder.onstop`.
// If the underlying MediaRecorder never fires `onstop` after `.stop()` is
// called (observed on some platforms when the capture device disappears
// mid-session), the returned Promise would hang forever — the caller's
// "Saving…" UI state (recordingSection.js) would never clear, with no error
// and no way to recover short of reloading the app.
//
// This drives the REAL recorder.js against a fake MediaRecorder whose
// .stop() intentionally never invokes onstop, and uses node:test's mock
// timers to fast-forward past the internal timeout without a real 8s wait.

import { test, beforeEach, afterEach, mock } from 'node:test';
import assert from 'node:assert/strict';

// ── Fake MediaRecorder ───────────────────────────────────────────────────
let firesOnStop = true;
let lastInstance = null;

class FakeMediaRecorder {
  constructor(stream, opts) {
    this.stream = stream;
    // 'audio/wav' so the success-path test skips convertToWav() entirely —
    // that path needs a real OfflineAudioContext, which isn't relevant to
    // what this file tests (the stop-timeout behavior). recorder.js only
    // branches into convertToWav when the recorded mimeType isn't wav.
    this.mimeType = opts?.mimeType || 'audio/wav';
    this.state = 'inactive';
    this.ondataavailable = null;
    this.onstop = null;
    lastInstance = this;
  }
  start() {
    this.state = 'recording';
  }
  stop() {
    this.state = 'inactive';
    if (firesOnStop) {
      // Real MediaRecorder fires onstop asynchronously (as a task), not
      // synchronously inside .stop(). Mirror that with a microtask so the
      // "never fires" test case is a faithful contrast, not just "faster".
      queueMicrotask(() => this.onstop?.());
    }
    // else: simulate the browser bug — .stop() is called but onstop is
    // never invoked. This is the exact scenario item 10 must guard against.
  }
  static isTypeSupported(candidate) {
    // Only claim support for 'audio/wav' so bestMimeType() in recorder.js
    // picks it, which lets the success-path test skip convertToWav()
    // entirely (that path needs a real OfflineAudioContext, irrelevant to
    // what this file tests).
    return candidate === 'audio/wav';
  }
}
globalThis.MediaRecorder = FakeMediaRecorder;

globalThis.navigator = {
  mediaDevices: {
    getUserMedia: async () => ({
      getTracks: () => [{ stop() {} }],
    }),
  },
};

// Blob/arrayBuffer + FileReader are exercised on the success path only; the
// timeout path never reaches them, so minimal fakes are enough to satisfy
// the module's top-level usage without a real browser.
globalThis.Blob = class {
  constructor(parts, opts) {
    this.parts = parts;
    this.type = opts?.type;
  }
  async arrayBuffer() {
    return new ArrayBuffer(4);
  }
};
globalThis.FileReader = class {
  readAsDataURL() {
    queueMicrotask(() => this.onload?.());
  }
  get result() {
    return 'data:audio/wav;base64,AAAA';
  }
};

// recorder.js's `invoke('save_session_audio', ...)` goes through
// platform/tauri.js, which honors the `__TAHLK_TEST_TAURI__` escape hatch
// (see that file's header comment) instead of touching the real Tauri
// runtime. `emit`/`on` are the REAL eventBus — it's a dependency-free
// pub/sub, so there's no need to mock it; subscribing with `on()` lets us
// observe exactly what recorder.js actually emits.
globalThis.__TAHLK_TEST_TAURI__ = {
  core: { invoke: async () => '/fake/path.wav' },
};

const { startRecording, stopRecording, isRecording } = await import('../../src/scribe/recorder.js');
const { on, _resetBus } = await import('../../src/core/eventBus.js');

let emitted = [];

beforeEach(() => {
  firesOnStop = true;
  lastInstance = null;
  emitted = [];
  _resetBus();
  on('scribe:recording_stopped', payload => emitted.push({ name: 'scribe:recording_stopped', payload }));
  on('scribe:audio_saved', payload => emitted.push({ name: 'scribe:audio_saved', payload }));
  on('scribe:audio_error', payload => emitted.push({ name: 'scribe:audio_error', payload }));
  mock.timers.enable({ apis: ['setTimeout'] });
});

afterEach(() => {
  mock.timers.reset();
});

test('stopRecording resolves normally when onstop fires promptly', async () => {
  await startRecording();
  assert.ok(isRecording());

  const resultPromise = stopRecording('enc-1');
  // Let the queued microtask (onstop) run before advancing timers.
  await Promise.resolve();
  await Promise.resolve();
  mock.timers.tick(0);

  const path = await resultPromise;
  assert.equal(path, '/fake/path.wav');
  assert.ok(
    emitted.some(e => e.name === 'scribe:recording_stopped'),
    'should emit recording_stopped on the normal path',
  );
});

test('stopRecording rejects with a timeout error if onstop never fires', async () => {
  firesOnStop = false; // simulate the stuck-MediaRecorder bug
  await startRecording();

  const resultPromise = stopRecording('enc-1');
  // Flush any pending microtasks (none should resolve this — onstop never
  // fires), then fast-forward past the internal timeout window.
  await Promise.resolve();
  mock.timers.tick(60_000);

  await assert.rejects(
    resultPromise,
    /did not stop in time/i,
    'must reject instead of hanging forever when onstop never fires',
  );
  assert.ok(
    emitted.some(e => e.name === 'scribe:audio_error'),
    'should emit audio_error so the UI can react',
  );
});

test('after a timeout rejection, a late-firing onstop does not double-settle', async () => {
  firesOnStop = false;
  await startRecording();

  const resultPromise = stopRecording('enc-1');
  await Promise.resolve();
  mock.timers.tick(60_000);
  await assert.rejects(resultPromise, /did not stop in time/i);

  // Simulate a very late onstop arriving after the timeout already fired.
  // Must not throw, must not re-emit a second stopped/saved event.
  assert.doesNotThrow(() => lastInstance.onstop?.());
});

test('isRecording() returns false after a timeout rejection (stream/state cleaned up)', async () => {
  firesOnStop = false;
  await startRecording();
  assert.ok(isRecording());

  const resultPromise = stopRecording('enc-1');
  await Promise.resolve();
  mock.timers.tick(60_000);
  await assert.rejects(resultPromise, /did not stop in time/i);

  assert.equal(isRecording(), false, 'recorder state must not be stuck as "recording"');
});
