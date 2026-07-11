// L11 regression: recordingSection.js previously guarded some
// getElementById lookups with `?.` (recordTimer, btn-transcribe) but not
// others (recordBtn, recordLabel) inside the click handler and the
// 'scribe:recording_stopped' subscriber. If the panel is torn down (e.g.
// the provider navigates away) while a recording is starting/stopping,
// those unguarded `recordBtn.disabled = ...` / `recordLabel.textContent =
// ...` writes threw a TypeError instead of silently no-oping — exactly the
// same failure shape as the noteSection.js "false Sign failed" bug fixed
// earlier in this review (item 2).
//
// This drives the REAL wireRecordingSection against a fake DOM, then
// deletes recordBtn/recordLabel from the registry mid-flow to simulate
// disposal, and asserts every code path that used to be unguarded no
// longer throws.

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

// ── Fake DOM ─────────────────────────────────────────────────────────────
let els;

class FakeEl {
  constructor(tag = 'div') {
    this.tagName = tag;
    this.id = '';
    this.textContent = '';
    this.disabled = false;
    this._on = {};
    this.classList = {
      _s: new Set(),
      add: c => this.classList._s.add(c),
      remove: c => this.classList._s.delete(c),
      contains: c => this.classList._s.has(c),
    };
  }
  addEventListener(type, fn) { this._on[type] = fn; }
  removeEventListener() {}
  click() { return this._on.click && this._on.click(); }
}

function resetDom() {
  els = new Map();
  for (const id of ['btn-record', 'record-label', 'record-timer', 'btn-transcribe']) {
    const e = new FakeEl();
    e.id = id;
    els.set(id, e);
  }
}

globalThis.document = {
  getElementById: id => els?.get(id) || null,
  querySelector: () => null,
};

// ── Fake MediaRecorder / getUserMedia so the REAL recorder.js functions
// (startRecording/stopRecording/isRecording) can run without a browser ────
let firesOnStop = true;
class FakeMediaRecorder {
  constructor(stream, opts) {
    this.mimeType = opts?.mimeType || 'audio/wav';
    this.state = 'inactive';
    this.ondataavailable = null;
    this.onstop = null;
  }
  start() { this.state = 'recording'; }
  stop() {
    this.state = 'inactive';
    if (firesOnStop) queueMicrotask(() => this.onstop?.());
  }
  static isTypeSupported(candidate) { return candidate === 'audio/wav'; }
}
globalThis.MediaRecorder = FakeMediaRecorder;
globalThis.navigator = {
  mediaDevices: {
    getUserMedia: async () => ({ getTracks: () => [{ stop() {} }] }),
  },
};
globalThis.Blob = class {
  constructor(parts, opts) { this.parts = parts; this.type = opts?.type; }
  async arrayBuffer() { return new ArrayBuffer(4); }
};
globalThis.FileReader = class {
  readAsDataURL() { queueMicrotask(() => this.onload?.()); }
  get result() { return 'data:audio/wav;base64,AAAA'; }
};
globalThis.__TAHLK_TEST_TAURI__ = { core: { invoke: async () => '/fake/path.wav' } };

const { wireRecordingSection } = await import('../../src/solo/encounter/recordingSection.js');
const { encountersRepo } = await import('../../src/data/encountersRepo.js');

function makeCtx() {
  const subs = {};
  return {
    currentEncounter: { id: 'enc-1', status: 'draft', audio_path: null },
    sub: (name, fn) => { subs[name] = fn; },
    onEncounterUpdated: () => {},
    _emit: (name, payload) => subs[name]?.(payload),
  };
}

beforeEach(() => {
  resetDom();
  firesOnStop = true;
  // Avoid hitting the real DB layer inside 'scribe:audio_saved'.
  encountersRepo.save = async () => {};
});

test('clicking start then stop with an intact DOM updates the button/label normally', async () => {
  const ctx = makeCtx();
  wireRecordingSection(ctx);

  await els.get('btn-record')._on.click(); // start
  assert.equal(els.get('record-label').textContent, 'Stop Recording');
  assert.ok(els.get('btn-record').classList.contains('btn-record--active'));

  await els.get('btn-record')._on.click(); // stop
  ctx._emit('scribe:recording_stopped', {});
  assert.equal(els.get('record-label').textContent, 'Re-record');
  assert.equal(els.get('btn-record').disabled, false);
});

// The core regression: recordBtn/recordLabel are missing from the
// DOM at the moment wireRecordingSection() runs (e.g. this panel's markup
// partially failed to render, or a future refactor renders the button
// conditionally). Every previously-unguarded write must no-op instead of
// throwing.
test('wiring with a missing record button/label does not throw on start, stop, or the stopped event', async () => {
  els.delete('btn-record');
  els.delete('record-label');
  const ctx = makeCtx();

  assert.doesNotThrow(() => wireRecordingSection(ctx));

  // No btn-record element means addEventListener was never attached (the
  // outer `recordBtn?.addEventListener` guard already handled that), so
  // there's no click handler to invoke here -- the real regression surface
  // is the 'scribe:recording_stopped' subscriber, which runs independently
  // of whether the button exists, and previously wrote
  // `recordLabel.textContent = ...` / `recordBtn.disabled = ...`
  // unconditionally.
  assert.doesNotThrow(() => ctx._emit('scribe:recording_stopped', {}));
});

// Mirrors the above but only recordLabel is missing (recordBtn present) --
// verifies the two elements are guarded independently, not just as a pair.
test('a missing record label alone does not throw when recording starts or stops', async () => {
  els.delete('record-label');
  const ctx = makeCtx();
  wireRecordingSection(ctx);

  await assert.doesNotReject(els.get('btn-record')._on.click()); // start
  assert.ok(els.get('btn-record').classList.contains('btn-record--active'));

  await assert.doesNotReject(els.get('btn-record')._on.click()); // stop
  assert.doesNotThrow(() => ctx._emit('scribe:recording_stopped', {}));
  assert.equal(els.get('btn-record').disabled, false);
});

// Mirrors the above but only recordBtn is missing (recordLabel present).
test('a missing record button alone does not throw on the recording_stopped event', async () => {
  els.delete('btn-record');
  const ctx = makeCtx();

  assert.doesNotThrow(() => wireRecordingSection(ctx));
  assert.doesNotThrow(() => ctx._emit('scribe:recording_stopped', {}));
  assert.equal(els.get('record-label').textContent, 'Re-record');
});

// The catch-path write (recordBtn.disabled = false / recordLabel.textContent
// = 'Start Recording' inside the stopRecording() failure branch, lines
// 40-42) must also be guarded independently of the try-path writes above.
// recordLabel is missing here (recordBtn present so the click handler
// attaches); stopRecording()'s own invoke('save_session_audio', ...) call
// is forced to reject via the Tauri test hook, driving the REAL catch
// branch inside the click handler.
test('a missing record label does not throw in the catch branch when stopRecording itself rejects', async () => {
  els.delete('record-label');
  const ctx = makeCtx();
  wireRecordingSection(ctx);

  await els.get('btn-record')._on.click(); // start

  globalThis.__TAHLK_TEST_TAURI__.core.invoke = async () => {
    throw { code: 'storage_error', message: 'disk full' };
  };

  await assert.doesNotReject(els.get('btn-record')._on.click()); // stop -> rejects internally
  // Button must be re-enabled by the catch branch's `if (recordBtn) ...`
  // guard even though recordLabel was missing right next to it.
  assert.equal(els.get('btn-record').disabled, false);
});
