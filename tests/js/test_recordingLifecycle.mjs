// Cross-patient PHI contamination regression.
//
// recorder.js holds _mediaRecorder/_stream/_chunks at MODULE scope, but an
// encounter panel does not — and wireRecordingSection registered no teardown,
// while panel.js discarded its return value. So a capture started under
// encounter A survived the panel's unmount: the microphone stayed live, the
// tick interval kept firing, and audio kept accumulating. Opening encounter B
// and pressing Record then short-circuited on `isRecording()` and routed to
// `stopRecording(ctx.currentEncounter.id)` — writing patient A's audio to disk
// under patient B's encounter id, from where it flowed into B's transcript,
// note, and signed hash.
//
// Two independent guards are asserted here:
//   1. panel dispose() stops the recorder (and SAVES to the correct encounter,
//      rather than discarding a real clinical recording)
//   2. stopRecording() refuses to persist under an encounter it was not
//      started for, as a last-resort assertion if (1) is ever bypassed
//
// Drives the REAL recorder.js and recordingSection.js against fake browser
// APIs, following the mocking pattern in test_recorder_stopTimeout.mjs.

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

// ── Fake DOM ─────────────────────────────────────────────────────────────
let els;

class FakeEl {
  constructor(tag = 'div') {
    this.tagName = tag;
    this.id = '';
    this.value = '';
    this.textContent = '';
    this.disabled = false;
    this._on = {};
    this.options = { length: 0 };
    this.classList = {
      _s: new Set(),
      add: c => this.classList._s.add(c),
      remove: c => this.classList._s.delete(c),
      contains: c => this.classList._s.has(c),
    };
  }
  addEventListener(type, fn) { this._on[type] = fn; }
  removeEventListener() {}
  setAttribute(a, v) { if (a === 'disabled') this.disabled = !!v; }
  removeAttribute(a) { if (a === 'disabled') this.disabled = false; }
  appendChild(child) { return child; }
  remove() {}
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
  createElement: tag => new FakeEl(tag),
};

// ── Fake browser capture APIs ────────────────────────────────────────────
// Track stop() calls so a leaked microphone is directly observable.
let stoppedTracks = 0;

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
    queueMicrotask(() => this.onstop?.());
  }
  static isTypeSupported(candidate) { return candidate === 'audio/wav'; }
}
globalThis.MediaRecorder = FakeMediaRecorder;

// Node 22+ exposes `navigator` as a getter-only accessor, so plain assignment
// throws; defineProperty works regardless (see test_recorder_stopTimeout.mjs).
Object.defineProperty(globalThis, 'navigator', {
  value: {
    mediaDevices: {
      getUserMedia: async () => ({
        getTracks: () => [{ stop() { stoppedTracks++; } }],
      }),
      enumerateDevices: async () => [],
    },
  },
  configurable: true,
  writable: true,
});

globalThis.Blob = class {
  constructor(parts, opts) { this.parts = parts; this.type = opts?.type; }
  async arrayBuffer() { return new ArrayBuffer(4); }
};
globalThis.FileReader = class {
  readAsDataURL() { queueMicrotask(() => this.onload?.()); }
  get result() { return 'data:audio/wav;base64,AAAA'; }
};

// Record every save so we can assert WHICH encounter id the audio landed under
// — the whole point of this file.
let saveCalls = [];
globalThis.__TAHLK_TEST_TAURI__ = {
  core: {
    invoke: async (cmd, args) => {
      if (cmd === 'save_session_audio') {
        saveCalls.push(args);
        return `/fake/${args.encounterId}.wav`;
      }
      return null;
    },
  },
};

const { startRecording, stopRecording, abortRecording, isRecording, recordingEncounterId } =
  await import('../../src/scribe/recorder.js');
const { wireRecordingSection } = await import('../../src/solo/encounter/recordingSection.js');
const { encountersRepo } = await import('../../src/data/encountersRepo.js');

function makeCtx(id) {
  const subs = {};
  return {
    currentEncounter: { id, status: 'draft', audio_path: null },
    sub: (name, fn) => { subs[name] = fn; },
    onEncounterUpdated: () => {},
    _emit: (name, payload) => subs[name]?.(payload),
  };
}

beforeEach(() => {
  resetDom();
  saveCalls = [];
  stoppedTracks = 0;
  encountersRepo.save = async () => {};
});

// ── The core regression ──────────────────────────────────────────────────

test('panel teardown stops the recorder instead of leaving the mic live', async () => {
  const ctx = makeCtx('enc-A');
  const recording = wireRecordingSection(ctx);

  await els.get('btn-record')._on.click(); // start on enc-A
  assert.ok(isRecording(), 'precondition: recording is live');

  await recording.stopForDispose();

  assert.equal(isRecording(), false, 'recorder must not survive panel teardown');
  assert.ok(stoppedTracks > 0, 'microphone tracks must be released on teardown');
});

test('teardown SAVES the in-flight capture to its own encounter, not discards it', async () => {
  const ctx = makeCtx('enc-A');
  const recording = wireRecordingSection(ctx);

  await els.get('btn-record')._on.click();
  await recording.stopForDispose();

  // Discarding would be silent loss of a real clinical recording; the capture
  // belongs to enc-A and must be persisted under enc-A.
  assert.equal(saveCalls.length, 1, 'the recording must be saved, not dropped');
  assert.equal(saveCalls[0].encounterId, 'enc-A');
});

test('a capture started under one encounter is never saved under another', async () => {
  await startRecording('enc-A');
  assert.equal(recordingEncounterId(), 'enc-A');

  // Simulates the old bug's end state: a live enc-A capture being stopped by a
  // panel that believes it owns enc-B.
  await assert.rejects(
    stopRecording('enc-B'),
    /different encounter/i,
    'must refuse to persist enc-A audio under enc-B',
  );

  assert.equal(saveCalls.length, 0, 'no audio may be written under the wrong encounter');
  assert.equal(isRecording(), false, 'the mismatched capture must be torn down, not left running');
  assert.ok(stoppedTracks > 0, 'microphone must be released even on the refusal path');
});

test('opening a second encounter after teardown records only its own audio', async () => {
  const ctxA = makeCtx('enc-A');
  const recordingA = wireRecordingSection(ctxA);
  await els.get('btn-record')._on.click();
  await recordingA.stopForDispose();

  // Fresh panel for a different patient, as after navigating away and back.
  resetDom();
  const ctxB = makeCtx('enc-B');
  wireRecordingSection(ctxB);
  await els.get('btn-record')._on.click(); // start fresh on enc-B
  assert.equal(recordingEncounterId(), 'enc-B', 'a new capture must own the new encounter');

  await els.get('btn-record')._on.click(); // stop
  await new Promise(r => queueMicrotask(r));
  await new Promise(r => setTimeout(r, 0));

  assert.deepEqual(
    saveCalls.map(c => c.encounterId),
    ['enc-A', 'enc-B'],
    'each encounter must receive exactly its own audio',
  );
});

// ── Supporting guards ────────────────────────────────────────────────────

test('abortRecording releases the microphone without persisting anything', async () => {
  await startRecording('enc-A');

  abortRecording();

  assert.equal(isRecording(), false);
  assert.equal(saveCalls.length, 0, 'abort must not write audio to disk');
  assert.ok(stoppedTracks > 0, 'abort must release the microphone');
  assert.equal(recordingEncounterId(), null, 'abort must clear capture ownership');
});

test('an audio_saved event for another encounter does not stamp this panel', async () => {
  const ctx = makeCtx('enc-A');
  wireRecordingSection(ctx);

  // The event bus is global; a save landing from a previously-open encounter
  // must not set audio_path on whichever encounter happens to be open now.
  await ctx._emit('scribe:audio_saved', { path: '/fake/enc-B.wav', encounterId: 'enc-B' });

  assert.equal(ctx.currentEncounter.audio_path, null, 'foreign save must be ignored');
  assert.equal(ctx.currentEncounter.status, 'draft');
});

test('an audio_saved event for this encounter is still applied', async () => {
  const ctx = makeCtx('enc-A');
  wireRecordingSection(ctx);

  await ctx._emit('scribe:audio_saved', { path: '/fake/enc-A.wav', encounterId: 'enc-A' });

  assert.equal(ctx.currentEncounter.audio_path, '/fake/enc-A.wav');
  assert.equal(ctx.currentEncounter.status, 'recording_done');
});
