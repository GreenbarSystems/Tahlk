// Minimal pub/sub. Scribe domain events use the `scribe:verb` convention.
//
// Catalogue:
//   scribe:recording_started   — mic opened, timer running
//   scribe:recording_tick      — once/sec while recording. detail: { duration }
//   scribe:recording_stopped   — MediaRecorder stopped, audio assembled
//   scribe:audio_saved         — WAV written to disk. detail: { path, encounterId }
//   scribe:audio_error         — capture/save failed. detail: { error, encounterId }
//   scribe:transcription_started
//   scribe:transcription_complete — detail: { transcript, quality, encounterId }
//     `quality` (finding #2) is the advisory TranscriptionQuality object
//     from whisper.rs (or null if unavailable) — see transcriptionQualityGate.js.
//   scribe:generation_started
//   scribe:note_chunk          — streaming token. detail: { text }
//   scribe:generation_complete — detail: { note, encounterId }
//   scribe:draft_saved         — detail: { encounterId }
//   scribe:note_signed         — detail: { encounterId, hash }
//   scribe:note_exported       — detail: { encounterId, format }
//   scribe:encounter_changed   — home list needs refresh
//
// Note: transcription/generation FAILURES do not emit an event. Errors are
// thrown from the scribe modules (caller toasts once) and recorded directly
// via telemetry.recordError. The old `*_error` events double-surfaced with
// the caller's catch site; see scribe/transcriber.js + noteGenerator.js.

const _subs = new Map();

export function on(name, fn) {
  if (typeof fn !== 'function') return () => {};
  let set = _subs.get(name);
  if (!set) { set = new Set(); _subs.set(name, set); }
  set.add(fn);
  return () => off(name, fn);
}

export function off(name, fn) {
  const set = _subs.get(name);
  if (set) set.delete(fn);
}

export function emit(name, detail) {
  const set = _subs.get(name);
  if (!set || !set.size) return;
  const snap = Array.from(set);
  for (const fn of snap) {
    try { fn(detail); }
    catch (e) { console.error(`eventBus handler for "${name}" threw`, e); }
  }
}

export function _resetBus() { _subs.clear(); }
export function _subscriberCount(name) { return _subs.get(name)?.size || 0; }
