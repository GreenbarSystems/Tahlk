// Minimal pub/sub. Scribe domain events use the `scribe:verb` convention.
//
// Catalogue:
//   scribe:recording_started   — mic opened, timer running
//   scribe:recording_tick      — once/sec while recording. detail: { duration }
//   scribe:recording_stopped   — MediaRecorder stopped, audio assembled
//   scribe:audio_saved         — WAV written to disk. detail: { path, encounterId }
//   scribe:audio_error         — capture/save failed. detail: { error, encounterId }
//   scribe:transcription_started
//   scribe:transcription_complete — detail: { transcript, encounterId }
//   scribe:transcription_error    — detail: { error, encounterId }
//   scribe:generation_started
//   scribe:note_chunk          — streaming token. detail: { text }
//   scribe:generation_complete — detail: { note, encounterId }
//   scribe:generation_error    — note generation failed. detail: { error, encounterId }
//   scribe:draft_saved         — detail: { encounterId }
//   scribe:note_signed         — detail: { encounterId, hash }
//   scribe:note_exported       — detail: { encounterId, format }
//   scribe:encounter_changed   — home list needs refresh

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
