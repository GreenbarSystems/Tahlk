// On-device, opt-in, PHI-scrubbed diagnostics.
//
// Design constraints for a HIPAA-context app:
//   - OFF by default. Nothing is recorded until the provider opts in.
//   - PHI can never enter the log: track() keeps only numbers/booleans and a
//     small allowlist of short, non-PHI string keys. Free-form strings (where a
//     transcript/alias/note would hide) are dropped. To record a string you
//     must consciously allowlist its key.
//   - No automatic network egress. The log lives on this device; exporting it
//     to share with support is an explicit user action.
//
// This makes field failures diagnosable without a telemetry backend or a
// third-party SDK — both of which would be compliance review items here.

import { kvGet, kvSet, kvEnsure } from './storageBackend.js';
import { on } from './eventBus.js';
import { invoke } from '../platform/tauri.js';
import { keys } from '../data/keys.js';
import { nowISO, todayISO } from '../utils/format.js';

const MAX_EVENTS = 500;

// String props are dropped unless their KEY is on this list — and even then
// they're length-capped. None of these can carry PHI.
const SAFE_STRING_KEYS = new Set(['code', 'kind', 'template', 'status', 'os', 'appVersion']);

// The shape of a machine-generated error code we're willing to record: a short,
// bounded token (e.g. "ENOENT", "ETIMEDOUT", "429", an app-internal category).
// It structurally cannot hold a sentence of free text, so no PHI fits.
const SAFE_ERROR_CODE = /^[A-Za-z0-9_.-]{1,64}$/;

// Secondary size safeguard on every recorded error field, carried over from the
// original 200-char message cap. The PRIMARY safeguard is the allowlist in
// recordError(): the raw error.message is never stored at all.
const MAX_ERROR_FIELD = 200;

export function isEnabled() {
  return kvGet(keys.telemetryEnabled()) === true;
}

export function setEnabled(on) {
  kvSet(keys.telemetryEnabled(), !!on);
}

function scrubProps(props) {
  const out = {};
  if (!props || typeof props !== 'object') return out;
  for (const [k, v] of Object.entries(props)) {
    if (typeof v === 'number' && Number.isFinite(v)) out[k] = v;
    else if (typeof v === 'boolean') out[k] = v;
    else if (typeof v === 'string' && SAFE_STRING_KEYS.has(k)) out[k] = v.slice(0, 64);
    // objects, arrays, and non-allowlisted strings are intentionally dropped
  }
  return out;
}

function append(record) {
  if (!isEnabled()) return; // opt-in gate — the single source of truth
  const events = (kvGet(keys.diagEvents()) || []).slice();
  events.push(record);
  if (events.length > MAX_EVENTS) events.splice(0, events.length - MAX_EVENTS);
  kvSet(keys.diagEvents(), events);
}

// Record a diagnostic event. `props` is scrubbed to non-PHI primitives.
export function track(event, props) {
  append({ t: nowISO(), event: String(event), ...scrubProps(props) });
}

// Record an error. Stores a stable caller-supplied `kind`, the error's type
// name, and — when present and safely shaped — a machine error `code`.
//
// The raw error.message is deliberately NOT stored. recordError() used to write
// it directly via append(), bypassing the SAFE_STRING_KEYS allowlist that
// track() applies to every other string; an exception message can embed
// fragments of whatever operation failed (a patient alias, note text, a DB
// value echoed back), so free-text messages are dropped here the same way
// track() drops non-allowlisted strings. `kind` and `name` are structural
// enums/class names, not free text, and are length-capped as a backstop.
export function recordError(kind, errOrMessage) {
  const name = errOrMessage && errOrMessage.name
    ? String(errOrMessage.name).slice(0, MAX_ERROR_FIELD)
    : 'Error';
  const record = {
    t: nowISO(),
    event: 'error',
    kind: String(kind).slice(0, MAX_ERROR_FIELD),
    name,
  };
  const code = errOrMessage && typeof errOrMessage === 'object' ? errOrMessage.code : undefined;
  if (typeof code === 'string' && SAFE_ERROR_CODE.test(code)) record.code = code.slice(0, MAX_ERROR_FIELD);
  else if (typeof code === 'number' && Number.isFinite(code)) record.code = code;
  append(record);
}

export function getEvents() {
  return kvGet(keys.diagEvents()) || [];
}

export function clear() {
  kvSet(keys.diagEvents(), []);
}

// Write the log to a user-chosen file (explicit egress, reviewed by the user).
export async function exportLog() {
  const events = getEvents();
  const content = JSON.stringify({ exportedAt: nowISO(), count: events.length, events }, null, 2);
  await invoke('export_note_to_file', {
    content,
    suggestedName: `tahlk-diagnostics-${todayISO()}.txt`,
  });
}

let _started = false;

// Load any persisted log into cache, then subscribe to the event bus. track()
// no-ops while disabled, so subscribing unconditionally is cheap and correct.
export async function init() {
  if (_started) return;
  _started = true;
  await kvEnsure([keys.diagEvents()]);
  track('app_started');

  on('scribe:recording_started',     () => track('recording_started'));
  on('scribe:transcription_complete', d => track('transcription_complete', { chars: d?.transcript?.length || 0 }));
  on('scribe:generation_complete',    d => track('note_generated', { chars: d?.note?.length || 0 }));
  on('scribe:note_signed',           () => track('note_signed'));
  on('scribe:note_exported',          d => track('note_exported', { kind: d?.format }));
  // NOTE: transcription/generation errors are recorded directly by the scribe
  // modules calling `recordError` — see scribe/transcriber.js + noteGenerator.js.
  // We used to bridge via `scribe:transcription_error`/`scribe:generation_error`
  // events, but that surface got double-toasted alongside the caller's catch
  // site; the emits are gone. Audio errors still flow through the event bus.
  on('scribe:audio_error',            d => recordError('audio', d?.error));
}
