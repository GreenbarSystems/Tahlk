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

// Record an error. Stores ONLY bounded, non-free-text fields:
//   - `kind`: the caller-supplied category ('audio' | 'transcription' | …)
//   - `name`: the error's class ('AppError', 'TypeError', 'TimeoutError', …)
//   - `code`: the stable machine-readable discriminator from the Rust IPC
//             boundary (e.g. 'secure_service_unreachable'), when present.
//
// The raw `error.message` is deliberately NOT stored. An exception thrown
// mid-operation can splice PHI (a patient alias, a note fragment, a DOB) into
// its free-text message, and this path previously persisted that message
// verbatim while bypassing the SAFE_STRING_KEYS allowlist that track() applies
// for exactly this reason. Restricting to the error's type/code closes that
// gap; the 200-char cap is retained as a secondary safeguard on every field.
export function recordError(kind, errOrMessage) {
  const isObj = errOrMessage && typeof errOrMessage === 'object';
  const record = {
    t: nowISO(),
    event: 'error',
    kind: String(kind).slice(0, 200),
    name: (isObj && errOrMessage.name ? String(errOrMessage.name) : 'Error').slice(0, 200),
  };
  if (isObj && typeof errOrMessage.code === 'string') {
    record.code = errOrMessage.code.slice(0, 200);
  }
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
