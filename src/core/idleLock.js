// Idle-lock settings + activity watcher ("Quick-Lock Timer" review
// recommendation — see hipaa-risk-assessment.md §3.1's "in-app PIN/
// idle-resume gate"). Locks the screen (solo/lockScreen.js renders the
// actual overlay) after a configurable period of no mouse/keyboard/touch
// activity, so a laptop left unattended between patients doesn't sit open
// with PHI on screen.
//
// Suspended while a recording is in progress: a provider mid-encounter is
// actively engaged even during a long silence in conversation, and locking
// out from under them would be disruptive rather than protective. The
// threat this control targets is walking away BETWEEN patients, not mid-
// session silence.

import { kvGet, kvSet, kvSetCacheOnly } from './storageBackend.js';
import { keys } from '../data/keys.js';
import { on } from './eventBus.js';
import { invoke, isTauri } from '../platform/tauri.js';
import { toast } from '../utils/format.js';

export const DEFAULT_TIMEOUT_MINUTES = 2;
const MIN_TIMEOUT_MINUTES = 1;
const MAX_TIMEOUT_MINUTES = 60;

// Absolute session ceiling: lock this long after the provider last came back,
// no matter how much activity there has been. The idle timer alone can be held
// open forever by continuous interaction, so a workstation that is genuinely in
// use all day never re-authenticates — and neither does one where a jiggling
// mouse, a stuck key, or a screen-sharing tool keeps producing events. This is
// the control that bounds how long a single unlock is worth.
//
// Deliberately a CONSTANT, not a setting. The idle timeout is tunable because
// clinics legitimately differ on it; a hard ceiling is a compliance floor, and
// making it configurable would mean a third audited Rust setter plus a
// protected KV key whose only purpose is letting someone raise the ceiling. A
// value the renderer cannot reach is a value a compromised WebView cannot
// weaken. Eight hours is a clinical day: long enough never to interrupt normal
// use, short enough that an unattended session cannot outlive the shift.
export const MAX_SESSION_MINUTES = 480;

// How often the wall-clock watchdog runs. Short enough that a resumed machine
// locks promptly; long enough to be free.
const HEARTBEAT_MS = 15_000;

// Activity events that count as "still here." pointerdown covers mouse AND
// touch in modern browsers, but mousemove/keydown/scroll are included too
// for environments where pointer events aren't fully wired through to the
// DOM the same way (e.g. some WebView configurations).
const ACTIVITY_EVENTS = ['mousemove', 'mousedown', 'pointerdown', 'keydown', 'scroll', 'touchstart'];

// ON by default (M4). The stored value is only ever `false` when the provider
// has explicitly turned the lock off in Settings; an absent/unset value means
// enabled. A laptop left unattended between patients must lock on its own
// rather than depend on the provider having opted in — the idle lock is a
// compliance control, not a convenience feature.
export function isLockEnabled() {
  return kvGet(keys.lockEnabled()) !== false;
}

export function setLockEnabled(enabled) {
  persistLockSetting(keys.lockEnabled(), !!enabled, 'lock_enabled_set', { enabled: !!enabled });
}

export function getLockTimeoutMinutes() {
  const v = kvGet(keys.lockTimeoutMinutes());
  const n = Number(v);
  if (!Number.isFinite(n)) return DEFAULT_TIMEOUT_MINUTES;
  return Math.min(MAX_TIMEOUT_MINUTES, Math.max(MIN_TIMEOUT_MINUTES, Math.round(n)));
}

export function setLockTimeoutMinutes(minutes) {
  // Number(minutes) || DEFAULT would silently replace a genuine 0 with the
  // default (0 is falsy) instead of clamping it to MIN_TIMEOUT_MINUTES —
  // only NaN (missing/non-numeric input) should fall back to the default.
  const raw = Number(minutes);
  const base = Number.isFinite(raw) ? raw : DEFAULT_TIMEOUT_MINUTES;
  const n = Math.min(MAX_TIMEOUT_MINUTES, Math.max(MIN_TIMEOUT_MINUTES, Math.round(base)));
  persistLockSetting(keys.lockTimeoutMinutes(), n, 'lock_timeout_set', { minutes: n });
}

// Persist a lock setting through its dedicated, audited Rust command
// (lock_enabled_set / lock_timeout_set), which writes the KV row AND a
// config_audit entry in one transaction. The generic kv_set is blocked for
// these keys server-side (secrets::guard_write_key), so a change to the
// auto-logoff safeguard can't be made without a tamper-evident record (M2).
//
// The cache is updated synchronously first so the idle watcher and the
// settings pane's immediate read-back (getLockTimeoutMinutes right after a set)
// see the new value without waiting on the round-trip; a failed write reverts
// the cache and warns, mirroring storageBackend's optimistic kvSet. In the
// non-Tauri web preview there is no Rust command, so fall back to the plain KV
// write (localStorage) — that dev-only mode has no server-side audit anyway.
function persistLockSetting(key, value, command, args) {
  if (!isTauri) {
    kvSet(key, value);
    return;
  }
  const prior = kvGet(key);
  kvSetCacheOnly(key, value);
  invoke(command, args).catch(e => {
    console.error(`${command} failed`, e);
    kvSetCacheOnly(key, prior);
    toast('Change was not saved — reverted', 4500);
  });
}

// Starts watching for inactivity. `onLock` fires once when the idle window
// elapses AND locking is currently enabled AND no recording is in
// progress. Returns a stop function that removes every listener/timer/
// subscription — callers must call this on teardown (there is only ever
// one app instance today, but this keeps the module testable/restartable
// without leaking listeners across tests).
export function startIdleWatcher(onLock) {
  let timer = null;
  let heartbeat = null;
  let isRecording = false;
  let stopped = false;

  // Start of the current session, for the MAX_SESSION_MINUTES ceiling. Reset
  // when the provider returns after a lock (see resetActivity), not when the
  // lock fires — otherwise a session locked overnight would blow its ceiling
  // the instant it was unlocked.
  let sessionStart = Date.now();
  let locked = false;

  // Wall-clock reading from the previous heartbeat. A gap much larger than
  // HEARTBEAT_MS means real time passed without us running: the machine slept
  // or hibernated, or the WebView throttled our timers while hidden.
  let lastTick = Date.now();

  const unsubStart = on('scribe:recording_started', () => { isRecording = true; });
  const unsubStop = on('scribe:recording_stopped', () => { isRecording = false; });

  function scheduleNext() {
    if (stopped) return;
    clearTimeout(timer);
    if (!isLockEnabled()) return; // don't even arm the timer if the feature is off
    const ms = getLockTimeoutMinutes() * 60_000;
    timer = setTimeout(fire, ms);
  }

  // Single lock path, so every reason goes through the same guards and the
  // same session bookkeeping. `reason` is passed to the caller for the audit
  // entry — "idle" and "the machine was asleep" are different events to an
  // investigator, and collapsing them loses that.
  function lock(reason) {
    locked = true;
    onLock(reason);
  }

  // Wall-clock watchdog. Covers the two cases setTimeout alone cannot:
  //
  //   1. The machine slept, hibernated, or the WebView throttled background
  //      timers. A pending setTimeout does not run during suspend, so without
  //      this the app could resume hours later still unlocked. Detected as a
  //      gap in real time larger than the idle window — which is exactly the
  //      same policy as idling, just measured against the clock instead of
  //      against events. Reusing the provider's own idle setting rather than
  //      inventing a second threshold means there is only one number to reason
  //      about: "this long without me is too long."
  //
  //   2. The absolute session ceiling, which no amount of activity can defer.
  function heartbeatCheck() {
    if (stopped) return;
    const now = Date.now();
    const gap = now - lastTick;
    lastTick = now;

    if (!isLockEnabled()) return;
    // Same deferral as the idle path: never lock out from under an active
    // recording. The ceiling is enforced as soon as the recording ends, so it
    // is deferred, not waived.
    if (isRecording) return;
    if (locked) return; // already locked; waiting for the provider to return

    if (gap > getLockTimeoutMinutes() * 60_000) {
      lock('suspend');
      return;
    }
    if (now - sessionStart > MAX_SESSION_MINUTES * 60_000) {
      lock('session_cap');
    }
  }

  function fire() {
    if (stopped) return;
    if (!isLockEnabled()) return; // setting may have changed while the timer was pending
    if (isRecording) {
      // Don't lock mid-session — just check again after another full
      // window rather than resetting on every recording tick, which would
      // otherwise pin the timer at "never fires" for a very long session.
      scheduleNext();
      return;
    }
    lock('idle');
    // Do NOT reschedule here. The activity listeners below are attached at
    // the document level, so interacting with the lock overlay itself
    // (typing a PIN, clicking Unlock) already calls resetActivity() and
    // re-arms the timer — a separate reschedule here would just double up
    // with that.
  }

  function resetActivity() {
    if (stopped) return;
    // First interaction after a lock means the provider has come back and
    // re-authenticated, so a fresh session ceiling starts here. Measuring from
    // the lock instead would count the locked interval against the new
    // session, and a machine locked overnight would hit its ceiling
    // immediately on unlock.
    if (locked) {
      locked = false;
      sessionStart = Date.now();
      lastTick = Date.now();
    }
    scheduleNext();
  }

  for (const evt of ACTIVITY_EVENTS) {
    document.addEventListener(evt, resetActivity, { capture: true, passive: true });
  }
  scheduleNext();
  heartbeat = setInterval(heartbeatCheck, HEARTBEAT_MS);

  return function stop() {
    stopped = true;
    clearTimeout(timer);
    clearInterval(heartbeat);
    for (const evt of ACTIVITY_EVENTS) {
      document.removeEventListener(evt, resetActivity, { capture: true });
    }
    unsubStart();
    unsubStop();
  };
}
