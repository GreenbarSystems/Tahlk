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

import { kvGet, kvSet } from './storageBackend.js';
import { keys } from '../data/keys.js';
import { on } from './eventBus.js';

export const DEFAULT_TIMEOUT_MINUTES = 2;
const MIN_TIMEOUT_MINUTES = 1;
const MAX_TIMEOUT_MINUTES = 60;

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
  kvSet(keys.lockEnabled(), !!enabled);
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
  kvSet(keys.lockTimeoutMinutes(), n);
}

// Starts watching for inactivity. `onLock` fires once when the idle window
// elapses AND locking is currently enabled AND no recording is in
// progress. Returns a stop function that removes every listener/timer/
// subscription — callers must call this on teardown (there is only ever
// one app instance today, but this keeps the module testable/restartable
// without leaking listeners across tests).
export function startIdleWatcher(onLock) {
  let timer = null;
  let isRecording = false;
  let stopped = false;

  const unsubStart = on('scribe:recording_started', () => { isRecording = true; });
  const unsubStop = on('scribe:recording_stopped', () => { isRecording = false; });

  function scheduleNext() {
    if (stopped) return;
    clearTimeout(timer);
    if (!isLockEnabled()) return; // don't even arm the timer if the feature is off
    const ms = getLockTimeoutMinutes() * 60_000;
    timer = setTimeout(fire, ms);
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
    onLock();
    // Do NOT reschedule here. The activity listeners below are attached at
    // the document level, so interacting with the lock overlay itself
    // (typing a PIN, clicking Unlock) already calls resetActivity() and
    // re-arms the timer — a separate reschedule here would just double up
    // with that.
  }

  function resetActivity() {
    if (stopped) return;
    scheduleNext();
  }

  for (const evt of ACTIVITY_EVENTS) {
    document.addEventListener(evt, resetActivity, { capture: true, passive: true });
  }
  scheduleNext();

  return function stop() {
    stopped = true;
    clearTimeout(timer);
    for (const evt of ACTIVITY_EVENTS) {
      document.removeEventListener(evt, resetActivity, { capture: true });
    }
    unsubStart();
    unsubStop();
  };
}
