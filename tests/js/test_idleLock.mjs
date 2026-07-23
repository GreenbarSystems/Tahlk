// Unit tests for the idle-lock watcher (core/idleLock.js) — the "Quick-Lock
// Timer" auto-lock control. Covers: settings persistence/clamping, the
// activity-resets-the-timer behavior, suspension while a recording is in
// progress, and full teardown via the returned stop() function.

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

globalThis.document = { getElementById: () => null };
globalThis.__TAHLK_TEST_TAURI__ = {
  core: { invoke: () => Promise.resolve(null) },
  event: { listen: () => () => {} },
};
globalThis.window = globalThis.window || {};

// Minimal fake document supporting addEventListener/removeEventListener so
// startIdleWatcher's activity listeners can be captured and fired manually.
// Overwrites the placeholder document above (idleLock.js is imported after
// this is installed, and only calls document.* inside function bodies that
// run later, so overwriting before first use is safe).
function installFakeDocument() {
  const listeners = new Map(); // event name -> Set(fn)
  globalThis.document = {
    getElementById: () => null,
    addEventListener(evt, fn) {
      if (!listeners.has(evt)) listeners.set(evt, new Set());
      listeners.get(evt).add(fn);
    },
    removeEventListener(evt, fn) {
      listeners.get(evt)?.delete(fn);
    },
    _fire(evt) {
      for (const fn of listeners.get(evt) || []) fn();
    },
    _listenerCount(evt) {
      return listeners.get(evt)?.size || 0;
    },
  };
  return globalThis.document;
}

const idleLock = await import('../../src/core/idleLock.js');
const { emit, _resetBus } = await import('../../src/core/eventBus.js');
const { kvRemove } = await import('../../src/core/storageBackend.js');
const { keys } = await import('../../src/data/keys.js');

const {
  DEFAULT_TIMEOUT_MINUTES,
  isLockEnabled,
  setLockEnabled,
  getLockTimeoutMinutes,
  setLockTimeoutMinutes,
  startIdleWatcher,
} = idleLock;

beforeEach(() => {
  setLockEnabled(false);
  setLockTimeoutMinutes(DEFAULT_TIMEOUT_MINUTES);
  _resetBus();
});

test('isLockEnabled defaults to ON when the setting was never set (M4)', () => {
  // An unset value must read as enabled — the lock ships on, not opt-in.
  kvRemove(keys.lockEnabled());
  assert.equal(isLockEnabled(), true, 'idle lock must be ON by default when unconfigured');
});

test('isLockEnabled is only OFF when explicitly disabled (M4)', () => {
  // A stored `false` (the provider's explicit choice) is the sole way off.
  setLockEnabled(false);
  assert.equal(isLockEnabled(), false);
  // Any other stored value — including a stale/garbage one — still reads ON,
  // failing safe toward locked rather than silently disabling the control.
  kvRemove(keys.lockEnabled());
  assert.equal(isLockEnabled(), true);
});

test('isLockEnabled/setLockEnabled round-trip through storage', () => {
  assert.equal(isLockEnabled(), false);
  setLockEnabled(true);
  assert.equal(isLockEnabled(), true);
  setLockEnabled(false);
  assert.equal(isLockEnabled(), false);
});

test('getLockTimeoutMinutes defaults to DEFAULT_TIMEOUT_MINUTES when unset', () => {
  assert.equal(getLockTimeoutMinutes(), DEFAULT_TIMEOUT_MINUTES);
});

test('setLockTimeoutMinutes clamps to the 1-60 range', () => {
  setLockTimeoutMinutes(0);
  assert.equal(getLockTimeoutMinutes(), 1);
  setLockTimeoutMinutes(999);
  assert.equal(getLockTimeoutMinutes(), 60);
  setLockTimeoutMinutes(5);
  assert.equal(getLockTimeoutMinutes(), 5);
});

test('setLockTimeoutMinutes falls back to the default for non-numeric input', () => {
  setLockTimeoutMinutes(NaN);
  assert.equal(getLockTimeoutMinutes(), DEFAULT_TIMEOUT_MINUTES);
});

test('startIdleWatcher never fires onLock while the feature is disabled', t => {
  installFakeDocument();
  t.mock.timers.enable({ apis: ['setTimeout'] });
  setLockEnabled(false);
  setLockTimeoutMinutes(2);

  let fired = false;
  const stop = startIdleWatcher(() => { fired = true; });

  t.mock.timers.tick(10 * 60_000);
  assert.equal(fired, false, 'disabled watcher must never lock');
  stop();
});

test('startIdleWatcher fires onLock after the configured idle window elapses', t => {
  installFakeDocument();
  t.mock.timers.enable({ apis: ['setTimeout'] });
  setLockEnabled(true);
  setLockTimeoutMinutes(2);

  let fired = false;
  const stop = startIdleWatcher(() => { fired = true; });

  t.mock.timers.tick(2 * 60_000 - 1);
  assert.equal(fired, false, 'must not fire before the full window elapses');
  t.mock.timers.tick(1);
  assert.equal(fired, true, 'must fire once the full window has elapsed');
  stop();
});

test('activity resets the idle window instead of letting the original deadline fire', t => {
  const doc = installFakeDocument();
  t.mock.timers.enable({ apis: ['setTimeout'] });
  setLockEnabled(true);
  setLockTimeoutMinutes(2);

  let fired = false;
  const stop = startIdleWatcher(() => { fired = true; });

  t.mock.timers.tick(90_000); // 1.5 min in
  doc._fire('keydown');       // resets the window
  t.mock.timers.tick(90_000); // another 1.5 min — 3 min total, but only 1.5 since reset
  assert.equal(fired, false, 'activity partway through must push the deadline out');

  t.mock.timers.tick(30_001); // completes the full 2 min from the reset point
  assert.equal(fired, true, 'must eventually fire once a full idle window passes uninterrupted');
  stop();
});

test('locking is suspended while a recording is in progress', t => {
  installFakeDocument();
  t.mock.timers.enable({ apis: ['setTimeout'] });
  setLockEnabled(true);
  setLockTimeoutMinutes(2);

  let fired = false;
  const stop = startIdleWatcher(() => { fired = true; });

  emit('scribe:recording_started');
  t.mock.timers.tick(10 * 60_000); // well past the timeout, but mid-recording
  assert.equal(fired, false, 'must not lock while a recording is in progress');

  emit('scribe:recording_stopped');
  t.mock.timers.tick(2 * 60_000); // one full window after recording ends
  assert.equal(fired, true, 'must lock once idle again after the recording ends');
  stop();
});

test('stop() removes all activity listeners and cancels the pending timer', t => {
  const doc = installFakeDocument();
  t.mock.timers.enable({ apis: ['setTimeout'] });
  setLockEnabled(true);
  setLockTimeoutMinutes(2);

  let fired = false;
  const stop = startIdleWatcher(() => { fired = true; });
  assert.ok(doc._listenerCount('keydown') > 0, 'listeners must be registered while running');

  stop();
  assert.equal(doc._listenerCount('keydown'), 0, 'stop() must remove every activity listener');

  t.mock.timers.tick(10 * 60_000);
  assert.equal(fired, false, 'a stopped watcher must never fire, even past the original deadline');

  // Firing an activity event post-stop must not resurrect the timer or throw.
  assert.doesNotThrow(() => doc._fire('keydown'));
  t.mock.timers.tick(10 * 60_000);
  assert.equal(fired, false);
});

test('re-enabling after being disabled at start requires a fresh activity event to arm (documented limitation)', t => {
  installFakeDocument();
  t.mock.timers.enable({ apis: ['setTimeout'] });
  setLockEnabled(false);
  setLockTimeoutMinutes(2);

  let fired = false;
  const stop = startIdleWatcher(() => { fired = true; });

  setLockEnabled(true); // flips the setting, but no timer is armed yet
  t.mock.timers.tick(5 * 60_000);
  assert.equal(fired, false, 'enabling alone does not retroactively arm an unarmed timer');
  stop();
});
