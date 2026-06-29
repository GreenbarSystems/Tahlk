// Unit tests for the pub/sub event bus.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { on, off, emit, _resetBus, _subscriberCount } from '../../src/core/eventBus.js';

test('emit delivers the detail payload to subscribers', () => {
  _resetBus();
  let received = null;
  on('scribe:test', d => { received = d; });
  emit('scribe:test', { value: 42 });
  assert.deepEqual(received, { value: 42 });
});

test('the function returned by on() unsubscribes', () => {
  _resetBus();
  let calls = 0;
  const unsub = on('scribe:test', () => { calls++; });
  emit('scribe:test');
  unsub();
  emit('scribe:test');
  assert.equal(calls, 1);
});

test('off() removes a specific handler', () => {
  _resetBus();
  let calls = 0;
  const fn = () => { calls++; };
  on('scribe:test', fn);
  off('scribe:test', fn);
  emit('scribe:test');
  assert.equal(calls, 0);
});

test('a throwing handler does not block other handlers', () => {
  _resetBus();
  let reached = false;
  on('scribe:test', () => { throw new Error('boom'); });
  on('scribe:test', () => { reached = true; });
  emit('scribe:test');
  assert.equal(reached, true);
});

test('_subscriberCount reflects active subscriptions', () => {
  _resetBus();
  assert.equal(_subscriberCount('scribe:test'), 0);
  const unsub = on('scribe:test', () => {});
  assert.equal(_subscriberCount('scribe:test'), 1);
  unsub();
  assert.equal(_subscriberCount('scribe:test'), 0);
});

test('on() ignores non-function handlers', () => {
  _resetBus();
  const unsub = on('scribe:test', null);
  assert.equal(typeof unsub, 'function');
  assert.equal(_subscriberCount('scribe:test'), 0);
});
