// Unit tests for the bounded-concurrency map (utils/asyncPool.js) used by the
// record-integrity sweeps (audit perf finding #12).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mapLimit } from '../../src/utils/asyncPool.js';

const tick = () => new Promise(r => setTimeout(r, 1));

test('preserves input order regardless of completion order', async () => {
  // Later items resolve sooner, so a naive push-on-complete would reorder.
  const out = await mapLimit([30, 20, 10], 3, async ms => {
    await new Promise(r => setTimeout(r, ms));
    return ms;
  });
  assert.deepEqual(out, [30, 20, 10]);
});

test('never exceeds the concurrency limit', async () => {
  let inFlight = 0;
  let peak = 0;
  await mapLimit([...Array(20).keys()], 4, async () => {
    inFlight++;
    peak = Math.max(peak, inFlight);
    await tick();
    inFlight--;
  });
  assert.ok(peak <= 4, `peak in-flight ${peak} must not exceed 4`);
  assert.ok(peak >= 2, 'should actually run concurrently, not serialize');
});

test('runs every item exactly once and passes the index', async () => {
  const seen = [];
  const out = await mapLimit(['a', 'b', 'c'], 2, async (v, i) => {
    seen.push(i);
    return `${v}${i}`;
  });
  assert.deepEqual(out, ['a0', 'b1', 'c2']);
  assert.deepEqual(seen.sort(), [0, 1, 2]);
});

test('empty input yields empty output', async () => {
  assert.deepEqual(await mapLimit([], 4, async x => x), []);
});

test('limit larger than the list is clamped, not an error', async () => {
  const out = await mapLimit([1, 2], 99, async x => x * 2);
  assert.deepEqual(out, [2, 4]);
});
