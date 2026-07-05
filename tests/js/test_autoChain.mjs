// S-UX-1: auto-chain sequencing (transcribe → generate).
//
// runScribeChain is the pure sequencer wired into the encounter panel's
// scribe:audio_saved handler. These tests pin the two behaviors that matter:
// generation runs only after a successful transcription, and a failed
// transcription stops the chain instead of silently proceeding.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runScribeChain } from '../../src/solo/encounter/autoChain.js';

test('happy path runs transcription then generation in order', async () => {
  const order = [];
  const transcribeNow = async (opts) => { order.push(['transcribe', opts]); return true; };
  const generateNow = async (opts) => { order.push(['generate', opts]); return true; };

  const ok = await runScribeChain({ transcribeNow, generateNow });

  assert.equal(ok, true);
  assert.deepEqual(order.map(o => o[0]), ['transcribe', 'generate']);
  // Both phases are told they are part of the chain so the shared status
  // banner stays continuous ("Transcribing…" → "Writing note…").
  assert.equal(order[0][1].chain, true);
  assert.equal(order[1][1].chain, true);
});

test('transcription failure stops the chain before generation', async () => {
  let generated = false;
  const transcribeNow = async () => false; // e.g. AppError surfaced to the user
  const generateNow = async () => { generated = true; return true; };

  const ok = await runScribeChain({ transcribeNow, generateNow });

  assert.equal(ok, false);
  assert.equal(generated, false, 'must not generate a note when transcription failed');
});
