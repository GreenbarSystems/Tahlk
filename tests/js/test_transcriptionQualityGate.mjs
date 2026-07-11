// Unit tests for the transcription confidence/duration sanity check
// (domain/transcriptionQualityGate.js) - Finding #2 of the drift-monitoring
// review.
//
// Covers the three heuristic checks (low overall confidence, abnormal
// words-per-minute, hallucination-signature segment count) plus their
// required false-positive guards - a false positive here is worse than
// useless, since it would train providers to distrust a routine, healthy
// transcription.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  checkTranscriptionQuality,
  describeTranscriptionQualityIssues,
  transcriptionQualityCallToAction,
} from '../../src/domain/transcriptionQualityGate.js';

// A realistic, healthy TranscriptionQuality object: high confidence, normal
// conversational pace, no flagged segments. Matches the exact snake_case
// shape Rust's TranscriptionQuality struct serializes (see whisper.rs).
function goodQuality(overrides = {}) {
  return {
    avg_confidence: 0.87,
    low_confidence_segment_count: 0,
    duration_secs: 120,
    words_per_minute: 130,
    ...overrides,
  };
}

// --- No signal available ---

test('null quality (no signal available) reports no issues', () => {
  const { ok, issues } = checkTranscriptionQuality(null);
  assert.equal(ok, true);
  assert.deepEqual(issues, []);
});

test('undefined quality reports no issues', () => {
  const { ok, issues } = checkTranscriptionQuality(undefined);
  assert.equal(ok, true);
  assert.deepEqual(issues, []);
});

// --- Happy path ---

test('a normal, high-confidence transcript reports no issues', () => {
  const { ok, issues } = checkTranscriptionQuality(goodQuality());
  assert.equal(ok, true);
  assert.deepEqual(issues, []);
});

// --- Low overall confidence ---

test('detects systemically low average confidence', () => {
  const q = goodQuality({ avg_confidence: 0.3 });
  const { ok, issues } = checkTranscriptionQuality(q);
  assert.equal(ok, false);
  assert.equal(issues.length, 1);
  assert.equal(issues[0].type, 'low_confidence');
});

test('does not flag confidence right at a healthy level', () => {
  const q = goodQuality({ avg_confidence: 0.9 });
  const { ok, issues } = checkTranscriptionQuality(q);
  assert.equal(ok, true);
  assert.deepEqual(issues, []);
});

// False positive guard: avg_confidence being null (no token data at all,
// e.g. an empty transcription array) must NOT be treated as "confidence is
// zero" - that would flag every silent/empty recording as low-confidence
// when there's simply no signal to judge.
test('does not flag when avg_confidence is null (no signal, not zero)', () => {
  const q = goodQuality({ avg_confidence: null });
  const { ok, issues } = checkTranscriptionQuality(q);
  assert.equal(ok, true);
  assert.deepEqual(issues, []);
});

// --- Abnormal words-per-minute ---

test('detects an abnormally fast implied speech rate', () => {
  const q = goodQuality({ words_per_minute: 400 });
  const { ok, issues } = checkTranscriptionQuality(q);
  assert.equal(ok, false);
  assert.ok(issues.some(i => i.type === 'abnormal_pace'));
});

test('detects an abnormally slow implied speech rate', () => {
  const q = goodQuality({ words_per_minute: 10 });
  const { ok, issues } = checkTranscriptionQuality(q);
  assert.equal(ok, false);
  assert.ok(issues.some(i => i.type === 'abnormal_pace'));
});

test('does not flag a normal conversational pace', () => {
  const q = goodQuality({ words_per_minute: 145 });
  const { ok, issues } = checkTranscriptionQuality(q);
  assert.equal(ok, true);
  assert.deepEqual(issues, []);
});

// False positive guard: a provider who speaks somewhat slowly and
// deliberately (common in clinical encounters) should not get flagged just
// for being on the slower edge of normal.
test('does not flag a deliberately slow but plausible clinical pace', () => {
  const q = goodQuality({ words_per_minute: 95 });
  const { ok, issues } = checkTranscriptionQuality(q);
  assert.equal(ok, true);
  assert.deepEqual(issues, []);
});

// False positive guard: words_per_minute being null (duration unavailable
// or near-zero) must NOT be treated as "0 WPM" (which would be far below
// MIN_PLAUSIBLE_WPM and incorrectly flagged).
test('does not flag when words_per_minute is null (duration unavailable)', () => {
  const q = goodQuality({ words_per_minute: null, duration_secs: null });
  const { ok, issues } = checkTranscriptionQuality(q);
  assert.equal(ok, true);
  assert.deepEqual(issues, []);
});

// --- Hallucination-signature segments ---

test('detects one or more hallucination-signature segments', () => {
  const q = goodQuality({ low_confidence_segment_count: 1 });
  const { ok, issues } = checkTranscriptionQuality(q);
  assert.equal(ok, false);
  assert.ok(issues.some(i => i.type === 'possible_hallucination'));
});

test('detects multiple hallucination-signature segments (still one issue entry)', () => {
  const q = goodQuality({ low_confidence_segment_count: 4 });
  const { ok, issues } = checkTranscriptionQuality(q);
  assert.equal(ok, false);
  const hallucinationIssues = issues.filter(i => i.type === 'possible_hallucination');
  assert.equal(hallucinationIssues.length, 1);
});

test('does not flag zero hallucination-signature segments', () => {
  const q = goodQuality({ low_confidence_segment_count: 0 });
  const { ok, issues } = checkTranscriptionQuality(q);
  assert.equal(ok, true);
  assert.deepEqual(issues, []);
});

// False positive guard: low_confidence_segment_count being absent entirely
// (a stale/partial object) must default to "no flagged segments," not throw
// or be treated as truthy.
test('treats a missing low_confidence_segment_count field as zero, not a flag', () => {
  const q = { avg_confidence: 0.9, duration_secs: 60, words_per_minute: 120 };
  const { ok, issues } = checkTranscriptionQuality(q);
  assert.equal(ok, true);
  assert.deepEqual(issues, []);
});

// --- Multiple simultaneous issues ---

test('reports multiple issues at once when multiple checks fail', () => {
  const q = goodQuality({
    avg_confidence: 0.2,
    words_per_minute: 500,
    low_confidence_segment_count: 2,
  });
  const { ok, issues } = checkTranscriptionQuality(q);
  assert.equal(ok, false);
  assert.equal(issues.length, 3);
  const types = issues.map(i => i.type).sort();
  assert.deepEqual(types, ['abnormal_pace', 'low_confidence', 'possible_hallucination']);
});

// --- describeTranscriptionQualityIssues / transcriptionQualityCallToAction ---

test('describeTranscriptionQualityIssues returns empty string for no issues', () => {
  assert.equal(describeTranscriptionQualityIssues([]), '');
  assert.equal(describeTranscriptionQualityIssues(null), '');
  assert.equal(describeTranscriptionQualityIssues(undefined), '');
});

test('describeTranscriptionQualityIssues joins multiple issue details with a space', () => {
  const { issues } = checkTranscriptionQuality(goodQuality({ avg_confidence: 0.1, words_per_minute: 500 }));
  const text = describeTranscriptionQualityIssues(issues);
  assert.ok(text.includes('low confidence'));
  assert.ok(text.includes('speech rate'));
  // Exactly one space between the two sentences, no run-together text.
  assert.equal(text.split('  ').length, 1);
});

test('transcriptionQualityCallToAction returns empty string for no issues', () => {
  assert.equal(transcriptionQualityCallToAction([]), '');
  assert.equal(transcriptionQualityCallToAction(null), '');
});

test('transcriptionQualityCallToAction returns a non-empty suffix when there are issues', () => {
  const { issues } = checkTranscriptionQuality(goodQuality({ avg_confidence: 0.1 }));
  const cta = transcriptionQualityCallToAction(issues);
  assert.ok(cta.length > 0);
  assert.ok(cta.toLowerCase().includes('double-check'));
});

// --- Boundary values (exact thresholds) ---

test('avg_confidence exactly at the threshold is NOT flagged (strict less-than)', () => {
  const q = goodQuality({ avg_confidence: 0.55 });
  const { ok } = checkTranscriptionQuality(q);
  assert.equal(ok, true);
});

test('avg_confidence just under the threshold IS flagged', () => {
  const q = goodQuality({ avg_confidence: 0.549 });
  const { ok, issues } = checkTranscriptionQuality(q);
  assert.equal(ok, false);
  assert.ok(issues.some(i => i.type === 'low_confidence'));
});

test('words_per_minute exactly at the lower bound is NOT flagged', () => {
  const q = goodQuality({ words_per_minute: 50 });
  const { ok } = checkTranscriptionQuality(q);
  assert.equal(ok, true);
});

test('words_per_minute exactly at the upper bound is NOT flagged', () => {
  const q = goodQuality({ words_per_minute: 250 });
  const { ok } = checkTranscriptionQuality(q);
  assert.equal(ok, true);
});

test('words_per_minute just past the upper bound IS flagged', () => {
  const q = goodQuality({ words_per_minute: 250.1 });
  const { ok, issues } = checkTranscriptionQuality(q);
  assert.equal(ok, false);
  assert.ok(issues.some(i => i.type === 'abnormal_pace'));
});
