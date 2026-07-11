// Unit tests for the note-generation quality gate (domain/noteQualityGate.js).
//
// This is the highest-leverage finding in the review: the note-generation
// pipeline validates transport integrity exhaustively but has ZERO content
// checks before a note is handed back to the provider for review/signing.
// These tests cover the three heuristic checks (refusal, truncation,
// suspiciously-short) plus their required false-positive guards — a false
// positive here is worse than useless, since it would train providers to
// ignore the warning.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkNoteQuality, describeQualityIssues, qualityIssuesCallToAction } from '../../src/domain/noteQualityGate.js';

const REALISTIC_TRANSCRIPT = `
Doctor: Good morning, how have you been feeling since our last visit?
Patient: Honestly, not great. The anxiety has been worse, especially at night.
I've been having trouble falling asleep, maybe getting four hours a night.
Doctor: Have you noticed any triggers for the anxiety?
Patient: Work has been really stressful. My manager keeps piling on projects.
I also stopped taking my sertraline about two weeks ago because I ran out
and couldn't get an appointment to refill it.
Doctor: I see. Let's talk about restarting that. Any other symptoms — appetite,
concentration, mood?
Patient: Appetite's been low. I've lost maybe five pounds. Mood is down most days.
No thoughts of hurting myself though, I want to be clear about that.
Doctor: Thank you for sharing that. Let's get you back on the sertraline at 50mg,
and I'd like to see you again in two weeks to check in on the sleep and anxiety.
Patient: That sounds good, thank you.
`.trim();

const GOOD_SOAP_NOTE = `
Subjective: Patient reports worsening anxiety over the past two weeks, with
difficulty falling asleep (averaging four hours nightly). Reports discontinuing
sertraline approximately two weeks ago due to a lapse in refill. Endorses low
appetite with an estimated five-pound weight loss and depressed mood most days.
Denies suicidal ideation.

Objective: Patient appeared alert and cooperative. Affect congruent with
reported mood.

Assessment: Anxiety and depressive symptoms, likely exacerbated by medication
discontinuation and situational work stress.

Plan: Restart sertraline 50mg daily. Follow-up in two weeks to reassess sleep,
anxiety, and mood. Discussed refill process to avoid future lapses.
`.trim();

test('a normal, complete SOAP note reports no issues', () => {
  const { ok, issues } = checkNoteQuality(GOOD_SOAP_NOTE, REALISTIC_TRANSCRIPT);
  assert.equal(ok, true);
  assert.deepEqual(issues, []);
});

// --- Refusal detection ---

test('detects a boilerplate refusal instead of a note', () => {
  const refusal = "I cannot provide medical advice or generate clinical documentation on your behalf. Please consult a licensed professional.";
  const { ok, issues } = checkNoteQuality(refusal, REALISTIC_TRANSCRIPT);
  assert.equal(ok, false);
  assert.equal(issues.length, 1);
  assert.equal(issues[0].type, 'refusal');
});

test('detects a variant refusal phrasing ("As an AI...")', () => {
  const refusal = "As an AI, I'm not able to generate clinical notes without oversight from a qualified provider.";
  const { issues } = checkNoteQuality(refusal, REALISTIC_TRANSCRIPT);
  assert.ok(issues.some(i => i.type === 'refusal'));
});

test('detects an apologetic refusal opener', () => {
  const refusal = "I apologize, but I cannot generate a clinical note from this transcript as it may contain sensitive content.";
  const { issues } = checkNoteQuality(refusal, REALISTIC_TRANSCRIPT);
  assert.ok(issues.some(i => i.type === 'refusal'));
});

// False positive guard: a genuine clinical note may legitimately quote a
// patient saying something like "I cannot..." mid-document — this must NOT
// be flagged as a refusal, since the refusal check only anchors to the
// START of the note (a real refusal is what the model opens with).
test('does not flag a genuine note that quotes a patient saying "I cannot" mid-document', () => {
  const note = `Subjective: Patient reports significant functional impairment, stating "I cannot
climb the stairs at home anymore without severe pain." Denies any acute distress today.

Objective: Gait steady with assistive device. No acute distress noted.

Assessment: Chronic pain, functional limitation as described.

Plan: Continue current pain management plan, referral to physical therapy.`;
  const { ok, issues } = checkNoteQuality(note, REALISTIC_TRANSCRIPT);
  assert.equal(ok, true);
  assert.deepEqual(issues, []);
});

// --- Truncation detection ---

test('detects a note that appears cut off mid-sentence', () => {
  const truncated = `Subjective: Patient reports worsening anxiety and difficulty sleeping over the
past two weeks, related to medication lapse and situational stress including work`;
  const { ok, issues } = checkNoteQuality(truncated, REALISTIC_TRANSCRIPT);
  assert.equal(ok, false);
  assert.ok(issues.some(i => i.type === 'truncated'));
});

test('does not flag a note ending in a normal bulleted Plan item without a period', () => {
  const note = `${GOOD_SOAP_NOTE}\n\nPlan:\n- Restart sertraline 50mg daily\n- Follow-up in two weeks\n- Discussed refill process`;
  const { issues } = checkNoteQuality(note, REALISTIC_TRANSCRIPT);
  assert.ok(!issues.some(i => i.type === 'truncated'));
});

// Known, accepted limitation: a bullet truncated mid-word ("- Restart
// sertraline 50mg da") is NOT caught by this heuristic, because a stricter
// last-word check was tried and reverted after it false-flagged legitimate
// short bullet endings ("...visit in") as truncated. This test documents
// that tradeoff explicitly rather than leaving it as a silent gap — closing
// it reliably requires Anthropic's own `stop_reason` field (currently
// discarded in notes.rs), not a text heuristic.
test('KNOWN LIMITATION: a bullet truncated mid-word is not caught by the text heuristic (documented tradeoff, not a target for this test suite)', () => {
  const truncatedBullet = 'Plan:\n- Restart sertraline 50mg da';
  const { issues } = checkNoteQuality(truncatedBullet, REALISTIC_TRANSCRIPT);
  assert.ok(!issues.some(i => i.type === 'truncated'), 'documented limitation: list items are exempted from truncation detection');
});

test('does not flag a note ending in the template\'s own "Not documented this visit" boilerplate', () => {
  const note = `${GOOD_SOAP_NOTE.slice(0, GOOD_SOAP_NOTE.indexOf('Plan:'))}Plan: Not documented this visit`;
  const { issues } = checkNoteQuality(note, REALISTIC_TRANSCRIPT);
  assert.ok(!issues.some(i => i.type === 'truncated'));
});

test('does not flag a note ending in a quoted terminal punctuation', () => {
  const note = `${GOOD_SOAP_NOTE}\n\nPatient stated, "I feel ready to try this again."`;
  const { issues } = checkNoteQuality(note, REALISTIC_TRANSCRIPT);
  assert.ok(!issues.some(i => i.type === 'truncated'));
});

// --- Suspiciously-short detection ---

test('detects a note that is suspiciously short relative to a substantial transcript', () => {
  const tinyNote = 'Pt seen. Doing okay.';
  const { ok, issues } = checkNoteQuality(tinyNote, REALISTIC_TRANSCRIPT);
  assert.equal(ok, false);
  assert.ok(issues.some(i => i.type === 'too_short'));
});

// False positive guard: a genuinely short VISIT (short transcript) must not
// be penalized just because the resulting note is also short — the ratio
// check should not even engage below the minimum transcript length.
test('does not flag a short note from a short, legitimately brief visit', () => {
  const shortTranscript = 'Doctor: How are you feeling? Patient: Better, thanks. No new issues.';
  const shortNote = 'Subjective: Patient reports feeling better, no new issues. Plan: Continue current regimen.';
  const { ok, issues } = checkNoteQuality(shortNote, shortTranscript);
  assert.equal(ok, true);
  assert.deepEqual(issues, []);
});

// False positive guard: normal clinical summarization condenses a
// transcript substantially by design — a well-written, complete note must
// not be flagged just because it's much shorter than the transcript it
// came from, as long as it clears the ratio floor.
test('does not flag normal summarization ratio on a complete, well-formed note', () => {
  const longTranscript = REALISTIC_TRANSCRIPT + '\n' + REALISTIC_TRANSCRIPT; // ~2x longer, still realistic
  const { ok, issues } = checkNoteQuality(GOOD_SOAP_NOTE, longTranscript);
  // GOOD_SOAP_NOTE is a genuine, complete SOAP note - should not be flagged
  // as "too short" even against a longer transcript, since it still clears
  // the minimum ratio.
  assert.ok(!issues.some(i => i.type === 'too_short'), `unexpected too_short finding: ${JSON.stringify(issues)}`);
});

// --- Empty note ---

test('flags an empty note distinctly from truncation/refusal', () => {
  const { ok, issues } = checkNoteQuality('', REALISTIC_TRANSCRIPT);
  assert.equal(ok, false);
  assert.equal(issues.length, 1);
  assert.equal(issues[0].type, 'empty');
});

test('flags a whitespace-only note as empty', () => {
  const { issues } = checkNoteQuality('   \n\n  ', REALISTIC_TRANSCRIPT);
  assert.equal(issues[0].type, 'empty');
});

// --- Refusal short-circuits other checks ---

test('a refusal reports only the refusal issue, not also truncated/too_short', () => {
  const refusal = "I cannot provide medical advice or generate clinical notes.";
  const { issues } = checkNoteQuality(refusal, REALISTIC_TRANSCRIPT);
  assert.equal(issues.length, 1);
  assert.equal(issues[0].type, 'refusal');
});

// --- Multiple simultaneous issues ---

test('a truncated AND suspiciously short note reports both issues', () => {
  const tinyTruncated = 'Pt reports feeling';
  const { issues } = checkNoteQuality(tinyTruncated, REALISTIC_TRANSCRIPT);
  const types = issues.map(i => i.type);
  assert.ok(types.includes('truncated'));
  assert.ok(types.includes('too_short'));
});

// --- describeQualityIssues / qualityIssuesCallToAction ---

test('describeQualityIssues returns empty string for no issues', () => {
  assert.equal(describeQualityIssues([]), '');
  assert.equal(describeQualityIssues(undefined), '');
});

test('describeQualityIssues has no jargon and no baked-in call-to-action suffix', () => {
  const { issues } = checkNoteQuality('Pt seen.', REALISTIC_TRANSCRIPT);
  const msg = describeQualityIssues(issues);
  assert.ok(!/sigma|heuristic|threshold/i.test(msg));
  assert.ok(!/before signing/i.test(msg), 'describeQualityIssues should not include the call-to-action suffix');
});

test('qualityIssuesCallToAction recommends regenerating for a refusal', () => {
  const { issues } = checkNoteQuality('I cannot provide medical advice.', REALISTIC_TRANSCRIPT);
  assert.match(qualityIssuesCallToAction(issues), /regenerate/i);
});

test('qualityIssuesCallToAction recommends reviewing for a non-refusal issue', () => {
  const { issues } = checkNoteQuality('Pt seen.', REALISTIC_TRANSCRIPT);
  assert.match(qualityIssuesCallToAction(issues), /review/i);
});

test('qualityIssuesCallToAction returns empty string for no issues', () => {
  assert.equal(qualityIssuesCallToAction([]), '');
});
