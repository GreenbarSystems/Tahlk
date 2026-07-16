// Unit tests for the note claim-grounding gate (domain/noteClaimGroundingGate.js).
//
// This exists for the highest-impact finding in the compliance audit
// report: no output-side check for hallucinated/unsupported clinical
// claims in AI-generated notes. These tests cover the core detection
// (a fabricated value with no transcript basis), the required
// false-positive guards (spelled-out numbers in the transcript that get
// digitized in the note — a normal, non-hallucinated LLM behavior, not an
// invented value), and the never-blocks/advisory-only contract every other
// gate in this codebase shares.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  checkClaimGrounding,
  describeGroundingIssues,
  groundingIssuesCallToAction,
} from '../../src/domain/noteClaimGroundingGate.js';

// ── Core detection ──────────────────────────────────────────────────────

test('flags a clinical value in the note with no basis anywhere in the transcript', () => {
  const transcript = 'Patient reports feeling tired lately, otherwise doing okay.';
  const note = 'Objective: BP 142/95, HR 110. Patient appears fatigued.';
  const { ok, issues } = checkClaimGrounding(note, transcript);
  assert.equal(ok, false);
  // Both sides of the BP reading, plus the HR, are unsupported.
  assert.equal(issues.length, 3);
  assert.ok(issues.every(i => i.type === 'unsupported_value'));
});

test('does not flag a clinical value that does appear in the transcript as digits', () => {
  const transcript = 'Doctor: Your blood pressure today is 118 over 76, which is good.';
  const note = 'Objective: BP 118/76.';
  const { ok, issues } = checkClaimGrounding(note, transcript);
  assert.equal(ok, true);
  assert.equal(issues.length, 0);
});

test('a partially-grounded note flags only the unsupported side', () => {
  const transcript = 'Doctor: Heart rate is 72 today.';
  const note = 'Objective: HR 72, temp 101.4.';
  const { issues } = checkClaimGrounding(note, transcript);
  assert.equal(issues.length, 1);
  assert.match(issues[0].detail, /101\.4/);
});

// ── Spelled-out-number false-positive guard ─────────────────────────────
// The exact scenario a naive digit-only match would false-positive on:
// natural speech uses number WORDS ("five pounds"), and the model
// correctly, non-hallucinogenically writes the digit form ("5 lb") in the
// note — this must NOT be flagged as an unsupported claim.

test('does not flag a note value whose transcript basis is a spelled-out number word', () => {
  const transcript = "Patient says she's lost about five pounds recently.";
  const note = 'Subjective: Reports an estimated 5 lb weight loss.';
  const { ok, issues } = checkClaimGrounding(note, transcript);
  assert.equal(ok, true, JSON.stringify(issues));
});

test('handles a spelled-out tens-and-ones compound ("fifty five")', () => {
  const transcript = "Let's restart the sertraline at fifty five milligrams.";
  const note = 'Plan: Restart sertraline 55mg.';
  const { ok } = checkClaimGrounding(note, transcript);
  assert.equal(ok, true);
});

// Mirrors test_noteQualityGate.mjs's realistic fixture pair, including its
// exact "five pounds" (spoken) / could-be-digitized weight-loss line — a
// direct regression guard tying this module to that shared, already-
// reviewed realistic example.
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

test('realistic fixture: grounded dosage and digitized spoken weight are both clean', () => {
  const note = 'Plan: Restart sertraline 50mg. Subjective: 5 lb weight loss reported.';
  const { ok, issues } = checkClaimGrounding(note, REALISTIC_TRANSCRIPT);
  assert.equal(ok, true, JSON.stringify(issues));
});

test('realistic fixture: a genuinely fabricated dose on top of the real transcript is still caught', () => {
  const note = 'Plan: Restart sertraline 200mg daily.'; // transcript says 50mg, not 200mg
  const { ok, issues } = checkClaimGrounding(note, REALISTIC_TRANSCRIPT);
  assert.equal(ok, false);
  assert.match(issues[0].detail, /200/);
});

// ── Scope guards ─────────────────────────────────────────────────────────

test('non-clinical numbers in the note (e.g. incidental dates) are not checked at all', () => {
  const transcript = 'Patient came in for a follow-up.';
  const note = 'Visit conducted on 2026-07-15. No vitals section this visit.';
  const { ok, issues } = checkClaimGrounding(note, transcript);
  assert.equal(ok, true, JSON.stringify(issues));
});

test('empty note or empty transcript short-circuits to ok (nothing to compare)', () => {
  assert.deepEqual(checkClaimGrounding('', 'some transcript'), { ok: true, issues: [] });
  assert.deepEqual(checkClaimGrounding('BP 120/80', ''), { ok: true, issues: [] });
  assert.deepEqual(checkClaimGrounding(null, null), { ok: true, issues: [] });
});

test('the same unsupported value cited with identical context twice is reported once', () => {
  const transcript = 'Patient seems fine today.';
  const note = 'Objective: Temp 103.2. Plan: recheck Temp 103.2 in one hour.';
  const { issues } = checkClaimGrounding(note, transcript);
  assert.equal(issues.length, 1, JSON.stringify(issues));
});

// ── Message helpers ──────────────────────────────────────────────────────

test('describeGroundingIssues returns empty string for no issues', () => {
  assert.equal(describeGroundingIssues([]), '');
  assert.equal(describeGroundingIssues(null), '');
});

test('describeGroundingIssues singular vs plural phrasing', () => {
  const one = [{ type: 'unsupported_value', detail: '"HR 110" — this value doesn\'t appear in the transcript.' }];
  const two = [...one, { type: 'unsupported_value', detail: '"temp 103.2" — this value doesn\'t appear in the transcript.' }];
  assert.match(describeGroundingIssues(one), /^A value in the note/);
  assert.match(describeGroundingIssues(two), /^2 values in the note/);
});

test('groundingIssuesCallToAction is empty for no issues and non-empty otherwise', () => {
  assert.equal(groundingIssuesCallToAction([]), '');
  assert.notEqual(groundingIssuesCallToAction([{ type: 'unsupported_value', detail: 'x' }]), '');
});

// ── Never blocks (advisory-only contract shared with every other gate) ──

test('checkClaimGrounding never throws on missing/undefined input', () => {
  assert.doesNotThrow(() => checkClaimGrounding(undefined, undefined));
  assert.doesNotThrow(() => checkClaimGrounding(undefined, 'a transcript'));
  assert.doesNotThrow(() => checkClaimGrounding('a note', undefined));
});
