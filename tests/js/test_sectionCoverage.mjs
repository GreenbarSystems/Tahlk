// Unit tests for the export/generation-structure consistency check
// (domain/sectionCoverage.js). This is the advisory drift detector: a
// template declares required `sections` (templates/data/*.json), and the
// LLM's free-text output is checked against that contract — nothing else
// in the app currently verifies this, so a truncated or non-compliant
// generation can otherwise ship with a compliance-critical section (e.g.
// "Risk Assessment") silently absent.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkSectionCoverage, describeMissingSections } from '../../src/domain/sectionCoverage.js';

const psychEvalLike = {
  id: 'psych-eval',
  sections: ['Chief Complaint', 'History of Present Illness', 'Mental Status Examination', 'Risk Assessment', 'Plan'],
};

test('a note containing every required section reports nothing missing', () => {
  const note = [
    'Chief Complaint: patient reports low mood.',
    'History of Present Illness: symptoms began three weeks ago.',
    'Mental Status Examination: alert, oriented, mood depressed.',
    'Risk Assessment: denies SI/HI, no plan or intent.',
    'Plan: start sertraline, follow up in 2 weeks.',
  ].join('\n\n');

  const { missing, present } = checkSectionCoverage(note, psychEvalLike);
  assert.deepEqual(missing, []);
  assert.equal(present.length, 5);
});

// The exact regression this feature exists to catch: a compliance-critical
// section silently absent from an otherwise normal-looking note.
test('flags a missing compliance-critical section (Risk Assessment)', () => {
  const note = [
    'Chief Complaint: patient reports low mood.',
    'History of Present Illness: symptoms began three weeks ago.',
    'Mental Status Examination: alert, oriented, mood depressed.',
    'Plan: start sertraline, follow up in 2 weeks.',
  ].join('\n\n'); // Risk Assessment omitted entirely

  const { missing, present } = checkSectionCoverage(note, psychEvalLike);
  assert.deepEqual(missing, ['Risk Assessment']);
  assert.equal(present.length, 4);
});

test('flags multiple missing sections and preserves template order', () => {
  const note = 'Chief Complaint: patient reports low mood.\n\nPlan: follow up in 2 weeks.';
  const { missing } = checkSectionCoverage(note, psychEvalLike);
  assert.deepEqual(missing, ['History of Present Illness', 'Mental Status Examination', 'Risk Assessment']);
});

// LLM output formatting varies in practice: markdown headers, bold labels,
// trailing colons, different casing. The matcher must tolerate all of these
// — the point is to catch a TRULY absent section, not to enforce one exact
// formatting style (that would produce false positives that erode trust in
// the warning and could pressure a provider to reformat instead of review).
test('tolerates markdown headers, bold labels, and case differences', () => {
  const note = [
    '## chief complaint',
    'low mood.',
    '**History of Present Illness**',
    'three weeks.',
    'MENTAL STATUS EXAMINATION:',
    'appropriate.',
    'Risk Assessment -',
    'denies SI/HI.',
    'Plan',
    'sertraline.',
  ].join('\n');

  const { missing } = checkSectionCoverage(note, psychEvalLike);
  assert.deepEqual(missing, []);
});

// The psych-eval systemPrompt itself introduces "(MSE)" as an initialism for
// "Mental Status Examination" — the parenthetical must not force a literal
// "(MSE)" match requirement, since normalize() strips parentheticals from
// the TEMPLATE section label, and the note text just needs to contain the
// core label text.
test('a parenthetical in the template label does not require an exact match', () => {
  const template = { sections: ['Mental Status Examination (MSE)'] };
  const note = 'Mental Status Examination: patient alert and oriented.';
  const { missing } = checkSectionCoverage(note, template);
  assert.deepEqual(missing, []);
});

test('a template with no sections array is not a violation (nothing to check)', () => {
  const { missing, present } = checkSectionCoverage('any note text', { id: 'custom-1' });
  assert.deepEqual(missing, []);
  assert.deepEqual(present, []);
});

test('a template with an empty sections array is not a violation', () => {
  const { missing } = checkSectionCoverage('any note text', { sections: [] });
  assert.deepEqual(missing, []);
});

test('an empty note flags every declared section as missing', () => {
  const { missing } = checkSectionCoverage('', psychEvalLike);
  assert.deepEqual(missing, psychEvalLike.sections);
});

test('a null/undefined note is handled the same as empty, not a throw', () => {
  assert.doesNotThrow(() => checkSectionCoverage(undefined, psychEvalLike));
  const { missing } = checkSectionCoverage(null, psychEvalLike);
  assert.equal(missing.length, psychEvalLike.sections.length);
});

test('describeMissingSections: no message when nothing is missing', () => {
  assert.equal(describeMissingSections([]), '');
});

test('describeMissingSections: singular phrasing for exactly one missing section', () => {
  const msg = describeMissingSections(['Risk Assessment']);
  assert.match(msg, /"Risk Assessment"/);
  assert.doesNotMatch(msg, /sections:/); // plural form shouldn't leak in
});

test('describeMissingSections: plural phrasing lists all missing sections', () => {
  const msg = describeMissingSections(['Risk Assessment', 'Plan']);
  assert.match(msg, /2 sections/);
  assert.match(msg, /Risk Assessment/);
  assert.match(msg, /Plan/);
});

test('describeMissingSections never uses developer jargon (plain language for clinicians)', () => {
  const msg = describeMissingSections(['Risk Assessment']);
  const lower = msg.toLowerCase();
  assert.ok(!lower.includes('coverage'));
  assert.ok(!lower.includes('template'));
  assert.ok(!lower.includes('null'));
});
