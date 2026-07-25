// Unit tests for the provider-jurisdiction module (domain/jurisdictions.js) —
// the single source of truth for US states and the state-specific legal
// classifications the app keys off (findings S1/S4/S5).

import { test } from 'node:test';
import assert from 'node:assert/strict';

const {
  US_STATES,
  isValidState,
  stateName,
  ALL_PARTY_CONSENT_STATES,
  requiresAllPartyConsent,
} = await import('../../src/domain/jurisdictions.js');

test('US_STATES covers all 50 states plus DC with no duplicates', () => {
  assert.equal(US_STATES.length, 51, 'expected 50 states + DC');
  const codes = US_STATES.map(s => s.value);
  assert.equal(new Set(codes).size, 51, 'state codes must be unique');
  assert.ok(codes.includes('DC'), 'DC must be present');
});

test('every state code is a 2-letter uppercase value with a non-empty label', () => {
  for (const { value, label } of US_STATES) {
    assert.match(value, /^[A-Z]{2}$/, `${value} should be 2 uppercase letters`);
    assert.ok(label && label.length > 0, `${value} must have a label`);
  }
});

test('isValidState accepts known codes and rejects everything else', () => {
  assert.equal(isValidState('CA'), true);
  assert.equal(isValidState('DC'), true);
  assert.equal(isValidState('ZZ'), false);
  assert.equal(isValidState('ca'), false, 'lowercase is not a stored value');
  assert.equal(isValidState(''), false);
  assert.equal(isValidState(null), false);
  assert.equal(isValidState(undefined), false);
});

test('stateName maps codes to names and fails safe', () => {
  assert.equal(stateName('WA'), 'Washington');
  assert.equal(stateName(''), '', 'empty stays empty, never "undefined"');
  assert.equal(stateName('ZZ'), 'ZZ', 'unknown code falls back to the code itself');
});

test('requiresAllPartyConsent is true for all-party states, false for one-party', () => {
  // Spot-check a few well-established all-party states.
  for (const s of ['CA', 'FL', 'IL', 'PA', 'WA']) {
    assert.equal(requiresAllPartyConsent(s), true, `${s} should require all-party consent`);
    assert.ok(ALL_PARTY_CONSENT_STATES.has(s));
  }
  // Spot-check clearly one-party states.
  for (const s of ['NY', 'TX', 'CO', 'AZ']) {
    assert.equal(requiresAllPartyConsent(s), false, `${s} is one-party`);
  }
});

test('requiresAllPartyConsent fails SAFE (true) for unknown/empty state', () => {
  // When we do not know where the provider practices, prompt for the stronger
  // consent rather than assuming the permissive one-party rule.
  assert.equal(requiresAllPartyConsent(''), true);
  assert.equal(requiresAllPartyConsent('ZZ'), true);
  assert.equal(requiresAllPartyConsent(null), true);
});
