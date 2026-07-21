// A provider stopped by a rule must be told which rule.
//
// Rust used AppError::InvalidInput for two unrelated things: genuine frontend
// invariant violations (path traversal, missing field) and provider-facing
// preconditions (litigation hold, signed-note immutability). userMessage
// deliberately swallows invalid_input — correctly, since its text is
// meaningless to a clinician — so the second group was swallowed too. A
// provider blocked by a legal hold saw "Delete failed: unknown error": the app
// knew exactly why and declined to say.
//
// precondition_failed is the second group. Its message is written for a
// clinician and is shown verbatim.

import { test } from 'node:test';
import assert from 'node:assert/strict';

const { userMessage, fromInvoke, AppError } = await import('../../src/platform/appError.js');

test('a precondition message reaches the provider verbatim', () => {
  const err = { code: 'precondition_failed', message: 'Litigation hold is active — encounter records cannot be deleted until the hold is lifted.' };
  assert.equal(
    userMessage(err, 'Delete failed.'),
    'Litigation hold is active — encounter records cannot be deleted until the hold is lifted.',
  );
});

test('a frontend-invariant violation is still swallowed', () => {
  // invalid_input text names internals ("kv secret namespace", "path
  // traversal") and would only confuse a clinician. The fallback stands.
  const err = { code: 'invalid_input', message: 'encounter.id is required and must be a non-empty string' };
  assert.equal(userMessage(err, 'Could not save.'), 'Could not save.');
});

test('a precondition with no usable message falls back rather than showing a code', () => {
  assert.equal(
    userMessage({ code: 'precondition_failed', message: 'precondition_failed' }, 'Action refused.'),
    'Action refused.',
  );
});

test('fromInvoke preserves the new code so callers can branch on it', () => {
  const e = fromInvoke({ code: 'precondition_failed', message: 'This note is signed and locked.' });
  assert.ok(e instanceof AppError);
  assert.equal(e.code, 'precondition_failed');
  assert.equal(e.message, 'This note is signed and locked.');
});
