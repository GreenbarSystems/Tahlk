// Unit tests for the LLM-audit drift monitor (domain/llmAuditDrift.js).
//
// llm_audit.rs captures per-call metadata (duration, response size, outcome)
// for every note-generation call, purely for §164.312(b) compliance — until
// this feature, nothing ever READ that table. This tests the pure
// statistical analysis (analyzeLlmAuditDrift) against fixture rows shaped
// exactly like llm_audit_list's real return shape (camelCase fields,
// newest-first ordering), plus the plain-language summary (describeDrift).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeLlmAuditDrift, describeDrift } from '../../src/domain/llmAuditDrift.js';

// Builds `count` rows, newest-first (row[0] is most recent), matching the
// shape llm_audit_list actually returns. `overrides(i)` lets a test vary
// fields by recency index (0 = most recent).
function buildRows(count, overrides = () => ({})) {
  const rows = [];
  for (let i = 0; i < count; i++) {
    rows.push({
      id: count - i,
      createdAt: `2026-07-04T14:${String(22 - i).padStart(2, '0')}:00Z`,
      encounterId: `enc-${count - i}`,
      providerId: 'jane@example.com',
      model: 'claude-haiku-4-5-20251001',
      endpoint: 'https://api.anthropic.com/v1/messages',
      requestBytes: 4096,
      responseBytes: 2048,
      upstreamReqid: `req_${count - i}`,
      outcome: 'ok',
      errorCode: null,
      durationMs: 800,
      ...overrides(i),
    });
  }
  return rows;
}

test('fewer rows than the baseline minimum reports insufficientData, not a false verdict', () => {
  const rows = buildRows(5);
  const result = analyzeLlmAuditDrift(rows);
  assert.equal(result.insufficientData, true);
  assert.equal(result.checked, 5);
  assert.deepEqual(result.findings, []);
});

test('a stable history with no variance reports ok with zero findings', () => {
  const rows = buildRows(40); // all identical duration/bytes/outcome
  const result = analyzeLlmAuditDrift(rows);
  assert.equal(result.insufficientData, false);
  assert.equal(result.ok, true);
  assert.deepEqual(result.findings, []);
});

// The core failure scenario from the review finding: "the last 5 calls all
// took 3x longer than baseline" — a latency regression that would otherwise
// hide inside individually-fine "outcome: ok" rows.
test('detects a recent latency spike against a stable baseline', () => {
  const rows = buildRows(40, i => {
    // Baseline (older rows, indices 8-39): duration jitters 750-850ms.
    // Recent (indices 0-7): a sustained spike to ~2400ms (3x).
    if (i < 8) return { durationMs: 2400 + (i % 3) * 10 };
    return { durationMs: 750 + (i % 5) * 20 };
  });
  const result = analyzeLlmAuditDrift(rows);
  assert.equal(result.ok, false);
  const finding = result.findings.find(f => f.metric === 'duration_ms');
  assert.ok(finding, 'expected a duration_ms finding');
  assert.equal(finding.direction, 'up');
  assert.ok(finding.recentMean > finding.baselineMean * 2);
});

test('detects a recent error-rate spike from an all-ok baseline', () => {
  const rows = buildRows(40, i => {
    // Recent 8 calls: 5 of them fail with rate_limited. Baseline: all ok.
    if (i < 5) return { outcome: 'rate_limited', errorCode: 'rate_limited' };
    return {};
  });
  const result = analyzeLlmAuditDrift(rows);
  assert.equal(result.ok, false);
  const finding = result.findings.find(f => f.metric === 'error_rate');
  assert.ok(finding, 'expected an error_rate finding');
  assert.equal(finding.topErrorCode, 'rate_limited');
  assert.ok(finding.recentMean > finding.baselineMean);
});

// A model producing suspiciously terse output is itself a content-quality
// signal (per the review finding: a truncated/hedged completion) that shows
// up as a response_bytes shift before anyone reads the actual notes.
test('detects a recent drop in response size (possible truncation/hedging)', () => {
  const rows = buildRows(40, i => {
    if (i < 8) return { responseBytes: 200 + (i % 3) * 5 }; // recent: much shorter
    return { responseBytes: 2048 + (i % 5) * 30 }; // baseline: normal length
  });
  const result = analyzeLlmAuditDrift(rows);
  assert.equal(result.ok, false);
  const finding = result.findings.find(f => f.metric === 'response_bytes');
  assert.ok(finding, 'expected a response_bytes finding');
  assert.equal(finding.direction, 'down');
});

// A single slow call, or a couple of failures scattered through otherwise
// normal history, must NOT trip the detector — this is meant to catch a
// sustained shift, not react to routine call-to-call noise (a single retry
// after a transient network blip is normal and must not alarm the user).
test('a single isolated slow call within an otherwise stable baseline is not flagged', () => {
  // Realistic irregular jitter (not a repeating pattern) so the baseline's
  // own natural variance isn't artificially tight — a periodic modulo
  // pattern understates how noisy real latency data is and would make even
  // normal recent values look like outliers against an unrealistically
  // narrow baseline.
  const jitter = [10, -15, 5, 30, -20, 0, 15, -5, 25, -10, 20, -25, 8, -12, 18];
  const rows = buildRows(40, i => {
    if (i === 0) return { durationMs: 1600 }; // one call, 2x baseline, but alone
    return { durationMs: 800 + jitter[i % jitter.length] };
  });
  const result = analyzeLlmAuditDrift(rows);
  assert.equal(result.ok, true);
  assert.deepEqual(result.findings, []);
});

test('a single isolated failure amid a healthy recent window is not flagged', () => {
  const rows = buildRows(40, i => {
    if (i === 3) return { outcome: 'network', errorCode: 'network' };
    return {};
  });
  const result = analyzeLlmAuditDrift(rows);
  assert.equal(result.ok, true);
});

test('rows with missing/non-finite duration are excluded from the metric, not crashing the analysis', () => {
  const rows = buildRows(40, i => {
    if (i === 0) return { durationMs: null };
    if (i < 8) return { durationMs: 2400 };
    return { durationMs: 800 };
  });
  assert.doesNotThrow(() => analyzeLlmAuditDrift(rows));
  const result = analyzeLlmAuditDrift(rows);
  assert.equal(result.ok, false); // the other 7 recent rows still carry the signal
});

test('non-array input is handled gracefully as zero rows', () => {
  assert.doesNotThrow(() => analyzeLlmAuditDrift(undefined));
  assert.doesNotThrow(() => analyzeLlmAuditDrift(null));
  const result = analyzeLlmAuditDrift(null);
  assert.equal(result.insufficientData, true);
  assert.equal(result.checked, 0);
});

// describeDrift — plain language, no statistics jargon (same S-UX-4
// principle already established for integrityAlert.js's toast copy).

test('describeDrift returns empty string for no findings', () => {
  assert.equal(describeDrift([]), '');
  assert.equal(describeDrift(undefined), '');
});

test('describeDrift avoids statistics jargon like sigma/stddev/baseline', () => {
  const msg = describeDrift([{ metric: 'duration_ms', direction: 'up', baselineMean: 800, recentMean: 2400, sigmas: 5 }]);
  const lower = msg.toLowerCase();
  assert.ok(!lower.includes('sigma'));
  assert.ok(!lower.includes('stddev'));
  assert.ok(!lower.includes('baseline'));
  assert.match(msg, /slower/);
});

test('describeDrift names the dominant error code for an error-rate finding', () => {
  const msg = describeDrift([{ metric: 'error_rate', baselineMean: 0, recentMean: 0.5, sigmas: null, topErrorCode: 'auth_failed' }]);
  assert.match(msg, /auth_failed/);
  assert.match(msg, /50%/);
});

test('describeDrift joins multiple simultaneous findings into one readable sentence', () => {
  const msg = describeDrift([
    { metric: 'duration_ms', direction: 'up', baselineMean: 800, recentMean: 2000 },
    { metric: 'response_bytes', direction: 'down', baselineMean: 2000, recentMean: 300 },
  ]);
  assert.match(msg, /slower/);
  assert.match(msg, /shorter/);
});
