// LLM-audit drift monitor — the log already exists (llm_audit.rs /
// llm_audit_list), nothing has ever read it. Every note-generation call
// through Anthropic is recorded with outcome, byte counts, and latency, but
// each individual row looking fine in isolation ("outcome: ok") hides a
// pattern only visible in aggregate: a silent upstream model-behavior
// change, a capacity-driven latency regression, or a spike in a specific
// error code. This module is a periodic (not per-call) statistical check
// over the existing rows — no new LLM calls, purely arithmetic on data
// that's already being captured for §164.312(b) compliance and otherwise
// going completely unused.
//
// Advisory only: never blocks generation or any user action. Surfaces a
// plain-language banner/toast so a provider (or, longer-term, an operator
// report) has an early-warning signal instead of discovering a quality
// regression only after noticing several bad notes in a row.

import { invoke, isTauri } from '../platform/tauri.js';

// A recent window this small can't establish a meaningful baseline — flag
// too few data points as "not enough history" rather than computing noisy
// statistics from 2-3 rows and reporting false confidence.
const MIN_ROWS_FOR_BASELINE = 10;

// How many of the most recent rows count as "recent" vs. "baseline" (the
// window before that). E.g. with 40 rows: last 8 are "recent", the
// remaining 32 are "baseline". A recent window that's too large relative to
// the baseline would just be comparing a set to a mostly-overlapping
// superset of itself, diluting any real shift — so recent is capped at a
// fixed size rather than a proportion.
const RECENT_WINDOW = 8;

// A deviation must clear this many standard deviations from the baseline
// mean to be worth surfacing. 2 sigma catches a real shift while staying
// well clear of the noise a small local dataset naturally has run-to-run.
const SIGMA_THRESHOLD = 2;

// Minimum absolute error-rate increase (percentage points) worth surfacing
// on its own, even for outcomes with too little variance for a sigma test
// to be meaningful (e.g. baseline error rate of exactly 0%, where stddev is
// 0 and ANY error would technically be "infinite sigma").
const MIN_ERROR_RATE_DELTA = 0.25; // 25 percentage points

function mean(xs) {
  return xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : 0;
}

function stddev(xs, avg = mean(xs)) {
  if (xs.length < 2) return 0;
  const variance = xs.reduce((sum, x) => sum + (x - avg) ** 2, 0) / xs.length;
  return Math.sqrt(variance);
}

// Compares a numeric metric's recent window against the baseline window.
// Returns null if there isn't enough baseline variance to say anything
// meaningful (stddev of 0 with recent values matching it exactly), otherwise
// { metric, baselineMean, recentMean, sigmas, direction }.
function checkMetricDrift(metric, baselineValues, recentValues) {
  const baselineMean = mean(baselineValues);
  const baselineStd = stddev(baselineValues, baselineMean);
  const recentMean = mean(recentValues);

  if (baselineStd === 0) {
    // No variance in the baseline at all (e.g. every call took exactly the
    // same duration) — any recent difference is automatically "infinite
    // sigma" and not a meaningful ratio. Fall back to a plain percentage
    // change so a real shift (e.g. 800ms -> 2400ms, flat baseline) is still
    // caught without dividing by zero.
    if (baselineMean === 0) return null;
    const pctChange = Math.abs(recentMean - baselineMean) / baselineMean;
    if (pctChange < 0.5) return null; // require a large, unambiguous jump when there's no baseline noise to compare against
    return {
      metric,
      baselineMean,
      recentMean,
      sigmas: null,
      direction: recentMean > baselineMean ? 'up' : 'down',
    };
  }

  const sigmas = Math.abs(recentMean - baselineMean) / baselineStd;
  if (sigmas < SIGMA_THRESHOLD) return null;

  // The mean-shift test above is sensitive to a single outlier dragging a
  // small recent window's average past the threshold even though most of
  // the window is perfectly normal (a lone slow call among 7 fast ones).
  // Require a majority of the recent rows to themselves sit clearly away
  // from the baseline mean (>1 sigma each) before calling this a sustained
  // drift rather than one-off noise — this is what distinguishes "the last
  // several calls were all slow" (the failure scenario this feature exists
  // to catch) from "one call happened to be slow."
  const individuallyShifted = recentValues.filter(
    v => Math.abs(v - baselineMean) / baselineStd >= 1.5
  ).length;
  if (individuallyShifted < Math.ceil(recentValues.length / 2)) return null;

  return {
    metric,
    baselineMean,
    recentMean,
    sigmas,
    direction: recentMean > baselineMean ? 'up' : 'down',
  };
}

// Core analysis, pure and synchronous so it can be unit-tested against
// fixture rows without any Tauri/invoke dependency. `rows` is expected in
// the same shape `llm_audit_list` returns (most-recent-first: id DESC),
// i.e. rows[0] is the newest call.
export function analyzeLlmAuditDrift(rows) {
  const list = Array.isArray(rows) ? rows : [];

  if (list.length < MIN_ROWS_FOR_BASELINE) {
    return { ok: true, insufficientData: true, checked: list.length, findings: [] };
  }

  // rows are newest-first; recent = the most recent RECENT_WINDOW calls,
  // baseline = everything older than that in the fetched window.
  const recent = list.slice(0, RECENT_WINDOW);
  const baseline = list.slice(RECENT_WINDOW);

  if (baseline.length < MIN_ROWS_FOR_BASELINE - RECENT_WINDOW || baseline.length === 0) {
    return { ok: true, insufficientData: true, checked: list.length, findings: [] };
  }

  const findings = [];

  // Latency drift.
  const durationBaseline = baseline.map(r => r.durationMs).filter(Number.isFinite);
  const durationRecent = recent.map(r => r.durationMs).filter(Number.isFinite);
  if (durationBaseline.length >= 2 && durationRecent.length >= 1) {
    const drift = checkMetricDrift('duration_ms', durationBaseline, durationRecent);
    if (drift) findings.push(drift);
  }

  // Response-size drift (a silent truncation or a model producing terser
  // output than usual both show up here before anyone notices the notes
  // themselves look thinner).
  const bytesBaseline = baseline.map(r => r.responseBytes).filter(Number.isFinite);
  const bytesRecent = recent.map(r => r.responseBytes).filter(Number.isFinite);
  if (bytesBaseline.length >= 2 && bytesRecent.length >= 1) {
    const drift = checkMetricDrift('response_bytes', bytesBaseline, bytesRecent);
    if (drift) findings.push(drift);
  }

  // Error-rate drift — treated separately from the sigma test above since
  // outcome is categorical, not a continuous metric, and a baseline of all
  // "ok" (0% error, 0 stddev) is the single most common and most important
  // case to still be able to flag.
  const baselineErrorRate = baseline.filter(r => r.outcome !== 'ok').length / baseline.length;
  const recentErrorRate = recent.filter(r => r.outcome !== 'ok').length / recent.length;
  if (recentErrorRate - baselineErrorRate >= MIN_ERROR_RATE_DELTA) {
    findings.push({
      metric: 'error_rate',
      baselineMean: baselineErrorRate,
      recentMean: recentErrorRate,
      sigmas: null,
      direction: 'up',
    });
  }

  // Which specific error_code is driving the spike, if any — this is the
  // detail that turns "something got worse" into "this is probably an
  // upstream rate-limit change" or "this is probably an auth issue."
  if (recentErrorRate > 0) {
    const counts = {};
    for (const r of recent) {
      if (r.outcome !== 'ok' && r.errorCode) counts[r.errorCode] = (counts[r.errorCode] || 0) + 1;
    }
    const top = Object.entries(counts).sort((a, b) => b[1] - a[1])[0];
    if (top) {
      const errFinding = findings.find(f => f.metric === 'error_rate');
      if (errFinding) errFinding.topErrorCode = top[0];
    }
  }

  return { ok: findings.length === 0, insufficientData: false, checked: list.length, findings };
}

// Orchestrator: fetches recent llm_audit rows via the existing (already
// registered, previously unused from JS) Tauri command and runs the
// analysis. Non-Tauri dev/test contexts have no llm_audit table at all
// (it's SQLite-only, no KV fallback — this data was never mirrored to KV),
// so this simply reports insufficientData rather than throwing.
export async function checkLlmAuditDrift({ limit = 100 } = {}) {
  if (!isTauri) {
    return { ok: true, insufficientData: true, checked: 0, findings: [] };
  }
  const rows = await invoke('llm_audit_list', { limit });
  return analyzeLlmAuditDrift(rows);
}

// Plain-language summary for a toast/banner (S-UX-4 style: no "sigma",
// "baseline", or "stddev" — a clinician needs "something changed", not the
// statistics). Returns '' when there's nothing to report.
export function describeDrift(findings) {
  if (!findings || findings.length === 0) return '';

  const parts = findings.map(f => {
    if (f.metric === 'error_rate') {
      const pct = Math.round(f.recentMean * 100);
      const codeNote = f.topErrorCode ? ` (mostly "${f.topErrorCode}")` : '';
      return `note-generation calls have been failing more than usual (${pct}% of recent calls)${codeNote}`;
    }
    if (f.metric === 'duration_ms') {
      return f.direction === 'up'
        ? 'note generation has been noticeably slower than usual'
        : 'note generation has been noticeably faster than usual';
    }
    if (f.metric === 'response_bytes') {
      return f.direction === 'up'
        ? 'generated notes have been noticeably longer than usual'
        : 'generated notes have been noticeably shorter than usual';
    }
    return null;
  }).filter(Boolean);

  if (parts.length === 0) return '';
  return `Recently, ${parts.join(', and ')}. This may reflect a change on Anthropic's end — review recent notes a bit more closely.`;
}
