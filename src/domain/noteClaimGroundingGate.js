// Note claim-grounding gate — advisory only, heuristic tier (no extra LLM
// call). Flags numeric clinical values in the generated note (vitals,
// dosages, measurements) that don't appear to have any matching value
// anywhere in the source transcript.
//
// This exists for the highest-impact finding in the compliance audit
// report: "No output-side check for hallucinated/unsupported clinical
// claims in AI-generated notes." A fluent but fabricated value (an invented
// exam finding, a dose that was never mentioned) currently passes every
// existing gate (noteQualityGate.js, transcriptionQualityGate.js,
// sectionCoverage.js) — all three check STRUCTURE (did the note truncate,
// refuse, cover the right sections, come from a confident transcription),
// never CONTENT accuracy.
//
// Deliberately scoped to stay a grounding check, not a fact-checker or
// clinical judgment: this module never evaluates whether a value is
// plausible, correct, or clinically sound — only whether it has an obvious
// textual match in what was actually said. Doing more than that would risk
// this becoming a decision-support feature in its own right, which is
// exactly the FDA SaMD/CDS boundary the compliance audit report's area 16
// discusses — the human clinician reviewing and attesting to the note is
// what keeps Tahlk outside that classification, and this check exists to
// make that review more effective, not to substitute for it. It NEVER
// blocks generation, editing, or signing — mirrors every other gate in this
// codebase (see noteQualityGate.js's own module doc for the same principle
// stated there).
//
// Known, accepted limitations (false positives AND false negatives are
// both expected — see the module docs on the existing gates for why that's
// an intentional tradeoff for an advisory-only heuristic):
//   - Only covers SIMPLE spoken numbers (ones 0-20, tens 20-90, and a
//     simple "tens [ones]" pair, e.g. "fifty five"). Compound spoken forms
//     clinicians commonly use for readings — "one twenty over eighty" for
//     a blood pressure of 120/80 — are NOT parsed and will false-positive.
//     A hand-rolled general spoken-number parser is a real rabbit hole;
//     under-flagging here was chosen over shipping a fragile one.
//   - A value the model correctly extracted but the transcript mis-heard
//     (or a legitimate unit conversion, e.g. transcript says "a hundred and
//     ten pounds" and the note writes "50 kg") will still false-positive.
//   - Matches on digit value only, not clinical meaning — a note claiming
//     "BP 120/80" when the transcript only mentions "120" in an unrelated
//     context (e.g. a room number) would false-negative. This is a
//     deliberately loose, cheap check, not clinical NLP.

// word -> digit value, covering the range vitals/dosages/measurements
// realistically fall in. Deliberately NOT attempting "twelve hundred" or
// higher compound forms — see the module doc's known-limitations note.
const ONES = {
  zero: 0, one: 1, two: 2, three: 3, four: 4, five: 5, six: 6, seven: 7,
  eight: 8, nine: 9, ten: 10, eleven: 11, twelve: 12, thirteen: 13,
  fourteen: 14, fifteen: 15, sixteen: 16, seventeen: 17, eighteen: 18,
  nineteen: 19,
};
const TENS = {
  twenty: 20, thirty: 30, forty: 40, fifty: 50, sixty: 60, seventy: 70,
  eighty: 80, ninety: 90,
};

// Extracts every number this module can recognize from free text — both
// literal digits already present, and simple spoken-number words converted
// to their digit value. Returns a Set of digit strings for O(1) lookup.
function extractNumbers(text) {
  const found = new Set();
  const digitMatches = (text || '').match(/\d+(?:\.\d+)?/g) || [];
  for (const d of digitMatches) found.add(d);

  const words = (text || '').toLowerCase().split(/[^a-z]+/).filter(Boolean);
  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    if (w in TENS) {
      const next = words[i + 1];
      if (next && next in ONES && ONES[next] < 10) {
        // "fifty five" -> 55. Only fold in a following ones-word below ten
        // so "fifty eleven" (not a real number) can't produce garbage.
        found.add(String(TENS[w] + ONES[next]));
        i++; // consume the ones-word too
      } else {
        found.add(String(TENS[w]));
      }
    } else if (w in ONES) {
      found.add(String(ONES[w]));
    }
  }
  return found;
}

// Clinical-value keywords that gate which numbers in the NOTE are even
// considered — deliberately keyword-anchored rather than checking every
// number in the note, so dates, section numbering, and template
// boilerplate don't drown out the actually risky claims (mirrors
// noteQualityGate.js's REFUSAL_PATTERNS being anchored to the note's start
// for the same false-positive-avoidance reason).
//
// Two patterns, not one, because clinical shorthand puts the unit on
// EITHER side of the number depending on what's being described:
//   * label-then-value: "BP 120/80", "HR 72", "Temp 103.2" — vitals are
//     conventionally written label-first.
//   * value-then-unit: "200mg", "5 lb", "10 kg" — dosages and many
//     measurements are conventionally written value-first. A regex that
//     only handled the first ordering would silently never even look at
//     the second, which is exactly as risky as not checking at all.
const LABEL_THEN_VALUE = /\b(bp|blood pressure|hr|heart rate|pulse|temp(?:erature)?|weight|wt|height|ht|o2 ?sat|spo2|oxygen saturation|resp(?:iratory rate)?|dose|dosage)\b[^\n.]{0,40}?(\d+(?:\.\d+)?(?:\s*\/\s*\d+(?:\.\d+)?)?)/gi;
const VALUE_THEN_UNIT = /(\d+(?:\.\d+)?)\s*(mg|mcg|ml|units?|lbs?|pounds?|kg)\b/gi;

function extractClinicalValueClaims(noteText) {
  const claims = [];

  const labelRe = new RegExp(LABEL_THEN_VALUE.source, LABEL_THEN_VALUE.flags);
  let m;
  while ((m = labelRe.exec(noteText)) !== null) {
    // A blood-pressure-shaped "120/80" is two separate claims, one per side.
    for (const piece of m[2].split('/')) {
      const value = piece.trim();
      if (value) claims.push({ value, context: m[0].trim() });
    }
  }

  const unitRe = new RegExp(VALUE_THEN_UNIT.source, VALUE_THEN_UNIT.flags);
  while ((m = unitRe.exec(noteText)) !== null) {
    claims.push({ value: m[1], context: m[0].trim() });
  }

  return claims;
}

/// Returns { ok, issues } — issues: Array<{ type: 'unsupported_value', detail }>.
export function checkClaimGrounding(noteText, transcript) {
  const note = (noteText || '').trim();
  const source = (transcript || '').trim();
  if (!note || !source) return { ok: true, issues: [] }; // nothing to compare against

  const transcriptNumbers = extractNumbers(source);
  const claims = extractClinicalValueClaims(note);

  const seen = new Set();
  const issues = [];
  for (const claim of claims) {
    if (transcriptNumbers.has(claim.value)) continue;
    const key = `${claim.value}::${claim.context}`;
    if (seen.has(key)) continue;
    seen.add(key);
    issues.push({
      type: 'unsupported_value',
      detail: `"${claim.context}" — this value doesn't appear in the transcript.`,
    });
  }
  return { ok: issues.length === 0, issues };
}

// Plain-language summary, same contract as noteQualityGate's
// describeQualityIssues (no trailing call-to-action, so callers can combine
// with other advisories and append one shared suffix).
export function describeGroundingIssues(issues) {
  if (!issues || issues.length === 0) return '';
  if (issues.length === 1) {
    return `A value in the note doesn't match the transcript: ${issues[0].detail}`;
  }
  return `${issues.length} values in the note don't appear to match the transcript. ${issues.map(i => i.detail).join(' ')}`;
}

export function groundingIssuesCallToAction(issues) {
  if (!issues || issues.length === 0) return '';
  return ' Double-check these values against your own recollection before signing.';
}
