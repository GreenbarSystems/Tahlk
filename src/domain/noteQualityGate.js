// Note-generation quality gate — advisory only, heuristic tier (no extra
// LLM call, near-zero cost).
//
// The pipeline validates TRANSPORT integrity exhaustively (BAA gate,
// prompt-injection hardening, SSE frame parsing, byte caps, error-code
// mapping — see notes.rs) but validates ZERO content quality before the
// note is handed back to the provider. `checkSectionCoverage`
// (domain/sectionCoverage.js) already closes one gap — missing template
// sections — but three more identified in the review are not covered by
// that check and are covered here instead:
//
//   1. Truncation: the note doesn't end with terminal punctuation, which is
//      the cheapest signal that a stream ended mid-sentence. NOTE: Rust's
//      `generate_note` (notes.rs) does not currently capture Anthropic's own
//      `stop_reason` field (message_delta events are silently ignored by the
//      `_ => {}` catch-all in the SSE loop) — that field would be a much
//      more reliable truncation signal than this text heuristic, since a
//      note can legitimately end without a period (e.g. a bulleted Plan
//      list) while still being a clean `stop_reason: "end_turn"` completion.
//      Surfacing `stop_reason` through to JS is a real, separate
//      improvement or Finding worth 5-10 minutes of Rust work — this
//      module's truncation heuristic is a stopgap for today's JS-only
//      constraint, deliberately biased toward NOT flagging normal
//      list/bullet endings (see TERMINAL_OK_ENDINGS below) to keep false
//      positives low until that stronger signal exists.
//   2. Refusal/boilerplate detection: the model returned a meta-commentary
//      refusal ("I cannot provide medical advice...") instead of a note.
//   3. Length-ratio sanity: a note wildly short relative to the transcript
//      it was generated from (a 20-minute session producing two sentences).
//      Templates like soap-generic.json explicitly instruct the model to
//      write "Not documented this visit" for genuinely empty sections, so a
//      short TRANSCRIPT legitimately produces a short note — the ratio
//      check compares against transcript length, not an absolute floor, to
//      avoid false-flagging a short-but-real visit.
//
// Never blocks generation, editing, or signing — mirrors sectionCoverage.js
// and the rest of this codebase's advisory-only philosophy (the provider is
// always the final human attestor).

// A note ending in one of these is a normal, clean completion even without
// terminal sentence punctuation — bulleted/numbered Plan items, a
// "Not documented this visit" boilerplate line, or a closing parenthetical
// are all common and must not be mistaken for truncation.
const NON_TRUNCATED_ENDING_PATTERNS = [
  /[.!?]['")\]]?\s*$/, // ends with terminal punctuation (optionally inside a quote/paren)
  /not (documented|addressed) this visit\.?\s*$/i,
  /:\s*$/, // ends with a colon (a section header with nothing after it, e.g. mid-template padding)
];

// A note commonly ends with a bulleted/numbered list item (Plan lists are
// the most common case, e.g. "- Follow-up in two weeks") that has no
// trailing sentence punctuation by normal writing convention — that is a
// clean, complete ending, not a sign of truncation. Checked against the
// LAST NON-BLANK LINE only, since only the very end of the note matters for
// a truncation signal.
//
// A bare-text heuristic cannot reliably distinguish a genuinely complete
// short list item ("- NPO", "- Follow-up in two weeks") from one truncated
// mid-word ("- Restart sertraline 50mg da") — attempting a stricter
// last-word check was tried and reverted after it false-flagged legitimate
// endings like "...visit in" as cut off. Given this module's own stated
// principle that false positives erode trust more than false negatives,
// list items are exempted from the truncation check entirely. The
// considerably more reliable fix — capturing Anthropic's own `stop_reason`
// field in notes.rs (currently discarded by the SSE loop's `_ => {}`
// catch-all) — is the right place to close this specific gap; see the
// module doc comment above.
const LIST_ITEM_LINE = /^\s*(?:[-*\u2022]|\d+[.)])\s+\S/;

function lastNonBlankLine(text) {
  const lines = text.split('\n').map(l => l.trim()).filter(Boolean);
  return lines.length ? lines[lines.length - 1] : '';
}

function looksTruncated(noteText) {
  const trimmed = (noteText || '').trim();
  if (!trimmed) return false; // empty note is its own, separate problem — not "truncation"
  if (LIST_ITEM_LINE.test(lastNonBlankLine(trimmed))) return false;
  return !NON_TRUNCATED_ENDING_PATTERNS.some(re => re.test(trimmed));
}

// Phrases characteristic of the model declining to produce clinical content
// at all, rather than actually generating a note. Deliberately anchored to
// the START of the trimmed note (a refusal is what the model opens with —
// matching this phrase anywhere in a genuine, lengthy clinical note risks
// false positives, e.g. a legitimate note documenting a patient who said
// "I cannot provide informed consent"). Matching only the first ~200 chars
// keeps this cheap and targeted at the actual failure mode described in the
// review: the model producing a short refusal INSTEAD OF a note.
const REFUSAL_PATTERNS = [
  /^i (cannot|can't|won't|will not|am (not able|unable)) (provide|generate|create|write|assist|help)/i,
  /^i'?m (not able|unable) to (provide|generate|create|write|assist|help)/i,
  /^as an ai\b/i,
  /^i don'?t have (enough|sufficient) (information|context) to/i,
  /^i apologize,? but i (cannot|can't|am unable)/i,
];

function looksLikeRefusal(noteText) {
  const head = (noteText || '').trim().slice(0, 220);
  if (!head) return false;
  return REFUSAL_PATTERNS.some(re => re.test(head));
}

// A note shorter than this fraction of the transcript is flagged as
// "suspiciously short" — but only once the transcript itself clears a
// minimum length, so a genuinely brief visit (a 90-second med check) never
// trips this on an already-short, legitimately-short note. The ratio is
// deliberately loose (clinical notes condense a transcript significantly by
// design — that's the whole point of a SOAP note) so this only fires on a
// real outlier, not routine summarization.
const MIN_TRANSCRIPT_LENGTH_FOR_RATIO_CHECK = 600; // ~90-120 seconds of speech
const MIN_NOTE_TO_TRANSCRIPT_RATIO = 0.03; // note at least 3% of transcript length

function looksSuspiciouslyShort(noteText, transcript) {
  const noteLen = (noteText || '').trim().length;
  const transcriptLen = (transcript || '').trim().length;
  if (transcriptLen < MIN_TRANSCRIPT_LENGTH_FOR_RATIO_CHECK) return false;
  if (noteLen === 0) return false; // empty note is caught elsewhere; don't double-report
  return noteLen / transcriptLen < MIN_NOTE_TO_TRANSCRIPT_RATIO;
}

// Runs all heuristic checks and returns a plain result object:
//   { ok: boolean, issues: Array<{ type, detail }> }
// `type` is one of 'truncated' | 'refusal' | 'too_short' — callers can use
// this to vary styling/urgency (e.g. a refusal is more severe than a
// possibly-truncated bulleted list) without parsing message text.
export function checkNoteQuality(noteText, transcript) {
  const issues = [];
  const trimmed = (noteText || '').trim();

  if (!trimmed) {
    issues.push({ type: 'empty', detail: 'The note is empty.' });
    return { ok: false, issues };
  }

  if (looksLikeRefusal(trimmed)) {
    issues.push({ type: 'refusal', detail: 'The response looks like a refusal or disclaimer rather than a clinical note.' });
    // A refusal makes the other two checks moot/misleading (of course a
    // refusal is "short" and doesn't end in clinical punctuation) — return
    // early so the summary doesn't pile on redundant, confusing detail.
    return { ok: false, issues };
  }

  if (looksTruncated(trimmed)) {
    issues.push({ type: 'truncated', detail: 'The note may have been cut off before it finished.' });
  }

  if (looksSuspiciouslyShort(trimmed, transcript)) {
    issues.push({ type: 'too_short', detail: 'The note looks short relative to the length of the session.' });
  }

  return { ok: issues.length === 0, issues };
}

// Plain-language summary for a toast/banner — same S-UX-4 principle as
// sectionCoverage.js's describeMissingSections and integrityAlert.js's
// INTEGRITY_FAILURE_MESSAGE: no jargon, tells the provider what to do.
//
// Mirrors describeMissingSections' contract exactly: returns only the
// detail sentence(s), with NO trailing call-to-action suffix, so callers
// combining this with other advisories (e.g. missing-section warnings) can
// append a single shared suffix instead of getting one baked in here that
// would duplicate when concatenated. Use `qualityIssuesCallToAction` for the
// suffix when this is shown standalone.
export function describeQualityIssues(issues) {
  if (!issues || issues.length === 0) return '';
  return issues.map(i => i.detail).join(' ');
}

// The suffix a caller should append after describeQualityIssues() when
// showing it standalone (not combined with other advisories) — a refusal
// means there's no usable note to review, so it calls for regenerating
// rather than reviewing.
export function qualityIssuesCallToAction(issues) {
  if (!issues || issues.length === 0) return '';
  return issues.some(i => i.type === 'refusal')
    ? ' Regenerate the note before signing.'
    : ' Review before signing.';
}
