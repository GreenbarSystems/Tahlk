// Transcription confidence/duration sanity check - advisory only, heuristic
// tier (Finding #2 of the drift-monitoring review).
//
// whisper.cpp's plain --output-txt path discards every piece of
// per-segment metadata the model computed during inference, so nothing
// downstream had any signal that a transcript might be unreliable. Whisper
// is documented to hallucinate fluent-sounding text during silence, noise,
// or cross-talk rather than fail loudly - the resulting transcript reads
// perfectly well while being substantively wrong, and generate_note trusts
// the transcript as ground truth by design (that's the whole point of the
// prompt-injection hardening: treat it as DATA, never suspect it). So a
// bad transcript silently becomes a bad note with zero warning anywhere in
// the pipeline.
//
// whisper.rs's transcribe_audio now also emits whisper.cpp's -ojf
// (output-json-full) JSON alongside the existing .txt, and derives a
// TranscriptionQuality summary from its per-token probabilities (see the
// Rust-side doc comment in whisper.rs for why this must be DERIVED -
// whisper.cpp's own CLI does not expose segment- or transcript-level
// confidence directly, only per-token `p`). This module turns that Rust
// summary into a plain-language warning, mirroring noteQualityGate.js's
// shape and philosophy exactly:
//
//   1. Low overall confidence: the transcript's average token probability
//      is low across the board - a systemic signal (bad mic, heavy
//      background noise/cross-talk) rather than one bad moment.
//   2. Abnormal words-per-minute: the transcript's implied speech rate is
//      far outside a normal conversational range in EITHER direction - too
//      fast suggests a garbled/duplicated transcription, too slow suggests
//      a transcript that's mostly filler/hallucinated padding relative to
//      the audio's real duration.
//   3. Hallucination-signature segments: the Rust side already flags
//      sustained (>=3s) low-confidence stretches that still produced fluent
//      text - whisper.cpp's classic "confidently wrong during silence"
//      failure mode. Any non-zero count here is itself the finding; no
//      further JS-side thresholding needed since Rust already applied the
//      duration + confidence + non-blank-text conditions.
//
// Never blocks the transcript from being used, edited, or fed into note
// generation - the provider is always the final human attestor, matching
// every other advisory check in this codebase (sectionCoverage.js,
// noteQualityGate.js, llmAuditDrift.js).

// Below this average token probability across the WHOLE transcript, flag
// it as systemically low-confidence. Deliberately looser than a per-segment
// threshold would need to be - a transcript-wide average smooths out
// normal per-word variance, so a low value here means a broad, sustained
// problem, not one mumbled word.
const LOW_OVERALL_CONFIDENCE_THRESHOLD = 0.55;

// Normal conversational English speech is commonly cited in the ~110-170
// WPM range; clinical encounters (patients pausing, providers speaking
// deliberately) run a bit slower on average. These bounds are deliberately
// wide - the point is to catch a transcript that's wildly outside any
// plausible speech rate (a strong signal of garbling, duplication, or
// padding), not to second-guess a slightly fast or slow talker.
const MIN_PLAUSIBLE_WPM = 50;
const MAX_PLAUSIBLE_WPM = 250;

// `quality`'s fields come straight off the wire from Rust's
// `TranscriptionQuality` struct (see whisper.rs). That struct itself has NO
// `#[serde(rename_all = "camelCase")]` attribute - only the OUTER wrapper
// (`TranscriptionResult`, which just has `transcript`/`quality`) does, and
// that attribute does not propagate into nested structs. So `quality`'s own
// fields serialize exactly as Rust wrote them: snake_case -
// `avg_confidence`, `low_confidence_segment_count`, `duration_secs`,
// `words_per_minute`. Verified directly against whisper.rs's struct
// definitions rather than assumed.

function looksLowConfidence(quality) {
  if (!quality || quality.avg_confidence == null) return false;
  return quality.avg_confidence < LOW_OVERALL_CONFIDENCE_THRESHOLD;
}

function looksAbnormalPace(quality) {
  if (!quality || quality.words_per_minute == null) return false;
  return quality.words_per_minute < MIN_PLAUSIBLE_WPM || quality.words_per_minute > MAX_PLAUSIBLE_WPM;
}

function hasHallucinationSignature(quality) {
  if (!quality) return false;
  return (quality.low_confidence_segment_count ?? 0) > 0;
}

// Runs all heuristic checks and returns a plain result object:
//   { ok: boolean, issues: Array<{ type, detail }> }
// `type` is one of 'low_confidence' | 'abnormal_pace' | 'possible_hallucination'.
//
// `quality` being null/undefined (whisper.cpp's JSON sidecar output was
// missing, malformed, or a version mismatch changed its schema) means "no
// signal available" - this always returns ok:true in that case. A missing
// ADVISORY signal must never itself look like a warning; that would train
// providers to distrust a routine, healthy transcription just because the
// bonus metadata didn't come through.
export function checkTranscriptionQuality(quality) {
  const issues = [];
  if (!quality) return { ok: true, issues };

  if (looksLowConfidence(quality)) {
    issues.push({
      type: 'low_confidence',
      detail: 'This transcription has unusually low confidence overall - background noise or a weak mic signal may have affected it.',
    });
  }

  if (looksAbnormalPace(quality)) {
    issues.push({
      type: 'abnormal_pace',
      detail: "The transcript's speech rate looks unusual for the length of the recording - it may be garbled or incomplete.",
    });
  }

  if (hasHallucinationSignature(quality)) {
    issues.push({
      type: 'possible_hallucination',
      detail: 'Part of this transcript may not reflect what was actually said - a stretch of audio produced text with unusually low confidence.',
    });
  }

  return { ok: issues.length === 0, issues };
}

// Plain-language summary for a toast/banner. Same contract as
// noteQualityGate.js's describeQualityIssues: returns only the detail
// sentence(s), no trailing call-to-action, so callers can combine this with
// other advisories under one shared suffix without duplicating text.
export function describeTranscriptionQualityIssues(issues) {
  if (!issues || issues.length === 0) return '';
  return issues.map(i => i.detail).join(' ');
}

// The suffix a caller should append after describeTranscriptionQualityIssues
// when showing it standalone. Unlike noteQualityGate's refusal case, there
// is no "regenerate" action for a transcript - the recommended action is
// always to double-check the transcript text against the recording before
// trusting it for note generation.
export function transcriptionQualityCallToAction(issues) {
  if (!issues || issues.length === 0) return '';
  return ' Double-check the transcript before generating the note.';
}
