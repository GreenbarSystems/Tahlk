//! Local Whisper.cpp transcription via the bundled sidecar.
//!
//! The .txt output path is derived from the caller-supplied `audio_path`,
//! so `transcribe_audio` canonicalizes both the audio file and the app's
//! audio directory and rejects anything that escapes the directory. Without
//! that check, an arbitrary read/write anywhere on disk would be possible
//! through the WebView.

use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};
use tauri_plugin_shell::ShellExt;

use crate::errors::AppError;

// --- Transcription quality signal (Finding #2) ---------------------------
//
// whisper.cpp's plain `--output-txt` path (the only one used before this
// change) discards every piece of per-segment metadata the model actually
// computed during inference — there is no confidence signal, no timing
// data, nothing downstream can use to notice a fluent-but-wrong transcript.
// Whisper is documented to hallucinate plausible-sounding text during
// silence/noise/cross-talk rather than fail loudly, so a garbled transcript
// looks identical to a good one to every later stage (including
// `generate_note`, which by design trusts the transcript as ground truth).
//
// Fix: also pass `--output-json-full` (`-ojf`) alongside the existing
// `--output-txt`. Both write from the SAME inference pass — whisper.cpp
// computes segments/tokens once and just serializes to two files — so this
// adds no extra inference cost, only a second, tiny file read. `-ojf`
// (rather than plain `-oj`/`--output-json`) is required because whisper.cpp
// only emits per-token data (including the token probability field `p`)
// when the "full" variant is requested; without it the JSON has no
// confidence signal at all, defeating the point.
//
// IMPORTANT — this is whisper.cpp's OWN JSON schema, not the OpenAI
// Python/API `verbose_json` schema. whisper.cpp does NOT emit
// `avg_logprob` / `no_speech_prob` / `compression_ratio` per segment (those
// are OpenAI-Whisper-specific fields from a different codebase). The only
// per-item confidence whisper.cpp's CLI exposes is a per-TOKEN probability
// `p` (0.0-1.0) inside `transcription[i].tokens[j].p`, present only under
// `-ojf`. Segment- and transcript-level confidence must be derived here by
// averaging token `p` values — whisper.cpp does not hand that number to us
// directly. Verified against `ggml-org/whisper.cpp` `examples/cli/cli.cpp`
// (the CLI this app's `SETUP.md` pins to v1.9.1) — see `output_json` for
// the exact field names below.

#[derive(Debug, Deserialize)]
struct WhisperJsonOutput {
    transcription: Vec<WhisperJsonSegment>,
}

#[derive(Debug, Deserialize)]
struct WhisperJsonSegment {
    offsets: WhisperJsonOffsets,
    text: String,
    #[serde(default)]
    tokens: Vec<WhisperJsonToken>,
}

#[derive(Debug, Deserialize)]
struct WhisperJsonOffsets {
    from: i64,
    to: i64,
}

#[derive(Debug, Deserialize)]
struct WhisperJsonToken {
    p: f32,
}

// Metadata surfaced alongside the transcript. Deliberately advisory-only —
// mirrors the rest of this codebase's philosophy (see noteQualityGate.js,
// sectionCoverage.js): the provider is always the final human attestor, so
// this is signal for them to act on, never something that blocks or alters
// the transcript itself.
#[derive(Debug, Serialize, Clone, PartialEq)]
pub(crate) struct TranscriptionQuality {
    // Mean of every token's `p` across the whole transcript. `None` when
    // the JSON sidecar output is missing/unparseable/empty — callers must
    // treat that as "no signal available," not "confidence is zero."
    pub(crate) avg_confidence: Option<f32>,
    // Segments whose own average token `p` falls under a low-confidence
    // threshold AND whose text is non-trivial (a long, low-confidence
    // segment is whisper.cpp's classic hallucination signature — it kept
    // producing fluent text despite not being sure of any of it).
    pub(crate) low_confidence_segment_count: u32,
    // Total wall-clock speech duration implied by the LAST segment's `to`
    // offset (whisper.cpp offsets are in centiseconds — hundredths of a
    // second — per `t0 * 10` / `t1 * 10` in its own source).
    pub(crate) duration_secs: Option<f32>,
    // Words per minute implied by (word count of the full transcript) /
    // (duration_secs). `None` whenever duration is unavailable or ~0 (a
    // near-instant/empty recording), since dividing by a near-zero duration
    // produces a meaningless, wildly large ratio rather than a real signal.
    pub(crate) words_per_minute: Option<f32>,
}

// A segment's own token `p` values averaged. Segments always have at least
// one token when whisper.cpp emits them with `-ojf`, but tolerate zero
// gracefully (returns None) rather than dividing by zero, since an empty
// `tokens` array is possible in principle (e.g. a segment covering total
// silence that still got an empty text node).
fn segment_avg_confidence(seg: &WhisperJsonSegment) -> Option<f32> {
    if seg.tokens.is_empty() {
        return None;
    }
    let sum: f32 = seg.tokens.iter().map(|t| t.p).sum();
    Some(sum / seg.tokens.len() as f32)
}

// A segment counts as "long" for hallucination-signature purposes once it
// spans more than this many centiseconds (3 seconds) — short low-confidence
// segments are common and unremarkable (a mumbled word, a brief overlap);
// it's a SUSTAINED low-confidence stretch that's the actual red flag the
// doc's review called out ("long silent/no-speech segments that whisper.cpp
// still emitted text for").
const LONG_SEGMENT_CENTISECONDS: i64 = 300;

// Below this average token probability, a segment is "low confidence."
// Chosen conservatively (many genuinely correct words score under 0.8 in
// normal fluent speech due to how the softmax spreads probability mass
// across plausible alternatives) — this threshold is deliberately loose to
// avoid false-flagging ordinary transcription, matching this codebase's
// stated principle elsewhere that false positives erode trust more than
// false negatives.
const LOW_CONFIDENCE_THRESHOLD: f32 = 0.5;

// Parse whisper.cpp's `-ojf` JSON output into the advisory quality summary.
// Extracted as a pure function (no I/O) so it's unit-testable against
// realistic fixture JSON without shelling out to a real whisper.cpp binary.
fn parse_quality_from_json(raw: &str) -> Option<TranscriptionQuality> {
    let parsed: WhisperJsonOutput = serde_json::from_str(raw).ok()?;
    if parsed.transcription.is_empty() {
        return Some(TranscriptionQuality {
            avg_confidence: None,
            low_confidence_segment_count: 0,
            duration_secs: Some(0.0),
            words_per_minute: None,
        });
    }

    let mut all_token_probs: Vec<f32> = Vec::new();
    let mut low_confidence_segment_count: u32 = 0;

    for seg in &parsed.transcription {
        all_token_probs.extend(seg.tokens.iter().map(|t| t.p));

        let span_centiseconds = seg.offsets.to - seg.offsets.from;
        let is_long = span_centiseconds >= LONG_SEGMENT_CENTISECONDS;
        let is_low_conf = segment_avg_confidence(seg)
            .map(|c| c < LOW_CONFIDENCE_THRESHOLD)
            .unwrap_or(false);
        // Non-trivial text guard: a segment whisper.cpp emitted as
        // essentially blank isn't a hallucination candidate even if long
        // and "low confidence" (few/no tokens to average in the first
        // place tends to produce a meaningless average).
        let has_text = !seg.text.trim().is_empty();
        if is_long && is_low_conf && has_text {
            low_confidence_segment_count += 1;
        }
    }

    let avg_confidence = if all_token_probs.is_empty() {
        None
    } else {
        Some(all_token_probs.iter().sum::<f32>() / all_token_probs.len() as f32)
    };

    // Duration from the last segment's end offset. whisper.cpp offsets are
    // centiseconds (t1 * 10 in its own source, where the internal ticks are
    // already 10ms units, so `offsets.to` is already in centiseconds).
    // Divide by 100.0 to get seconds.
    let last_to = parsed
        .transcription
        .last()
        .map(|s| s.offsets.to)
        .unwrap_or(0);
    let duration_secs = Some(last_to as f32 / 100.0);

    let full_text: String = parsed
        .transcription
        .iter()
        .map(|s| s.text.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    let word_count = full_text.split_whitespace().count();

    let words_per_minute = match duration_secs {
        Some(secs) if secs > 1.0 => Some(word_count as f32 / (secs / 60.0)),
        _ => None,
    };

    Some(TranscriptionQuality {
        avg_confidence,
        low_confidence_segment_count,
        duration_secs,
        words_per_minute,
    })
}

// RAII wrapper that deletes the wrapped path when it drops. The whisper.cpp
// sidecar writes its output to a `.txt` next to the audio file; if we return
// from `transcribe_audio` on any error path (bad UTF-8 in the file, disk
// unmount between write and read, etc.) without an explicit remove call, that
// scratch file leaks PHI onto the filesystem. `Drop` runs on the success
// path, error paths, and panic paths alike — unlike the previous `let _ =
// remove_file(...)` at the end which was skipped whenever the function
// returned early.
//
// Errors from `remove_file` are swallowed intentionally: there's nothing
// sensible to do at drop time, and the file may legitimately be gone if
// the sidecar never created it (bad model, empty audio). Best-effort.
// [audit M3]
struct ScratchFileCleanup(PathBuf);

impl Drop for ScratchFileCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

// Session audio lives on disk encrypted (`<id>.wav.enc`), but whisper.cpp only
// reads plaintext `.wav`. transcribe_audio decrypts to a transient plaintext
// `.wav` next to the encrypted file, points the sidecar at it, and MUST unlink
// it afterward — otherwise decrypting for transcription would silently leave
// plaintext PHI on disk, defeating the whole at-rest-encryption feature.
//
// Same RAII shape and rationale as ScratchFileCleanup: `Drop` runs on the success
// path, every error/early-return path, and panics alike. Errors from
// `remove_file` are swallowed intentionally — the file may already be gone
// (decrypt failed before write, disk unmount) and there is nothing sensible to
// do at drop time. [audit: at-rest audio]
struct WavCleanup(PathBuf);

impl Drop for WavCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

// Redact a whisper.cpp stderr blob for surfacing through `AppError` /
// telemetry. Raw stderr echoes absolute paths (appdata layout, home dir)
// and, in some failure modes, the model file name — not PHI, but a
// path-disclosure that helps a local attacker enumerate the app's on-disk
// layout. Keep the first non-empty line only, drop everything after the
// first `--` (a common whisper.cpp option-parsing echo separator), and cap
// at 200 chars so an unbounded upstream can't blow up the audit log.
// [audit M2]
//
// Extracted from `transcribe_audio` so the shape is unit-testable and future
// call sites (retry path, sync-side transcription) can reuse it.
fn redact_whisper_stderr(raw: &str) -> String {
    let first_line = raw
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("transcription failed");
    // Split on `--` (space-hyphen-hyphen); take the head so that an echoed
    // "invalid option: --output-txt \"...\"" doesn't drag the argv into logs.
    let head = first_line.split(" --").next().unwrap_or(first_line).trim();
    // Char-safe truncation: byte slicing can split a multi-byte UTF-8 code
    // point mid-sequence. 200 chars is well under any reasonable log line.
    const MAX_CHARS: usize = 200;
    if head.chars().count() <= MAX_CHARS {
        head.to_string()
    } else {
        let mut out: String = head.chars().take(MAX_CHARS).collect();
        out.push_str("…");
        out
    }
}

fn model_path(app: &AppHandle) -> Result<PathBuf, AppError> {
    app.path()
        .resource_dir()
        .map_err(AppError::internal_from)
        .map(|d| d.join("ggml-base.en.bin"))
}

// Return shape for `transcribe_audio`. Previously a bare `String` — widened
// to also carry the advisory `TranscriptionQuality` signal (Finding #2)
// alongside the transcript, without changing what the transcript text
// itself contains. `#[serde(rename_all = "camelCase")]` matches the JS side's
// convention (see noteQualityGate.js's camelCase exports) so the frontend
// reads `result.quality`/`result.transcript` without a snake_case bridge.
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TranscriptionResult {
    pub(crate) transcript: String,
    pub(crate) quality: Option<TranscriptionQuality>,
}

#[tauri::command]
pub(crate) async fn transcribe_audio(app: AppHandle, audio_path: String) -> Result<TranscriptionResult, AppError> {
    let model = model_path(&app)?;
    if !tokio::fs::try_exists(&model).await.unwrap_or(false) {
        return Err(AppError::NoModel);
    }

    // Confine transcription to the app's audio directory. The output .txt path is
    // derived from audio_path, so an unconstrained path would let the WebView
    // read an arbitrary file AND write a .txt next to it (arbitrary write).
    let audio_dir = app
        .path()
        .app_data_dir()
        .map_err(AppError::internal_from)?
        .join("audio");
    let canon = std::path::Path::new(&audio_path)
        .canonicalize()
        .map_err(|_| AppError::invalid("audio file not found"))?;
    let dir_canon = audio_dir.canonicalize().map_err(AppError::storage_from)?;
    if !canon.starts_with(&dir_canon) {
        return Err(AppError::invalid(
            "audio path is outside the session audio directory",
        ));
    }

    // Session audio is encrypted at rest (`<id>.wav.enc`). whisper.cpp can't
    // read ciphertext, so decrypt to a transient plaintext `.wav` inside the
    // (already containment-checked) audio directory. The WavCleanup guard
    // below unlinks it on EVERY exit path so plaintext PHI never lingers.
    let key = crate::audio_crypto::audio_key()?;
    let ciphertext = tokio::fs::read(&canon).await.map_err(AppError::storage_from)?;
    let plaintext = crate::audio_crypto::decrypt(&key, &ciphertext)?;

    // Unique temp name inside audio_dir so a decrypt can't collide with (or
    // have its cleanup clobber) a concurrent one. Random suffix from getrandom.
    let mut rand = [0u8; 8];
    getrandom::getrandom(&mut rand).map_err(AppError::internal_from)?;
    let suffix: String = rand.iter().map(|b| format!("{:02x}", b)).collect();
    let temp_wav = audio_dir.join(format!("transcribe-{}.wav", suffix));
    let temp_wav_str = temp_wav.to_string_lossy().into_owned();

    // L9: create the plaintext scratch file with mode 0600 from the first
    // syscall (crate::perms::write_0600_unix), instead of writing at the
    // default umask mode and narrowing permissions afterward. The
    // create-then-chmod pattern leaves a brief window — between file
    // creation and the chmod call — where this plaintext PHI-containing
    // audio is at whatever mode the process umask produced (typically
    // world/group-readable). Opening with O_CREAT + mode 0600 atomically
    // closes that window. No-op fallback to a plain write on Windows, where
    // Unix permission bits don't apply (NTFS ACLs are handled at the
    // app-data-dir level).
    crate::perms::write_0600_unix(&temp_wav, &plaintext)
        .await
        .map_err(AppError::storage_from)?;
    // Guard registered immediately after the write so any early return past
    // this point still unlinks the plaintext scratch file. [at-rest audio]
    let _wav_cleanup = WavCleanup(temp_wav.clone());

    let output_base = temp_wav_str.trim_end_matches(".wav").to_string();

    let output = app
        .shell()
        .sidecar("whisper-cpp")
        .map_err(AppError::internal_from)?
        .args([
            "-m", &model.to_string_lossy(),
            "-f", &temp_wav_str,
            "--output-txt",
            // Finding #2: also emit the full per-token JSON alongside the
            // existing .txt. Same inference pass, no extra decode cost —
            // whisper.cpp just serializes what it already computed to a
            // second file. `-ojf` (not plain `-oj`) is required to get
            // per-token `p` (confidence) data; see the module doc comment
            // above `TranscriptionQuality` for why.
            "--output-json-full",
            "--output-file", &output_base,
            "--language", "en",
            "--no-prints",
        ])
        .output()
        .await
        .map_err(AppError::internal_from)?;

    // Register cleanup BEFORE checking `output.status`: the sidecar may have
    // written the `.txt`/`.json` even when it exits non-zero (partial
    // transcription, then a post-write assertion). The RAII guard means
    // every return path — including `.await?`-style early exits below —
    // unlinks both files. [audit M3]
    let txt_path = format!("{}.txt", output_base);
    let _cleanup = ScratchFileCleanup(PathBuf::from(&txt_path));
    let json_path = format!("{}.json", output_base);
    let _json_cleanup = ScratchFileCleanup(PathBuf::from(&json_path));

    if !output.status.success() {
        let raw = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::Transcription(redact_whisper_stderr(&raw)));
    }

    // Tighten permissions on the scratch files before we read them. Even
    // though the RAII guards above ensure deletion on the way out, each
    // file has to exist for the duration of the read — during that window
    // it lives at whatever mode the sidecar wrote it with. Clamp to 0600
    // (M1). Applied to the JSON sidecar output too — it contains the same
    // PHI-derived transcript text as the .txt file, just with extra
    // structure, so it carries identical at-rest sensitivity.
    //
    // L9: unlike temp_wav above, these files are created by the whisper-cpp
    // sidecar process, not by us — we don't control the open()/create() call
    // that produces them, so there's no O_CREAT+mode syscall we can
    // substitute in. create-then-chmod is the best available option here;
    // the window is bounded to "until this line runs after the sidecar
    // exits," not indefinite.
    crate::perms::chmod_0600_unix(Path::new(&txt_path));
    crate::perms::chmod_0600_unix(Path::new(&json_path));

    let transcript = tokio::fs::read_to_string(&txt_path)
        .await
        .map_err(AppError::storage_from)?;

    // The JSON sidecar output is treated as best-effort/advisory only — if
    // it's missing, malformed, or fails to read for any reason, the
    // transcript itself (the actual clinical content) must still be
    // returned successfully. Losing a "nice to have" quality signal must
    // never fail the whole transcription. `quality: None` tells the JS
    // layer "no signal available," which it must treat as neutral, not as
    // a low-confidence flag.
    let quality = match tokio::fs::read_to_string(&json_path).await {
        Ok(raw) => parse_quality_from_json(&raw),
        Err(_) => None,
    };

    Ok(TranscriptionResult {
        transcript: transcript.trim().to_string(),
        quality,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- parse_quality_from_json tests (Finding #2) -----------------------
    //
    // Fixture JSON matches whisper.cpp's ACTUAL `-ojf` schema as verified
    // against `examples/cli/cli.cpp`'s `output_json` function — NOT the
    // OpenAI Python/API `verbose_json` schema, which uses different field
    // names (`avg_logprob`, `no_speech_prob`, etc.) that whisper.cpp's CLI
    // does not emit. Each segment has `offsets.from`/`offsets.to` in
    // centiseconds and, under `-ojf`, a `tokens` array where each token has
    // a `p` (probability) field.

    // A normal, confident, fluent transcript: high per-token `p`, no long
    // low-confidence stretches. Confirms the happy path produces a
    // reasonable avg_confidence and zero hallucination flags.
    #[test]
    fn parse_quality_normal_transcript() {
        let json = r#"{
            "transcription": [
                {
                    "offsets": { "from": 0, "to": 200 },
                    "text": " How have you been feeling this week?",
                    "tokens": [
                        { "text": " How", "p": 0.95 },
                        { "text": " have", "p": 0.93 },
                        { "text": " you", "p": 0.97 },
                        { "text": " been", "p": 0.91 }
                    ]
                },
                {
                    "offsets": { "from": 200, "to": 450 },
                    "text": " A bit better, sleeping more regularly.",
                    "tokens": [
                        { "text": " A", "p": 0.88 },
                        { "text": " bit", "p": 0.90 },
                        { "text": " better", "p": 0.85 }
                    ]
                }
            ]
        }"#;
        let q = parse_quality_from_json(json).expect("should parse");
        assert!(q.avg_confidence.unwrap() > 0.85, "expected high avg confidence, got {:?}", q.avg_confidence);
        assert_eq!(q.low_confidence_segment_count, 0);
        assert_eq!(q.duration_secs, Some(4.5)); // 450 centiseconds = 4.5s
        assert!(q.words_per_minute.is_some());
    }

    // The core hallucination-signature case the doc's review called out: a
    // long segment (>= 3s) with low average token probability AND non-empty
    // text — whisper.cpp confidently emitting fluent-sounding text despite
    // being unsure of nearly every token, the classic "hallucinated during
    // silence/noise" pattern.
    #[test]
    fn parse_quality_flags_long_low_confidence_segment_as_hallucination_signature() {
        let json = r#"{
            "transcription": [
                {
                    "offsets": { "from": 0, "to": 100 },
                    "text": " Normal confident speech here.",
                    "tokens": [
                        { "text": " Normal", "p": 0.94 },
                        { "text": " confident", "p": 0.92 }
                    ]
                },
                {
                    "offsets": { "from": 100, "to": 900 },
                    "text": " the the the you know um the the",
                    "tokens": [
                        { "text": " the", "p": 0.12 },
                        { "text": " the", "p": 0.08 },
                        { "text": " the", "p": 0.15 },
                        { "text": " you", "p": 0.10 },
                        { "text": " know", "p": 0.20 }
                    ]
                }
            ]
        }"#;
        let q = parse_quality_from_json(json).expect("should parse");
        assert_eq!(q.low_confidence_segment_count, 1, "the 8-second low-confidence segment should be flagged");
    }

    // A short low-confidence segment (under the 3-second threshold) must
    // NOT be flagged — a brief mumbled word or overlap is normal and
    // unremarkable; only SUSTAINED low confidence is the red flag. Guards
    // against over-eager flagging that would erode trust in the signal.
    #[test]
    fn parse_quality_does_not_flag_short_low_confidence_segment() {
        let json = r#"{
            "transcription": [
                {
                    "offsets": { "from": 0, "to": 80 },
                    "text": " mm hm",
                    "tokens": [
                        { "text": " mm", "p": 0.10 },
                        { "text": " hm", "p": 0.15 }
                    ]
                }
            ]
        }"#;
        let q = parse_quality_from_json(json).expect("should parse");
        assert_eq!(q.low_confidence_segment_count, 0, "an 0.8s segment is too short to be a hallucination signature");
    }

    // A long segment with LOW confidence but effectively BLANK text (e.g.
    // whisper.cpp emitted a near-empty string for a genuine silence gap)
    // must not be flagged — the hallucination signature specifically
    // requires fluent TEXT despite low confidence, not just "long and
    // uncertain," which describes ordinary detected silence too.
    #[test]
    fn parse_quality_does_not_flag_long_low_confidence_segment_with_blank_text() {
        let json = r#"{
            "transcription": [
                {
                    "offsets": { "from": 0, "to": 900 },
                    "text": "   ",
                    "tokens": [
                        { "text": " ", "p": 0.05 }
                    ]
                }
            ]
        }"#;
        let q = parse_quality_from_json(json).expect("should parse");
        assert_eq!(q.low_confidence_segment_count, 0, "blank text is not a hallucination candidate regardless of confidence");
    }

    // Malformed/garbage JSON (e.g. a truncated write, a whisper.cpp version
    // mismatch that changed the schema) must return None rather than
    // panicking or propagating an error — losing this advisory signal must
    // never break transcription itself.
    #[test]
    fn parse_quality_returns_none_on_malformed_json() {
        assert!(parse_quality_from_json("{ not valid json").is_none());
        assert!(parse_quality_from_json("").is_none());
        assert!(parse_quality_from_json("{}").is_none()); // missing required `transcription` key
    }

    // An empty `transcription` array (e.g. a silent recording whisper.cpp
    // correctly detected as having no speech at all) is a valid, parseable
    // result — distinct from malformed JSON — and must report "no signal"
    // rather than a misleading zero/default confidence.
    #[test]
    fn parse_quality_handles_empty_transcription_array() {
        let json = r#"{ "transcription": [] }"#;
        let q = parse_quality_from_json(json).expect("should parse");
        assert_eq!(q.avg_confidence, None);
        assert_eq!(q.low_confidence_segment_count, 0);
        assert_eq!(q.words_per_minute, None);
    }

    // words_per_minute must be None (not a wild/meaningless ratio) when the
    // implied duration is at or under the 1-second floor — dividing a word
    // count by a near-zero duration produces a huge, meaningless WPM figure
    // that would falsely look like a "garbled/rushed" flag.
    #[test]
    fn parse_quality_wpm_none_for_near_zero_duration() {
        let json = r#"{
            "transcription": [
                {
                    "offsets": { "from": 0, "to": 50 },
                    "text": " Hi.",
                    "tokens": [ { "text": " Hi", "p": 0.9 } ]
                }
            ]
        }"#;
        let q = parse_quality_from_json(json).expect("should parse");
        assert_eq!(q.words_per_minute, None, "0.5s duration is under the 1-second floor");
    }

    // A segment with a `tokens` array present but empty (allowed by
    // `#[serde(default)]`) must not panic on division by zero and must not
    // itself be counted as low-confidence (no data to average is not the
    // same as confirmed-low-confidence data).
    #[test]
    fn parse_quality_handles_segment_with_no_tokens() {
        let json = r#"{
            "transcription": [
                {
                    "offsets": { "from": 0, "to": 900 },
                    "text": " some long segment text with no token data"
                }
            ]
        }"#;
        let q = parse_quality_from_json(json).expect("should parse");
        assert_eq!(q.low_confidence_segment_count, 0);
        assert_eq!(q.avg_confidence, None, "no tokens anywhere means no confidence signal");
    }

    // Basic redaction: a multi-line stderr collapses to the first non-empty
    // line. Absolute paths that follow later lines never surface.
    #[test]
    fn redact_whisper_stderr_keeps_first_nonempty_line() {
        let raw = "\n\nerror: model load failed\n/Users/alice/Library/Application Support/tahlk/resources/ggml-base.en.bin\nadditional detail here";
        let out = redact_whisper_stderr(raw);
        assert_eq!(out, "error: model load failed");
    }

    // The `--` separator drops any argv echo that whisper.cpp appends when
    // it fails to parse options. Prevents leaking the model path via the
    // `-m /path/to/model` argument.
    #[test]
    fn redact_whisper_stderr_drops_argv_echo() {
        let raw = "invalid parameter --output-txt \"/private/var/whisper/output\"";
        let out = redact_whisper_stderr(raw);
        assert_eq!(out, "invalid parameter");
    }

    // Cap the redacted output at 200 chars. Unbounded upstream messages
    // must not blow up audit rows or log lines.
    #[test]
    fn redact_whisper_stderr_caps_length() {
        let raw = "a".repeat(500);
        let out = redact_whisper_stderr(&raw);
        // 200 chars + the ellipsis marker.
        assert_eq!(out.chars().count(), 201);
        assert!(out.ends_with('\u{2026}'));
    }

    // Empty / whitespace-only stderr should never produce an empty error
    // message — that confuses UI toasts and telemetry.
    #[test]
    fn redact_whisper_stderr_falls_back_on_empty_input() {
        assert_eq!(redact_whisper_stderr(""), "transcription failed");
        assert_eq!(redact_whisper_stderr("   \n\n  "), "transcription failed");
    }

    // Multi-byte UTF-8 must not panic under the char cap. A pathological
    // stderr with a run of 4-byte code points at the boundary would panic
    // under naive byte slicing; the char-based truncation keeps it safe.
    #[test]
    fn redact_whisper_stderr_handles_multibyte_utf8() {
        let raw = "🚀".repeat(300); // 300 rockets, 4 bytes each
        let out = redact_whisper_stderr(&raw);
        assert!(out.chars().count() <= 201, "expected ≤ 201 chars, got {}", out.chars().count());
    }

    // ScratchFileCleanup drops the underlying file on scope exit. Verifies M3's
    // guarantee that the scratch file cannot leak past an early return.
    #[test]
    fn scratch_file_cleanup_removes_file_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scratch.txt");
        std::fs::write(&path, "transcript").unwrap();
        assert!(path.exists());
        {
            let _g = ScratchFileCleanup(path.clone());
        } // Drop runs here.
        assert!(!path.exists(), "ScratchFileCleanup should have removed the file");
    }

    // Cleanup must not panic when the file was never written (e.g. sidecar
    // never produced output). Matches the sidecar-failed-early scenario.
    #[test]
    fn scratch_file_cleanup_ignores_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("never_existed.txt");
        let _g = ScratchFileCleanup(path.clone()); // dropped at end of test
        // No panic — test passes.
    }

    // WavCleanup unlinks the transient decrypted plaintext on scope exit —
    // the guarantee that decrypting for transcription can't leak plaintext PHI.
    #[test]
    fn wav_cleanup_removes_file_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transcribe-abcd.wav");
        std::fs::write(&path, b"decrypted pcm").unwrap();
        assert!(path.exists());
        {
            let _g = WavCleanup(path.clone());
        } // Drop runs here.
        assert!(!path.exists(), "WavCleanup should have removed the plaintext");
    }

    // Missing file must not panic — decrypt may fail before the temp write, so
    // the guard can outlive a never-created file.
    #[test]
    fn wav_cleanup_ignores_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("never_written.wav");
        let _g = WavCleanup(path.clone());
        // No panic — test passes.
    }

    // The whole point of RAII: the plaintext is unlinked even when the scope
    // exits via a panic (an error path in transcribe_audio unwinds through
    // Drop). Catch the unwind and assert the file is gone.
    #[test]
    fn wav_cleanup_removes_file_on_panic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transcribe-panic.wav");
        std::fs::write(&path, b"decrypted pcm").unwrap();
        let p = path.clone();
        let result = std::panic::catch_unwind(move || {
            let _g = WavCleanup(p);
            panic!("simulated error path after decrypt");
        });
        assert!(result.is_err(), "the closure should have panicked");
        assert!(!path.exists(), "WavCleanup must unlink even on panic unwind");
    }
}
