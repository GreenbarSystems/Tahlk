//! Local Whisper.cpp transcription via the bundled sidecar.
//!
//! The .txt output path is derived from the caller-supplied `audio_path`,
//! so `transcribe_audio` canonicalizes both the audio file and the app's
//! audio directory and rejects anything that escapes the directory. Without
//! that check, an arbitrary read/write anywhere on disk would be possible
//! through the WebView.

use std::path::{Path, PathBuf};
use tauri::{AppHandle, Manager};
use tauri_plugin_shell::ShellExt;

use crate::errors::AppError;

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
struct TxtCleanup(PathBuf);

impl Drop for TxtCleanup {
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
// Same RAII shape and rationale as TxtCleanup: `Drop` runs on the success
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

#[tauri::command]
pub(crate) async fn transcribe_audio(app: AppHandle, audio_path: String) -> Result<String, AppError> {
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

    tokio::fs::write(&temp_wav, &plaintext).await.map_err(AppError::storage_from)?;
    // Guard registered immediately after the write so any early return past
    // this point still unlinks the plaintext scratch file. [at-rest audio]
    let _wav_cleanup = WavCleanup(temp_wav.clone());
    // Defense-in-depth: clamp the transient plaintext to owner-only 0600 for
    // the brief window it exists (same treatment as the encrypted file and the
    // .txt scratch). No-op on Windows.
    crate::perms::chmod_0600_unix(&temp_wav);

    let output_base = temp_wav_str.trim_end_matches(".wav").to_string();

    let output = app
        .shell()
        .sidecar("whisper-cpp")
        .map_err(AppError::internal_from)?
        .args([
            "-m", &model.to_string_lossy(),
            "-f", &temp_wav_str,
            "--output-txt",
            "--output-file", &output_base,
            "--language", "en",
            "--no-prints",
        ])
        .output()
        .await
        .map_err(AppError::internal_from)?;

    // Register cleanup BEFORE checking `output.status`: the sidecar may have
    // written the `.txt` even when it exits non-zero (partial transcription,
    // then a post-write assertion). The RAII guard means every return path
    // — including `.await?`-style early exits below — unlinks the file.
    // [audit M3]
    let txt_path = format!("{}.txt", output_base);
    let _cleanup = TxtCleanup(PathBuf::from(&txt_path));

    if !output.status.success() {
        let raw = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::Transcription(redact_whisper_stderr(&raw)));
    }

    // Tighten permissions on the scratch file before we read it. Even though
    // the RAII guard above ensures deletion on the way out, the file has to
    // exist for the duration of the read — during that window it lives at
    // whatever mode the sidecar wrote it with. Clamp to 0600 (M1).
    crate::perms::chmod_0600_unix(Path::new(&txt_path));

    let transcript = tokio::fs::read_to_string(&txt_path)
        .await
        .map_err(AppError::storage_from)?;
    Ok(transcript.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    // TxtCleanup drops the underlying file on scope exit. Verifies M3's
    // guarantee that the scratch file cannot leak past an early return.
    #[test]
    fn txt_cleanup_removes_file_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scratch.txt");
        std::fs::write(&path, "transcript").unwrap();
        assert!(path.exists());
        {
            let _g = TxtCleanup(path.clone());
        } // Drop runs here.
        assert!(!path.exists(), "TxtCleanup should have removed the file");
    }

    // Cleanup must not panic when the file was never written (e.g. sidecar
    // never produced output). Matches the sidecar-failed-early scenario.
    #[test]
    fn txt_cleanup_ignores_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("never_existed.txt");
        let _g = TxtCleanup(path.clone()); // dropped at end of test
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
