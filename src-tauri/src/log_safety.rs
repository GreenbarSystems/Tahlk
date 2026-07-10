//! Log redaction helpers — defense in depth for the app log file.
//!
//! `tauri_plugin_log` writes to the OS standard log directory, which lives
//! OUTSIDE `app_data_dir()` and therefore outside this app's encryption and
//! 0600-permission boundary. Anything handed to a `log::` macro can end up as
//! plaintext on disk that an ordinary local read could pick up. Two guardrails
//! defend against a future contributor accidentally leaking data through it:
//!
//!   1. A CI grep (see `.github/workflows/ci.yml`) statically rejects `log::`
//!      lines that interpolate obviously-PHI-named variables — a blunt regex
//!      backstop.
//!   2. These helpers, applied at the current call sites, bound what any single
//!      value can disclose: filenames are path-stripped so a full on-disk layout
//!      can't leak, and every string is length-capped so an unbounded upstream
//!      (a giant error, an attacker-influenced path) can't blow up a log line.
//!
//! This mirrors `telemetry.js`'s allowlist philosophy (bounded, capped strings
//! only) and copies `whisper::redact_whisper_stderr`'s char-boundary-safe
//! truncation technique verbatim so multi-byte UTF-8 can never panic a cap.

/// Max chars any redacted value may contribute to a log line. Matches
/// `redact_whisper_stderr`'s cap exactly — one number, one policy.
const MAX_CHARS: usize = 200;

/// Truncate `s` to [`MAX_CHARS`] characters, appending an ellipsis if it was
/// cut. Char-based (not byte-based) so a multi-byte UTF-8 code point at the
/// boundary is never split mid-sequence — copied from
/// `whisper::redact_whisper_stderr`. Newlines are flattened to spaces so a
/// value can't inject extra log lines.
pub(crate) fn cap_len(s: &str) -> String {
    let flattened = s.replace(['\n', '\r'], " ");
    if flattened.chars().count() <= MAX_CHARS {
        flattened
    } else {
        let mut out: String = flattened.chars().take(MAX_CHARS).collect();
        out.push('\u{2026}');
        out
    }
}

/// Reduce a filesystem path to just its final component before capping. A value
/// like `/Users/alice/Library/.../audio/enc-abc.wav` or `../../etc/passwd`
/// collapses to `enc-abc.wav` / `passwd`, so a logged filename can't disclose
/// the full on-disk layout even if a caller passes a whole path. Splits on BOTH
/// `/` and `\` regardless of the host OS: a path string can be produced on one
/// platform and end up in a log inspected on another, and `std::path` only
/// recognizes the native separator. Falls back to the capped raw string when
/// there is no final component (empty, or a trailing-separator path).
pub(crate) fn redact_filename(name: &str) -> String {
    let stripped = name.rsplit(['/', '\\']).find(|s| !s.is_empty()).unwrap_or(name);
    cap_len(stripped)
}

#[cfg(test)]
mod tests {
    use super::*;

    // (a) A normal filename passes through recognizably — the common case must
    // not be mangled.
    #[test]
    fn redact_filename_passes_normal_name_through() {
        assert_eq!(redact_filename("enc-l9k3a-x7q2.wav"), "enc-l9k3a-x7q2.wav");
        assert_eq!(redact_filename("enc-1.wav.enc"), "enc-1.wav.enc");
    }

    // (b) Absolute paths and traversal are stripped to the final component, so a
    // logged value can't disclose the app's on-disk layout or escape upward.
    #[test]
    fn redact_filename_strips_paths_and_traversal() {
        assert_eq!(
            redact_filename("/Users/alice/Library/Application Support/com.tahlk.app/audio/enc-9.wav"),
            "enc-9.wav"
        );
        assert_eq!(redact_filename("../../../../etc/passwd"), "passwd");
        assert_eq!(redact_filename("C:\\Users\\bob\\audio\\enc-3.wav.enc"), "enc-3.wav.enc");
    }

    // (c) An oversized string is truncated with the ellipsis marker, at exactly
    // the MAX_CHARS cap (mirrors redact_whisper_stderr).
    #[test]
    fn cap_len_truncates_oversized_with_ellipsis() {
        let out = cap_len(&"a".repeat(500));
        assert_eq!(out.chars().count(), MAX_CHARS + 1); // 200 + ellipsis
        assert!(out.ends_with('\u{2026}'));
    }

    // Multi-byte UTF-8 at the boundary must not panic — the exact hazard the
    // char-based (not byte-based) truncation defends against.
    #[test]
    fn cap_len_handles_multibyte_utf8() {
        let out = cap_len(&"🚀".repeat(300)); // 4 bytes each
        assert!(out.chars().count() <= MAX_CHARS + 1);
        assert!(out.ends_with('\u{2026}'));
    }

    // Short input under the cap is returned unchanged (no stray ellipsis).
    #[test]
    fn cap_len_leaves_short_input_untouched() {
        assert_eq!(cap_len("audio at-rest migration: disk full"), "audio at-rest migration: disk full");
    }

    // Newlines are flattened so a value can't forge additional log lines.
    #[test]
    fn cap_len_flattens_newlines() {
        assert_eq!(cap_len("line one\nloglevel=ERROR forged"), "line one loglevel=ERROR forged");
        assert!(!cap_len("a\r\nb").contains('\n'));
    }

    // A path whose final component is itself normal survives redaction; an empty
    // string falls back safely without panicking.
    #[test]
    fn redact_filename_handles_edge_cases() {
        assert_eq!(redact_filename(""), "");
        assert_eq!(redact_filename("bare.wav"), "bare.wav");
    }
}
