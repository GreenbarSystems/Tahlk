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
//!      can't leak, every string is length-capped so an unbounded upstream
//!      (a giant error, an attacker-influenced path) can't blow up a log line,
//!      and long hex runs (DEK/KEK/HMAC key material is 64 hex chars) are
//!      redacted so a value that carried a raw key — e.g. a rusqlite error that
//!      echoed a `KEY "x'<hex>'"` clause — can't survive into the log even if a
//!      call site forgot to discard it. This last guard is the value-level
//!      second layer behind the name-level CI grep, which cannot follow a
//!      variable's value.
//!
//! This mirrors `telemetry.js`'s allowlist philosophy (bounded, capped strings
//! only). The char-boundary-safe truncation below was originally derived from
//! `whisper::redact_whisper_stderr`; that function now calls [`cap_len`] instead
//! of keeping its own copy, so this module is the single owner of the policy.

/// Max chars any redacted value may contribute to a log line. The one cap for
/// the whole crate — `whisper::redact_whisper_stderr` routes through
/// [`cap_len`] rather than defining its own, so this is one number, one policy.
const MAX_CHARS: usize = 200;

/// Minimum length of a contiguous hex run that [`scrub_hex_secrets`] treats as
/// key material. The DEK/KEK and every HMAC-SHA256 key/tag serialize to 64 hex
/// chars; a bare (hyphen-less) UUID is 32. Setting the floor at 48 catches the
/// 64-char secrets while leaving 32-char identifiers legible for debugging.
const HEX_SECRET_MIN: usize = 48;

/// Replace any contiguous run of ≥ [`HEX_SECRET_MIN`] ASCII hex digits with a
/// `[redacted]` marker. This is a *value-level* backstop: even when a call site
/// forgets the generic-error discipline and hands `cap_len` a string that
/// embedded a raw `x'<DEK>'` key clause, the 64-hex run is stripped before it
/// can reach the log file. Hex digits are all ASCII, so run detection is
/// byte-safe; non-hex bytes (including multi-byte UTF-8) are copied verbatim.
pub(crate) fn scrub_hex_secrets(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut run = String::new();
    for c in s.chars() {
        if c.is_ascii_hexdigit() {
            run.push(c);
            continue;
        }
        if run.len() >= HEX_SECRET_MIN {
            out.push_str("[redacted]");
        } else {
            out.push_str(&run);
        }
        run.clear();
        out.push(c);
    }
    if run.len() >= HEX_SECRET_MIN {
        out.push_str("[redacted]");
    } else {
        out.push_str(&run);
    }
    out
}

/// Truncate `s` to [`MAX_CHARS`] characters, appending an ellipsis if it was
/// cut. Char-based (not byte-based) so a multi-byte UTF-8 code point at the
/// boundary is never split mid-sequence. Long hex runs are redacted first (see
/// [`scrub_hex_secrets`]), then newlines are flattened to spaces so a value
/// can't inject extra log lines.
pub(crate) fn cap_len(s: &str) -> String {
    let flattened = scrub_hex_secrets(s).replace(['\n', '\r'], " ");
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
    // the MAX_CHARS cap (mirrors redact_whisper_stderr). Uses a NON-hex fill
    // ('z') so this exercises truncation in isolation — an all-hex fill would be
    // collapsed by scrub_hex_secrets first (see the dedicated tests below).
    #[test]
    fn cap_len_truncates_oversized_with_ellipsis() {
        let out = cap_len(&"z".repeat(500));
        assert_eq!(out.chars().count(), MAX_CHARS + 1); // 200 + ellipsis
        assert!(out.ends_with('\u{2026}'));
    }

    // A 64-hex DEK-shaped run embedded in an error string is redacted, and the
    // surrounding non-secret context is preserved — the value-level backstop.
    #[test]
    fn cap_len_redacts_embedded_hex_key() {
        let dek = "a".repeat(64); // 64 hex chars, DEK-shaped
        let msg = format!("attach failed near KEY \"x'{dek}'\": disk full");
        let out = cap_len(&msg);
        assert!(!out.contains(&dek), "the raw hex key must not survive");
        assert!(out.contains("[redacted]"));
        assert!(out.contains("disk full"), "non-secret context is kept");
    }

    // A hyphen-less UUID (32 hex) stays legible — below the HEX_SECRET_MIN floor
    // — so ordinary identifiers remain debuggable.
    #[test]
    fn scrub_leaves_short_hex_ids_legible() {
        let uuid = "0123456789abcdef0123456789abcdef"; // 32 hex
        assert_eq!(scrub_hex_secrets(uuid), uuid);
        // A canonical hyphenated UUID is never a long contiguous run.
        let hy = "0123abcd-89ab-cdef-0123-456789abcdef";
        assert_eq!(scrub_hex_secrets(hy), hy);
    }

    // Exactly at the floor redacts; one below does not.
    #[test]
    fn scrub_respects_the_floor_boundary() {
        assert_eq!(scrub_hex_secrets(&"f".repeat(HEX_SECRET_MIN)), "[redacted]");
        let just_under = "f".repeat(HEX_SECRET_MIN - 1);
        assert_eq!(scrub_hex_secrets(&just_under), just_under);
    }

    // Multiple runs and a trailing run are each handled.
    #[test]
    fn scrub_handles_multiple_and_trailing_runs() {
        let a = "a".repeat(64);
        let b = "b".repeat(50);
        let out = scrub_hex_secrets(&format!("{a} middle {b}"));
        assert_eq!(out, "[redacted] middle [redacted]");
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
