//! Shared unkeyed hashing helper.
//!
//! `sha256_hex` previously existed as three byte-identical private copies in
//! `encounters.rs`, `note_audit.rs`, and `note_history.rs` (maintainability
//! finding M1). This is its single home now, so a future change to the digest
//! or its encoding happens once rather than drifting across three security-
//! critical modules. Keyed helpers (HKDF-derived MAC key, HMAC) live in
//! `audit_mac.rs`; this module is only the unkeyed content hash used for the
//! audit hash chains (`entry_hash`) and for blinding `encounter_id` on
//! destruction.

/// SHA-256 of `data`, as a 64-char lowercase-hex string.
///
/// Byte-for-byte identical to JS's `sha256Hex` in `contentHash.js` for the same
/// input bytes — required so an `entry_hash` computed by the Rust server-side
/// commands verifies under the JS `verifyHistoryChain` / `verifyAuditChain`.
pub(crate) fn sha256_hex(data: &[u8]) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, data);
    crate::hex::to_hex(d.as_ref())
}

/// The sign-off content hash — the SHA-256 that binds a provider's signature to
/// the exact transcript + note text at sign time (audit finding #7).
///
/// Byte-for-byte identical to JS's `computeNoteHash` in `contentHash.js`:
/// `sha256Hex(JSON.stringify({ encounterId, signedBy, transcript, noteContent }))`,
/// with the fields in that fixed insertion order. This lets Rust **derive** the
/// hash from the content it already stores instead of trusting a client-supplied
/// value. The byte-exactness against `JSON.stringify` — control chars escaped,
/// non-ASCII emitted as UTF-8, `/` and `<>&` left unescaped — is pinned by
/// `sign_content_hash_matches_js_goldens` below, which checks digests produced
/// by the real JS function across ASCII / escape / unicode / control-char inputs.
pub(crate) fn sign_content_hash(
    encounter_id: &str,
    signed_by: &str,
    transcript: &str,
    note_content: &str,
) -> String {
    // Field order and JSON key names mirror the JS object literal exactly.
    #[derive(serde::Serialize)]
    struct Payload<'a> {
        #[serde(rename = "encounterId")]
        encounter_id: &'a str,
        #[serde(rename = "signedBy")]
        signed_by: &'a str,
        transcript: &'a str,
        #[serde(rename = "noteContent")]
        note_content: &'a str,
    }
    // Serializing this fixed struct cannot fail, so `unwrap_or_default` is
    // unreachable in practice (and a default "" would only ever mis-hash, never
    // panic).
    let json = serde_json::to_string(&Payload {
        encounter_id,
        signed_by,
        transcript,
        note_content,
    })
    .unwrap_or_default();
    sha256_hex(json.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_known_empty_string_vector() {
        // SHA-256("") — a fixed test vector pins the digest + hex encoding.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn output_is_64_char_lowercase_hex() {
        let h = sha256_hex(b"tahlk");
        assert_eq!(h.len(), 64);
        assert!(h.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    }

    // Byte-exactness gate for the server-side sign hash (finding #7): the digests
    // in this fixture were produced by the REAL JS `computeNoteHash`
    // (contentHash.js), so if serde_json's escaping ever diverges from
    // JSON.stringify for any input class the assert fails. Regenerate the
    // fixture from JS (never hand-edit it) if the canonicalization intentionally
    // changes on BOTH sides.
    #[test]
    fn sign_content_hash_matches_js_goldens() {
        let raw = include_str!("../assets/sign_hash_goldens.json");
        let cases: Vec<serde_json::Value> = serde_json::from_str(raw).unwrap();
        assert!(cases.len() >= 5, "fixture should cover several input classes");
        for c in &cases {
            let got = sign_content_hash(
                c["encounterId"].as_str().unwrap(),
                c["signedBy"].as_str().unwrap(),
                c["transcript"].as_str().unwrap(),
                c["noteContent"].as_str().unwrap(),
            );
            assert_eq!(
                got,
                c["hash"].as_str().unwrap(),
                "Rust sign_content_hash diverged from JS computeNoteHash for case {}",
                c["name"]
            );
        }
    }
}
