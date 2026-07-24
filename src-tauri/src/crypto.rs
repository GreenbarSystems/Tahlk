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
}
