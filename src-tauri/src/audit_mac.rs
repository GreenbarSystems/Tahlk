//! Keyed MAC anchor for the tamper-evident audit chains.
//!
//! The `note_history` and `note_audit` chains are SHA-256 hash chains: each
//! row's `entry_hash` commits to its canonical payload and the prior row's
//! hash, so any EDIT to a stored row is detectable by recomputation
//! (`verifyHistoryChain` / `verifyAuditChain` in contentHash.js). But a hash
//! chain proves only INTERNAL CONSISTENCY, not AUTHENTICITY: an attacker who
//! can write the (decrypted) database can discard the real chain and author a
//! brand-new, internally-consistent one over fabricated content — every hash
//! recomputes correctly because the attacker computed them the same way the
//! app does. This is exactly what the adversarial test
//! `tests/js/test_privacy_chain_adversarial.mjs` ("wholesale-substitution")
//! documents as a known limit, and what the privacy audit flagged as the last
//! code-level residual on the sign-off attestation chain.
//!
//! This module closes that gap by adding a KEYED MAC over each row, chained:
//!
//! ```text
//!   chain_mac_i = HMAC-SHA256(K, entry_hash_i ‖ "\n" ‖ chain_mac_{i-1})
//! ```
//!
//! `K` is HKDF-SHA256-derived from the SQLCipher DEK with a domain-separating
//! `info` label — the SAME root of trust as `audio_crypto`'s audio key, held
//! only in the OS keychain (or the password-wrapped session DEK), never written
//! to the database and never handed to the WebView. An attacker who substitutes
//! or edits a chain cannot produce valid MACs without `K`, so [`verify_chain`]
//! detects the forgery. `entry_hash` is used as the MAC input (not the raw
//! payload) because it is a stable, collision-resistant commitment to the
//! payload that is PRESERVED across lawful `note_audit` scrubbing — so a scrubbed
//! (tombstoned) row still verifies, while a maliciously rewritten one does not.
//!
//! ## Scope
//!
//! Per-entry MACs defeat SUBSTITUTION and EDIT (authenticity) — the residual
//! High from the audit. Like any append chain, they do not by themselves detect
//! TRUNCATION of the newest entries (a MAC-valid prefix is still MAC-valid). On
//! this single-user local-first app that truncation residual is an ACCEPTED
//! RISK (see `AUDIT-RESIDUAL-RISK.md`): an external tip anchor was prototyped
//! and then removed as over-engineered for this deployment model, because the
//! only party who can truncate the decrypted database is the DEK holder — who
//! could equally re-forge any external anchor keyed off that same DEK.
//!
//! A NULL `chain_mac` is treated as legacy ONLY as an unbroken prefix; once any
//! anchored row is seen, a later NULL is reported as tamper (F2), so stripping
//! the MAC off a row — including the tail row, which has no following row to
//! catch it — cannot launder an edit past verification.

use ring::hkdf;
use ring::hmac;

use crate::errors::AppError;

/// Domain-separation label for HKDF. MUST stay distinct from
/// `audio_crypto::HKDF_INFO` (and any DB-key usage) so this MAC key is
/// cryptographically independent from the audio key and the SQLCipher key even
/// though all three descend from the same DEK. Changing this string would
/// orphan every already-written `chain_mac` (they'd re-derive under a different
/// key and fail verification) — treat it as a stable on-disk format constant.
const HKDF_INFO: &[u8] = b"tahlk-audit-chain-mac-key-v1";

/// DEK / derived-key length in bytes (256-bit).
const KEY_LEN: usize = 32;

/// Decode the 64-char lowercase-hex DEK into its 32 raw bytes. Mirrors
/// `audio_crypto::dek_hex_to_bytes`'s fixed-size, error-returning contract so a
/// wrong-length DEK is rejected loudly rather than silently truncated.
fn dek_hex_to_bytes(dek_hex: &str) -> Result<[u8; KEY_LEN], AppError> {
    let bytes = crate::hex::from_hex(dek_hex)
        .ok_or_else(|| AppError::internal_from("audit MAC key: DEK is not valid hex"))?;
    let arr: [u8; KEY_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| AppError::internal_from("audit MAC key: DEK is not 32 bytes"))?;
    Ok(arr)
}

/// Derive the raw 256-bit MAC key bytes from the DEK via HKDF-SHA256 with the
/// domain-separating [`HKDF_INFO`] label. Empty salt is fine: the DEK is a
/// full-entropy CSPRNG key, so HKDF-Extract's salt adds nothing (RFC 5869).
fn derive_mac_key_bytes(dek_hex: &str) -> Result<[u8; KEY_LEN], AppError> {
    let ikm = dek_hex_to_bytes(dek_hex)?;
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
    let prk = salt.extract(&ikm);
    let okm = prk
        .expand(&[HKDF_INFO], hkdf::HKDF_SHA256)
        .map_err(|_| AppError::internal_from("audit MAC key HKDF expand failed"))?;
    let mut key = [0u8; KEY_LEN];
    okm.fill(&mut key)
        .map_err(|_| AppError::internal_from("audit MAC key HKDF fill failed"))?;
    Ok(key)
}

/// Resolve the audit-MAC HMAC key. Source order matches `audio_crypto::audio_key`:
/// the unlocked session DEK once auth is configured, else the keychain DEK on a
/// not-yet-configured install. Errors if no DEK can be resolved (the caller
/// decides whether that is fatal — the append path treats it as best-effort;
/// the verify path treats it as an error).
pub(crate) fn mac_key() -> Result<hmac::Key, AppError> {
    let dek_hex = match crate::auth::session_dek_hex() {
        Some(hex) => hex,
        None => crate::db_key::load_or_generate_dek()?,
    };
    let bytes = derive_mac_key_bytes(&dek_hex)?;
    Ok(hmac::Key::new(hmac::HMAC_SHA256, &bytes))
}

/// Build the MAC input for one row: `entry_hash ‖ "\n" ‖ prev_mac`.
/// The newline is a fixed unambiguous separator; `entry_hash` is fixed-width
/// hex so there is no length-extension ambiguity between the two fields.
fn mac_input(entry_hash: &str, prev_mac: Option<&str>) -> Vec<u8> {
    let mut msg = Vec::with_capacity(entry_hash.len() + 1 + 64);
    msg.extend_from_slice(entry_hash.as_bytes());
    msg.push(b'\n');
    if let Some(p) = prev_mac {
        msg.extend_from_slice(p.as_bytes());
    }
    msg
}

/// Compute the chained MAC (lowercase hex) for a row, given its `entry_hash`
/// and the previous row's stored `chain_mac` (`None` for the genesis row or
/// when the predecessor is a legacy/unanchored row).
pub(crate) fn compute(key: &hmac::Key, entry_hash: &str, prev_mac: Option<&str>) -> String {
    let tag = hmac::sign(key, &mac_input(entry_hash, prev_mac));
    crate::hex::to_hex(tag.as_ref())
}

/// Best-effort compute used by the append paths: returns `None` (store a NULL
/// `chain_mac`) when the MAC key cannot be resolved, rather than failing the
/// clinical write. In normal operation (post-unlock) the key always resolves;
/// a NULL row is treated as legacy/unverifiable by [`verify_chain`], and —
/// crucially — cannot be exploited to forge a chain (see the module doc: a NULL
/// predecessor makes the following anchored row fail verification).
pub(crate) fn compute_best_effort(entry_hash: &str, prev_mac: Option<&str>) -> Option<String> {
    let key = mac_key().ok()?;
    Some(compute(&key, entry_hash, prev_mac))
}

/// Constant-time verification of one row's stored MAC.
fn verify_one(key: &hmac::Key, entry_hash: &str, prev_mac: Option<&str>, stored_mac: &str) -> bool {
    match crate::hex::from_hex(stored_mac) {
        Some(tag_bytes) => hmac::verify(key, &mac_input(entry_hash, prev_mac), &tag_bytes).is_ok(),
        None => false,
    }
}

/// Verdict from verifying one chain.
pub(crate) struct MacVerdict {
    pub ok: bool,
    /// `seq` of the first row that failed, if any.
    pub broken_at: Option<i64>,
    pub reason: Option<String>,
    /// Count of legacy (unanchored, NULL-`chain_mac`) rows skipped.
    pub legacy_skipped: i64,
}

/// Verify a seq-ordered chain of `(seq, entry_hash, stored_chain_mac)` rows.
///
/// Legacy rows (`stored_chain_mac == None`, written before this feature or when
/// the key was unavailable) are unverifiable and skipped; the running
/// `prev_mac` follows the STORED value (`None` for legacy) exactly as the append
/// path computed it, so the legacy→anchored transition verifies correctly.
pub(crate) fn verify_chain<'a>(
    key: &hmac::Key,
    rows: impl Iterator<Item = (i64, &'a str, Option<&'a str>)>,
) -> MacVerdict {
    let mut prev_mac: Option<String> = None;
    let mut legacy_skipped = 0;
    let mut anchored_started = false;
    for (seq, entry_hash, stored) in rows {
        match stored {
            None => {
                // A NULL chain_mac is only legitimate as an unbroken LEGACY
                // PREFIX (rows written before this feature, or when the key was
                // unavailable). Once any anchored row has been seen, a NULL is
                // tamper, not legacy: an attacker who can write the decrypted DB
                // could otherwise strip the MAC off a row — the tail row most
                // dangerously, since without this it has no following row to
                // catch it (F2) — and rewrite its entry_hash freely. Flag it.
                if anchored_started {
                    return MacVerdict {
                        ok: false,
                        broken_at: Some(seq),
                        reason: Some("null chain_mac after anchoring (MAC-strip tamper)".to_string()),
                        legacy_skipped,
                    };
                }
                legacy_skipped += 1;
            }
            Some(mac) => {
                if !verify_one(key, entry_hash, prev_mac.as_deref(), mac) {
                    return MacVerdict {
                        ok: false,
                        broken_at: Some(seq),
                        reason: Some("chain_mac mismatch".to_string()),
                        legacy_skipped,
                    };
                }
                anchored_started = true;
            }
        }
        prev_mac = stored.map(|s| s.to_string());
    }
    MacVerdict { ok: true, broken_at: None, reason: None, legacy_skipped }
}

#[cfg(test)]
mod tests {
    //! These exercise the security property directly with a FIXED test key
    //! (no keychain needed): a well-formed keyed chain verifies, and every
    //! tampering an attacker with DB write access could attempt is caught.

    use super::*;

    fn test_key() -> hmac::Key {
        // Deterministic 32-byte test key — NOT derived from a DEK, so these
        // tests run without a keychain (unit-test environment has none).
        hmac::Key::new(hmac::HMAC_SHA256, &[0x11u8; KEY_LEN])
    }

    // Build a valid chain of `entry_hashes` the way the append path does.
    fn build(key: &hmac::Key, entry_hashes: &[&str]) -> Vec<(i64, String, Option<String>)> {
        let mut out = Vec::new();
        let mut prev: Option<String> = None;
        for (i, eh) in entry_hashes.iter().enumerate() {
            let mac = compute(key, eh, prev.as_deref());
            out.push(((i as i64) + 1, eh.to_string(), Some(mac.clone())));
            prev = Some(mac);
        }
        out
    }

    fn verdict(key: &hmac::Key, rows: &[(i64, String, Option<String>)]) -> MacVerdict {
        verify_chain(key, rows.iter().map(|(s, h, m)| (*s, h.as_str(), m.as_deref())))
    }

    #[test]
    fn well_formed_chain_verifies() {
        let key = test_key();
        let rows = build(&key, &["hash-a", "hash-b", "hash-c"]);
        let v = verdict(&key, &rows);
        assert!(v.ok, "a correctly-keyed chain must verify");
        assert_eq!(v.legacy_skipped, 0);
    }

    #[test]
    fn edited_entry_hash_is_caught() {
        let key = test_key();
        let mut rows = build(&key, &["hash-a", "hash-b", "hash-c"]);
        // Attacker rewrites row 2's content (entry_hash) but leaves its MAC.
        rows[1].1 = "forged-hash-b".to_string();
        let v = verdict(&key, &rows);
        assert!(!v.ok, "an edited entry_hash must break the MAC chain");
        assert_eq!(v.broken_at, Some(2));
    }

    #[test]
    fn wholesale_substitution_without_key_is_caught() {
        let key = test_key();
        // Attacker forges a brand-new, internally-consistent chain but does NOT
        // have K, so they must guess/omit the MACs. Model that as a chain built
        // under the WRONG key.
        let wrong = hmac::Key::new(hmac::HMAC_SHA256, &[0x22u8; KEY_LEN]);
        let forged = build(&wrong, &["fabricated-note", "fabricated-sign"]);
        let v = verdict(&key, &forged); // verify with the REAL key
        assert!(!v.ok, "a chain forged under a different key must fail verification");
        assert_eq!(v.broken_at, Some(1));
    }

    #[test]
    fn truncation_of_tail_is_not_caught_by_per_entry_mac() {
        // Documents the known limit: a MAC-valid prefix is still MAC-valid.
        let key = test_key();
        let full = build(&key, &["a", "b", "c"]);
        let truncated = &full[..2];
        assert!(verdict(&key, truncated).ok, "per-entry MACs do not detect a dropped tail");
    }

    #[test]
    fn nulling_an_interior_mac_is_caught_at_that_row() {
        // An attacker can't turn an anchored row into a legacy one to launder an
        // edit: a NULL chain_mac after anchoring is itself flagged (F2), so
        // dropping row 2's MAC surfaces AT row 2, not silently.
        let key = test_key();
        let mut rows = build(&key, &["a", "b", "c"]);
        rows[1].2 = None; // NULL out row 2's chain_mac
        let v = verdict(&key, &rows);
        assert!(!v.ok, "a NULL'd MAC after anchoring must be flagged");
        assert_eq!(v.broken_at, Some(2));
    }

    #[test]
    fn nulling_the_tail_mac_and_editing_it_is_caught() {
        // The F2 hole: the LAST row has no following row, so before this fix an
        // attacker could NULL its chain_mac (legacy-skip) and rewrite its
        // entry_hash undetected. Now a NULL after anchoring is tamper.
        let key = test_key();
        let mut rows = build(&key, &["a", "b", "c"]);
        rows[2].1 = "forged-tail-content".to_string(); // rewrite the tail's entry_hash
        rows[2].2 = None; // and strip its MAC to skip verification
        let v = verdict(&key, &rows);
        assert!(!v.ok, "a stripped-and-rewritten tail row must be caught");
        assert_eq!(v.broken_at, Some(3));
    }

    #[test]
    fn legacy_prefix_then_anchored_verifies() {
        let key = test_key();
        // Two legacy (pre-feature) rows with no MAC, then anchored rows whose
        // genesis prev_mac is None because the last legacy row's mac is NULL.
        let mut rows: Vec<(i64, String, Option<String>)> = vec![
            (1, "legacy-1".to_string(), None),
            (2, "legacy-2".to_string(), None),
        ];
        let mut prev: Option<String> = None; // matches the NULL predecessor
        for (i, eh) in ["anchored-3", "anchored-4"].iter().enumerate() {
            let mac = compute(&key, eh, prev.as_deref());
            rows.push(((i as i64) + 3, eh.to_string(), Some(mac.clone())));
            prev = Some(mac);
        }
        let v = verdict(&key, &rows);
        assert!(v.ok, "legacy prefix followed by anchored rows must verify");
        assert_eq!(v.legacy_skipped, 2);
    }

    #[test]
    fn hkdf_is_domain_separated_and_deterministic() {
        // Same DEK → same key (deterministic); and the derived key is 32 bytes.
        let dek = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let k1 = derive_mac_key_bytes(dek).unwrap();
        let k2 = derive_mac_key_bytes(dek).unwrap();
        assert_eq!(k1, k2, "derivation must be deterministic");
        // A different DEK yields a different key.
        let other = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
        assert_ne!(k1, derive_mac_key_bytes(other).unwrap());
    }

    #[test]
    fn dek_hex_validation_rejects_bad_input() {
        assert!(dek_hex_to_bytes("nothex").is_err());
        assert!(dek_hex_to_bytes("aabb").is_err()); // too short
    }
}
