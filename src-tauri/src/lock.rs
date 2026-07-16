//! In-app idle-lock PIN — obscures note/transcript content after inactivity
//! and requires a locally-set PIN to resume ("Quick-Lock Timer" review
//! recommendation; already named as planned remediation in
//! hipaa-risk-assessment.md §3.1's "in-app PIN/idle-resume gate").
//!
//! Deliberately a Tahlk-local PIN, not the real OS login password: Tahlk
//! has no safe, reliable, cross-platform way to verify an attempt against
//! the actual OS credential — that would need native OS authentication
//! APIs (Windows `LogonUserW`, macOS `LocalAuthentication`) well outside
//! this crate's dependency surface, and re-implementing password
//! verification against a credential Tahlk doesn't own is itself a
//! security anti-pattern (don't roll your own auth against someone else's
//! secret). A locally-set PIN, hashed and never stored in plaintext, gives
//! the same practical protection against the actual named threat — a
//! passerby glancing at or using an unlocked laptop between patients —
//! without Tahlk taking on OS-credential-verification responsibility it
//! can't safely discharge.
//!
//! The PIN hash lives in the OS keychain, never the SQLite `kv` table,
//! matching `db_key.rs`/`secrets.rs`'s existing pattern for anything this
//! sensitive. Hashed with PBKDF2-HMAC-SHA256 (`ring::pbkdf2`, already a
//! direct dependency for audio_crypto.rs — no new crate needed) at
//! 210,000 iterations (OWASP's 2023 minimum recommendation for this
//! algorithm), with a fresh random salt per PIN and the iteration count
//! stored alongside the hash so a future increase never breaks
//! verification of an already-set PIN.

use std::num::NonZeroU32;

use ring::pbkdf2;

use crate::errors::AppError;
use crate::hex::{from_hex, to_hex};

/// This module's own keychain item name. Deliberately distinct from
/// `secrets`'s and `db_key`'s — see `keychain.rs`'s module doc.
pub(crate) const KEYRING_USER: &str = "lock_pin_hash";

const PBKDF2_ITERATIONS: u32 = 210_000;
const SALT_LEN: usize = 16;
const HASH_LEN: usize = 32;

/// A PIN shorter than this is trivially guessable in a handful of tries by
/// someone with physical access; longer than this is almost certainly a
/// paste-in-the-wrong-field mistake, not a real PIN.
const PIN_MIN_LEN: usize = 4;
const PIN_MAX_LEN: usize = 64;

fn keyring_entry() -> Result<keyring::Entry, AppError> {
    crate::keychain::entry(KEYRING_USER)
}

pub(crate) fn validate_pin(pin: &str) -> Result<(), AppError> {
    if pin.len() < PIN_MIN_LEN {
        return Err(AppError::invalid(format!("PIN must be at least {PIN_MIN_LEN} characters")));
    }
    if pin.len() > PIN_MAX_LEN {
        return Err(AppError::invalid(format!("PIN exceeds {PIN_MAX_LEN} characters")));
    }
    Ok(())
}

fn hash_pin(pin: &str, salt: &[u8], iterations: u32) -> Result<[u8; HASH_LEN], AppError> {
    let nz = NonZeroU32::new(iterations)
        .ok_or_else(|| AppError::internal_from("PBKDF2 iteration count must be nonzero"))?;
    let mut hash = [0u8; HASH_LEN];
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, nz, salt, pin.as_bytes(), &mut hash);
    Ok(hash)
}

/// Stored shape: `"<iterations>:<salt_hex>:<hash_hex>"`. Iterations travel
/// with the hash (not a crate-wide const alone) so a future bump to
/// PBKDF2_ITERATIONS doesn't invalidate a PIN set under the old count —
/// verification always uses whatever count the hash was actually derived
/// with.
pub(crate) fn set_pin(pin: &str) -> Result<(), AppError> {
    validate_pin(pin)?;
    let mut salt = [0u8; SALT_LEN];
    getrandom::getrandom(&mut salt).map_err(AppError::internal_from)?;
    let hash = hash_pin(pin, &salt, PBKDF2_ITERATIONS)?;
    let stored = format!("{PBKDF2_ITERATIONS}:{}:{}", to_hex(&salt), to_hex(&hash));
    keyring_entry()?.set_password(&stored).map_err(AppError::internal_from)?;
    Ok(())
}

/// Verifies `pin` against the stored hash. Returns `Ok(false)` (not an
/// error) for "no PIN set," "stored entry is malformed," or "PIN doesn't
/// match" alike — none of those should surface as a hard error to the lock
/// screen, which only cares about true/false. Uses `ring::pbkdf2::verify`,
/// which compares in constant time internally rather than a naive `==` on
/// the derived bytes.
pub(crate) fn verify_pin(pin: &str) -> Result<bool, AppError> {
    if pin.len() > PIN_MAX_LEN {
        return Ok(false);
    }
    let entry = keyring_entry()?;
    let stored = match entry.get_password() {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    let parts: Vec<&str> = stored.splitn(3, ':').collect();
    if parts.len() != 3 {
        return Ok(false);
    }
    let (iterations_str, salt_hex, hash_hex) = (parts[0], parts[1], parts[2]);
    let Ok(iterations) = iterations_str.parse::<u32>() else { return Ok(false) };
    let Some(nz) = NonZeroU32::new(iterations) else { return Ok(false) };
    let Some(salt) = from_hex(salt_hex) else { return Ok(false) };
    let Some(expected) = from_hex(hash_hex) else { return Ok(false) };

    Ok(pbkdf2::verify(pbkdf2::PBKDF2_HMAC_SHA256, nz, &salt, pin.as_bytes(), &expected).is_ok())
}

pub(crate) fn clear_pin() {
    if let Ok(entry) = keyring_entry() {
        let _ = entry.delete_credential(); // ignore "no entry"
    }
}

pub(crate) fn is_pin_set() -> bool {
    keyring_entry().and_then(|e| e.get_password().map_err(AppError::internal_from)).is_ok()
}

#[tauri::command]
pub(crate) fn lock_pin_set(pin: String) -> Result<(), AppError> {
    set_pin(&pin)
}

#[tauri::command]
pub(crate) fn lock_pin_verify(pin: String) -> Result<bool, AppError> {
    verify_pin(&pin)
}

#[tauri::command]
pub(crate) fn lock_pin_clear() -> Result<(), AppError> {
    clear_pin();
    Ok(())
}

#[tauri::command]
pub(crate) fn lock_pin_is_set() -> Result<bool, AppError> {
    Ok(is_pin_set())
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: hex encode/decode moved to `hex.rs`; its tests moved with it.

    #[test]
    fn validate_pin_enforces_length_bounds() {
        assert!(validate_pin("123").is_err()); // 3 chars, below MIN
        assert!(validate_pin("1234").is_ok()); // exactly MIN
        assert!(validate_pin(&"1".repeat(PIN_MAX_LEN)).is_ok()); // exactly MAX
        assert!(validate_pin(&"1".repeat(PIN_MAX_LEN + 1)).is_err()); // over MAX
    }

    // hash_pin + pbkdf2::verify round-trip, independent of the OS keychain
    // (which the set_pin/verify_pin commands need but this pure helper
    // doesn't) — this is the actual cryptographic core under test.
    #[test]
    fn hash_pin_round_trips_through_pbkdf2_verify() {
        let salt = [7u8; SALT_LEN];
        let hash = hash_pin("correct-pin-4821", &salt, 1000).unwrap(); // low iteration count: test speed only
        let nz = NonZeroU32::new(1000).unwrap();
        assert!(pbkdf2::verify(pbkdf2::PBKDF2_HMAC_SHA256, nz, &salt, b"correct-pin-4821", &hash).is_ok());
        assert!(pbkdf2::verify(pbkdf2::PBKDF2_HMAC_SHA256, nz, &salt, b"wrong-pin", &hash).is_err());
    }

    #[test]
    fn stored_format_parses_back_into_matching_iterations_salt_hash() {
        let salt = [3u8; SALT_LEN];
        let hash = hash_pin("test-pin-0007", &salt, 5000).unwrap();
        let stored = format!("5000:{}:{}", to_hex(&salt), to_hex(&hash));
        let parts: Vec<&str> = stored.splitn(3, ':').collect();
        assert_eq!(parts[0], "5000");
        assert_eq!(from_hex(parts[1]).unwrap(), salt.to_vec());
        assert_eq!(from_hex(parts[2]).unwrap(), hash.to_vec());
    }

    #[test]
    fn different_salts_produce_different_hashes_for_the_same_pin() {
        let h1 = hash_pin("same-pin-1234", &[1u8; SALT_LEN], 1000).unwrap();
        let h2 = hash_pin("same-pin-1234", &[2u8; SALT_LEN], 1000).unwrap();
        assert_ne!(h1, h2, "salting must actually vary the derived hash");
    }
}
