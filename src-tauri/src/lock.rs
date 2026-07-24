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
use tauri::{AppHandle, State};

use crate::errors::AppError;
use crate::hex::{from_hex, to_hex};
use crate::DbState;

/// This module's own keychain item name. Deliberately distinct from
/// `secrets`'s and `db_key`'s — see `keychain.rs`'s module doc.
pub(crate) const KEYRING_USER: &str = "lock_pin_hash";

const PBKDF2_ITERATIONS: u32 = 210_000;
const SALT_LEN: usize = 16;
const HASH_LEN: usize = 32;

/// A PIN shorter than this is trivially guessable by someone with physical
/// access; longer than the max is almost certainly a paste-in-the-wrong-field
/// mistake, not a real PIN.
///
/// Raised from 4 to 6: a 4-digit numeric PIN is a 10^4 keyspace, small enough
/// that even the new lockout only stretches an exhaustive search rather than
/// preventing it. Six digits is 100x the work for one extra keypress. Applies
/// to newly-set PINs only — `validate_pin` runs on set, not on verify, so an
/// existing shorter PIN keeps working until the provider changes it.
const PIN_MIN_LEN: usize = 6;
const PIN_MAX_LEN: usize = 64;

/// KV keys for the idle-lock policy settings. Mirrored in JS as
/// `keys.lockEnabled()` / `keys.lockTimeoutMinutes()` (src/data/keys.js).
/// Writes go through the audited `lock_enabled_set` / `lock_timeout_set`
/// commands below, never the generic `kv_set` — `secrets::guard_write_key`
/// blocks those keys on the write path — so a change to the auto-logoff
/// safeguard always lands a `config_audit` row (§164.312(b), audit finding M2).
/// Reads stay open, so the JS warmup → synchronous `kvGet()` path is unchanged.
pub(crate) const KV_LOCK_ENABLED: &str = "note_settings_v1::lock_enabled";
pub(crate) const KV_LOCK_TIMEOUT: &str = "note_settings_v1::lock_timeout_minutes";

/// Idle-lock timeout bounds (minutes). Mirrors idleLock.js's MIN/MAX so the
/// server-side validation matches the client's clamp.
const MIN_TIMEOUT_MINUTES: i64 = 1;
const MAX_TIMEOUT_MINUTES: i64 = 60;

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
pub(crate) fn lock_pin_set(app: AppHandle, pin: String) -> Result<(), AppError> {
    // Setting/changing the idle-lock PIN is a credential-lifecycle event —
    // record it in the auth trail alongside pin_verify (H1 / M2, §164.312(b)).
    let r = set_pin(&pin);
    crate::auth::record_auth_event(
        &app,
        "pin_set",
        if r.is_ok() { "success" } else { "failure" },
    );
    r
}

/// Throttle scope for the idle-lock PIN. The sharpest case for rate limiting
/// in the app: a 4-character numeric PIN is a 10^4 keyspace, which unlimited
/// guessing exhausts in minutes.
const THROTTLE_SCOPE: &str = "lock_pin";

#[tauri::command]
pub(crate) fn lock_pin_verify(app: AppHandle, pin: String) -> Result<bool, AppError> {
    // Audit finding H1: the idle-lock PIN gate is one of the credential-
    // verification paths that must leave a durable trace (§164.312(b)).
    if let Err(e) = crate::throttle::check(THROTTLE_SCOPE) {
        crate::auth::record_auth_event(&app, "pin_verify", "throttled");
        return Err(e);
    }
    let ok = verify_pin(&pin)?;
    if ok {
        crate::throttle::record_success(THROTTLE_SCOPE);
        crate::auth::record_auth_event(&app, "pin_verify", "success");
    } else {
        crate::throttle::record_failure(THROTTLE_SCOPE);
        crate::auth::record_auth_event(&app, "pin_verify", "failure");
    }
    Ok(ok)
}

#[tauri::command]
pub(crate) fn lock_pin_clear(app: AppHandle) -> Result<(), AppError> {
    clear_pin();
    // Removing the PIN also disables the idle lock (see settingsModal.js), so
    // this is a safeguard-weakening event worth recording.
    crate::auth::record_auth_event(&app, "pin_cleared", "success");
    Ok(())
}

#[tauri::command]
pub(crate) fn lock_pin_is_set() -> Result<bool, AppError> {
    Ok(is_pin_set())
}

/// Enable or disable the idle auto-logoff (§164.312(a)(2)(iii)). Routes through
/// the shared `set_policy_value` helper so the KV write and its `config_audit`
/// row (`lock_enabled_changed`, with old→new value and server-derived actor)
/// land in one transaction — disabling a required safeguard must be provable,
/// and "changed but not logged" must not be a reachable state (audit M2).
#[tauri::command]
pub(crate) fn lock_enabled_set(state: State<DbState>, enabled: bool) -> Result<(), AppError> {
    let mut conn = state.conn()?;
    crate::retention::set_policy_value(
        &mut conn,
        KV_LOCK_ENABLED,
        if enabled { "true" } else { "false" },
        "lock_enabled_changed",
    )
}

/// Set the idle auto-logoff timeout in minutes (1–60, matching idleLock.js).
/// Same atomic KV-write + `config_audit` (`lock_timeout_changed`) as
/// `lock_enabled_set`; validation lives here so a compromised WebView can't
/// stash an out-of-range value via the generic `kv_set` (which is now blocked
/// for this key).
#[tauri::command]
pub(crate) fn lock_timeout_set(state: State<DbState>, minutes: i64) -> Result<(), AppError> {
    if !(MIN_TIMEOUT_MINUTES..=MAX_TIMEOUT_MINUTES).contains(&minutes) {
        return Err(AppError::invalid(format!(
            "lock timeout must be between {MIN_TIMEOUT_MINUTES} and {MAX_TIMEOUT_MINUTES} minutes"
        )));
    }
    let mut conn = state.conn()?;
    crate::retention::set_policy_value(
        &mut conn,
        KV_LOCK_TIMEOUT,
        &minutes.to_string(),
        "lock_timeout_changed",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: hex encode/decode moved to `hex.rs`; its tests moved with it.

    #[test]
    fn validate_pin_enforces_length_bounds() {
        // Derived from the constant rather than hardcoded, so a future change
        // to PIN_MIN_LEN does not silently leave this test asserting the old
        // boundary — which is exactly what happened when it moved 4 -> 6.
        assert!(validate_pin(&"1".repeat(PIN_MIN_LEN - 1)).is_err(), "below MIN");
        assert!(validate_pin(&"1".repeat(PIN_MIN_LEN)).is_ok(), "exactly MIN");
        assert!(validate_pin(&"1".repeat(PIN_MAX_LEN)).is_ok(), "exactly MAX");
        assert!(validate_pin(&"1".repeat(PIN_MAX_LEN + 1)).is_err(), "over MAX");
    }

    #[test]
    fn a_four_digit_pin_is_no_longer_accepted() {
        // 10^4 is small enough that even the new lockout only stretches an
        // exhaustive search rather than preventing it.
        assert!(validate_pin("1234").is_err());
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

    // ── Idle-lock policy settings (M2, §164.312(a)(2)(iii) + (b)) ─────────────

    #[test]
    fn lock_kv_keys_match_the_js_side() {
        // These MUST equal src/data/keys.js's keys.lockEnabled() /
        // keys.lockTimeoutMinutes(); if they drift, the audited Rust write
        // targets a different row than the JS idle watcher reads.
        assert_eq!(KV_LOCK_ENABLED, "note_settings_v1::lock_enabled");
        assert_eq!(KV_LOCK_TIMEOUT, "note_settings_v1::lock_timeout_minutes");
    }

    #[test]
    fn lock_timeout_bounds_match_the_client_clamp() {
        // idleLock.js clamps to [1, 60]; the server-side validation must agree,
        // or a value the client accepts gets rejected (or vice versa).
        assert_eq!((MIN_TIMEOUT_MINUTES, MAX_TIMEOUT_MINUTES), (1, 60));
    }

    #[test]
    fn setting_the_lock_writes_kv_and_a_config_audit_row_atomically() {
        // End-to-end: the audited path (shared with retention) must land BOTH
        // the kv row the JS reads AND a config_audit row, in one unit.
        use rusqlite::Connection;
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL);",
        )
        .unwrap();
        crate::config_audit::init_schema(&conn).unwrap();

        crate::retention::set_policy_value(&mut conn, KV_LOCK_ENABLED, "false", "lock_enabled_changed")
            .unwrap();

        let stored: String = conn
            .query_row(
                "SELECT value FROM kv WHERE key = ?1",
                rusqlite::params![KV_LOCK_ENABLED],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(stored, "false", "the JS-readable kv row must reflect the change");

        let (action, new_value): (String, String) = conn
            .query_row(
                "SELECT action, new_value FROM config_audit ORDER BY id DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(action, "lock_enabled_changed");
        assert_eq!(new_value, "false");
    }
}
