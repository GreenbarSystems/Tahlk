//! Anthropic API key handling.
//!
//! The key lives in the OS secure store (Windows Credential Manager /
//! macOS Keychain / Linux Secret Service) via the `keyring` crate — never
//! in the app database. It is write-only from JS (set via `set_api_key`,
//! presence-checked via `has_api_key`) and read only inside `generate_note`.
//!
//! `API_KEY_KV` is the LEGACY SQLite location. It is no longer written; it
//! is read once and migrated into the keychain (then deleted) so existing
//! installs stop keeping the key in plaintext on disk.

use rusqlite::{params, OptionalExtension};
use serde_json::Value;
use tauri::State;

use crate::errors::AppError;
use crate::DbState;

pub(crate) const API_KEY_KV: &str = "secret_v1::anthropic_api_key";
const KEYRING_SERVICE: &str = "com.tahlk.app";
const KEYRING_USER: &str = "anthropic_api_key";

/// KV keys that must never be reachable through the generic `kv_*` commands.
///
/// Historically `guard_key` used `key.starts_with("secret_")` (audit H5). That
/// is fragile in both directions:
///
///   * Any future keychain-item KV key that doesn't start with `secret_` would
///     silently bypass the guard.
///   * Any legitimate app data whose key happens to start with `secret_` would
///     be silently rejected — a footgun waiting for the next reviewer.
///
/// The explicit allowlist below is the single source of truth. Both
/// `is_secret_key` (used by `guard_key`) and the `kv_list` post-filter consult
/// it, so add-a-key requires exactly one edit and the enumeration path is
/// guaranteed to stay in sync.
///
/// # Adding a new keychain-backed KV key
/// 1. Append the exact key string here (and update the pin in
///    `keychain_only_keys_is_pinned` in the same commit).
/// 2. Add a `#[tauri::command]` in `secrets.rs` that reads/writes the value via
///    the OS keychain (never the SQLite `kv` table).
/// 3. Extend the `kv_list_hides_keychain_only_keys` test in `kv.rs` to seed
///    the new key and assert it stays hidden through enumeration.
pub(crate) const KEYCHAIN_ONLY_KEYS: &[&str] = &[
    API_KEY_KV,
];

/// True when `key` names a value that must live in the OS keychain and is
/// therefore forbidden from the generic KV API. Pure function — no DB.
pub(crate) fn is_secret_key(key: &str) -> bool {
    KEYCHAIN_ONLY_KEYS.contains(&key)
}

fn keyring_entry() -> Result<keyring::Entry, AppError> {
    keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER).map_err(AppError::internal_from)
}

// Read the API key, keychain-first. If absent there but present in the legacy
// SQLite location, migrate it into the keychain and delete the plaintext copy.
pub(crate) fn read_api_key(state: &DbState) -> Option<String> {
    if let Ok(entry) = keyring_entry() {
        if let Ok(pw) = entry.get_password() {
            if !pw.is_empty() {
                return Some(pw);
            }
        }
    }

    // Legacy fallback + one-time migration off plaintext disk.
    let legacy: Option<String> = {
        let conn = state.0.lock();
        conn.query_row("SELECT value FROM kv WHERE key = ?1", params![API_KEY_KV], |r| {
            r.get::<_, String>(0)
        })
        .optional()
        .ok()
        .flatten()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .and_then(|v| v.as_str().map(str::to_string))
    };
    if let Some(key) = legacy {
        if let Ok(entry) = keyring_entry() {
            let _ = entry.set_password(&key);
        }
        let conn = state.0.lock();
        let _ = conn.execute("DELETE FROM kv WHERE key = ?1", params![API_KEY_KV]);
        return Some(key);
    }
    None
}

// Reject any attempt to reach a keychain-backed namespace through the generic
// KV API. Consults `KEYCHAIN_ONLY_KEYS` — the single source of truth shared
// with `kv_list`'s enumeration filter (audit H5).
pub(crate) fn guard_key(key: &str) -> Result<(), AppError> {
    if is_secret_key(key) {
        return Err(AppError::invalid(
            "secret keys are not accessible via the KV API",
        ));
    }
    Ok(())
}

#[tauri::command]
pub(crate) fn set_api_key(state: State<DbState>, key: String) -> Result<(), AppError> {
    keyring_entry()?.set_password(&key).map_err(AppError::internal_from)?;
    // Remove any legacy plaintext copy so the key no longer lives on disk.
    let conn = state.0.lock();
    let _ = conn.execute("DELETE FROM kv WHERE key = ?1", params![API_KEY_KV]);
    Ok(())
}

#[tauri::command]
pub(crate) fn clear_api_key(state: State<DbState>) -> Result<(), AppError> {
    if let Ok(entry) = keyring_entry() {
        let _ = entry.delete_credential(); // ignore "no entry"
    }
    let conn = state.0.lock();
    let _ = conn.execute("DELETE FROM kv WHERE key = ?1", params![API_KEY_KV]);
    Ok(())
}

#[tauri::command]
pub(crate) fn has_api_key(state: State<DbState>) -> Result<bool, AppError> {
    Ok(read_api_key(&state).is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Round-trips a credential through the real OS secure store to confirm the
    // keyring backend works on this platform. Uses a dedicated service name and
    // cleans up after itself, so it never touches a real saved key.
    #[test]
    fn keyring_roundtrip() {
        let entry = keyring::Entry::new("com.tahlk.app.test", "roundtrip").unwrap();
        entry.set_password("sk-ant-test-value").unwrap();
        assert_eq!(entry.get_password().unwrap(), "sk-ant-test-value");
        entry.delete_credential().unwrap();
        assert!(entry.get_password().is_err(), "credential should be gone after delete");
    }

    // Belt-and-braces: iterate the allowlist and confirm every listed key is
    // (a) rejected by guard_key with the expected AppError variant, and (b)
    // recognized by is_secret_key. If a future edit adds a keychain-backed
    // key here but forgets the coordinated `#[tauri::command]`, this test
    // still passes — but it will catch a regression that accidentally removes
    // a key from the list or replaces the allowlist with a laxer check.
    #[test]
    fn every_keychain_only_key_is_guarded() {
        for key in KEYCHAIN_ONLY_KEYS {
            assert!(is_secret_key(key), "{key} should be a secret key");
            let err = guard_key(key).unwrap_err();
            assert!(
                matches!(err, AppError::InvalidInput(_)),
                "guard_key({key}) should return InvalidInput, got {err:?}"
            );
        }
    }

    // A former `starts_with("secret_")` check would have blocked any key that
    // happens to begin with that string — legitimate future app data (e.g.
    // `secret_question_hint` for a security-questions flow) would be silently
    // rejected. The explicit allowlist must NOT reject such keys.
    #[test]
    fn keys_with_secret_prefix_but_not_on_allowlist_are_allowed() {
        for key in [
            "secret_question_hint",
            "secret_v2::anthropic_api_key", // hypothetical future variant
            "secret",
            "secretly_public_setting",
        ] {
            assert!(!is_secret_key(key), "{key} should NOT be a secret key");
            assert!(guard_key(key).is_ok(), "guard_key({key}) should accept");
        }
    }

    // Non-secret shapes we actually use must pass. These match `kv.rs`'s
    // realistic_key_shapes_all_fit list so the two guards stay in lockstep.
    #[test]
    fn realistic_kv_keys_are_not_guarded() {
        for key in [
            "note_settings_v1::baa_ack",
            "note_settings_v1::onboarded",
            "note_provider_v1::profile",
            "note_content_v1::enc-l9k3a-x7q2",
            "note_content_v1::transcript::enc-l9k3a-x7q2",
            "note_history_v1::enc-l9k3a-x7q2",
            "note_templates_v1::psych-eval",
            "note_diag_v1::events",
        ] {
            assert!(!is_secret_key(key), "{key} should NOT be a secret key");
            assert!(guard_key(key).is_ok(), "guard_key({key}) should accept");
        }
    }

    // Pin the exact allowlist so a merge that adds/removes an entry surfaces
    // as a test diff during review. Anyone extending the list must update
    // this test in the same commit, which forces a second reviewer to see
    // the change.
    #[test]
    fn keychain_only_keys_is_pinned() {
        assert_eq!(
            KEYCHAIN_ONLY_KEYS,
            &[API_KEY_KV],
            "KEYCHAIN_ONLY_KEYS changed — review carefully and update this pin."
        );
    }
}
