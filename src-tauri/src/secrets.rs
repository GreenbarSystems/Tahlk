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

use crate::DbState;

pub(crate) const API_KEY_KV: &str = "secret_v1::anthropic_api_key";
const KEYRING_SERVICE: &str = "com.tahlk.app";
const KEYRING_USER: &str = "anthropic_api_key";

fn keyring_entry() -> Result<keyring::Entry, String> {
    keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER).map_err(|e| e.to_string())
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

// Reject any attempt to reach the secret namespace through the generic KV API.
pub(crate) fn guard_key(key: &str) -> Result<(), String> {
    if key.starts_with("secret_") {
        return Err("access denied: secret keys are not accessible via the KV API".into());
    }
    Ok(())
}

#[tauri::command]
pub(crate) fn set_api_key(state: State<DbState>, key: String) -> Result<(), String> {
    keyring_entry()?.set_password(&key).map_err(|e| e.to_string())?;
    // Remove any legacy plaintext copy so the key no longer lives on disk.
    let conn = state.0.lock();
    let _ = conn.execute("DELETE FROM kv WHERE key = ?1", params![API_KEY_KV]);
    Ok(())
}

#[tauri::command]
pub(crate) fn clear_api_key(state: State<DbState>) -> Result<(), String> {
    if let Ok(entry) = keyring_entry() {
        let _ = entry.delete_credential(); // ignore "no entry"
    }
    let conn = state.0.lock();
    let _ = conn.execute("DELETE FROM kv WHERE key = ?1", params![API_KEY_KV]);
    Ok(())
}

#[tauri::command]
pub(crate) fn has_api_key(state: State<DbState>) -> Result<bool, String> {
    Ok(read_api_key(&state).is_some())
}

#[cfg(test)]
mod tests {
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
}
