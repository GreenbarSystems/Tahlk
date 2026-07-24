//! Guarded KV namespaces + the provider-profile write path.
//!
//! Since the BYOK Anthropic key was retired (Phase 2b), this module no longer
//! stores any user-supplied credential. In managed mode the only bearer
//! credential is the per-device proxy token, which `device.rs` owns end to end
//! (mint / store / refresh via `kv_ops` directly). This module's job is the KV
//! guard surface: it declares which `kv` keys are unreachable or write-blocked
//! through the generic `kv_*` commands, and hosts the dedicated
//! `set_provider_profile` write path.

use serde_json::Value;
use tauri::State;

use crate::errors::AppError;
use crate::DbState;

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
/// Despite the name, this list now covers two categories, not just literal
/// OS-keychain items:
///   * `device::DEVICE_TOKEN_KV` — the per-device managed-proxy bearer token.
///     It authenticates PHI transmission through the proxy, so it is treated
///     like the retired API key: unreachable from the generic KV surface.
///     `device.rs` reaches its row via `kv_ops` directly.
///   * `baa::BAA_ACK_KEY` — the BAA attestation row (audit finding H3: "BAA
///     acknowledgment row is writable via the generic kv_set command,
///     bypassing baa_ack_set's guarantees"). This one stays in the SQLite
///     `kv` table — it isn't keychain material — but it's the single gate
///     standing in front of every PHI transmission to Anthropic, so it must
///     be exactly as unreachable from the generic KV surface as a secret.
///     `baa.rs`'s own `baa_ack_status`/`baa_ack_set`/`baa_ack_clear` commands
///     are unaffected: they read/write via `crate::kv_ops` directly, never
///     through `guard_key`, so this only closes the generic-command path.
///
/// # Adding a new key here
/// 1. Append the exact key string here (and update the pin in
///    `keychain_only_keys_is_pinned` in the same commit).
/// 2. Make sure a dedicated `#[tauri::command]` already exists (in this file
///    or elsewhere) that reads/writes the value WITHOUT going through
///    `kv::kv_get`/`kv_set`/`kv_remove` — otherwise the guard would make the
///    value permanently unreachable.
/// 3. Extend the `kv_list_hides_keychain_only_keys` test in `kv.rs` to seed
///    the new key and assert it stays hidden through enumeration.
pub(crate) const KEYCHAIN_ONLY_KEYS: &[&str] = &[
    crate::device::DEVICE_TOKEN_KV,
    crate::baa::BAA_ACK_KEY,
];

/// Provider profile KV key. The profile is the source of truth for the actor
/// identity stamped on patient audit trail entries. Its write path is guarded
/// so a compromised WebView cannot forge audit identity via `kv_set` (C3 fix).
/// Reads remain accessible via `kv_get`/`kv_list` so the existing synchronous
/// read pattern (cache warmup → `kvGet()` in JS) continues to work.
pub(crate) const NOTE_PROVIDER_PROFILE_KEY: &str = "note_provider_v1::profile";

/// KV keys that must not be written through the generic `kv_set`/`kv_remove`
/// commands but ARE still readable via `kv_get`/`kv_list`. Distinct from
/// `KEYCHAIN_ONLY_KEYS` which blocks both reads and writes.
///
/// # Adding a new key here
/// 1. Append the exact key string and update the `write_only_protected_keys_is_pinned` pin.
/// 2. Create a dedicated `#[tauri::command]` for the write path (bypasses `guard_write_key`).
/// 3. The read path via `kv_get`/`kv_list` remains open — no extra steps needed for reads.
pub(crate) const WRITE_ONLY_PROTECTED_KEYS: &[&str] = &[
    NOTE_PROVIDER_PROFILE_KEY,
    // Both gate PHI destruction, so a generic write to either is a destruction
    // primitive. Left unguarded, three permitted invokes destroyed every signed
    // encounter in the database:
    //   kv_set(litigation_hold, "false")   → lifts a legal hold, and because it
    //                                        bypasses retention_hold_set it
    //                                        writes NO config_audit row, so the
    //                                        tamper-evident trail shows nothing
    //   kv_set(retention_years, "0")       → bypasses the 1..=30 validation that
    //                                        lives only in retention_set_years
    //   retention_destroy_eligible()       → cutoff becomes today; every signed
    //                                        encounter is "expired"
    // and the resulting destruction_log is full of legitimate-looking
    // `retention_expired` rows. Writes now go only through retention_set_years /
    // retention_hold_set, which validate and audit. Reads stay open.
    crate::retention::KV_RETENTION_YEARS,
    crate::retention::KV_LITIGATION_HOLD,
    // The idle auto-logoff settings (§164.312(a)(2)(iii)). A generic write to
    // either bypasses lock_enabled_set / lock_timeout_set — which validate the
    // timeout range AND write a config_audit row — so a compromised WebView
    // could silently disable the screen lock, or set a 9999-minute timeout,
    // with nothing in the tamper-evident trail. Writes now go only through
    // those two audited commands (audit finding M2). Reads stay open so the JS
    // warmup → kvGet() idle-watcher path is unchanged.
    crate::lock::KV_LOCK_ENABLED,
    crate::lock::KV_LOCK_TIMEOUT,
];

/// True when `key` names a value that must live in the OS keychain and is
/// therefore forbidden from the generic KV API. Pure function — no DB.
pub(crate) fn is_secret_key(key: &str) -> bool {
    KEYCHAIN_ONLY_KEYS.contains(&key)
}

/// Legacy KV prefixes that the relational audit/history tables were migrated
/// out of, blocked on the WRITE path only.
///
/// `note_audit::migrate_from_kv` and `note_history::migrate_from_kv` run on
/// every launch and ingest whatever they find under these prefixes, accepting
/// the caller's `prevHash`/`entryHash` verbatim, for any encounter that has no
/// rows yet. Since the prefixes were never guarded, a compromised WebView
/// could `kv_set` a forged array under `note_audit_v1::<any-id>` and have the
/// next launch import it as genuine migrated history — manufacturing
/// `record_viewed` / `note_signed` entries attributed to the provider. That
/// goes around the whole point of the narrow server-side append commands,
/// which derive actor and timestamp precisely so the trail cannot be forged
/// from JS.
///
/// Safe to block: on the Tauri path both modules branch on `isTauri` and use
/// the relational commands, so nothing live writes these keys. The
/// localStorage dev/preview backend uses them but never goes through `kv_set`.
/// Reads stay open, and the migrations' own cleanup DELETEs use `kv_ops`
/// directly rather than the guarded command, so an in-progress migration is
/// unaffected.
const LEGACY_MIGRATION_PREFIXES: &[&str] = &[
    "note_audit_v1::",
    "note_audit_archive_v1::",
    "note_history_v1::",
];

/// True when `key` must not be written through the generic `kv_set`/`kv_remove`
/// commands (covers keychain-only, write-only-protected, and legacy-migration
/// keys).
pub(crate) fn is_write_protected(key: &str) -> bool {
    is_secret_key(key)
        || WRITE_ONLY_PROTECTED_KEYS.contains(&key)
        || LEGACY_MIGRATION_PREFIXES.iter().any(|p| key.starts_with(p))
}

/// Reject writes (set / remove) to any guarded key. Used in `kv_set` and
/// `kv_remove` instead of `guard_key` so write-protected-but-readable keys
/// (like the provider profile) are blocked only on the mutation path.
pub(crate) fn guard_write_key(key: &str) -> Result<(), AppError> {
    if is_write_protected(key) {
        return Err(AppError::invalid(
            "this key cannot be written via the generic KV API; use the dedicated command",
        ));
    }
    Ok(())
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

/// Dedicated write path for the provider profile (audit finding C3). Bypasses
/// `guard_write_key` (which blocks the generic `kv_set` route) and validates
/// profile shape before persisting. This is the ONLY write route for
/// `note_provider_v1::profile` — generic `kv_set` and `kv_remove` are blocked.
///
/// Reads continue to work via `kv_get`/`kv_list` so the existing synchronous
/// cache warmup path (`kvGet()` in JS) is undisturbed.
#[tauri::command]
pub(crate) fn set_provider_profile(state: State<DbState>, profile: Value) -> Result<(), AppError> {
    match profile["name"].as_str() {
        Some(n) if !n.trim().is_empty() => {}
        _ => return Err(AppError::invalid("provider profile name is required")),
    }
    let json = serde_json::to_string(&profile).map_err(AppError::internal_from)?;
    if json.len() > crate::kv::MAX_KV_VALUE_BYTES {
        return Err(AppError::invalid("provider profile value too large"));
    }
    let conn = state.conn()?;
    crate::kv_ops::upsert_json(&conn, NOTE_PROVIDER_PROFILE_KEY, &json)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    // note_settings_v1::baa_ack is deliberately NOT in this list any more —
    // it moved to KEYCHAIN_ONLY_KEYS (audit finding H3) and is covered by
    // every_keychain_only_key_is_guarded instead.
    #[test]
    fn realistic_kv_keys_are_not_guarded() {
        for key in [
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
            &[crate::device::DEVICE_TOKEN_KV, crate::baa::BAA_ACK_KEY],
            "KEYCHAIN_ONLY_KEYS changed — review carefully and update this pin."
        );
    }

    // Pin the write-only-protected list. Same discipline as keychain_only_keys_is_pinned:
    // any addition requires a coordinated dedicated read/write command and a test update.
    #[test]
    fn write_only_protected_keys_is_pinned() {
        assert_eq!(
            WRITE_ONLY_PROTECTED_KEYS,
            &[
                NOTE_PROVIDER_PROFILE_KEY,
                crate::retention::KV_RETENTION_YEARS,
                crate::retention::KV_LITIGATION_HOLD,
                crate::lock::KV_LOCK_ENABLED,
                crate::lock::KV_LOCK_TIMEOUT,
            ],
            "WRITE_ONLY_PROTECTED_KEYS changed — review carefully and update this pin."
        );
    }

    // M2: the idle-lock settings must be blocked on the generic write path
    // (so a change can't bypass lock_enabled_set/lock_timeout_set and their
    // config_audit row) while staying readable for the JS warmup → kvGet path.
    #[test]
    fn idle_lock_setting_keys_are_write_blocked_but_readable() {
        for key in [crate::lock::KV_LOCK_ENABLED, crate::lock::KV_LOCK_TIMEOUT] {
            assert!(
                guard_write_key(key).is_err(),
                "{key} must not be writable via generic kv_set — it would skip the config_audit row"
            );
            assert!(guard_key(key).is_ok(), "{key} must stay readable for the idle watcher");
        }
    }

    // A forged blob under a legacy migration prefix is imported as genuine
    // history on the next launch, so the write path must be closed even
    // though nothing live writes these keys any more.
    #[test]
    fn legacy_migration_prefixes_are_write_blocked_but_readable() {
        for key in [
            "note_audit_v1::enc-forged",
            "note_audit_archive_v1::enc-forged",
            "note_history_v1::enc-forged",
        ] {
            assert!(
                guard_write_key(key).is_err(),
                "{key} must not be writable — migrate_from_kv would ingest it as genuine"
            );
            assert!(guard_key(key).is_ok(), "{key} must stay readable");
        }
    }

    #[test]
    fn the_prefix_block_does_not_catch_unrelated_keys() {
        // starts_with is blunt; make sure it only covers the intended
        // namespaces and not, say, a future note_audit_settings key.
        for key in [
            "note_audit_summary_v1::x",
            "note_history_settings_v1::x",
            "note_content_v1::enc-1",
            "note_settings_v1::onboarded",
        ] {
            assert!(guard_write_key(key).is_ok(), "{key} should remain writable");
        }
    }

    // C-4: the retention window and litigation-hold flag gate PHI destruction.
    // A generic write to either is a destruction primitive (see the chain
    // documented on WRITE_ONLY_PROTECTED_KEYS), so both must be blocked on the
    // write path while staying readable — the Settings pane reads them, and
    // blocking reads would strand the UI.
    #[test]
    fn retention_policy_keys_are_write_blocked_but_readable() {
        for key in [
            crate::retention::KV_RETENTION_YEARS,
            crate::retention::KV_LITIGATION_HOLD,
        ] {
            let err = guard_write_key(key).unwrap_err();
            assert!(
                matches!(err, AppError::InvalidInput(_)),
                "guard_write_key({key}) must reject: it gates PHI destruction"
            );
            assert!(
                guard_key(key).is_ok(),
                "guard_key({key}) must allow — reads stay open for the Settings pane"
            );
            assert!(
                !is_secret_key(key),
                "{key} is write-protected, not keychain-only — reads must not be blocked"
            );
        }
    }

    // C3: the provider profile key must be blocked from generic writes but still
    // readable via guard_key (which only checks KEYCHAIN_ONLY_KEYS).
    #[test]
    fn provider_profile_write_is_blocked_but_read_is_allowed() {
        // Write path: guard_write_key must reject the profile key.
        let write_err = guard_write_key(NOTE_PROVIDER_PROFILE_KEY).unwrap_err();
        assert!(
            matches!(write_err, AppError::InvalidInput(_)),
            "guard_write_key must reject the profile key"
        );
        // Read path: guard_key (used by kv_get) must allow the profile key.
        assert!(
            guard_key(NOTE_PROVIDER_PROFILE_KEY).is_ok(),
            "guard_key must allow the profile key — reads remain accessible"
        );
    }

    // audit finding H3: the BAA ack row must be exactly as unreachable via
    // the generic KV surface as the API key. every_keychain_only_key_is_guarded
    // already covers this by iterating KEYCHAIN_ONLY_KEYS, but this test
    // pins the specific scenario the finding described so a future refactor
    // that accidentally drops the entry fails loudly with a finding-shaped
    // name, not just a generic allowlist-iteration failure.
    #[test]
    fn baa_ack_key_cannot_be_forged_via_generic_kv_set() {
        let err = guard_key(crate::baa::BAA_ACK_KEY).unwrap_err();
        assert!(matches!(err, AppError::InvalidInput(_)));
    }
}
