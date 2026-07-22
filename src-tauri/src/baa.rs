//! Anthropic BAA acknowledgment gate (fixes audit finding C2).
//!
//! Under 45 CFR §164.502(e), Anthropic is a "business associate" when Tahlk
//! transmits PHI-bearing transcripts to their API. Anthropic *does* offer a
//! BAA-eligible tier, but a standard consumer API key is NOT covered by it —
//! the covered entity must have executed a BAA with Anthropic separately and
//! be using the account/endpoint that BAA names. Without that, every note
//! generation is a §164.502(a)(1) impermissible disclosure.
//!
//! We can't verify Anthropic's contracts from the client. What we CAN do is
//! refuse to transmit until the provider has affirmatively attested that the
//! account they entered IS covered — and record the attestation with a
//! timestamp + provider identity so the practice has an audit trail if HHS
//! ever asks.
//!
//! Storage lives in the KV table under `note_settings_v1::baa_ack` so the
//! ack is encrypted at rest with the rest of the DB (see `db` module).
//! Removing the key un-acknowledges the gate; a fresh install requires the
//! ack again before any `generate_note` call can succeed.
//!
//! Wire shape (also matches the JS side under `keys.baaAck()`):
//! ```json
//! {
//!   "acknowledged": true,
//!   "acknowledged_at": "2026-07-04T14:22:11Z",
//!   "provider_id": "dr.jane.smith@example.com",   // may be empty string
//!   "attestation_version": 1
//! }
//! ```
//!
//! We deliberately do NOT store the API key or any Anthropic account
//! identifier here — the covered entity can inspect the KV row and share
//! that during an audit without leaking the credential.
//!
//! Bumping `ATTESTATION_VERSION` forces the user through the modal again
//! (e.g., if we materially change what they're attesting to).
//!
//! The gate is enforced in `notes::generate_note` before ANY network I/O so
//! a compromised WebView can't bypass it by skipping the JS-side modal.

use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::State;

use crate::errors::AppError;
use crate::DbState;

// KV key format matches the JS `keys.baaAck()` helper. Living under
// `note_settings_v1::` groups it with the existing onboarded / telemetry
// flags rather than inventing a new prefix.
pub(crate) const BAA_ACK_KEY: &str = "note_settings_v1::baa_ack";

/// Runtime toggle for gate ENFORCEMENT (storage, Settings UI, and this
/// module's tests are unaffected either way). Set to `false` for the current
/// beta phase — see ADR 0003 (`docs/adr/0003-disable-baa-gate-for-beta.md`):
/// testers use synthetic/test data only until Tahlk's managed Anthropic key
/// (with an org-level BAA) ships, so per-provider BYOK attestation is pure
/// friction with no compliance benefit right now.
///
/// MUST be flipped back to `true` before any real PHI reaches this build —
/// either once the managed-key proxy lands, or sooner if beta scope changes.
/// This is a single choke-point flag, not a deletion: re-enabling is a
/// one-line change plus restoring the onboarding step (see the ADR).
pub(crate) const GATE_ENABLED: bool = true;

/// Attestation schema version. Bumping this forces the user through the
/// modal again on next launch. Keep the JS `BAA_ATTESTATION_VERSION`
/// constant in `src/data/baa.js` in sync.
pub(crate) const ATTESTATION_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BaaAck {
    /// True iff the provider explicitly checked the box in the modal.
    /// Anything else (missing row, `false`, older attestation_version) is
    /// treated as un-acknowledged.
    pub acknowledged: bool,
    /// ISO-8601 UTC timestamp captured on the JS side when the box was
    /// checked. Not validated by Rust (client clocks lie) — it's an
    /// evidentiary breadcrumb, not a security control.
    #[serde(default)]
    pub acknowledged_at: String,
    /// Free-text provider identity for the audit trail. Whatever the
    /// clinician entered at onboarding — we do not attempt to normalize
    /// or verify it. Empty string is allowed but frowned upon.
    #[serde(default)]
    pub provider_id: String,
    /// Version of the attestation copy the provider agreed to. Bumping
    /// `ATTESTATION_VERSION` invalidates older acks so the user re-consents.
    #[serde(default)]
    pub attestation_version: u32,
}

/// Reads the BAA ack row from KV. Returns `None` if the row is missing,
/// malformed, or represents an older / rejected attestation. Callers get
/// a Some only when the gate is currently satisfied for the CURRENT
/// attestation version.
pub(crate) fn read_ack(state: &State<DbState>) -> Result<Option<BaaAck>, AppError> {
    let conn = state.0.get()?;
    let row: Option<String> = conn
        .query_row(
            "SELECT value FROM kv WHERE key = ?1",
            params![BAA_ACK_KEY],
            |r| r.get(0),
        )
        .optional()?;
    drop(conn);

    let Some(json) = row else { return Ok(None) };
    // Malformed rows (schema drift, corruption) count as un-acknowledged
    // rather than blowing up note generation with a serde error. Fail
    // closed on the gate, not on the app itself.
    let ack: BaaAck = match serde_json::from_str(&json) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    if !ack.acknowledged || ack.attestation_version < ATTESTATION_VERSION {
        return Ok(None);
    }
    Ok(Some(ack))
}

/// Pure decision logic for `require_ack`, extracted so it is unit-testable
/// without a live `State<DbState>` (see the existing `read_ack`/`parse_ack_json`
/// split above for the same pattern). When the gate is disabled, a real stored
/// ack is still honored and returned — so a tester whose org already has a BAA
/// keeps accurate attribution in the `llm_audit` table — but a missing ack no
/// longer errors; a placeholder (unacknowledged, empty provider_id) fills in.
fn resolve_ack(stored: Option<BaaAck>, gate_enabled: bool) -> Result<BaaAck, AppError> {
    if gate_enabled {
        return stored.ok_or(AppError::BaaRequired);
    }
    Ok(stored.unwrap_or(BaaAck {
        acknowledged: false,
        acknowledged_at: String::new(),
        provider_id: String::new(),
        attestation_version: 0,
    }))
}

/// The single choke point every PHI-egress command must call before doing
/// network I/O. Returns `AppError::BaaRequired` if the ack is missing or
/// stale AND `GATE_ENABLED` is true, so the JS side can surface a specific
/// "open BAA modal" CTA. See `GATE_ENABLED`'s doc comment for why this is
/// currently non-blocking.
pub(crate) fn require_ack(state: &State<DbState>) -> Result<BaaAck, AppError> {
    resolve_ack(read_ack(state)?, GATE_ENABLED)
}

/// #[tauri::command] wrapper — returns the current ack (or null) so the
/// Settings UI can render a green / red state without having to speak KV.
/// Deliberately narrow: callers get exactly what's needed to render, no
/// access to arbitrary KV rows through this path.
#[tauri::command]
pub(crate) fn baa_ack_status(state: State<DbState>) -> Result<Value, AppError> {
    let ack = read_ack(&state)?;
    Ok(match ack {
        Some(a) => serde_json::json!({
            "acknowledged": true,
            "acknowledged_at": a.acknowledged_at,
            "provider_id": a.provider_id,
            "attestation_version": a.attestation_version,
        }),
        None => serde_json::json!({
            "acknowledged": false,
            "attestation_version_required": ATTESTATION_VERSION,
        }),
    })
}

/// #[tauri::command] wrapper — writes the ack row. `provider_id` is
/// clamped to `crate::MAX_PROVIDER_ID_BYTES` so a compromised WebView can't
/// stash arbitrary data in the audit trail. Timestamp is captured server-side
/// too so we have a Rust-generated witness alongside the JS-provided one.
#[tauri::command]
pub(crate) fn baa_ack_set(
    state: State<DbState>,
    acknowledged: bool,
    acknowledged_at: String,
    provider_id: String,
) -> Result<(), AppError> {
    if acknowledged_at.len() > 64 {
        return Err(AppError::invalid("acknowledged_at exceeds 64 bytes"));
    }
    if provider_id.len() > crate::MAX_PROVIDER_ID_BYTES {
        return Err(AppError::invalid(format!(
            "provider_id exceeds {} bytes",
            crate::MAX_PROVIDER_ID_BYTES
        )));
    }

    let ack = BaaAck {
        acknowledged,
        acknowledged_at,
        provider_id,
        attestation_version: ATTESTATION_VERSION,
    };
    let json = serde_json::to_string(&ack).map_err(AppError::internal_from)?;
    let conn = state.0.get()?;
    crate::kv_ops::upsert_json(&conn, BAA_ACK_KEY, &json)
}

/// #[tauri::command] wrapper — clears the ack. Idempotent (no error if
/// the row didn't exist). Used by Settings when a provider needs to
/// re-attest after a BAA renegotiation, or by uninstall/reset flows.
#[tauri::command]
pub(crate) fn baa_ack_clear(state: State<DbState>) -> Result<(), AppError> {
    let conn = state.0.get()?;
    crate::kv_ops::delete_by_key(&conn, BAA_ACK_KEY)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    //! These live under db-integration territory (they need a Connection),
    //! so they set up an in-memory SQLite and drive `read_ack` through raw
    //! rusqlite instead of through the Tauri `State<DbState>` wrapper.

    use super::*;
    use rusqlite::Connection;

    fn fresh_kv() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE kv (
                key        TEXT PRIMARY KEY,
                value      TEXT NOT NULL,
                updated_at INTEGER NOT NULL
             );",
        )
        .unwrap();
        conn
    }

    fn put_ack(conn: &Connection, json: &str) {
        conn.execute(
            "INSERT INTO kv (key, value, updated_at) VALUES (?1, ?2, 0)",
            params![BAA_ACK_KEY, json],
        )
        .unwrap();
    }

    // Parses (and version-checks) an ack blob the way `read_ack` does,
    // but against a bare Connection so tests don't need to build a full
    // Tauri State stack.
    fn parse_ack_json(conn: &Connection) -> Option<BaaAck> {
        let row: Option<String> = conn
            .query_row(
                "SELECT value FROM kv WHERE key = ?1",
                params![BAA_ACK_KEY],
                |r| r.get(0),
            )
            .optional()
            .unwrap();
        let json = row?;
        let ack: BaaAck = serde_json::from_str(&json).ok()?;
        if !ack.acknowledged || ack.attestation_version < ATTESTATION_VERSION {
            return None;
        }
        Some(ack)
    }

    #[test]
    fn missing_row_is_unack() {
        let conn = fresh_kv();
        assert!(parse_ack_json(&conn).is_none());
    }

    #[test]
    fn happy_path_ack() {
        let conn = fresh_kv();
        put_ack(
            &conn,
            &format!(
                r#"{{"acknowledged":true,"acknowledged_at":"2026-07-04T14:22:11Z","provider_id":"jane@example.com","attestation_version":{}}}"#,
                ATTESTATION_VERSION
            ),
        );
        let ack = parse_ack_json(&conn).expect("should be acknowledged");
        assert_eq!(ack.provider_id, "jane@example.com");
    }

    #[test]
    fn stale_attestation_version_is_unack() {
        let conn = fresh_kv();
        put_ack(
            &conn,
            r#"{"acknowledged":true,"acknowledged_at":"2026-01-01T00:00:00Z","provider_id":"x","attestation_version":0}"#,
        );
        assert!(
            parse_ack_json(&conn).is_none(),
            "older attestation_version must not satisfy the gate"
        );
    }

    #[test]
    fn acknowledged_false_is_unack() {
        let conn = fresh_kv();
        put_ack(
            &conn,
            &format!(
                r#"{{"acknowledged":false,"acknowledged_at":"","provider_id":"","attestation_version":{}}}"#,
                ATTESTATION_VERSION
            ),
        );
        assert!(parse_ack_json(&conn).is_none());
    }

    #[test]
    fn malformed_row_is_unack_not_error() {
        let conn = fresh_kv();
        put_ack(&conn, "not json at all");
        // `read_ack` swallows serde errors; we replicate that here.
        let row: Option<String> = conn
            .query_row(
                "SELECT value FROM kv WHERE key = ?1",
                params![BAA_ACK_KEY],
                |r| r.get(0),
            )
            .optional()
            .unwrap();
        let json = row.unwrap();
        let parsed: Result<BaaAck, _> = serde_json::from_str(&json);
        assert!(parsed.is_err(), "malformed rows must be a serde err");
        // read_ack maps that err to Ok(None), so the effective gate state
        // is un-acknowledged — the app must NOT crash.
    }

    // ── resolve_ack: gate enabled/disabled decision logic (ADR 0003) ────────

    fn sample_ack(provider_id: &str) -> BaaAck {
        BaaAck {
            acknowledged: true,
            acknowledged_at: "2026-07-04T14:22:11Z".into(),
            provider_id: provider_id.into(),
            attestation_version: ATTESTATION_VERSION,
        }
    }

    #[test]
    fn gate_enabled_requires_ack() {
        assert!(matches!(resolve_ack(None, true), Err(AppError::BaaRequired)));
    }

    #[test]
    fn gate_enabled_passes_through_existing_ack() {
        let got = resolve_ack(Some(sample_ack("jane")), true).unwrap();
        assert_eq!(got.provider_id, "jane");
    }

    #[test]
    fn gate_disabled_allows_missing_ack() {
        let got = resolve_ack(None, false).expect("disabled gate must not error on missing ack");
        assert!(!got.acknowledged);
        assert_eq!(got.provider_id, "");
    }

    #[test]
    fn gate_disabled_still_preserves_a_real_acks_identity() {
        // A tester whose org already has its own BAA can still record it via
        // Settings; the disabled gate must not discard that attribution.
        let got = resolve_ack(Some(sample_ack("jane")), false).unwrap();
        assert_eq!(got.provider_id, "jane");
    }

    #[test]
    fn error_code_wire_shape() {
        // The JS side branches on `code === 'baa_required'`. Guard that
        // string here so a rename in errors.rs breaks this test loudly.
        let err = AppError::BaaRequired;
        let json = serde_json::to_string(&err).unwrap();
        assert!(
            json.contains(r#""code":"baa_required""#),
            "unexpected serialized shape: {}",
            json
        );
    }
}
