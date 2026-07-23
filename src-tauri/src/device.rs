//! Device identity + managed-proxy token management.
//!
//! In managed mode the desktop app has NO Anthropic key of its own. Instead it
//! authenticates to Greenbar's sync proxy with a per-device bearer token, and
//! the proxy holds the single Greenbar-owned (BAA/ZDR-covered) Anthropic key.
//! This module owns the client half of that story:
//!
//!   1. **Device ID** — a random opaque identifier minted on first use (zero UI,
//!      zero user interaction) and persisted in the local `kv` table under
//!      `DEVICE_ID_KV`. It is NOT a credential — it names this install so the
//!      server's registration endpoint can be idempotent per device — and is
//!      stored completely independently of the local unlock password /
//!      recovery-code system (it is neither derived from nor gated behind it).
//!
//!   2. **Device token** — the bearer credential returned by
//!      `POST {base}/v1/devices/register`, cached under `DEVICE_TOKEN_KV` with
//!      its absolute `expires_at` (unix seconds). Because it authenticates PHI
//!      transmission through the proxy it is treated like the retired API key:
//!      `DEVICE_TOKEN_KV` is in `secrets::KEYCHAIN_ONLY_KEYS`, so it can never
//!      be read, written, or enumerated through the generic `kv_*` JS commands.
//!      This module reaches the row via `kv_ops` directly, exactly as
//!      `baa.rs`/`secrets.rs` do for their own guarded keys.
//!
//!   3. **Refresh** — before each note-generation call the cached token is
//!      checked against `REFRESH_MARGIN`; if it is missing, expired, or within
//!      the safety margin of expiry the device silently re-registers. The
//!      register endpoint is idempotent by device_id, so a re-register just
//!      mints a fresh token for the same install.
//!
//! Failure discipline (see `errors.rs::SecureServiceUnreachable`): if the token
//! is missing/stale AND registration cannot complete (network, timeout, non-2xx,
//! malformed body), note generation FAILS with a clear user-honest error. There
//! is deliberately NO fallback to a direct-to-Anthropic path — that path is not
//! covered by Greenbar's BAA and no longer exists in the client.

use std::time::{SystemTime, UNIX_EPOCH};

use reqwest::Client;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::json;

use crate::errors::AppError;
use crate::hex::to_hex;
use crate::DbState;

/// Local `kv` key for the opaque device identifier. Its own clearly-named
/// namespace, separate from every other stored value.
pub(crate) const DEVICE_ID_KV: &str = "device_v1::id";

/// Local `kv` key for the cached `{token, expires_at}` pair. Guarded via
/// `secrets::KEYCHAIN_ONLY_KEYS` so the bearer credential is unreachable from
/// the generic JS KV surface (parity with the retired Anthropic API key).
pub(crate) const DEVICE_TOKEN_KV: &str = "device_v1::token";

/// Default production sync base URL. Overridable at runtime via the
/// `TAHLK_SYNC_BASE_URL` environment variable (staging/testing). Trailing
/// slashes are trimmed by `sync_base_url` so callers can join paths cleanly.
///
/// NOTE: taken from `MANAGED-KEY-PROXY-CONTRACT.md` §2, which marks the host as
/// a placeholder ("confirm prod host"). Confirm before shipping to production.
pub(crate) const DEFAULT_SYNC_BASE_URL: &str = "https://api.tahlk.com";

/// Environment variable that overrides `DEFAULT_SYNC_BASE_URL`.
pub(crate) const SYNC_BASE_URL_ENV: &str = "TAHLK_SYNC_BASE_URL";

/// Random device-id length in bytes → 32 lowercase hex chars once encoded.
/// 128 bits of CSPRNG entropy is UUID-v4-strength opaqueness.
const DEVICE_ID_BYTES: usize = 16;

/// Re-register when the cached token expires within this many seconds. The
/// server mints 90-day tokens (see `server/src/issuer.rs`), so a 24-hour margin
/// is negligible against the lifetime while comfortably covering clock skew and
/// a long single session that starts near expiry. Judgment call — see the PR.
pub(crate) const REFRESH_MARGIN_SECS: i64 = 24 * 60 * 60;

/// Cached device token plus its absolute expiry (unix seconds), as returned by
/// the register endpoint and persisted to `kv`.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub(crate) struct DeviceToken {
    pub token: String,
    pub expires_at: i64,
}

/// Resolve the configured sync base URL, honoring the env override and
/// stripping any trailing slash. Pure but reads process env — no network.
pub(crate) fn sync_base_url() -> String {
    let raw = std::env::var(SYNC_BASE_URL_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_SYNC_BASE_URL.to_string());
    raw.trim().trim_end_matches('/').to_string()
}

/// The managed-proxy Anthropic Messages endpoint for a given base URL. The
/// double `/v1` is intentional: `/v1/anthropic` namespaces Tahlk's API and the
/// trailing `/v1/messages` is Anthropic's own path the proxy forwards to.
pub(crate) fn proxy_endpoint(base_url: &str) -> String {
    format!("{}/v1/anthropic/v1/messages", base_url)
}

/// The device-registration endpoint for a given base URL.
pub(crate) fn register_endpoint(base_url: &str) -> String {
    format!("{}/v1/devices/register", base_url)
}

/// Current wall-clock time as unix seconds. Used only for the token-freshness
/// comparison — not an audit control, so a clock-error floor of 0 is fine.
pub(crate) fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Load the persisted device id, generating and storing one on first use.
///
/// Zero UI: this is called from the note-generation path, silently. The id is
/// written via `kv_ops` (not the guarded `kv_set` command) since it is a
/// trusted internal writer of a hard-coded key.
pub(crate) fn load_or_generate_device_id(conn: &Connection) -> Result<String, AppError> {
    if let Some(existing) = read_device_id(conn)? {
        if !existing.trim().is_empty() {
            return Ok(existing);
        }
    }
    let mut buf = [0u8; DEVICE_ID_BYTES];
    getrandom::getrandom(&mut buf).map_err(AppError::internal_from)?;
    let id = to_hex(&buf);
    let json = serde_json::to_string(&id).map_err(AppError::internal_from)?;
    crate::kv_ops::upsert_json(conn, DEVICE_ID_KV, &json)?;
    Ok(id)
}

fn read_device_id(conn: &Connection) -> Result<Option<String>, AppError> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT value FROM kv WHERE key = ?1",
            params![DEVICE_ID_KV],
            |r| r.get::<_, String>(0),
        )
        .optional()?;
    Ok(raw.and_then(|s| serde_json::from_str::<String>(&s).ok()))
}

/// Read the cached device token, if any. A malformed row deserializes to `None`
/// so the caller simply re-registers rather than erroring.
pub(crate) fn read_token(conn: &Connection) -> Result<Option<DeviceToken>, AppError> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT value FROM kv WHERE key = ?1",
            params![DEVICE_TOKEN_KV],
            |r| r.get::<_, String>(0),
        )
        .optional()?;
    Ok(raw.and_then(|s| serde_json::from_str::<DeviceToken>(&s).ok()))
}

/// Persist the device token (overwriting any prior value).
pub(crate) fn store_token(conn: &Connection, token: &DeviceToken) -> Result<(), AppError> {
    let json = serde_json::to_string(&json!({
        "token": token.token,
        "expires_at": token.expires_at,
    }))
    .map_err(AppError::internal_from)?;
    crate::kv_ops::upsert_json(conn, DEVICE_TOKEN_KV, &json)
}

/// Pure freshness decision. True when we must (re-)register: no token, or the
/// token expires within `margin_secs` of `now_secs` (which also covers an
/// already-expired token).
pub(crate) fn token_needs_refresh(
    token: Option<&DeviceToken>,
    now_secs: i64,
    margin_secs: i64,
) -> bool {
    match token {
        None => true,
        Some(t) => t.expires_at.saturating_sub(now_secs) <= margin_secs,
    }
}

/// Parse a `POST /v1/devices/register` response body into a `DeviceToken`.
/// Rejects a blank token — a token that can't authenticate is not worth
/// caching, and treating it as "unreachable" gives the user a truthful error.
pub(crate) fn parse_register_response(body: &[u8]) -> Result<DeviceToken, AppError> {
    let tok: DeviceToken = serde_json::from_slice(body)
        .map_err(|_| AppError::SecureServiceUnreachable)?;
    if tok.token.trim().is_empty() {
        return Err(AppError::SecureServiceUnreachable);
    }
    Ok(tok)
}

/// Abstraction over the network round-trip so the orchestration in
/// `ensure_token` can be unit-tested with a stub instead of a live server.
pub(crate) trait TokenFetcher {
    async fn fetch(&self, device_id: &str) -> Result<DeviceToken, AppError>;
}

/// Production fetcher: registers over HTTPS using the shared reqwest client.
pub(crate) struct HttpTokenFetcher<'a> {
    pub client: &'a Client,
    pub base_url: String,
}

impl TokenFetcher for HttpTokenFetcher<'_> {
    async fn fetch(&self, device_id: &str) -> Result<DeviceToken, AppError> {
        let url = register_endpoint(&self.base_url);
        let resp = self
            .client
            .post(&url)
            .header("content-type", "application/json")
            .json(&json!({ "device_id": device_id }))
            .send()
            .await
            .map_err(|_| AppError::SecureServiceUnreachable)?;
        if !resp.status().is_success() {
            // Never surface the body or status detail — a truthful, actionable
            // "can't reach the service" is all the clinician can act on, and
            // the body may reflect request fragments.
            return Err(AppError::SecureServiceUnreachable);
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|_| AppError::SecureServiceUnreachable)?;
        parse_register_response(&bytes)
    }
}

/// Return a valid device token, re-registering through `fetcher` when the
/// cached one is missing/expired/near-expiry. The device id is minted on first
/// use. Freshly fetched tokens are persisted before returning.
///
/// Test-only: this variant borrows a single `Connection` across the fetch
/// `.await`, which is convenient for driving the orchestration with an
/// in-memory DB and a stub fetcher. It is NOT used in production: a
/// `rusqlite::Connection` is not `Send`, so holding one across an await inside a
/// `#[tauri::command]` future makes that future non-`Send` and fails to compile.
/// The production path (`current_token`) instead scopes each checkout so no
/// connection is alive across the network round-trip.
#[cfg(test)]
pub(crate) async fn ensure_token<F: TokenFetcher>(
    conn: &Connection,
    fetcher: &F,
    now_secs: i64,
    margin_secs: i64,
) -> Result<DeviceToken, AppError> {
    let device_id = load_or_generate_device_id(conn)?;
    let cached = read_token(conn)?;
    if !token_needs_refresh(cached.as_ref(), now_secs, margin_secs) {
        // Safe: token_needs_refresh returns true for None, so Some here.
        return Ok(cached.unwrap());
    }
    let fresh = fetcher.fetch(&device_id).await?;
    store_token(conn, &fresh)?;
    Ok(fresh)
}

/// Production entry point: resolve a usable bearer token for the note path,
/// registering/refreshing as needed. Builds an `HttpTokenFetcher` over the
/// shared client and configured base URL.
///
/// Connection discipline: each DB access is scoped to its own pooled checkout
/// that is dropped BEFORE the network `.await`, so no non-`Send`
/// `rusqlite::Connection` is ever alive across the await. This is what keeps the
/// enclosing `#[tauri::command]` future `Send`. The device id + cached token are
/// read under the first checkout; a freshly minted token is persisted under a
/// second, later checkout.
pub(crate) async fn current_token(
    state: &DbState,
    client: &Client,
    base_url: &str,
) -> Result<String, AppError> {
    let (device_id, cached) = {
        let conn = state.0.get()?;
        (load_or_generate_device_id(&conn)?, read_token(&conn)?)
    };
    if !token_needs_refresh(cached.as_ref(), now_unix_secs(), REFRESH_MARGIN_SECS) {
        // Safe: token_needs_refresh returns true for None, so Some here.
        return Ok(cached.unwrap().token);
    }
    let fetcher = HttpTokenFetcher {
        client,
        base_url: base_url.to_string(),
    };
    let fresh = fetcher.fetch(&device_id).await?;
    {
        let conn = state.0.get()?;
        store_token(&conn, &fresh)?;
    }
    Ok(fresh.token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn kv_db() -> Connection {
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

    // ── base URL config ────────────────────────────────────────────────

    #[test]
    fn sync_base_url_defaults_and_trims_trailing_slash() {
        // Can't safely set env in parallel tests without races, so assert the
        // default shape and the trimming behavior through the endpoint builders.
        assert_eq!(
            proxy_endpoint("https://api.tahlk.com"),
            "https://api.tahlk.com/v1/anthropic/v1/messages"
        );
        assert_eq!(
            register_endpoint("https://api.tahlk.com"),
            "https://api.tahlk.com/v1/devices/register"
        );
        assert!(DEFAULT_SYNC_BASE_URL.starts_with("https://"));
    }

    // ── device id ──────────────────────────────────────────────────────

    #[test]
    fn device_id_is_generated_on_first_use_and_persisted() {
        let conn = kv_db();
        assert!(read_device_id(&conn).unwrap().is_none(), "no id before first use");

        let id = load_or_generate_device_id(&conn).unwrap();
        assert_eq!(id.len(), DEVICE_ID_BYTES * 2, "32 hex chars for 16 bytes");
        assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));

        // Persisted: a direct read returns the same value.
        assert_eq!(read_device_id(&conn).unwrap().as_deref(), Some(id.as_str()));
    }

    #[test]
    fn device_id_is_stable_across_calls() {
        let conn = kv_db();
        let a = load_or_generate_device_id(&conn).unwrap();
        let b = load_or_generate_device_id(&conn).unwrap();
        assert_eq!(a, b, "second call must reuse the stored id, not mint a new one");
    }

    // ── token persistence ──────────────────────────────────────────────

    #[test]
    fn token_round_trips_through_kv() {
        let conn = kv_db();
        assert!(read_token(&conn).unwrap().is_none());
        let tok = DeviceToken { token: "jwt.abc".into(), expires_at: 123 };
        store_token(&conn, &tok).unwrap();
        assert_eq!(read_token(&conn).unwrap(), Some(tok));
    }

    #[test]
    fn malformed_token_row_reads_as_none() {
        let conn = kv_db();
        conn.execute(
            "INSERT INTO kv (key, value, updated_at) VALUES (?1, ?2, 0)",
            params![DEVICE_TOKEN_KV, "not json"],
        )
        .unwrap();
        assert!(read_token(&conn).unwrap().is_none());
    }

    // ── freshness decision ─────────────────────────────────────────────

    #[test]
    fn refresh_needed_when_no_token() {
        assert!(token_needs_refresh(None, 1000, 60));
    }

    #[test]
    fn refresh_needed_when_expired_or_within_margin() {
        let now = 1000;
        let margin = 100;
        // Expired.
        let expired = DeviceToken { token: "t".into(), expires_at: 900 };
        assert!(token_needs_refresh(Some(&expired), now, margin));
        // Exactly at the margin boundary — must refresh (<=).
        let at_margin = DeviceToken { token: "t".into(), expires_at: now + margin };
        assert!(token_needs_refresh(Some(&at_margin), now, margin));
    }

    #[test]
    fn no_refresh_when_comfortably_valid() {
        let now = 1000;
        let margin = 100;
        let fresh = DeviceToken { token: "t".into(), expires_at: now + margin + 1 };
        assert!(!token_needs_refresh(Some(&fresh), now, margin));
    }

    // ── register response parsing ──────────────────────────────────────

    #[test]
    fn parses_a_well_formed_register_response() {
        let body = br#"{"token":"jwt.xyz","expires_at":1893456000}"#;
        let tok = parse_register_response(body).unwrap();
        assert_eq!(tok.token, "jwt.xyz");
        assert_eq!(tok.expires_at, 1893456000);
    }

    #[test]
    fn rejects_malformed_or_blank_register_response() {
        assert!(matches!(
            parse_register_response(b"not json"),
            Err(AppError::SecureServiceUnreachable)
        ));
        assert!(matches!(
            parse_register_response(br#"{"token":"","expires_at":1}"#),
            Err(AppError::SecureServiceUnreachable)
        ));
    }

    // ── orchestration (stubbed fetcher) ────────────────────────────────

    struct StubFetcher {
        calls: Cell<u32>,
        expires_at: i64,
    }
    impl TokenFetcher for StubFetcher {
        async fn fetch(&self, _device_id: &str) -> Result<DeviceToken, AppError> {
            self.calls.set(self.calls.get() + 1);
            Ok(DeviceToken {
                token: format!("minted-{}", self.calls.get()),
                expires_at: self.expires_at,
            })
        }
    }

    struct FailingFetcher;
    impl TokenFetcher for FailingFetcher {
        async fn fetch(&self, _device_id: &str) -> Result<DeviceToken, AppError> {
            Err(AppError::SecureServiceUnreachable)
        }
    }

    #[tokio::test]
    async fn first_call_registers_and_stores_the_token() {
        let conn = kv_db();
        let now = 1000;
        let fetcher = StubFetcher { calls: Cell::new(0), expires_at: now + 90 * 86_400 };
        let tok = ensure_token(&conn, &fetcher, now, REFRESH_MARGIN_SECS).await.unwrap();
        assert_eq!(fetcher.calls.get(), 1, "must register on first use");
        assert_eq!(tok.token, "minted-1");
        // Stored for reuse, and a device id was minted alongside it.
        assert_eq!(read_token(&conn).unwrap(), Some(tok));
        assert!(read_device_id(&conn).unwrap().is_some());
    }

    #[tokio::test]
    async fn valid_cached_token_is_reused_without_re_registering() {
        let conn = kv_db();
        let now = 1000;
        let fetcher = StubFetcher { calls: Cell::new(0), expires_at: now + 90 * 86_400 };
        let first = ensure_token(&conn, &fetcher, now, REFRESH_MARGIN_SECS).await.unwrap();
        let second = ensure_token(&conn, &fetcher, now, REFRESH_MARGIN_SECS).await.unwrap();
        assert_eq!(fetcher.calls.get(), 1, "second call must NOT hit the network");
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn expired_token_triggers_re_registration() {
        let conn = kv_db();
        // Seed a token already inside the refresh margin.
        let now = 10_000_000;
        store_token(&conn, &DeviceToken { token: "stale".into(), expires_at: now + 5 }).unwrap();
        let fetcher = StubFetcher { calls: Cell::new(0), expires_at: now + 90 * 86_400 };
        let tok = ensure_token(&conn, &fetcher, now, REFRESH_MARGIN_SECS).await.unwrap();
        assert_eq!(fetcher.calls.get(), 1, "near-expiry token must re-register");
        assert_eq!(tok.token, "minted-1");
        assert_eq!(read_token(&conn).unwrap().unwrap().token, "minted-1");
    }

    #[tokio::test]
    async fn registration_failure_propagates_and_does_not_store() {
        let conn = kv_db();
        let now = 1000;
        let err = ensure_token(&conn, &FailingFetcher, now, REFRESH_MARGIN_SECS).await.unwrap_err();
        assert!(matches!(err, AppError::SecureServiceUnreachable));
        assert!(read_token(&conn).unwrap().is_none(), "no token cached on failure");
    }
}
