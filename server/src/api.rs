use axum::{
    extract::{Path, Query, State},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::auth::TenantCtx;
use crate::error::ApiError;
use crate::model::{AuditEntry, Encounter};
use crate::AppState;

// Liveness — process is up. Readiness — dependencies reachable (db/cache ping in
// the production impl). Kept separate so orchestrators can route traffic only
// once ready while still restarting on liveness failure.
pub async fn healthz() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

pub async fn readyz(State(_state): State<AppState>) -> impl IntoResponse {
    Json(json!({ "status": "ready" }))
}

#[derive(Deserialize)]
pub struct ListParams {
    pub limit: Option<usize>,
}

// Encounter lifecycle states the server will accept. Rejecting anything else at
// the boundary keeps bad client state out of the store.
const ALLOWED_STATUS: [&str; 6] = [
    "recording",
    "recording_done",
    "transcribing",
    "draft",
    "signed",
    "exported",
];

// Cache the full recent window once per tenant and truncate per request, so any
// limit is served from one cache entry and invalidation is a single key.
//
// The key is versioned (see `cache.rs`'s `Cache::bump_version` doc comment for
// the full rationale): `put_encounter` bumps the tenant's version before a
// concurrent `list_encounters`'s stale `set()` can land under a key any
// future reader will still ask for. This closes a stale-set-after-invalidate
// race that a plain "write store, then invalidate(key)" / "miss, read store,
// then set(key)" pairing has — see the regression test
// `list_after_concurrent_write_never_serves_a_stale_snapshot` in this module.
fn list_cache_prefix(tenant: &str) -> String {
    format!("enc:list:{tenant}")
}
fn list_cache_key(tenant: &str, version: u64) -> String {
    format!("{}:v{version}", list_cache_prefix(tenant))
}
const LIST_WINDOW: usize = 500;
const LIST_TTL: Duration = Duration::from_secs(30);

pub async fn list_encounters(
    State(state): State<AppState>,
    ctx: TenantCtx,
    Query(params): Query<ListParams>,
) -> Result<Json<Vec<Encounter>>, ApiError> {
    let limit = params.limit.unwrap_or(50).min(LIST_WINDOW);
    let prefix = list_cache_prefix(&ctx.tenant);
    // Snapshot the version BEFORE reading the store. If a write bumps the
    // version after this point but before our `set()` below, our `set()`
    // targets the (now-stale) key we snapshotted — a key no future reader
    // will request — instead of clobbering the fresh entry the writer's own
    // invalidation created space for.
    let version = state.cache.current_version(&prefix).await;
    let key = list_cache_key(&ctx.tenant, version);

    let mut rows: Vec<Encounter> = match state.cache.get(&key).await {
        Some(cached) => serde_json::from_str(&cached).unwrap_or_default(),
        None => {
            let fresh = state.store.list(&ctx.tenant, LIST_WINDOW).await?;
            if let Ok(json) = serde_json::to_string(&fresh) {
                state.cache.set(&key, json, LIST_TTL).await;
            }
            fresh
        }
    };
    rows.truncate(limit);
    Ok(Json(rows))
}

pub async fn get_encounter(
    State(state): State<AppState>,
    ctx: TenantCtx,
    Path(id): Path<String>,
) -> Result<Json<Encounter>, ApiError> {
    state
        .store
        .get(&ctx.tenant, &id)
        .await?
        .map(Json)
        .ok_or(ApiError::NotFound)
}

pub async fn put_encounter(
    State(state): State<AppState>,
    ctx: TenantCtx,
    Path(id): Path<String>,
    Json(mut enc): Json<Encounter>,
) -> Result<Json<Encounter>, ApiError> {
    if !enc.status.is_empty() && !ALLOWED_STATUS.contains(&enc.status.as_str()) {
        return Err(ApiError::BadRequest(format!("invalid status: {}", enc.status)));
    }
    // Path id and authenticated provider are authoritative — never trust the
    // body for identity. updated_at is the server's last-writer-wins clock.
    enc.id = id;
    enc.provider_id = ctx.provider.clone();
    enc.updated_at = now_ms();

    state.store.upsert(&ctx.tenant, enc.clone()).await?;
    // Bump (not delete): see `list_cache_prefix`'s doc comment. Any concurrent
    // reader who snapshotted the old version can still finish writing to the
    // old key harmlessly — nobody will read it again.
    state.cache.bump_version(&list_cache_prefix(&ctx.tenant)).await;
    Ok(Json(enc))
}

pub async fn post_audit(
    State(state): State<AppState>,
    ctx: TenantCtx,
    Path(id): Path<String>,
    Json(mut entry): Json<AuditEntry>,
) -> Result<Json<AuditEntry>, ApiError> {
    entry.encounter_id = id;
    entry.received_at = now_ms();
    state.store.append_audit(&ctx.tenant, entry.clone()).await?;
    Ok(Json(entry))
}

pub async fn list_audit(
    State(state): State<AppState>,
    ctx: TenantCtx,
    Path(id): Path<String>,
) -> Result<Json<Vec<AuditEntry>>, ApiError> {
    Ok(Json(state.store.list_audit(&ctx.tenant, &id).await?))
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
