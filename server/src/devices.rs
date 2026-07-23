// Device registration — POST /v1/devices/register.
//
// The one PUBLIC, unauthenticated route in the tenant API. A first-time device
// has no token yet (chicken-and-egg), so this route is registered OUTSIDE the
// `require_auth`/per-tenant `rate_limit` stack in `main.rs` and instead guarded
// by a per-source-IP limiter (see `AppState::device_limiter`) — there is no
// verified tenant to key a limiter on at this point in the pipeline.
//
// Flow: validate the opaque device_id, record it in the `DeviceStore` (auditable
// + a hook for future revocation), mint an RS256 token via `JwtSigner`, and
// return it. The token's `tenant_id` claim IS the device_id, so the very same
// `JwtVerifier` that guards the protected routes will accept it on the device's
// next call. Idempotent by device_id: repeat calls succeed and return a fresh
// token so a device that lost its token can silently re-enroll.

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::AppState;

// Upper bound on device_id length. It's an opaque client-generated key (a random
// UUID/hash in practice), so 256 bytes is comfortably generous while capping what
// an anonymous caller can push into the tenant claim / registry key.
const MAX_DEVICE_ID_BYTES: usize = 256;

#[derive(Deserialize)]
pub struct RegisterRequest {
    // `default` so a missing field deserializes to an empty string and is
    // rejected by the same non-empty check below with a 400 — rather than
    // surfacing serde's 422 for an absent field, which would split "missing" and
    // "empty" into two different status codes for what is the same client error.
    #[serde(default)]
    pub device_id: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub token: String,
    // Absolute token expiry as a unix timestamp (seconds). Unix rather than
    // ISO-8601 to avoid a date-formatting dependency for a machine consumer.
    pub expires_at: i64,
}

// The per-IP rate limit runs as middleware in `main.rs` before this handler, so
// by the time we're here the caller is within budget. `device_id` is validated
// for basic sanity only (it's opaque to us); `serde` already guarantees valid
// UTF-8, so we only check non-empty and length.
pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, ApiError> {
    // Reject blank/whitespace-only ids: they're useless as a tenant key AND the
    // verifier rejects a blank `tenant_id` claim, so a token minted from one
    // would be dead on arrival. Fail loudly at registration instead.
    if req.device_id.trim().is_empty() {
        return Err(ApiError::BadRequest("device_id must not be empty".to_string()));
    }
    if req.device_id.len() > MAX_DEVICE_ID_BYTES {
        return Err(ApiError::BadRequest(format!(
            "device_id exceeds maximum length of {MAX_DEVICE_ID_BYTES} bytes"
        )));
    }

    state.devices.register(&req.device_id).await?;
    let (token, expires_at) = state.signer.mint(&req.device_id)?;
    Ok(Json(RegisterResponse { token, expires_at }))
}
