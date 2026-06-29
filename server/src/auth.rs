use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::error::ApiError;

// Authenticated request context. Extracted before any handler runs, so a
// handler cannot execute without a tenant + provider. This stub validates the
// shape of a bearer token and reads tenant/provider headers; the production
// build verifies a signed JWT (issuer, audience, expiry, signature) and derives
// tenant_id + provider_id from its claims rather than trusting headers.
pub struct TenantCtx {
    pub tenant: String,
    pub provider: String,
}

impl<S: Send + Sync> FromRequestParts<S> for TenantCtx {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let headers = &parts.headers;

        let has_bearer = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.starts_with("Bearer "))
            .unwrap_or(false);

        let tenant = headers
            .get("x-tenant-id")
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        let provider = headers
            .get("x-provider-id")
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        match (has_bearer, tenant, provider) {
            (true, Some(tenant), Some(provider)) => Ok(TenantCtx { tenant, provider }),
            _ => Err(ApiError::Unauthorized),
        }
    }
}
