use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Debug)]
pub enum ApiError {
    Unauthorized,
    TooManyRequests,
    NotFound,
    BadRequest(String),
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".to_string()),
            ApiError::TooManyRequests => (StatusCode::TOO_MANY_REQUESTS, "too many requests".to_string()),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not found".to_string()),
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            ApiError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
        };
        // Never leak internals to clients in the body; full detail goes to logs.
        if status == StatusCode::INTERNAL_SERVER_ERROR {
            tracing::error!("internal error: {message}");
            return (status, Json(json!({ "error": "internal error" }))).into_response();
        }
        (status, Json(json!({ "error": message }))).into_response()
    }
}

// Store errors surface as 500s without exposing their detail to the client.
impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError::Internal(e.to_string())
    }
}

// S1: any JWT verification failure (bad signature, expired, wrong issuer/
// audience, missing/blank claims, malformed token, unknown `kid`) collapses to
// a 401 — never a 500 that would leak internals or imply a server bug. The
// specific reason is logged at debug for operators; the client only learns
// "unauthorized".
impl From<jsonwebtoken::errors::Error> for ApiError {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        tracing::debug!("jwt verification failed: {e}");
        ApiError::Unauthorized
    }
}
