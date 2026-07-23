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
    // Managed-key Anthropic proxy upstream failures. Status-only by design: the
    // upstream response body is never forwarded, so nothing data-like (or the
    // state of Greenbar's own key) can leak to the client. See anthropic_proxy.rs.
    BadGateway,          // upstream returned an unmapped 4xx/5xx (incl. its own 401/403)
    ServiceUnavailable,  // upstream overloaded (Anthropic 529)
    GatewayTimeout,      // upstream call exceeded the proxy deadline / transport error
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".to_string()),
            ApiError::TooManyRequests => (StatusCode::TOO_MANY_REQUESTS, "too many requests".to_string()),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not found".to_string()),
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            ApiError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
            ApiError::BadGateway => (StatusCode::BAD_GATEWAY, "upstream error".to_string()),
            ApiError::ServiceUnavailable => {
                (StatusCode::SERVICE_UNAVAILABLE, "upstream unavailable".to_string())
            }
            ApiError::GatewayTimeout => (StatusCode::GATEWAY_TIMEOUT, "upstream timeout".to_string()),
        };
        // Never leak internals to clients in the body; full detail goes to logs.
        if status == StatusCode::INTERNAL_SERVER_ERROR {
            // S3: do NOT string-interpolate the raw error into the log *message*.
            // The message stays a stable static string; the (redacted) detail
            // rides in a named `error` field. This keeps a fixed shape that log
            // processors can filter/redact on, and `redact` scrubs the obvious
            // sensitive substrings (URL credentials, `password=`/`secret=` in a
            // libpq-style connection string) that a store error could embed once
            // the Postgres backend lands.
            tracing::error!(error = %redact(&message), "internal server error");
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
// specific reason is logged (structured + redacted) at debug for operators; the
// client only learns "unauthorized".
impl From<jsonwebtoken::errors::Error> for ApiError {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        tracing::debug!(error = %redact(&e.to_string()), "jwt verification failed");
        ApiError::Unauthorized
    }
}

// S3 redaction. A dependency-free filter over the two substrings a store/driver
// error is most likely to embed:
//   * URL userinfo — `scheme://user:pass@host/…` → `scheme://[REDACTED]@host/…`
//   * sensitive `key=value` pairs (libpq DSN / query strings) → `key=[REDACTED]`
//
// This is intentionally modest for the current in-memory state (no real DB
// traffic). The documented plan (see docs/security/pre-deploy-checklist.md, S3)
// is to promote this to a `tracing_subscriber` `Layer` that redacts *every*
// field on *every* event once the Postgres store — whose errors can carry SQL
// fragments with tenant IDs — is wired in.
fn redact(detail: &str) -> String {
    redact_kv_secrets(&redact_url_userinfo(detail))
}

fn redact_url_userinfo(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find("://") {
        let (before, after_scheme) = rest.split_at(pos + 3);
        out.push_str(before); // includes the "://"
        // Authority ends at the first path/query/quote/space or end of string.
        let auth_end = after_scheme
            .find(|c: char| matches!(c, '/' | '?' | ' ' | '"' | '\'' | '\t' | '\n'))
            .unwrap_or(after_scheme.len());
        let authority = &after_scheme[..auth_end];
        match authority.find('@') {
            Some(at) => {
                out.push_str("[REDACTED]@");
                out.push_str(&authority[at + 1..]);
            }
            None => out.push_str(authority),
        }
        rest = &after_scheme[auth_end..];
    }
    out.push_str(rest);
    out
}

const SENSITIVE_KEYS: [&str; 7] = [
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
];

fn redact_kv_secrets(s: &str) -> String {
    let lower = s.to_ascii_lowercase();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        // A sensitive key matches only at a word boundary and must be followed
        // (allowing spaces) by '='. `eq` is the index of that '='.
        let boundary = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
        let eq = boundary
            .then(|| {
                SENSITIVE_KEYS.iter().find_map(|key| {
                    if !lower[i..].starts_with(key) {
                        return None;
                    }
                    let mut j = i + key.len();
                    while j < bytes.len() && bytes[j] == b' ' {
                        j += 1;
                    }
                    (j < bytes.len() && bytes[j] == b'=').then_some(j)
                })
            })
            .flatten();

        if let Some(eq) = eq {
            out.push_str(&s[i..=eq]); // key + interior spaces + '='
            // Preserve any spaces between '=' and the value, then mask the value
            // itself up to the next delimiter.
            let mut p = eq + 1;
            while p < bytes.len() && bytes[p] == b' ' {
                out.push(' ');
                p += 1;
            }
            out.push_str("[REDACTED]");
            let mut k = p;
            while k < bytes.len() && !matches!(bytes[k], b' ' | b';' | b'&' | b'\t' | b'\n') {
                k += 1;
            }
            i = k;
            continue;
        }

        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_url_credentials() {
        assert_eq!(
            redact("connect failed: postgres://tahlk:hunter2@db.internal:5432/tahlk_prod timed out"),
            "connect failed: postgres://[REDACTED]@db.internal:5432/tahlk_prod timed out"
        );
    }

    #[test]
    fn redacts_url_without_userinfo_is_unchanged_authority() {
        assert_eq!(
            redact("GET https://api.example.com/jwks failed"),
            "GET https://api.example.com/jwks failed"
        );
    }

    #[test]
    fn redacts_sensitive_kv_pairs() {
        assert_eq!(
            redact("host=db.internal password=s3cr3t dbname=tahlk"),
            "host=db.internal password=[REDACTED] dbname=tahlk"
        );
        // Case-insensitive key, spaces around '=', semicolon-delimited value.
        assert_eq!(
            redact("Server=db;PWD = topsecret;Db=tahlk"),
            "Server=db;PWD = [REDACTED];Db=tahlk"
        );
    }

    #[test]
    fn does_not_redact_non_sensitive_or_substring_keys() {
        // `dbname` contains no sensitive key at a boundary; `token_count` is not
        // a bare `token=` value.
        assert_eq!(redact("dbname=tahlk rows=42"), "dbname=tahlk rows=42");
        assert_eq!(redact("token_count=42"), "token_count=42");
    }

    #[test]
    fn benign_message_passes_through() {
        let msg = "row not found for encounter enc-1";
        assert_eq!(redact(msg), msg);
    }
}
