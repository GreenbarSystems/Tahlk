// Managed-key Anthropic proxy (Phase 1).
//
// A thin passthrough for the Anthropic Messages API at
// `POST /v1/anthropic/v1/messages`. The desktop client sends the same body it
// sends to Anthropic today, minus any credentials; this proxy injects Greenbar's
// own ZDR-covered `x-api-key`, forwards to `{upstream}/v1/messages`, and streams
// the SSE response straight back. It exists because the direct-to-Anthropic BYOK
// path is NOT covered by Greenbar's BAA/ZDR agreement — only the managed key is.
//
// HIPAA-critical: every request body is PHI (a session transcript). This module
// NEVER logs, buffers-to-disk, or persists request/response content — only
// per-call metadata (tenant, provider, model, byte counts, outcome, latency).
// See MANAGED-KEY-PROXY-CONTRACT.md §7.
//
// The route is registered inside the same `protected` router as the encounter
// API, so it inherits `require_auth` + per-tenant `rate_limit` unchanged.

use std::time::Instant;

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::Response;
use futures_util::StreamExt;
use reqwest::Client;

use crate::auth::TenantCtx;
use crate::config::AnthropicConfig;
use crate::error::ApiError;
use crate::AppState;

// Headers the proxy sets on the upstream call. The client's token authenticates
// it to us; the Anthropic key is added here and never accepted from the client.
const ANTHROPIC_VERSION: &str = "2023-06-01";

// Holds the shared upstream client and policy. One per process, cloned cheaply
// via the `Arc` in `AppState` (reqwest::Client is itself an Arc internally).
pub struct AnthropicProxy {
    client: Client,
    base_url: String,
    api_key: String,
    max_response_bytes: usize,
}

impl AnthropicProxy {
    pub fn new(cfg: &AnthropicConfig) -> Self {
        // TLS 1.2+ enforced on the upstream hop (rustls), mirroring notes.rs.
        let client = Client::builder()
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .connect_timeout(cfg.connect_timeout)
            .timeout(cfg.request_timeout)
            .build()
            .expect("failed to build Anthropic upstream client");
        Self {
            client,
            base_url: cfg.base_url.trim_end_matches('/').to_string(),
            api_key: cfg.api_key.clone(),
            max_response_bytes: cfg.max_response_bytes,
        }
    }
}

// Metadata-only audit record. Deliberately carries NO body/prompt/note text.
struct CallAudit {
    tenant: String,
    provider: String,
    model: String,
    request_bytes: usize,
    started: Instant,
}

impl CallAudit {
    // Emitted once the outcome is known (streaming responses log after the body
    // drains, so `response_bytes` is the true count actually proxied through).
    fn emit(&self, status: u16, outcome: &str, response_bytes: usize) {
        tracing::info!(
            tenant = %self.tenant,
            provider = %self.provider,
            model = %self.model,
            request_bytes = self.request_bytes,
            response_bytes,
            upstream_status = status,
            outcome,
            latency_ms = self.started.elapsed().as_millis() as u64,
            "anthropic proxy call"
        );
    }
}

// POST /v1/anthropic/v1/messages
//
// `TenantCtx` proves auth + rate-limit middleware already ran (the handler is
// unreachable without a verified tenant — see the extractor in auth.rs, which
// fails closed with 401 if the context is absent). The request body is taken as
// opaque bytes and forwarded verbatim; we parse it only enough to (a) confirm it
// is a JSON object shaped like a Messages request and (b) pull the model name
// for the audit log — never inspecting or transforming the PHI content.
pub async fn proxy_messages(
    State(state): State<AppState>,
    ctx: TenantCtx,
    body: Bytes,
) -> Result<Response, ApiError> {
    let proxy = &state.anthropic;
    let audit = CallAudit {
        tenant: ctx.tenant.clone(),
        provider: ctx.provider.clone(),
        model: extract_model(&body)?,
        request_bytes: body.len(),
        started: Instant::now(),
    };

    let url = format!("{}/v1/messages", proxy.base_url);
    let upstream = proxy
        .client
        .post(&url)
        .header("x-api-key", &proxy.api_key)
        .header("anthropic-version", ANTHROPIC_VERSION)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await;

    let resp = match upstream {
        Ok(r) => r,
        Err(e) => {
            // Transport failure or deadline. Never surface the reqwest error
            // text (it can embed the upstream URL); map to status only.
            let (outcome, err) = if e.is_timeout() || e.is_connect() {
                ("timeout", ApiError::GatewayTimeout)
            } else {
                ("error", ApiError::BadGateway)
            };
            audit.emit(0, outcome, 0);
            return Err(err);
        }
    };

    let status = resp.status();
    if !status.is_success() {
        let err = map_upstream_status(status);
        audit.emit(status.as_u16(), "upstream_error", 0);
        return Err(err);
    }

    // Streaming passthrough: forward the upstream SSE body straight through as a
    // streaming axum response, counting bytes and aborting if the hard cap is
    // exceeded. We do NOT buffer the whole response — that would break the
    // token-by-token UX and let a misbehaving upstream force unbounded memory.
    let content_type = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("text/event-stream")
        .to_string();

    let stream = capped_stream(resp, proxy.max_response_bytes, status.as_u16(), audit);

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from_stream(stream))
        .map_err(|e| ApiError::Internal(e.to_string()))
}

// Wrap the upstream byte stream, enforcing the size cap and emitting the audit
// log once the stream terminates (success, cap-exceeded, or upstream error).
// Aborting mid-stream simply ends the response body; the client sees a truncated
// SSE stream, which is the intended fail-closed behavior for a runaway upstream.
fn capped_stream(
    resp: reqwest::Response,
    max_bytes: usize,
    status: u16,
    audit: CallAudit,
) -> impl futures_util::Stream<Item = Result<Bytes, std::io::Error>> {
    async_stream::stream! {
        let mut upstream = resp.bytes_stream();
        let mut total: usize = 0;
        let mut outcome = "success";
        while let Some(item) = upstream.next().await {
            match item {
                Ok(chunk) => {
                    if total.saturating_add(chunk.len()) > max_bytes {
                        outcome = "response_cap_exceeded";
                        yield Err(std::io::Error::other("upstream response exceeded size cap"));
                        break;
                    }
                    total += chunk.len();
                    yield Ok(chunk);
                }
                Err(_) => {
                    // Never propagate the upstream error text (may embed URL).
                    outcome = "upstream_stream_error";
                    yield Err(std::io::Error::other("upstream stream error"));
                    break;
                }
            }
        }
        audit.emit(status, outcome, total);
    }
}

// Parse just enough to validate the Messages request shape and pull the model
// name for the audit log. Returns the model (or "unknown" if absent) on success.
// The full body is still forwarded verbatim regardless — this only gates
// obviously-malformed input and never mutates the payload.
fn extract_model(body: &[u8]) -> Result<String, ApiError> {
    let value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|_| ApiError::BadRequest("request body must be valid JSON".to_string()))?;
    let obj = value
        .as_object()
        .ok_or_else(|| ApiError::BadRequest("request body must be a JSON object".to_string()))?;
    if !obj.contains_key("messages") {
        return Err(ApiError::BadRequest(
            "request body missing 'messages'".to_string(),
        ));
    }
    Ok(obj
        .get("model")
        .and_then(|m| m.as_str())
        .unwrap_or("unknown")
        .to_string())
}

// Upstream status → client-facing status, per MANAGED-KEY-PROXY-CONTRACT.md §6.
// Anthropic 401/403 are OUR key's problem and must never leak to the client, so
// they collapse to 502 like any other unmapped error. 429 passes through (client
// back-off is correct). 529 (overloaded) → 503.
fn map_upstream_status(status: StatusCode) -> ApiError {
    match status.as_u16() {
        429 => ApiError::TooManyRequests,
        529 => ApiError::ServiceUnavailable,
        _ => ApiError::BadGateway,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::testkit::{self, MintOpts};
    use crate::{app, rate_limiter, AppState};
    use axum::http::Request;
    use axum::response::IntoResponse;
    use axum::routing::{any, post};
    use axum::Router;
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use std::time::Duration;
    use tower::ServiceExt;

    const PROXY_PATH: &str = "/v1/anthropic/v1/messages";
    const SAMPLE_BODY: &str =
        r#"{"model":"claude-haiku-4-5-20251001","max_tokens":2048,"messages":[]}"#;

    // Spin up a throwaway upstream on an ephemeral loopback port serving `router`,
    // returning its base URL (e.g. "http://127.0.0.1:54321"). The server task is
    // detached; it lives until the test process exits. Hand-rolled with the
    // existing axum/tokio deps rather than pulling in wiremock for one shape.
    async fn spawn_upstream(router: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        format!("http://{addr}")
    }

    // An AppState wired like production (test JWT verifier, real limiter) with the
    // proxy pointed at `base_url`.
    fn state_with_upstream(base_url: &str) -> AppState {
        AppState {
            store: Arc::new(crate::store::InMemoryStore::new()),
            cache: Arc::new(crate::cache::InMemoryCache::new()),
            auth: Arc::new(testkit::verifier()),
            limiter: Arc::new(rate_limiter()),
            anthropic: Arc::new(AnthropicProxy::new(&AnthropicConfig {
                api_key: "test-managed-key".to_string(),
                base_url: base_url.to_string(),
                connect_timeout: Duration::from_secs(2),
                request_timeout: Duration::from_secs(10),
                max_response_bytes: 1024,
            })),
        }
    }

    fn token() -> String {
        testkit::mint(&MintOpts::default())
    }

    fn proxy_request(token: Option<&str>) -> Request<Body> {
        let mut b = Request::builder()
            .method("POST")
            .uri(PROXY_PATH)
            .header("content-type", "application/json");
        if let Some(t) = token {
            b = b.header("authorization", format!("Bearer {t}"));
        }
        b.body(Body::from(SAMPLE_BODY)).unwrap()
    }

    // Auth: the proxy route inherits `require_auth`, so no token → 401. It never
    // reaches the (unreachable) upstream, proving auth runs first / fails closed.
    #[tokio::test]
    async fn proxy_requires_a_token() {
        let app = app(state_with_upstream("http://127.0.0.1:1"));
        let resp = app.oneshot(proxy_request(None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // Streaming passthrough: a small SSE stream from the mock upstream comes back
    // intact, with the SSE content-type preserved.
    #[tokio::test]
    async fn streams_sse_passthrough() {
        let sse = "event: message_start\ndata: {\"type\":\"message_start\"}\n\n\
                   event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
        let upstream = Router::new().route(
            "/v1/messages",
            post(move || async move {
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/event-stream")
                    .body(Body::from(sse))
                    .unwrap()
            }),
        );
        let base = spawn_upstream(upstream).await;
        let app = app(state_with_upstream(&base));

        let resp = app.oneshot(proxy_request(Some(&token()))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/event-stream"
        );
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], sse.as_bytes());
    }

    // Size cap: an upstream that returns more than `max_response_bytes` (1024 in
    // tests) has its stream aborted. axum surfaces a mid-stream body error by
    // terminating the connection, so collecting the body errors out.
    #[tokio::test]
    async fn oversized_response_is_capped() {
        let huge = vec![b'x'; 4096];
        let upstream = Router::new().route(
            "/v1/messages",
            post(move || {
                let huge = huge.clone();
                async move {
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "text/event-stream")
                        .body(Body::from(huge))
                        .unwrap()
                }
            }),
        );
        let base = spawn_upstream(upstream).await;
        let app = app(state_with_upstream(&base));

        let resp = app.oneshot(proxy_request(Some(&token()))).await.unwrap();
        // Headers (200) are sent before the body streams, so the status is OK;
        // the cap manifests as a body-stream error partway through.
        assert_eq!(resp.status(), StatusCode::OK);
        let collected = resp.into_body().collect().await;
        assert!(
            collected.is_err(),
            "streaming past the size cap must abort the body, not deliver it whole"
        );
    }

    // Upstream 401/403 (OUR key's problem) must NOT leak to the client — it maps
    // to 502, never 401/403.
    #[tokio::test]
    async fn upstream_auth_failure_maps_to_502_not_leaked() {
        let upstream = Router::new().route(
            "/v1/messages",
            any(|| async { (StatusCode::UNAUTHORIZED, "invalid x-api-key").into_response() }),
        );
        let base = spawn_upstream(upstream).await;
        let app = app(state_with_upstream(&base));

        let resp = app.oneshot(proxy_request(Some(&token()))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    // Upstream 429 passes through as 429 so the client backs off.
    #[tokio::test]
    async fn upstream_rate_limit_maps_to_429() {
        let upstream = Router::new().route(
            "/v1/messages",
            any(|| async { StatusCode::TOO_MANY_REQUESTS.into_response() }),
        );
        let base = spawn_upstream(upstream).await;
        let app = app(state_with_upstream(&base));

        let resp = app.oneshot(proxy_request(Some(&token()))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    // A malformed (non-JSON) body is rejected at the boundary before any upstream
    // call, so a broken client can't spend Greenbar's key on garbage.
    #[tokio::test]
    async fn malformed_body_is_rejected_before_forwarding() {
        let app = app(state_with_upstream("http://127.0.0.1:1"));
        let req = Request::builder()
            .method("POST")
            .uri(PROXY_PATH)
            .header("authorization", format!("Bearer {}", token()))
            .header("content-type", "application/json")
            .body(Body::from("not json"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // Per-tenant rate limiting applies to the proxy route too, since it shares the
    // exact `rate_limit` + `require_auth` stack. Point at a mock upstream that
    // 200s so the budget requests succeed, then confirm the (budget+1)th is 429.
    #[tokio::test]
    async fn rate_limit_applies_to_proxy_route() {
        let upstream = Router::new().route(
            "/v1/messages",
            post(|| async {
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/event-stream")
                    .body(Body::from("data: {}\n\n"))
                    .unwrap()
            }),
        );
        let base = spawn_upstream(upstream).await;
        let app = app(state_with_upstream(&base));
        let tok = token();

        for _ in 0..crate::RATE_LIMIT_PER_MIN {
            let resp = app.clone().oneshot(proxy_request(Some(&tok))).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }
        let resp = app.oneshot(proxy_request(Some(&tok))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
