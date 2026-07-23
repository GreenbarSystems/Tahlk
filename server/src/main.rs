// tahlk-sync — Group-tier sync service.
//
// Layered: api (HTTP handlers) → store (data access) + cache, with auth/tenant
// extraction as middleware. The store and cache are traits behind Arc<dyn _>;
// the in-memory impls here let the service run with zero infrastructure, and
// the Postgres/Redis impls (see migrations/ + README) drop in without touching
// the handlers. Everything is tenant-scoped at the API boundary AND, in the
// Postgres impl, at the database via row-level security (defense in depth).
//
// Request pipeline for the tenant API (/v1/*): a global body-size limit and
// trace layer wrap everything; then `require_auth` verifies the JWT and derives
// the tenant, and `rate_limit` throttles per verified tenant. Health endpoints
// are intentionally left unauthenticated so orchestrators can probe them.

mod anthropic_proxy;
mod api;
mod auth;
mod cache;
mod config;
mod devices;
mod error;
mod issuer;
mod model;
mod store;

use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::Arc;

use axum::{
    extract::{ConnectInfo, State},
    middleware,
    routing::{get, post},
    Router,
};
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use auth::{require_auth, JwtVerifier, TenantCtx};
use cache::{Cache, InMemoryCache, RedisCache};
use config::{CacheConfig, Config};
use error::ApiError;
use issuer::JwtSigner;

// Max accepted request body. Encounters/audit entries are small JSON documents;
// 1 MiB is generous and caps memory a single request can force us to buffer.
const MAX_BODY_BYTES: usize = 1024 * 1024;
// Per-tenant request budget. Keyed on the verified tenant (never the source IP),
// so one noisy tenant can't exhaust capacity for the others and a shared NAT
// egress doesn't collapse independent tenants into one bucket.
const RATE_LIMIT_PER_MIN: u32 = 100;

// Per-source-IP budget for the PUBLIC device-registration route. This route is
// unauthenticated (no tenant exists yet), so it can't use the per-tenant limiter
// above — it's keyed on the source IP instead. Deliberately much tighter than
// the per-tenant budget: a legitimate device registers ~once and only re-hits
// this on reinstall/token-loss, so single digits per minute per IP is ample for
// real use while blocking registration spam that would otherwise churn the
// signer and grow the device registry. It's best-effort (a NAT'd fleet shares an
// IP, and the IP is spoofable without a trusted proxy), a coarse abuse throttle
// rather than a security control.
const DEVICE_RATE_LIMIT_PER_MIN: u32 = 10;

// Keyed rate limiter over verified tenant ids.
pub type TenantRateLimiter = DefaultKeyedRateLimiter<String>;
// Keyed rate limiter over source IPs, for the public registration route.
pub type IpRateLimiter = DefaultKeyedRateLimiter<IpAddr>;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn store::EncounterStore>,
    pub cache: Arc<dyn cache::Cache>,
    pub auth: Arc<JwtVerifier>,
    pub limiter: Arc<TenantRateLimiter>,
    pub anthropic: Arc<anthropic_proxy::AnthropicProxy>,
    // Signing side of the JWT story: mints tokens for POST /v1/devices/register.
    pub signer: Arc<JwtSigner>,
    // Registry of devices that have registered (auditable; revocation hook).
    pub devices: Arc<dyn store::DeviceStore>,
    // Per-IP limiter guarding the public registration route (see above).
    pub device_limiter: Arc<IpRateLimiter>,
}

// Middleware: throttle per verified tenant. Runs after `require_auth`, so the
// `TenantCtx` is already in extensions; if it isn't, fail closed with 401 rather
// than fall back to an unkeyed (bypassable) limit.
async fn rate_limit(
    State(state): State<AppState>,
    req: axum::extract::Request,
    next: middleware::Next,
) -> Result<axum::response::Response, ApiError> {
    let ctx = req
        .extensions()
        .get::<TenantCtx>()
        .cloned()
        .ok_or(ApiError::Unauthorized)?;
    if state.limiter.check_key(&ctx.tenant).is_err() {
        return Err(ApiError::TooManyRequests);
    }
    Ok(next.run(req).await)
}

// Middleware: throttle the public registration route per source IP. Runs before
// the handler (and before its body is parsed) so registration spam is rejected
// cheaply. The peer address comes from `ConnectInfo`, populated in production by
// `into_make_service_with_connect_info` (see `main`); fail closed with 401 if
// it's somehow absent rather than silently skipping the limit. Keyed on the IP
// only (port discarded) so a single client's ephemeral ports share one bucket.
async fn ip_rate_limit(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: axum::extract::Request,
    next: middleware::Next,
) -> Result<axum::response::Response, ApiError> {
    if state.device_limiter.check_key(&addr.ip()).is_err() {
        return Err(ApiError::TooManyRequests);
    }
    Ok(next.run(req).await)
}

// S2 fail-closed bind gate. TLS termination is an upstream responsibility (see
// server/README.md), so binding a non-loopback address exposes plaintext to the
// network. Refuse it unless the operator explicitly opted in with
// TAHLK_ALLOW_INSECURE=1. Pure function so it can be unit-tested.
fn enforce_bind_policy(addr: std::net::SocketAddr, allow_insecure: bool) -> Result<(), String> {
    let loopback = match addr.ip() {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    };
    if loopback || allow_insecure {
        return Ok(());
    }
    Err(format!(
        "refusing to bind non-loopback address {addr} without TLS: TLS termination is an \
         upstream responsibility. Set TAHLK_ALLOW_INSECURE=1 only if a TLS-terminating proxy \
         sits in front of this listener."
    ))
}

// Build the /v1 tenant API with auth + rate limiting. Split out so the
// integration tests can construct the exact same router the binary serves.
fn app(state: AppState) -> Router {
    // Tower layers wrap inside-out: the last `.layer` added is outermost. We
    // want auth to run before rate limiting (rate limiting needs the verified
    // tenant), so auth is added last.
    let protected = Router::new()
        .route("/v1/encounters", get(api::list_encounters))
        .route(
            "/v1/encounters/{id}",
            get(api::get_encounter).put(api::put_encounter),
        )
        .route(
            "/v1/encounters/{id}/audit",
            get(api::list_audit).post(api::post_audit),
        )
        // Managed-key Anthropic proxy. Registered here so it inherits the exact
        // `require_auth` + per-tenant `rate_limit` stack the encounter API uses —
        // no separate router, no duplicated auth/rate-limit layering.
        .route(
            "/v1/anthropic/v1/messages",
            post(anthropic_proxy::proxy_messages),
        )
        .layer(middleware::from_fn_with_state(state.clone(), rate_limit))
        .layer(middleware::from_fn_with_state(state.clone(), require_auth));

    // Public, unauthenticated registration route. Registered at the top level
    // (NOT inside `protected`) because a first-time device has no token yet; its
    // only gate is the per-IP limiter, applied here via `route_layer` so it
    // covers just this route and nothing else.
    let register = Router::new()
        .route("/v1/devices/register", post(devices::register))
        .route_layer(middleware::from_fn_with_state(state.clone(), ip_rate_limit));

    Router::new()
        .route("/healthz", get(api::healthz))
        .route("/readyz", get(api::readyz))
        .merge(protected)
        .merge(register)
        .with_state(state)
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(TraceLayer::new_for_http())
}

fn rate_limiter() -> TenantRateLimiter {
    let quota = Quota::per_minute(NonZeroU32::new(RATE_LIMIT_PER_MIN).expect("nonzero quota"));
    RateLimiter::keyed(quota)
}

fn device_rate_limiter() -> IpRateLimiter {
    let quota = Quota::per_minute(NonZeroU32::new(DEVICE_RATE_LIMIT_PER_MIN).expect("nonzero quota"));
    RateLimiter::keyed(quota)
}

// S4: construct the configured cache backend. `InMemory` is infallible; `Redis`
// connects eagerly and fails closed (exit 1) if the URL is unreachable, so a
// horizontally-scaled deployment never silently degrades to a per-replica cache
// (the stale-read bug S4 is about) — it either shares the cache or refuses to
// start.
async fn build_cache(cfg: &CacheConfig) -> Arc<dyn Cache> {
    match cfg {
        CacheConfig::InMemory => Arc::new(InMemoryCache::new()),
        CacheConfig::Redis { url } => match RedisCache::connect(url).await {
            Ok(c) => Arc::new(c),
            Err(e) => {
                eprintln!("redis cache init failed: {e}");
                std::process::exit(1);
            }
        },
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let cfg: Config = config::from_env();

    // S2: refuse to expose plaintext on a non-loopback address unless explicitly
    // opted in. Checked before we build anything else so misconfig fails fast.
    if let Err(e) = enforce_bind_policy(cfg.addr, cfg.allow_insecure_bind) {
        eprintln!("{e}");
        std::process::exit(1);
    }

    // S1: build the JWT verifier, failing closed if the JWKS can't be loaded (or
    // the auth config is incomplete) rather than serving unauthenticated traffic.
    let auth = match JwtVerifier::init(&cfg.auth).await {
        Ok(v) => Arc::new(v),
        Err(e) => {
            eprintln!("auth init failed: {e}");
            std::process::exit(1);
        }
    };

    // S4: select the cache backend. Defaults to the process-local in-memory
    // cache; `TAHLK_CACHE_BACKEND=redis` opts into the shared Redis cache
    // required before horizontal scaling. Fail closed if a configured Redis is
    // unreachable rather than silently degrading to a per-replica cache (which
    // is exactly the stale-read bug S4 is about).
    let cache = build_cache(&cfg.cache).await;

    // Managed-key proxy fail-closed gate: refuse to start without Greenbar's
    // server-side Anthropic key rather than let the proxy route 500 (or leak a
    // missing-key error) per request. Same posture as the JWKS/auth gate above.
    if cfg.anthropic.api_key.trim().is_empty() {
        eprintln!(
            "ANTHROPIC_API_KEY is not set: refusing to start the managed-key proxy without it"
        );
        std::process::exit(1);
    }
    let anthropic = Arc::new(anthropic_proxy::AnthropicProxy::new(&cfg.anthropic));

    // Token-issuance signing key gate: fail closed at startup if the signing key
    // (or its kid) is missing/malformed, so POST /v1/devices/register never 500s
    // per-request on a bad key. Same posture as the JWKS/auth and Anthropic gates
    // above. Reuses the verifier's issuer/audience so minted tokens verify.
    let signer = match JwtSigner::init(&cfg.auth.issuer, &cfg.auth.audience, &cfg.issuer) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("token issuer init failed: {e}");
            std::process::exit(1);
        }
    };

    // Swap InMemoryStore/InMemoryDeviceStore for the Postgres impls in production
    // (see README).
    let state = AppState {
        store: Arc::new(store::InMemoryStore::new()),
        cache,
        auth,
        limiter: Arc::new(rate_limiter()),
        anthropic,
        signer,
        devices: Arc::new(store::InMemoryDeviceStore::new()),
        device_limiter: Arc::new(device_rate_limiter()),
    };

    let app = app(state);

    let listener = tokio::net::TcpListener::bind(cfg.addr)
        .await
        .expect("failed to bind listener");
    tracing::info!("tahlk-sync listening on http://{}", cfg.addr);
    // `into_make_service_with_connect_info` surfaces the peer `SocketAddr` to the
    // per-IP registration limiter (`ip_rate_limit`); the rest of the app ignores
    // it. Without this the `ConnectInfo` extractor in that middleware would fail.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("server error");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::testkit::{self, MintOpts};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use std::time::Duration;
    use tower::ServiceExt;

    // A no-network Anthropic proxy for the router tests here (which never call the
    // proxy route). Points at an unroutable base URL; proxy-specific behavior is
    // covered in `anthropic_proxy`'s own tests against a mock upstream.
    fn test_anthropic() -> Arc<anthropic_proxy::AnthropicProxy> {
        Arc::new(anthropic_proxy::AnthropicProxy::new(&config::AnthropicConfig {
            api_key: "test-managed-key".to_string(),
            base_url: "http://127.0.0.1:1".to_string(),
            connect_timeout: Duration::from_secs(1),
            request_timeout: Duration::from_secs(5),
            max_response_bytes: 1024 * 1024,
        }))
    }

    // A router wired exactly like production but with the network-free test
    // verifier (trusts the embedded test key, no JWKS fetch) and a matching test
    // signer (signs with the same keypair the verifier trusts).
    fn test_app() -> Router {
        app(test_state())
    }

    // Shared AppState builder for the router tests, so the new signer/device
    // fields live in one place rather than being repeated per test.
    fn test_state() -> AppState {
        AppState {
            store: Arc::new(store::InMemoryStore::new()),
            cache: Arc::new(cache::InMemoryCache::new()),
            auth: Arc::new(testkit::verifier()),
            limiter: Arc::new(rate_limiter()),
            anthropic: test_anthropic(),
            signer: Arc::new(issuer::test_signer()),
            devices: Arc::new(store::InMemoryDeviceStore::new()),
            device_limiter: Arc::new(device_rate_limiter()),
        }
    }

    fn valid_token() -> String {
        testkit::mint(&MintOpts::default())
    }

    // Build a POST /v1/devices/register request, injecting a `ConnectInfo` peer
    // address into the request extensions (production sets this via
    // `into_make_service_with_connect_info`; `oneshot` in tests does not, so the
    // per-IP limiter middleware would otherwise 401 on a missing ConnectInfo).
    fn register_request(body: &str, ip: &str) -> Request<Body> {
        let mut req = Request::builder()
            .method("POST")
            .uri("/v1/devices/register")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(format!("{ip}:12345").parse::<SocketAddr>().unwrap()));
        req
    }

    #[tokio::test]
    async fn health_is_unauthenticated() {
        let resp = test_app()
            .oneshot(Request::builder().uri("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn protected_route_requires_a_token() {
        let resp = test_app()
            .oneshot(
                Request::builder()
                    .uri("/v1/encounters")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn valid_token_reaches_handler() {
        let resp = test_app()
            .oneshot(
                Request::builder()
                    .uri("/v1/encounters")
                    .header("authorization", format!("Bearer {}", valid_token()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // S1 regression: the old code trusted x-tenant-id. Prove that spoofing it
    // does nothing now — the tenant comes from the token, and the response for
    // an empty store is an empty list regardless of the header.
    #[tokio::test]
    async fn spoofed_tenant_header_is_ignored() {
        let app = test_app();
        // Seed one encounter under the token's real tenant (tenant-a) by PUTting it.
        let put = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v1/encounters/e1")
                    .header("authorization", format!("Bearer {}", valid_token()))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"status":"draft"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put.status(), StatusCode::OK);

        // Now list with a spoofed x-tenant-id pointing at a different tenant. If
        // the header were trusted we'd see an empty list for "victim"; instead
        // the verified tenant (tenant-a) is used and the seeded row comes back.
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/encounters")
                    .header("authorization", format!("Bearer {}", valid_token()))
                    .header("x-tenant-id", "victim")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let rows: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(rows.len(), 1, "verified tenant's data returned, header ignored");
    }

    #[tokio::test]
    async fn oversized_body_is_rejected_with_413() {
        // 2 MiB payload exceeds the 1 MiB limit.
        let big = vec![b'x'; 2 * 1024 * 1024];
        let resp = test_app()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v1/encounters/e1")
                    .header("authorization", format!("Bearer {}", valid_token()))
                    .header("content-type", "application/json")
                    .body(Body::from(big))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn rate_limit_kicks_in_after_the_budget() {
        let app = test_app();
        let token = valid_token();
        // The first RATE_LIMIT_PER_MIN requests are allowed; the next is 429.
        let mut last = StatusCode::OK;
        for _ in 0..RATE_LIMIT_PER_MIN {
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/v1/encounters")
                        .header("authorization", format!("Bearer {}", token))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            last = resp.status();
        }
        assert_eq!(last, StatusCode::OK, "budget requests should succeed");

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/encounters")
                    .header("authorization", format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    // --- Device registration (POST /v1/devices/register) ---------------------

    fn now_secs() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    async fn register_json(app: &Router, body: &str, ip: &str) -> (StatusCode, serde_json::Value) {
        let resp = app
            .clone()
            .oneshot(register_request(body, ip))
            .await
            .unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    #[tokio::test]
    async fn register_returns_a_token_and_sensible_expiry() {
        let app = test_app();
        let (status, json) = register_json(&app, r#"{"device_id":"device-abc"}"#, "203.0.113.7").await;
        assert_eq!(status, StatusCode::OK);
        let token = json["token"].as_str().expect("response carries a token");
        assert_eq!(token.split('.').count(), 3, "token is a well-formed JWS (three segments)");
        let exp = json["expires_at"].as_i64().expect("response carries expires_at");
        // ~90 days out (allow a wide margin so this never flakes on clock/CI).
        assert!(exp > now_secs() + 89 * 24 * 60 * 60, "expiry should be ~90 days in the future");
        assert!(exp < now_secs() + 91 * 24 * 60 * 60, "expiry should not exceed the 90-day lifetime");
    }

    #[tokio::test]
    async fn register_is_idempotent_by_device_id() {
        let app = test_app();
        let (s1, j1) = register_json(&app, r#"{"device_id":"same-device"}"#, "203.0.113.8").await;
        let (s2, j2) = register_json(&app, r#"{"device_id":"same-device"}"#, "203.0.113.8").await;
        assert_eq!(s1, StatusCode::OK);
        assert_eq!(s2, StatusCode::OK, "re-registering the same device_id must succeed, not error");
        assert!(j1["token"].is_string() && j2["token"].is_string(), "each call returns a fresh token");
    }

    #[tokio::test]
    async fn register_rejects_empty_missing_and_oversized_device_id() {
        let app = test_app();
        // Empty string.
        let (s_empty, _) = register_json(&app, r#"{"device_id":""}"#, "203.0.113.9").await;
        assert_eq!(s_empty, StatusCode::BAD_REQUEST);
        // Whitespace-only (would mint a token the verifier rejects as blank tenant).
        let (s_blank, _) = register_json(&app, r#"{"device_id":"   "}"#, "203.0.113.9").await;
        assert_eq!(s_blank, StatusCode::BAD_REQUEST);
        // Missing field entirely (serde default -> empty -> same 400 path).
        let (s_missing, _) = register_json(&app, r#"{}"#, "203.0.113.9").await;
        assert_eq!(s_missing, StatusCode::BAD_REQUEST);
        // Oversized (> 256 bytes).
        let huge = format!(r#"{{"device_id":"{}"}}"#, "x".repeat(257));
        let (s_big, _) = register_json(&app, &huge, "203.0.113.9").await;
        assert_eq!(s_big, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn register_is_rate_limited_per_ip() {
        let app = test_app();
        let ip = "198.51.100.42";
        // The first DEVICE_RATE_LIMIT_PER_MIN requests from one IP are allowed.
        for _ in 0..DEVICE_RATE_LIMIT_PER_MIN {
            let (status, _) = register_json(&app, r#"{"device_id":"d"}"#, ip).await;
            assert_eq!(status, StatusCode::OK);
        }
        // The next one from the same IP is throttled.
        let (status, _) = register_json(&app, r#"{"device_id":"d"}"#, ip).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        // A different IP still has its own budget (limiter is keyed per IP).
        let (other, _) = register_json(&app, r#"{"device_id":"d"}"#, "198.51.100.43").await;
        assert_eq!(other, StatusCode::OK);
    }

    // THE critical end-to-end test: a token minted by the registration endpoint
    // is accepted by the EXISTING `require_auth` middleware on an existing
    // protected route. This is the real proof that issuance (issuer.rs) and
    // verification (auth.rs) interoperate — not just that each works in isolation.
    #[tokio::test]
    async fn token_minted_by_register_is_accepted_by_require_auth() {
        let app = test_app();

        // 1. Register a device to obtain a token.
        let (status, json) = register_json(&app, r#"{"device_id":"interop-device"}"#, "203.0.113.10").await;
        assert_eq!(status, StatusCode::OK);
        let token = json["token"].as_str().unwrap().to_string();

        // 2. Use that token on a protected route guarded by `require_auth`.
        //    A 200 (not 401) proves the minted token verified end to end.
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/encounters")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a token minted by /v1/devices/register must be accepted by require_auth"
        );
    }

    // The public registration route must NOT sit behind `require_auth` — an
    // unauthenticated first-time caller (no token yet) must be able to reach it.
    #[tokio::test]
    async fn register_route_is_public() {
        let app = test_app();
        let (status, _) = register_json(&app, r#"{"device_id":"no-token-needed"}"#, "203.0.113.11").await;
        assert_ne!(status, StatusCode::UNAUTHORIZED, "registration must be reachable without a token");
        assert_eq!(status, StatusCode::OK);
    }

    #[test]
    fn bind_gate_allows_loopback() {
        assert!(enforce_bind_policy("127.0.0.1:8080".parse().unwrap(), false).is_ok());
        assert!(enforce_bind_policy("[::1]:8080".parse().unwrap(), false).is_ok());
    }

    #[test]
    fn bind_gate_refuses_non_loopback_by_default() {
        assert!(enforce_bind_policy("0.0.0.0:8080".parse().unwrap(), false).is_err());
        assert!(enforce_bind_policy("192.168.1.10:8080".parse().unwrap(), false).is_err());
    }

    #[test]
    fn bind_gate_allows_non_loopback_when_opted_in() {
        assert!(enforce_bind_policy("0.0.0.0:8080".parse().unwrap(), true).is_ok());
    }

    // --- Cache stale-set-after-invalidate race regression ---
    //
    // Reproduces the exact interleaving the bug report describes:
    //   1. Request A (a list) misses the cache and starts reading the store.
    //   2. Before A's `set()` lands, Request B (a write) commits to the store
    //      and invalidates/bumps the cache.
    //   3. A's now-stale `set()` finally lands.
    // With plain invalidate-then-set, step 3 repopulates the SAME key B just
    // cleared, serving stale data for a full TTL. With versioning, step 3
    // writes to the OLD version's key, which nothing will read again.
    //
    // `DelayedSetCache` wraps the real `InMemoryCache` and, on demand, makes
    // exactly one `set()` call block until a signal is sent — giving the test
    // full control over the interleaving instead of hoping a race window gets
    // hit by chance.
    struct DelayedSetCache {
        inner: cache::InMemoryCache,
        // Taken (leaving None) by the first `set()` call after being armed;
        // that call then awaits the receiver before actually writing through.
        gate: std::sync::Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
    }

    impl DelayedSetCache {
        fn new() -> (Arc<Self>, tokio::sync::oneshot::Sender<()>) {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let this = Arc::new(Self {
                inner: cache::InMemoryCache::new(),
                gate: std::sync::Mutex::new(Some(rx)),
            });
            (this, tx)
        }
    }

    #[async_trait::async_trait]
    impl cache::Cache for DelayedSetCache {
        async fn get(&self, key: &str) -> Option<String> {
            self.inner.get(key).await
        }
        async fn set(&self, key: &str, value: String, ttl: std::time::Duration) {
            let rx = self.gate.lock().unwrap().take();
            if let Some(rx) = rx {
                let _ = rx.await; // block this one call until the test releases it
            }
            self.inner.set(key, value, ttl).await;
        }
        async fn invalidate(&self, key: &str) {
            self.inner.invalidate(key).await;
        }
        async fn bump_version(&self, prefix: &str) -> u64 {
            self.inner.bump_version(prefix).await
        }
        async fn current_version(&self, prefix: &str) -> u64 {
            self.inner.current_version(prefix).await
        }
    }

    #[tokio::test]
    async fn list_after_concurrent_write_never_serves_a_stale_snapshot() {
        let (cache, release_stale_set) = DelayedSetCache::new();
        let state = AppState {
            cache,
            ..test_state()
        };
        let app = app(state);
        let token = valid_token();

        // Seed one encounter so the first list has something to (mis)cache.
        let seed = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v1/encounters/e1")
                    .header("authorization", format!("Bearer {}", token))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"status":"draft"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(seed.status(), StatusCode::OK);

        // Request A: start a list. Its cache miss will read the store (status
        // "draft") and then block on `set()` until we release it below — this
        // is us pinning down the exact race window instead of hoping for it.
        let app_a = app.clone();
        let token_a = token.clone();
        let list_task = tokio::spawn(async move {
            app_a
                .oneshot(
                    Request::builder()
                        .uri("/v1/encounters")
                        .header("authorization", format!("Bearer {}", token_a))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
        });

        // Give request A a moment to reach its (now-blocked) set() call.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        // Request B: write commits fresh data ("signed") to the store and
        // bumps/invalidates the cache — this is the concurrent write that
        // races A's stale set().
        let write = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v1/encounters/e1")
                    .header("authorization", format!("Bearer {}", token))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"status":"signed"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(write.status(), StatusCode::OK);

        // NOW let A's delayed set() finally land — after B's write/invalidate
        // already happened. This is the exact ordering that reproduces the bug.
        release_stale_set.send(()).unwrap();
        let list_a_resp = list_task.await.unwrap();
        assert_eq!(list_a_resp.status(), StatusCode::OK);

        // The bug: with plain invalidate-then-set, A's stale "draft" snapshot
        // would now sit in the cache under the same key, and this second list
        // request (a fresh cache lookup) would read it back instead of going
        // to the store. With versioning, A's stale set() landed under the OLD
        // version's key, so this fresh lookup misses and reads the store,
        // observing B's write.
        let list_b_resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/encounters")
                    .header("authorization", format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(list_b_resp.status(), StatusCode::OK);
        let body = list_b_resp.into_body().collect().await.unwrap().to_bytes();
        let rows: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            rows[0]["status"], "signed",
            "a list after a concurrent write must never observe a stale pre-write snapshot, \
             even when a racing reader's cache write lands after the writer's invalidation"
        );
    }
}
