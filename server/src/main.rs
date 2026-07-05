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

mod api;
mod auth;
mod cache;
mod config;
mod error;
mod model;
mod store;

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;

use axum::{extract::State, middleware, routing::get, Router};
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use auth::{require_auth, JwtVerifier, TenantCtx};
use cache::{Cache, InMemoryCache, RedisCache};
use config::{CacheConfig, Config};
use error::ApiError;

// Max accepted request body. Encounters/audit entries are small JSON documents;
// 1 MiB is generous and caps memory a single request can force us to buffer.
const MAX_BODY_BYTES: usize = 1024 * 1024;
// Per-tenant request budget. Keyed on the verified tenant (never the source IP),
// so one noisy tenant can't exhaust capacity for the others and a shared NAT
// egress doesn't collapse independent tenants into one bucket.
const RATE_LIMIT_PER_MIN: u32 = 100;

// Keyed rate limiter over verified tenant ids.
pub type TenantRateLimiter = DefaultKeyedRateLimiter<String>;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn store::EncounterStore>,
    pub cache: Arc<dyn cache::Cache>,
    pub auth: Arc<JwtVerifier>,
    pub limiter: Arc<TenantRateLimiter>,
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
        .layer(middleware::from_fn_with_state(state.clone(), rate_limit))
        .layer(middleware::from_fn_with_state(state.clone(), require_auth));

    Router::new()
        .route("/healthz", get(api::healthz))
        .route("/readyz", get(api::readyz))
        .merge(protected)
        .with_state(state)
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(TraceLayer::new_for_http())
}

fn rate_limiter() -> TenantRateLimiter {
    let quota = Quota::per_minute(NonZeroU32::new(RATE_LIMIT_PER_MIN).expect("nonzero quota"));
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

    // Swap InMemoryStore for PostgresStore in production (see README).
    let state = AppState {
        store: Arc::new(store::InMemoryStore::new()),
        cache,
        auth,
        limiter: Arc::new(rate_limiter()),
    };

    let app = app(state);

    let listener = tokio::net::TcpListener::bind(cfg.addr)
        .await
        .expect("failed to bind listener");
    tracing::info!("tahlk-sync listening on http://{}", cfg.addr);
    axum::serve(listener, app).await.expect("server error");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::testkit::{self, MintOpts};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    // A router wired exactly like production but with the network-free test
    // verifier (trusts the embedded test key, no JWKS fetch).
    fn test_app() -> Router {
        let state = AppState {
            store: Arc::new(store::InMemoryStore::new()),
            cache: Arc::new(cache::InMemoryCache::new()),
            auth: Arc::new(testkit::verifier()),
            limiter: Arc::new(rate_limiter()),
        };
        app(state)
    }

    fn valid_token() -> String {
        testkit::mint(&MintOpts::default())
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
}
