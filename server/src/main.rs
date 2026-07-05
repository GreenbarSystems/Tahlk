// tahlk-sync — Group-tier sync service.
//
// Layered: api (HTTP handlers) → store (data access) + cache, with auth/tenant
// extraction as middleware. The store and cache are traits behind Arc<dyn _>;
// the in-memory impls here let the service run with zero infrastructure, and
// the Postgres/Redis impls (see migrations/ + README) drop in without touching
// the handlers. Everything is tenant-scoped at the API boundary AND, in the
// Postgres impl, at the database via row-level security (defense in depth).
//
// SECURITY — DO NOT DEPLOY. Open audit findings S1 (stub auth) and S2 (no TLS,
// no rate limits, no body-size limit, no fail-closed bind gate) make this
// service unsafe for any deployment against real tenants. The service is
// frozen per ADR 0001, so the fixes are intentionally deferred; see
// server/README.md and docs/security/pre-deploy-checklist.md for the concrete
// remediation plan that MUST land before unfreeze.

mod api;
mod auth;
mod cache;
mod config;
mod error;
mod model;
mod store;

use std::sync::Arc;

use axum::{routing::get, Router};
use tower_http::trace::TraceLayer;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn store::EncounterStore>,
    pub cache: Arc<dyn cache::Cache>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let cfg = config::from_env();

    // Swap these two lines for PostgresStore / RedisCache in production.
    let state = AppState {
        store: Arc::new(store::InMemoryStore::new()),
        cache: Arc::new(cache::InMemoryCache::new()),
    };

    let app = Router::new()
        .route("/healthz", get(api::healthz))
        .route("/readyz", get(api::readyz))
        .route("/v1/encounters", get(api::list_encounters))
        .route("/v1/encounters/{id}", get(api::get_encounter).put(api::put_encounter))
        .route("/v1/encounters/{id}/audit", get(api::list_audit).post(api::post_audit))
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(cfg.addr)
        .await
        .expect("failed to bind listener");
    tracing::info!("tahlk-sync listening on http://{}", cfg.addr);
    axum::serve(listener, app).await.expect("server error");
}
