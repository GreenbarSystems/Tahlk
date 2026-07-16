// S1 remediation — real JWT verification.
//
// Before this change `TenantCtx` only checked that `Authorization` started with
// `Bearer ` and then trusted the `x-tenant-id` / `x-provider-id` request headers
// verbatim, so any client could read any tenant by spoofing a header. That path
// is gone. Requests are now authenticated by a signed JWT whose signature is
// verified against a JWKS fetched from the configured issuer; `tenant` and
// `provider` are derived from the token's claims and never from headers.
//
// Shape:
//   * `JwtVerifier` holds the issuer/audience it will accept plus a `kid`-keyed
//     cache of decoding keys. On a `kid` cache miss it refreshes the JWKS once
//     and retries, so key rotation at the IdP is picked up without a restart.
//   * `require_auth` middleware runs before any handler, verifies the token, and
//     inserts the resulting `TenantCtx` into request extensions. `TenantCtx`'s
//     extractor just reads it back, so a handler still cannot run without one.
//   * Startup fails closed if the JWKS is unreachable (see `JwtVerifier::init`),
//     unless the operator explicitly opts into the local dev-bypass mode.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use axum::extract::{FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::header::AUTHORIZATION;
use axum::middleware::Next;
use axum::response::Response;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Header, Validation};
use parking_lot::RwLock;
use serde::Deserialize;

use crate::config::AuthConfig;
use crate::error::ApiError;
use crate::AppState;

// Authenticated request context. Derived entirely from verified JWT claims.
#[derive(Clone, Debug)]
pub struct TenantCtx {
    pub tenant: String,
    pub provider: String,
}

// Claims we read out of the token. `exp`, `nbf`, `iss`, and `aud` are validated
// by `jsonwebtoken` itself (via `Validation`) against a separately-parsed
// registered-claims struct, so they don't need to appear here; we only pull the
// two custom claims that identify the caller.
#[derive(Debug, Deserialize)]
struct Claims {
    #[serde(default)]
    tenant_id: String,
    #[serde(default)]
    provider_id: String,
}

// Minimum time between JWKS fetches triggered by a `kid` cache miss. Without
// this, a client that sends requests with random/unknown `kid` values forces
// one JWKS HTTP round-trip PER REQUEST (`select_key` refreshes on every miss),
// which is an amplification vector: a small stream of bad requests to us turns
// into sustained load against the IdP's JWKS endpoint, and each of our own
// requests now blocks on that extra network hop too. A real key rotation still
// gets picked up promptly (worst case one cooldown window of delay), which is
// an acceptable trade for not being an amplifier.
const JWKS_REFRESH_COOLDOWN: Duration = Duration::from_secs(30);

pub struct JwtVerifier {
    issuer: String,
    audience: String,
    // kid -> decoding key, refreshed from the JWKS endpoint.
    keys: RwLock<HashMap<String, DecodingKey>>,
    // None in production (keys come from the JWKS); Some in local dev-bypass mode,
    // where a symmetric HS256 secret stands in for a real IdP.
    dev_hs256: Option<DecodingKey>,
    // Empty in dev-bypass mode.
    jwks_url: String,
    http: reqwest::Client,
    // Last time `refresh_jwks` actually hit the network, plus a single-flight
    // lock so concurrent misses coalesce into one fetch instead of a thundering
    // herd. `tokio::sync::Mutex` (not `parking_lot`) because we hold it across
    // the `.await` of the HTTP call.
    last_refresh: RwLock<Option<Instant>>,
    refresh_lock: tokio::sync::Mutex<()>,
}

impl JwtVerifier {
    // Build the verifier from environment config, failing closed on any
    // misconfiguration or an unreachable JWKS endpoint. Returns `Err(reason)` so
    // `main` can abort startup rather than silently serving unauthenticated
    // traffic.
    pub async fn init(cfg: &AuthConfig) -> Result<Self, String> {
        if cfg.dev_bypass {
            let secret = cfg.dev_hs256_secret.as_deref().ok_or_else(|| {
                "TAHLK_AUTH_DEV_BYPASS=1 requires TAHLK_AUTH_DEV_HS256_SECRET to be set".to_string()
            })?;
            if cfg.issuer.is_empty() || cfg.audience.is_empty() {
                return Err("dev bypass still requires TAHLK_JWT_ISSUER and TAHLK_JWT_AUDIENCE".into());
            }
            tracing::warn!(
                "AUTH DEV BYPASS ACTIVE — verifying HS256 tokens with a local shared secret. \
                 This must never be enabled in production."
            );
            return Ok(Self {
                issuer: cfg.issuer.clone(),
                audience: cfg.audience.clone(),
                keys: RwLock::new(HashMap::new()),
                dev_hs256: Some(DecodingKey::from_secret(secret.as_bytes())),
                jwks_url: String::new(),
                http: reqwest::Client::new(),
                last_refresh: RwLock::new(None),
                refresh_lock: tokio::sync::Mutex::new(()),
            });
        }

        if cfg.issuer.is_empty() || cfg.audience.is_empty() || cfg.jwks_url.is_empty() {
            return Err(
                "missing JWT config: set TAHLK_JWT_ISSUER, TAHLK_JWT_AUDIENCE, and TAHLK_JWKS_URL \
                 (or TAHLK_AUTH_DEV_BYPASS=1 for local dev). See docs/security/pre-deploy-checklist.md"
                    .into(),
            );
        }

        let verifier = Self {
            issuer: cfg.issuer.clone(),
            audience: cfg.audience.clone(),
            keys: RwLock::new(HashMap::new()),
            dev_hs256: None,
            jwks_url: cfg.jwks_url.clone(),
            http: reqwest::Client::new(),
            last_refresh: RwLock::new(None),
            refresh_lock: tokio::sync::Mutex::new(()),
        };
        // Fail closed: if we can't load the signing keys at startup, refuse to
        // serve rather than fall through to accepting nothing (or, worse, no
        // auth at all).
        verifier
            .refresh_jwks()
            .await
            .map_err(|e| format!("JWKS unreachable at startup ({e}); refusing to start (fail-closed)"))?;
        Ok(verifier)
    }

    // Fetch the JWKS and replace the in-memory key cache. Only keys with a `kid`
    // are cached, since selection is `kid`-based.
    async fn refresh_jwks(&self) -> Result<(), String> {
        let set: JwkSet = self
            .http
            .get(&self.jwks_url)
            .send()
            .await
            .map_err(|e| e.to_string())?
            .error_for_status()
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;

        let mut fresh = HashMap::new();
        for jwk in &set.keys {
            if let Some(kid) = jwk.common.key_id.clone() {
                if let Ok(key) = DecodingKey::from_jwk(jwk) {
                    fresh.insert(kid, key);
                }
            }
        }
        if fresh.is_empty() {
            return Err("JWKS contained no usable keys with a kid".into());
        }
        *self.keys.write() = fresh;
        *self.last_refresh.write() = Some(Instant::now());
        Ok(())
    }

    // Refresh path used by the `kid`-miss lookup in `select_key`, guarded so a
    // stream of requests bearing unknown `kid`s can't turn into unlimited JWKS
    // fetches (see `JWKS_REFRESH_COOLDOWN`).
    //
    // Two layers:
    //   * Single-flight: `refresh_lock` ensures only one refresh is ever
    //     in-flight; concurrent callers queue behind it rather than each firing
    //     their own HTTP request. Once the lock is acquired, we re-check the
    //     cooldown (another caller may have just refreshed while we waited).
    //   * Cooldown: if the last successful refresh was within
    //     `JWKS_REFRESH_COOLDOWN`, skip the network call entirely and return Ok
    //     without changing `keys` — the caller's subsequent `keys.read().get()`
    //     will then correctly report "still not found" for a genuinely-unknown
    //     kid, rather than us refetching once per request.
    async fn refresh_jwks_throttled(&self) -> Result<(), String> {
        let _guard = self.refresh_lock.lock().await;
        let recently_refreshed = self
            .last_refresh
            .read()
            .is_some_and(|t| t.elapsed() < JWKS_REFRESH_COOLDOWN);
        if recently_refreshed {
            return Ok(());
        }
        self.refresh_jwks().await
    }

    // Algorithm-confusion defense (audit finding, Medium: "JWT verification
    // trusts client-supplied alg header instead of a server-side algorithm
    // allowlist"). The previous version of `select_key` returned
    // `header.alg` verbatim — whatever algorithm the TOKEN claimed — which
    // `verify` then fed straight into `Validation::new(alg)`. That is the
    // textbook shape of an algorithm-confusion vulnerability: an attacker
    // who can get a server to validate a token using an algorithm THEY
    // chose (rather than one the server expects for that key) can, in the
    // classic case, present an HS256 token "signed" with the RSA public key
    // bytes as the HMAC secret — the public key is public precisely because
    // it's published in the JWKS, so nothing about it is secret to an
    // attacker.
    //
    // The fix: each key path has exactly one algorithm it will EVER accept,
    // decided by which path is active — never by what the token claims.
    // `header.alg` is checked against that fixed expectation and rejected
    // on any mismatch BEFORE a key is even selected, so a mismatched-alg
    // token never reaches key lookup or signature verification at all.
    const DEV_ALG: Algorithm = Algorithm::HS256;
    const PROD_ALG: Algorithm = Algorithm::RS256;

    // Pick the decoding key + algorithm for a token. In dev-bypass mode the
    // symmetric key is always used; otherwise the token's `kid` selects the key,
    // refreshing the JWKS once on a miss so IdP rotation is handled live.
    async fn select_key(&self, header: &Header) -> Result<(DecodingKey, Algorithm), ApiError> {
        if let Some(dev) = &self.dev_hs256 {
            if header.alg != Self::DEV_ALG {
                return Err(ApiError::Unauthorized);
            }
            return Ok((dev.clone(), Self::DEV_ALG));
        }
        if header.alg != Self::PROD_ALG {
            return Err(ApiError::Unauthorized);
        }
        let kid = header.kid.clone().ok_or(ApiError::Unauthorized)?;
        if let Some(key) = self.keys.read().get(&kid).cloned() {
            return Ok((key, Self::PROD_ALG));
        }
        self.refresh_jwks_throttled().await.map_err(|_| ApiError::Unauthorized)?;
        self.keys
            .read()
            .get(&kid)
            .cloned()
            .map(|key| (key, Self::PROD_ALG))
            .ok_or(ApiError::Unauthorized)
    }

    // Verify a bearer token end to end and return the caller's tenant/provider.
    // Any failure is a 401 (via `From<jsonwebtoken::errors::Error>` or an
    // explicit `Unauthorized`), never a 500.
    pub async fn verify(&self, token: &str) -> Result<TenantCtx, ApiError> {
        let header = decode_header(token)?;
        let (key, alg) = self.select_key(&header).await?;

        let mut validation = Validation::new(alg);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.audience.as_str()]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        // `iss`/`aud` are validated only if we also require them to be present,
        // so a token that simply omits them can't slip through.
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);

        let data = decode::<Claims>(token, &key, &validation)?;
        let claims = data.claims;
        // A structurally-valid token with a blank/absent tenant or provider is
        // useless (and dangerous, since downstream keys on tenant) — reject it.
        if claims.tenant_id.trim().is_empty() || claims.provider_id.trim().is_empty() {
            return Err(ApiError::Unauthorized);
        }
        Ok(TenantCtx {
            tenant: claims.tenant_id,
            provider: claims.provider_id,
        })
    }
}

// Pull the raw bearer token out of the Authorization header, if present.
fn bearer_token(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

// Middleware: verify the JWT once and stash the derived context in extensions.
// Runs before the rate limiter and the handlers, so both see a verified tenant.
pub async fn require_auth(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let token = bearer_token(req.headers()).ok_or(ApiError::Unauthorized)?;
    let ctx = state.auth.verify(&token).await?;
    req.extensions_mut().insert(ctx);
    Ok(next.run(req).await)
}

// Handlers keep taking `TenantCtx` as an extractor; it now reads the context the
// middleware verified rather than parsing headers itself. If it's missing (a
// route wired without `require_auth`), fail closed with 401.
impl<S: Send + Sync> FromRequestParts<S> for TenantCtx {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<TenantCtx>()
            .cloned()
            .ok_or(ApiError::Unauthorized)
    }
}

// Test-only crypto/kit shared by this module's unit tests and the router-level
// integration tests in `main.rs`. Kept behind `cfg(test)` so no key material or
// token-minting helper is compiled into the shipping binary.
#[cfg(test)]
pub(crate) mod testkit {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey};
    use serde::Serialize;
    use std::time::{SystemTime, UNIX_EPOCH};

    pub const ISSUER: &str = "https://issuer.test/";
    pub const AUDIENCE: &str = "tahlk-sync";
    pub const KID: &str = "test-key-1";

    // RSA-2048 keypair generated once for tests. `PRIV_PEM` signs tokens; the
    // verifier trusts `PUB_PEM` under `KID`. `PRIV_PEM2` is an unrelated key used
    // to forge a "signed by the wrong key" token.
    pub const PRIV_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCnQrrJvBkg/zbs
35FmwrVtZUowR/piAM/7rJ3Lbwip/KmWN902tzJEAsCwuf9iPNs2jgKCuW5NmMso
keY60+W0ZGOVfSzP9yhO3vqyp3zBEmYBrQdiByepRJkykbldBWKHOkth0SAc3T78
8seNj/DbIbsWQZwGfumikr5EJKF32vfsSBeODFGqmGMhD9C8b679LTKD4l51THgm
fbht7ir/g9GWFbFA1QQHMFtA/l5GS2thEGr7kQRH0nqGmhm92K7NFQxV0T7bF3hU
P7/t/9gc5Jfr+bbQE+eOIT0ZuxBCpl4JELyYGhRZuMdooZXOWUntPG/lTPnsH4yP
QMhs2wSLAgMBAAECggEAApFkeEluCrSSE3CQbmwri87RbxARUGGCjJRy86SZbFJ7
+x0LCMJPVHBZOPNHkdMY5En6V0+d4FBtQM46vlNDTosntdRKIiF3UzKrkeKPuWDq
l79qTLv2tA11A7lmqYwUbvB81uZiSPa9/dpbNiBDzeWu6lrnJf+KWLAUcPRImTGx
oPu66tmjEYB5Uje8rtKAVJEJ9CbQzSAJ91N8vlQj4bvwfpjf/TupIZ1UZNbW8Upn
GCwl40RxDhZbXFMxt+dIfY8zth3iwmMB4SsQrVg/c/bznaQAUAsszO89SwiBhW6Z
9uSR7eKR7avOKPECuZkNwjVWWwoj6DPaqHwRTNz0aQKBgQDbYZbPJsad1Xz21YmP
NjL16G1mNGUilMladwq/d4T2D0Wmk4Ktsnp23chRUz3dX9V8raxUOIfswIbRx6nu
CnRFdLXHRUEczWKqyK+nkZ4hLykzKe3j71dhUKOfrB2fY4tvQY2BPJrbqzHY6ffu
2sgawFL6tIJQ0Xw5K7p9Zjfs0wKBgQDDLfhF5GxE0f1b0oXpubR8TzT01GYSroEj
PlCWTiTi9vhqwunuodN6jVNccnn4FE9qgcvknU9aJb0Zi2H7akqDhjT+LDQuwlQB
lZR1srYunaHKNC/e1oCSqnSXg4GzhTAR3WlMgKFJ0+G3xTxvHFTohoTzH3VM9haO
YFxHxrRWaQKBgQCSVVcmGGRVtajkcO2P9IQrmX0Xto1bcsmYqV0m+A9dnjREd5Ks
UCf2D9vlu1PBzYH251XS29524rlLRxanbJvAFKiIIj7benh9GN5qNOy4j9+4fBht
eSHdDNAH2uPrhJfmf2BnO0jEjD30xaQW1CK0DWOMTUm7pPBqpiuAJ+XX9wKBgCSN
Ck6EbWYh8RFuBlfzyAHzj1Y+JHNhLJveApdzQOMkHvdXUxm2QnVT3AWXBpJXs1ud
vQIuF3spUBVljc7YY+Xnjyr+OjN7fuHhEjFMa2Olb3P/e+t+Pgu5UiZBoVtuGMdv
sFV8TTgXLtEMZbnlE12MO3+QJ5ZnC2hUUVO7uW/pAoGBALZshUs64jeQkcg+7j7F
oV8tH9upYzd9t58gIeMJG3K3n8yw/nrvZv47GQZvVNoPzi1x6YGxtcc7SG7j33Hz
hQkB93JQT4tbQTZJfonttCkI0Rcr4VR4A9dr3WFZps5GLK2x8XW7JF+NSUKTojbD
B53wE59iwxS5Mc8xscnGGdhY
-----END PRIVATE KEY-----";

    pub const PUB_PEM: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp0K6ybwZIP827N+RZsK1
bWVKMEf6YgDP+6ydy28IqfypljfdNrcyRALAsLn/YjzbNo4CgrluTZjLKJHmOtPl
tGRjlX0sz/coTt76sqd8wRJmAa0HYgcnqUSZMpG5XQVihzpLYdEgHN0+/PLHjY/w
2yG7FkGcBn7popK+RCShd9r37EgXjgxRqphjIQ/QvG+u/S0yg+JedUx4Jn24be4q
/4PRlhWxQNUEBzBbQP5eRktrYRBq+5EER9J6hpoZvdiuzRUMVdE+2xd4VD+/7f/Y
HOSX6/m20BPnjiE9GbsQQqZeCRC8mBoUWbjHaKGVzllJ7Txv5Uz57B+Mj0DIbNsE
iwIDAQAB
-----END PUBLIC KEY-----";

    pub const PRIV_PEM2: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCnxWNHwZ7BxYVU
V7mY9qxcu+jrIgNt4iK1+HHf4Y6oq5i9FKh+PTNNdjACrIply8bw6gO1Ewe1GoHc
bqeMIWSsl/rNQtAip5/rg6By9Dyz4fIX9zZVnGnED6fulcoIrHJB0OG2BJZUMhx1
wA3faOTCEQAsJ4GTu9VLGvtq/6Cd6mVpmp/7/29ZRRYgZt071h4wBNMNkELfCoUz
YaHzDWchMLsA1l4DEZYJnaDKuEfBOoe40wXRivmRJGS5/5qm2YkmqGYYDG0WrWUn
qfkKPPqUhZvIYaY/Y0HlPHM++f9FM8KTqHP8hTUVtZctMcefj63GueqktrkXOmGL
MinvrPUhAgMBAAECggEAJYgFxras0kJiqlSZo3uDYZdz6q4IQFu3UigLKX9nD5qb
p6jobJ06TdjjsqVwrIcisSBYxfhE4CHW7T4f4zxRLj8tjx+kOixvnRssGKtErSUd
qHjYQdyk2IR8F+aQdNJHGSwmYjayfpFbRog5UkI/8p4lALuxxB/f/lZB6lTXVJwP
ZljXSaTomQPint/ugh9v5to8M9+gH4nFqrc1vkAJw/g+8Ox78SNqHWWm10gnScXl
LjnGTgmi0zrtDRkITcxNPRb6/WawofP2GRJ3IrUMZS+47bco8suiVDJMgmot4lCp
br/XI+ZW/fcKQrT19x+Ubw6wv57qKF+HS2ZUaSfIVQKBgQDT/i225OuOwFtSuN+G
mC0ZFRvCwlHyZQRfnpJHHSE7q8hrGnvsd0DVEyL9Yx4k2lhppdAxlq7ODdXHNPWD
AF0TsNb0yye3Pc9oxehpxK9OBswtE74XPbiqL6pLnixlOEUUkRRftwNwvzXPIUr2
2Q+4LFCPNyhSgBnXc+t4GT4r/wKBgQDKmScAetSg2PPlr2PDWjOXop3/IKiIDZdZ
8G54uKlGeJpJsrZ7/p4Bv1ua/VC4F6q7J2gYYnaZm9O8O9Kg2L8kkpukmFB2oEPE
UCUwrkzs/8eKBl+oU39NzG8q4YUmTvYfZYJkkCVCR+akV7J9YPhqRLWYti8DeZsE
yuyq5aNe3wKBgF/CnZvUZKOjOJ1xbWc7LoP6CQQ9Cw9XmlYnJySAgBaYTnwzBm+W
nu6hKlkTgPZcuztd72G3E1d44GyP+6clbuYKJ8+ERXh8r0hAve+pLRct8uUZ2fBd
rSETTvXBiYRfmrTjpDRoU2GGviPGgjpnarZjLjDDVa+Oth2g+2jQ3ki5AoGAAgfx
BSc2FHq4Tzgn5uBznfSKYvFf3yVLvCIV6W3ofIVe/pglDi8qRFg3weECOyY5lvC5
MW1jRPzz7XIoFWa229YAa3D/dYD7zO8EwG0u5j1WMcMImHZl01DWWHa0UAMAoqXw
3bM4PGbeIA2lA27CbsZLj8FbzUwdyrmCD+CHd78CgYEAsmaKKNhxhGyzkxxfcjv/
Zkz3ym8MXzd9dfk8dm+hGcen0dSxG3lNOttJ/ga2uiVcwaJZT8jWpHMmlhf0u9OU
MEapLWrl0jIuZO8/n8qmBaYFu3SptyeIPp7Frx0c3iddpdWDsVDQ1hsrCcjio2tX
EazcBoQzeLMAdK4yNGlpoaw=
-----END PRIVATE KEY-----";

    // A verifier that trusts `PUB_PEM` under `KID` with no network dependency.
    pub fn verifier() -> JwtVerifier {
        let mut keys = HashMap::new();
        keys.insert(
            KID.to_string(),
            DecodingKey::from_rsa_pem(PUB_PEM.as_bytes()).unwrap(),
        );
        JwtVerifier {
            issuer: ISSUER.to_string(),
            audience: AUDIENCE.to_string(),
            keys: RwLock::new(keys),
            dev_hs256: None,
            jwks_url: String::new(),
            http: reqwest::Client::new(),
            last_refresh: RwLock::new(None),
            refresh_lock: tokio::sync::Mutex::new(()),
        }
    }

    #[derive(Serialize)]
    struct TestClaims {
        iss: String,
        aud: String,
        exp: i64,
        nbf: i64,
        tenant_id: String,
        provider_id: String,
    }

    pub struct MintOpts<'a> {
        pub tenant: &'a str,
        pub provider: &'a str,
        pub exp_offset_secs: i64,
        pub kid: &'a str,
        pub signing_key_pem: &'a str,
        pub include_iss: bool,
        pub include_aud: bool,
    }

    impl<'a> Default for MintOpts<'a> {
        fn default() -> Self {
            Self {
                tenant: "tenant-a",
                provider: "provider-1",
                exp_offset_secs: 3600,
                kid: KID,
                signing_key_pem: PRIV_PEM,
                include_iss: true,
                include_aud: true,
            }
        }
    }

    fn now() -> i64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
    }

    // Mint an RS256 token per the options. `include_iss/aud` toggle presence so
    // tests can prove a token missing a required registered claim is rejected.
    pub fn mint(opts: &MintOpts) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(opts.kid.to_string());
        let claims = TestClaims {
            iss: if opts.include_iss { ISSUER.into() } else { String::new() },
            aud: if opts.include_aud { AUDIENCE.into() } else { String::new() },
            exp: now() + opts.exp_offset_secs,
            nbf: now() - 60,
            tenant_id: opts.tenant.to_string(),
            provider_id: opts.provider.to_string(),
        };
        let key = EncodingKey::from_rsa_pem(opts.signing_key_pem.as_bytes()).unwrap();
        encode(&header, &claims, &key).unwrap()
    }

    // Mint a token that deliberately omits tenant_id/provider_id.
    pub fn mint_missing_claims() -> String {
        #[derive(Serialize)]
        struct Bare {
            iss: String,
            aud: String,
            exp: i64,
        }
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(KID.to_string());
        let claims = Bare {
            iss: ISSUER.into(),
            aud: AUDIENCE.into(),
            exp: now() + 3600,
        };
        let key = EncodingKey::from_rsa_pem(PRIV_PEM.as_bytes()).unwrap();
        encode(&header, &claims, &key).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::*;
    use super::*;
    use jsonwebtoken::{encode, EncodingKey};
    use serde::Serialize;

    #[tokio::test]
    async fn valid_token_yields_claims_derived_context() {
        let v = verifier();
        let token = mint(&MintOpts { tenant: "acme", provider: "dr-jones", ..Default::default() });
        let ctx = v.verify(&token).await.expect("valid token should verify");
        assert_eq!(ctx.tenant, "acme");
        assert_eq!(ctx.provider, "dr-jones");
    }

    #[tokio::test]
    async fn expired_token_is_rejected() {
        let v = verifier();
        // Past the default 60s validation leeway so it's unambiguously expired.
        let token = mint(&MintOpts { exp_offset_secs: -120, ..Default::default() });
        assert!(matches!(v.verify(&token).await, Err(ApiError::Unauthorized)));
    }

    #[tokio::test]
    async fn token_signed_by_wrong_key_is_rejected() {
        let v = verifier();
        // Signed with an unrelated private key but presented under the trusted kid.
        let token = mint(&MintOpts { signing_key_pem: PRIV_PEM2, ..Default::default() });
        assert!(matches!(v.verify(&token).await, Err(ApiError::Unauthorized)));
    }

    #[tokio::test]
    async fn token_missing_required_claims_is_rejected() {
        let v = verifier();
        let token = mint_missing_claims();
        assert!(matches!(v.verify(&token).await, Err(ApiError::Unauthorized)));
    }

    #[tokio::test]
    async fn token_with_blank_tenant_is_rejected() {
        let v = verifier();
        let token = mint(&MintOpts { tenant: "", ..Default::default() });
        assert!(matches!(v.verify(&token).await, Err(ApiError::Unauthorized)));
    }

    #[tokio::test]
    async fn wrong_issuer_is_rejected() {
        // Verifier expects a different issuer than the one baked into the token.
        let mut v = verifier();
        v.issuer = "https://someone-else.test/".into();
        let token = mint(&MintOpts::default());
        assert!(matches!(v.verify(&token).await, Err(ApiError::Unauthorized)));
    }

    #[tokio::test]
    async fn wrong_audience_is_rejected() {
        let mut v = verifier();
        v.audience = "some-other-api".into();
        let token = mint(&MintOpts::default());
        assert!(matches!(v.verify(&token).await, Err(ApiError::Unauthorized)));
    }

    #[tokio::test]
    async fn unknown_kid_with_no_jwks_is_rejected() {
        let v = verifier();
        let token = mint(&MintOpts { kid: "some-other-kid", ..Default::default() });
        // kid miss triggers a JWKS refresh; jwks_url is empty here so it fails
        // and the token is rejected rather than accepted.
        assert!(matches!(v.verify(&token).await, Err(ApiError::Unauthorized)));
    }

    // --- Algorithm-confusion defense -----------------------------------------

    // The classic attack: an attacker crafts a token with alg=HS256 and
    // "signs" it using the RSA public key's own bytes as the HMAC secret —
    // the public key is, definitionally, public (it's published in the
    // JWKS), so nothing stops an attacker from reading it and using it as
    // an HMAC key. If the server ever validated using whatever algorithm
    // the TOKEN claimed (the old behavior), this would potentially let an
    // attacker forge tokens without ever having the RSA private key. With
    // the fix, the header's declared alg (HS256) is checked against the
    // fixed expectation for the production/JWKS path (RS256) and rejected
    // before any key lookup or signature check happens at all.
    #[tokio::test]
    async fn hs256_token_is_rejected_against_the_rs256_production_verifier() {
        let v = verifier();
        #[derive(Serialize)]
        struct C { iss: String, aud: String, exp: i64, nbf: i64, tenant_id: String, provider_id: String }
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(KID.to_string());
        let claims = C {
            iss: ISSUER.into(), aud: AUDIENCE.into(),
            exp: now_for_test() + 3600, nbf: now_for_test() - 60,
            tenant_id: "tenant-a".into(), provider_id: "provider-1".into(),
        };
        // Use the RSA public key's own PEM bytes as the HMAC secret — the
        // exact "public key as HMAC secret" attack shape.
        let key = EncodingKey::from_secret(PUB_PEM.as_bytes());
        let token = encode(&header, &claims, &key).unwrap();
        assert!(
            matches!(v.verify(&token).await, Err(ApiError::Unauthorized)),
            "an HS256 token must never validate against the RS256 production verifier, \
             regardless of what secret it was signed with"
        );
    }

    // Mirror case: the dev-bypass (HS256) verifier must reject an RS256
    // token even if it's a genuinely validly-signed one from the real
    // issuer's key material — dev-bypass only ever trusts its one symmetric
    // secret, never the token's own claimed algorithm.
    #[tokio::test]
    async fn rs256_token_is_rejected_against_the_hs256_dev_bypass_verifier() {
        let mut v = verifier();
        v.dev_hs256 = Some(DecodingKey::from_secret(b"dev-only-secret"));
        let token = mint(&MintOpts::default()); // a normal RS256 token
        assert!(
            matches!(v.verify(&token).await, Err(ApiError::Unauthorized)),
            "an RS256 token must never validate against the HS256 dev-bypass verifier"
        );
    }

    // Belt-and-suspenders: even a token whose alg matches what the verifier
    // expects, but is signed with a DIFFERENT HS256 secret than the
    // configured one, must still be rejected — proves the alg check isn't
    // papering over a missing signature check.
    #[tokio::test]
    async fn hs256_token_with_wrong_secret_is_rejected_by_dev_bypass_verifier() {
        let mut v = verifier();
        v.dev_hs256 = Some(DecodingKey::from_secret(b"the-real-secret"));
        #[derive(Serialize)]
        struct C { iss: String, aud: String, exp: i64, nbf: i64, tenant_id: String, provider_id: String }
        let header = Header::new(Algorithm::HS256);
        let claims = C {
            iss: ISSUER.into(), aud: AUDIENCE.into(),
            exp: now_for_test() + 3600, nbf: now_for_test() - 60,
            tenant_id: "tenant-a".into(), provider_id: "provider-1".into(),
        };
        let key = EncodingKey::from_secret(b"a-different-secret-entirely");
        let token = encode(&header, &claims, &key).unwrap();
        assert!(matches!(v.verify(&token).await, Err(ApiError::Unauthorized)));
    }

    fn now_for_test() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    #[tokio::test]
    async fn malformed_token_is_rejected() {
        let v = verifier();
        assert!(matches!(v.verify("not.a.jwt").await, Err(ApiError::Unauthorized)));
        assert!(matches!(v.verify("garbage").await, Err(ApiError::Unauthorized)));
    }

    #[tokio::test]
    async fn init_fails_closed_when_jwks_unreachable() {
        // Port 1 refuses connections immediately, so this exercises the
        // startup fail-closed path without a long network timeout.
        let cfg = AuthConfig {
            issuer: ISSUER.into(),
            audience: AUDIENCE.into(),
            jwks_url: "http://127.0.0.1:1/jwks.json".into(),
            dev_bypass: false,
            dev_hs256_secret: None,
        };
        assert!(JwtVerifier::init(&cfg).await.is_err());
    }

    #[tokio::test]
    async fn init_fails_closed_when_config_missing() {
        let cfg = AuthConfig {
            issuer: String::new(),
            audience: String::new(),
            jwks_url: String::new(),
            dev_bypass: false,
            dev_hs256_secret: None,
        };
        assert!(JwtVerifier::init(&cfg).await.is_err());
    }

    fn hdr(v: &str) -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        h.insert(AUTHORIZATION, v.parse().unwrap());
        h
    }

    #[test]
    fn bearer_token_parsing() {
        assert_eq!(bearer_token(&hdr("Bearer abc.def.ghi")).as_deref(), Some("abc.def.ghi"));
        assert_eq!(bearer_token(&hdr("Bearer   ")), None); // whitespace-only
        assert_eq!(bearer_token(&hdr("Basic abc")), None); // wrong scheme
        assert_eq!(bearer_token(&axum::http::HeaderMap::new()), None); // absent
    }

    // --- JWKS refresh cooldown / single-flight (amplification regression) ---
    //
    // A minimal raw-TCP JWKS stub: no mock-HTTP crate is in the dependency
    // tree, so this hand-rolls just enough HTTP/1.1 to satisfy `reqwest`'s
    // GET + `JwkSet` JSON parse, while counting how many times it was hit.
    // That hit count is exactly what the amplification bug (a full JWKS fetch
    // per request on every `kid` miss) would blow up.
    struct JwksStub {
        addr: std::net::SocketAddr,
        hits: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl JwksStub {
        async fn start() -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let hits_clone = hits.clone();
            // Precomputed JWK for `testkit::PUB_PEM` (n/e extracted once
            // offline); embedding the literal avoids pulling in an RSA-parsing
            // crate just for this test stub.
            const TEST_KEY_N: &str = "p0K6ybwZIP827N-RZsK1bWVKMEf6YgDP-6ydy28IqfypljfdNrcyRALAsLn_YjzbNo4CgrluTZjLKJHmOtPltGRjlX0sz_coTt76sqd8wRJmAa0HYgcnqUSZMpG5XQVihzpLYdEgHN0-_PLHjY_w2yG7FkGcBn7popK-RCShd9r37EgXjgxRqphjIQ_QvG-u_S0yg-JedUx4Jn24be4q_4PRlhWxQNUEBzBbQP5eRktrYRBq-5EER9J6hpoZvdiuzRUMVdE-2xd4VD-_7f_YHOSX6_m20BPnjiE9GbsQQqZeCRC8mBoUWbjHaKGVzllJ7Txv5Uz57B-Mj0DIbNsEiw";
            let body = serde_json::json!({
                "keys": [{
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": KID,
                    "n": TEST_KEY_N,
                    "e": "AQAB",
                }]
            })
            .to_string();
            tokio::spawn(async move {
                loop {
                    let (mut sock, _) = match listener.accept().await {
                        Ok(s) => s,
                        Err(_) => break,
                    };
                    hits_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let body = body.clone();
                    tokio::spawn(async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        // Drain the request (don't care about its contents).
                        let mut buf = [0u8; 1024];
                        let _ = sock.read(&mut buf).await;
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = sock.write_all(resp.as_bytes()).await;
                        let _ = sock.shutdown().await;
                    });
                }
            });
            Self { addr, hits }
        }

        fn url(&self) -> String {
            format!("http://{}/jwks.json", self.addr)
        }

        fn hit_count(&self) -> usize {
            self.hits.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    fn verifier_with_jwks_url(url: String) -> JwtVerifier {
        let v = verifier();
        JwtVerifier {
            jwks_url: url,
            keys: RwLock::new(HashMap::new()), // start with no cached keys, forcing a miss
            ..v
        }
    }

    #[tokio::test]
    async fn kid_miss_storm_triggers_only_one_jwks_fetch_within_cooldown() {
        let stub = JwksStub::start().await;
        let v = verifier_with_jwks_url(stub.url());
        // Every one of these tokens has the SAME known kid but the verifier's
        // cache starts empty, so each individual `verify()` call is a `kid`
        // miss until the first refresh populates the cache. Fire many in a
        // row, simulating a burst of requests.
        let token = mint(&MintOpts::default());
        for _ in 0..25 {
            let _ = v.verify(&token).await;
        }
        // Without the cooldown/single-flight guard this would be up to 25 hits
        // (one JWKS fetch per request). With it, concurrent/rapid misses
        // coalesce: the very first refresh populates the kid, so every
        // subsequent call hits the warm cache and never calls refresh again.
        assert_eq!(
            stub.hit_count(),
            1,
            "expected exactly one JWKS fetch for a burst of requests bearing the same known kid"
        );
    }

    #[tokio::test]
    async fn unknown_kid_storm_is_bounded_by_cooldown_not_unbounded() {
        let stub = JwksStub::start().await;
        let v = verifier_with_jwks_url(stub.url());
        // These tokens carry a kid the JWKS will never contain, so every call
        // is a genuine, permanent miss. The old code would refetch the JWKS on
        // every single one of these (amplification). The guarded code should
        // fetch once (the first miss, cache empty) and then respect the
        // cooldown for the rest of the burst.
        let token = mint(&MintOpts { kid: "kid-that-does-not-exist", ..Default::default() });
        for _ in 0..40 {
            let result = v.verify(&token).await;
            assert!(matches!(result, Err(ApiError::Unauthorized)));
        }
        assert_eq!(
            stub.hit_count(),
            1,
            "unknown-kid burst should be throttled to one fetch per cooldown window, not one per request"
        );
    }

    #[tokio::test]
    async fn concurrent_kid_misses_single_flight_into_one_fetch() {
        let stub = JwksStub::start().await;
        let v = std::sync::Arc::new(verifier_with_jwks_url(stub.url()));
        let token = mint(&MintOpts::default());
        // Fire many verifications truly concurrently (not sequentially) so the
        // single-flight lock — not just the cooldown timestamp — is what's
        // under test: without it, N concurrent misses would race to the
        // network before any of them observes a fresh `last_refresh`.
        let mut handles = Vec::new();
        for _ in 0..20 {
            let v = v.clone();
            let token = token.clone();
            handles.push(tokio::spawn(async move { v.verify(&token).await }));
        }
        for h in handles {
            assert!(h.await.unwrap().is_ok());
        }
        assert_eq!(
            stub.hit_count(),
            1,
            "concurrent misses should coalesce into a single in-flight JWKS fetch"
        );
    }

    #[tokio::test]
    async fn a_genuine_rotation_is_still_picked_up_after_the_cooldown_elapses() {
        // Proves the guard is a throttle, not a permanent latch: once the
        // cooldown window has passed, a still-unknown kid triggers a fresh
        // fetch again (e.g. to observe a newly-rotated key at the IdP).
        let stub = JwksStub::start().await;
        let mut v = verifier_with_jwks_url(stub.url());
        v.last_refresh = RwLock::new(Some(Instant::now() - JWKS_REFRESH_COOLDOWN - Duration::from_millis(50)));
        let token = mint(&MintOpts::default());
        let result = v.verify(&token).await;
        assert!(result.is_ok(), "expected the cooldown to have elapsed and the fetch to succeed");
        assert_eq!(stub.hit_count(), 1, "expected exactly one fetch once the cooldown window had passed");
    }
}
