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
        Ok(())
    }

    // Pick the decoding key + algorithm for a token. In dev-bypass mode the
    // symmetric key is always used; otherwise the token's `kid` selects the key,
    // refreshing the JWKS once on a miss so IdP rotation is handled live.
    async fn select_key(&self, header: &Header) -> Result<(DecodingKey, Algorithm), ApiError> {
        if let Some(dev) = &self.dev_hs256 {
            return Ok((dev.clone(), Algorithm::HS256));
        }
        let kid = header.kid.clone().ok_or(ApiError::Unauthorized)?;
        if let Some(key) = self.keys.read().get(&kid).cloned() {
            return Ok((key, header.alg));
        }
        self.refresh_jwks().await.map_err(|_| ApiError::Unauthorized)?;
        self.keys
            .read()
            .get(&kid)
            .cloned()
            .map(|key| (key, header.alg))
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
}
