// Token issuance — the signing counterpart to `auth.rs`'s `JwtVerifier`.
//
// `JwtVerifier` only ever verifies tokens minted elsewhere (a real IdP in
// production). This module adds the missing signing side so the server can mint
// its own tokens for the device-registration flow (POST /v1/devices/register):
// a first-time, unauthenticated device presents an opaque device_id and gets
// back a long-lived RS256 JWT the SAME verifier will subsequently accept.
//
// The tokens are deliberately shaped to satisfy `JwtVerifier::verify` exactly:
//   * signed RS256 with a `kid` published in the JWKS the verifier fetches,
//   * `iss`/`aud` reusing the verifier's configured issuer/audience (never new
//     strings — the verifier would reject anything else),
//   * `tenant_id` = the caller's device_id (an opaque per-installation key that
//     doubles as the tenant), `provider_id` = a fixed constant identifying the
//     desktop client,
//   * `exp`/`nbf`/`iat` set so the token is immediately valid and long-lived.
//
// Like the verifier, this fails closed at construction: a missing or malformed
// signing key is a startup error (`init` returns `Err`), never a per-request 500.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;

use crate::config::IssuerConfig;
use crate::error::ApiError;

// Fixed `provider_id` claim for every device-registration token. There are no
// per-provider distinctions at this layer — the desktop client is the only
// caller of this endpoint — so a single constant identifies the issuing surface.
pub const PROVIDER_ID: &str = "tahlk-desktop";

// Token lifetime: 90 days. The client is local-first with no accounts and
// registers exactly once with zero UI, so a short expiry would force silent
// re-registration churn for no security benefit — there's no session to revoke
// mid-life and re-enrollment is always available (the register route is
// idempotent by device_id) if a token is lost or does expire. 90 days keeps a
// bounded blast radius if a token leaks while not making the happy path chatty.
pub const TOKEN_LIFETIME: Duration = Duration::from_secs(90 * 24 * 60 * 60);

pub struct JwtSigner {
    key: EncodingKey,
    kid: String,
    issuer: String,
    audience: String,
    lifetime: Duration,
}

// Claims mirror what `JwtVerifier` validates: registered claims (`iss`/`aud`/
// `exp`/`nbf`) plus the two custom claims (`tenant_id`/`provider_id`) it derives
// the caller identity from. `iat` is informational.
#[derive(Serialize)]
struct Claims<'a> {
    iss: &'a str,
    aud: &'a str,
    iat: i64,
    nbf: i64,
    exp: i64,
    tenant_id: &'a str,
    provider_id: &'a str,
}

impl JwtSigner {
    // Build the signer, failing closed on any misconfiguration so `main` can
    // abort startup rather than let the register route 500 per request. `issuer`
    // and `audience` are the verifier's own configured values (passed in from
    // `AuthConfig`) so minted tokens are guaranteed acceptance-shaped.
    pub fn init(issuer: &str, audience: &str, cfg: &IssuerConfig) -> Result<Self, String> {
        if issuer.is_empty() || audience.is_empty() {
            return Err(
                "token issuance requires TAHLK_JWT_ISSUER and TAHLK_JWT_AUDIENCE (the same values \
                 the verifier accepts)"
                    .into(),
            );
        }
        if cfg.signing_kid.trim().is_empty() {
            return Err("TAHLK_JWT_SIGNING_KID is not set: minted tokens need a kid the JWKS publishes".into());
        }
        if cfg.signing_key_pem.trim().is_empty() {
            return Err("TAHLK_JWT_SIGNING_KEY is not set: refusing to start without a signing key".into());
        }
        let key = EncodingKey::from_rsa_pem(cfg.signing_key_pem.as_bytes())
            .map_err(|e| format!("TAHLK_JWT_SIGNING_KEY is not a valid RSA private key PEM: {e}"))?;
        Ok(Self {
            key,
            kid: cfg.signing_kid.clone(),
            issuer: issuer.to_string(),
            audience: audience.to_string(),
            lifetime: TOKEN_LIFETIME,
        })
    }

    // Mint a token for `tenant_id` (the device_id). Returns the encoded token
    // and its absolute expiry as a unix timestamp (seconds) so the caller can
    // surface `expires_at` without recomputing the lifetime. Encoding failure is
    // an internal error (the key already parsed at startup, so this is not a
    // client-caused condition).
    pub fn mint(&self, tenant_id: &str) -> Result<(String, i64), ApiError> {
        let now = now_secs();
        let exp = now + self.lifetime.as_secs() as i64;
        let claims = Claims {
            iss: &self.issuer,
            aud: &self.audience,
            iat: now,
            nbf: now,
            exp,
            tenant_id,
            provider_id: PROVIDER_ID,
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.clone());
        let token = encode(&header, &claims, &self.key)
            .map_err(|e| ApiError::Internal(format!("failed to sign device token: {e}")))?;
        Ok((token, exp))
    }
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// A signer wired to the test keypair/issuer/audience in `auth::testkit`, so a
// token it mints verifies against `auth::testkit::verifier()` with no network.
// Kept behind `cfg(test)` so no signing helper leaks into the shipping binary.
#[cfg(test)]
pub(crate) fn test_signer() -> JwtSigner {
    use crate::auth::testkit;
    JwtSigner {
        key: EncodingKey::from_rsa_pem(testkit::PRIV_PEM.as_bytes()).unwrap(),
        kid: testkit::KID.to_string(),
        issuer: testkit::ISSUER.to_string(),
        audience: testkit::AUDIENCE.to_string(),
        lifetime: TOKEN_LIFETIME,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::testkit;

    #[test]
    fn init_fails_closed_on_missing_key() {
        let cfg = IssuerConfig { signing_key_pem: String::new(), signing_kid: "k1".into() };
        assert!(JwtSigner::init(testkit::ISSUER, testkit::AUDIENCE, &cfg).is_err());
    }

    #[test]
    fn init_fails_closed_on_malformed_key() {
        let cfg = IssuerConfig {
            signing_key_pem: "-----BEGIN PRIVATE KEY-----\nnot-base64\n-----END PRIVATE KEY-----".into(),
            signing_kid: "k1".into(),
        };
        assert!(JwtSigner::init(testkit::ISSUER, testkit::AUDIENCE, &cfg).is_err());
    }

    #[test]
    fn init_fails_closed_on_missing_kid() {
        let cfg = IssuerConfig {
            signing_key_pem: testkit::PRIV_PEM.into(),
            signing_kid: String::new(),
        };
        assert!(JwtSigner::init(testkit::ISSUER, testkit::AUDIENCE, &cfg).is_err());
    }

    #[test]
    fn init_fails_closed_on_missing_issuer_audience() {
        let cfg = IssuerConfig { signing_key_pem: testkit::PRIV_PEM.into(), signing_kid: "k1".into() };
        assert!(JwtSigner::init("", testkit::AUDIENCE, &cfg).is_err());
        assert!(JwtSigner::init(testkit::ISSUER, "", &cfg).is_err());
    }

    #[test]
    fn init_succeeds_with_valid_config() {
        let cfg = IssuerConfig {
            signing_key_pem: testkit::PRIV_PEM.into(),
            signing_kid: testkit::KID.into(),
        };
        assert!(JwtSigner::init(testkit::ISSUER, testkit::AUDIENCE, &cfg).is_ok());
    }

    #[tokio::test]
    async fn minted_token_verifies_against_the_verifier() {
        let signer = test_signer();
        let (token, exp) = signer.mint("device-123").unwrap();
        assert!(exp > now_secs() + 89 * 24 * 60 * 60, "expiry should be ~90 days out");

        let ctx = testkit::verifier().verify(&token).await.expect("minted token must verify");
        assert_eq!(ctx.tenant, "device-123", "tenant_id claim carries the device_id");
        assert_eq!(ctx.provider, PROVIDER_ID);
    }
}
