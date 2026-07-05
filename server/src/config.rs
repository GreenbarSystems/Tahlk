use std::net::SocketAddr;

pub struct Config {
    pub addr: SocketAddr,
    pub auth: AuthConfig,
    // S2 fail-closed bind gate: `main` refuses to bind a non-loopback address
    // unless this was explicitly opted into. Sourced from `TAHLK_ALLOW_INSECURE=1`.
    pub allow_insecure_bind: bool,
}

// S1 auth configuration. In production all three of `issuer`, `audience`, and
// `jwks_url` must be set; `main` fails closed at startup if the JWKS cannot be
// fetched. For local development without a real IdP, `dev_hs256_secret`
// (from `TAHLK_AUTH_DEV_HS256_SECRET`, only honored when
// `TAHLK_AUTH_DEV_BYPASS=1`) installs a symmetric verification key so the
// service can still be exercised end to end — the header-trust path is gone
// either way.
pub struct AuthConfig {
    pub issuer: String,
    pub audience: String,
    pub jwks_url: String,
    pub dev_bypass: bool,
    pub dev_hs256_secret: Option<String>,
}

// 12-factor: configuration comes from the environment.
pub fn from_env() -> Config {
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    let dev_bypass = env_flag("TAHLK_AUTH_DEV_BYPASS");
    let auth = AuthConfig {
        issuer: std::env::var("TAHLK_JWT_ISSUER").unwrap_or_default(),
        audience: std::env::var("TAHLK_JWT_AUDIENCE").unwrap_or_else(|_| "tahlk-sync".to_string()),
        jwks_url: std::env::var("TAHLK_JWKS_URL").unwrap_or_default(),
        dev_bypass,
        dev_hs256_secret: std::env::var("TAHLK_AUTH_DEV_HS256_SECRET").ok().filter(|s| !s.is_empty()),
    };

    Config {
        addr: SocketAddr::from(([0, 0, 0, 0], port)),
        auth,
        allow_insecure_bind: env_flag("TAHLK_ALLOW_INSECURE"),
    }
}

// Treat only an explicit "1" as on, so a stray "false"/"0"/"" never accidentally
// opens the gate.
fn env_flag(name: &str) -> bool {
    std::env::var(name).map(|v| v == "1").unwrap_or(false)
}
