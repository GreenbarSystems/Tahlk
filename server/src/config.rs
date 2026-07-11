use std::net::{IpAddr, SocketAddr};

pub struct Config {
    pub addr: SocketAddr,
    pub auth: AuthConfig,
    // S2 fail-closed bind gate: `main` refuses to bind a non-loopback address
    // unless this was explicitly opted into. Sourced from `TAHLK_ALLOW_INSECURE=1`.
    pub allow_insecure_bind: bool,
    // S4 cache backend selection.
    pub cache: CacheConfig,
}

// S4 cache backend. Defaults to the process-local in-memory cache (correct for
// a single instance). A horizontally-scaled deployment must select `Redis` so
// invalidations are shared across replicas; `main` then fails closed at startup
// if the Redis URL is unreachable.
pub enum CacheConfig {
    InMemory,
    Redis { url: String },
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
        addr: SocketAddr::new(parse_bind_ip(std::env::var("TAHLK_BIND_ADDR").ok()), port),
        auth,
        allow_insecure_bind: env_flag("TAHLK_ALLOW_INSECURE"),
        cache: cache_from_env(),
    }
}

// The address to bind was previously hardcoded to 0.0.0.0 unconditionally —
// which contradicted both the README ("cargo run # listens on
// 127.0.0.1:8080") and the whole point of `enforce_bind_policy` in main.rs:
// that gate exists to make binding a non-loopback address an explicit,
// deliberate opt-in, but there was no way to configure a loopback bind at
// all, so every real invocation was forced through the
// `TAHLK_ALLOW_INSECURE=1` bypass just to start up — training operators to
// reach for the insecure escape hatch by default instead of only when a
// TLS-terminating proxy is genuinely in front of this listener.
//
// `TAHLK_BIND_ADDR` now controls the bind IP directly, defaulting to
// `127.0.0.1` as documented. Setting it to `0.0.0.0` (or any other
// non-loopback address) still requires `TAHLK_ALLOW_INSECURE=1` to pass
// `enforce_bind_policy` — this only fixes the missing configuration knob, it
// does not touch or weaken the gate itself.
// Pure function (takes the already-read env value rather than reading the
// environment itself) so it's trivially unit-testable without mutating
// process-global state, which would race against other tests running in
// parallel in the same binary.
fn parse_bind_ip(env_value: Option<String>) -> IpAddr {
    match env_value {
        Some(v) if !v.is_empty() => v.parse().unwrap_or_else(|e| {
            panic!("TAHLK_BIND_ADDR={v:?} is not a valid IP address: {e}")
        }),
        _ => IpAddr::from([127, 0, 0, 1]),
    }
}

// `TAHLK_CACHE_BACKEND=redis` selects the shared cache (requires
// `TAHLK_REDIS_URL`); anything else (including unset) keeps the in-memory
// default so single-instance behavior is unchanged unless explicitly opted in.
fn cache_from_env() -> CacheConfig {
    match std::env::var("TAHLK_CACHE_BACKEND").as_deref() {
        Ok("redis") => {
            let url = std::env::var("TAHLK_REDIS_URL")
                .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
            CacheConfig::Redis { url }
        }
        _ => CacheConfig::InMemory,
    }
}

// Treat only an explicit "1" as on, so a stray "false"/"0"/"" never accidentally
// opens the gate.
fn env_flag(name: &str) -> bool {
    std::env::var(name).map(|v| v == "1").unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_loopback_when_unset() {
        assert_eq!(parse_bind_ip(None), IpAddr::from([127, 0, 0, 1]));
    }

    #[test]
    fn defaults_to_loopback_when_set_to_empty_string() {
        assert_eq!(parse_bind_ip(Some(String::new())), IpAddr::from([127, 0, 0, 1]));
    }

    #[test]
    fn honors_an_explicit_loopback_override() {
        assert_eq!(parse_bind_ip(Some("127.0.0.1".to_string())), IpAddr::from([127, 0, 0, 1]));
    }

    #[test]
    fn honors_an_explicit_non_loopback_override() {
        // The value itself isn't gated here — `enforce_bind_policy` in main.rs
        // is what refuses to actually bind a non-loopback address without
        // TAHLK_ALLOW_INSECURE=1. This function's job is only to parse the
        // configured value correctly.
        assert_eq!(parse_bind_ip(Some("0.0.0.0".to_string())), IpAddr::from([0, 0, 0, 0]));
    }

    #[test]
    fn honors_an_explicit_ipv6_override() {
        assert_eq!(parse_bind_ip(Some("::1".to_string())), "::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    #[should_panic(expected = "is not a valid IP address")]
    fn rejects_a_malformed_address_instead_of_silently_falling_back() {
        // Silently falling back to loopback on a typo'd TAHLK_BIND_ADDR would
        // be its own footgun (operator thinks they set a custom bind address,
        // service quietly binds loopback instead) — fail loudly at startup.
        parse_bind_ip(Some("not-an-ip".to_string()));
    }

    // Guards against a regression where `from_env()` stops actually calling
    // `parse_bind_ip` (e.g. someone "simplifies" it back to a hardcoded
    // `SocketAddr::from(([0, 0, 0, 0], port))`, which is exactly the bug this
    // whole fix addresses) — `parse_bind_ip`'s own unit tests above only prove
    // the helper is correct in isolation, not that `from_env` is wired to it.
    //
    // Both tests below mutate the real `TAHLK_BIND_ADDR` process env var, so
    // they'd race each other if `cargo test` (which runs tests in parallel
    // threads by default) scheduled them concurrently. `ENV_MUTEX` forces
    // them to run one at a time relative to each other; each still restores
    // the var to its prior state before releasing the lock so neither can
    // leak into any other test in the binary.
    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn from_env_actually_uses_tahlk_bind_addr_when_set() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let prior = std::env::var("TAHLK_BIND_ADDR").ok();
        std::env::set_var("TAHLK_BIND_ADDR", "10.20.30.40");
        let cfg = from_env();
        match prior {
            Some(p) => std::env::set_var("TAHLK_BIND_ADDR", p),
            None => std::env::remove_var("TAHLK_BIND_ADDR"),
        }
        assert_eq!(cfg.addr.ip(), IpAddr::from([10, 20, 30, 40]));
    }

    #[test]
    fn from_env_defaults_to_loopback_when_tahlk_bind_addr_is_unset() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let prior = std::env::var("TAHLK_BIND_ADDR").ok();
        std::env::remove_var("TAHLK_BIND_ADDR");
        let cfg = from_env();
        if let Some(p) = prior {
            std::env::set_var("TAHLK_BIND_ADDR", p);
        }
        assert_eq!(
            cfg.addr.ip(),
            IpAddr::from([127, 0, 0, 1]),
            "the documented default (README: 'cargo run # listens on 127.0.0.1:8080') must hold with no TAHLK_BIND_ADDR set"
        );
    }
}
