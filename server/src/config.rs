use std::net::SocketAddr;

pub struct Config {
    pub addr: SocketAddr,
}

// 12-factor: configuration comes from the environment. PORT is the only knob the
// minimal build needs; the Postgres/Redis impls read DATABASE_URL / REDIS_URL.
pub fn from_env() -> Config {
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);
    Config {
        addr: SocketAddr::from(([0, 0, 0, 0], port)),
    }
}
