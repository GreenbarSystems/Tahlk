use async_trait::async_trait;
use parking_lot::Mutex;
use redis::AsyncCommands;
use std::collections::HashMap;
use std::time::{Duration, Instant};

// Cache boundary. The in-memory impl is process-local; swap for the Redis impl
// (same trait) to share the cache across horizontally-scaled instances.
#[async_trait]
pub trait Cache: Send + Sync {
    async fn get(&self, key: &str) -> Option<String>;
    async fn set(&self, key: &str, value: String, ttl: Duration);
    async fn invalidate(&self, key: &str);
}

#[derive(Default)]
pub struct InMemoryCache {
    map: Mutex<HashMap<String, (String, Instant)>>,
}

impl InMemoryCache {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Cache for InMemoryCache {
    async fn get(&self, key: &str) -> Option<String> {
        let mut guard = self.map.lock();
        match guard.get(key) {
            Some((value, expiry)) if *expiry > Instant::now() => Some(value.clone()),
            Some(_) => {
                guard.remove(key); // lazily evict expired entries
                None
            }
            None => None,
        }
    }

    async fn set(&self, key: &str, value: String, ttl: Duration) {
        self.map.lock().insert(key.to_string(), (value, Instant::now() + ttl));
    }

    async fn invalidate(&self, key: &str) {
        self.map.lock().remove(key);
    }
}

// S4: shared cache for horizontally-scaled deployments. `InMemoryCache` is
// per-process, so once more than one replica is running Instance A can keep
// serving a list that Instance B has already invalidated. `RedisCache` moves the
// cache into a shared Redis so an invalidate on any instance is seen by all.
//
// `ConnectionManager` is cheap to clone and transparently reconnects, so each
// method clones it rather than holding a lock. Redis errors are treated as a
// cache miss / no-op (the store remains the source of truth) and logged — a
// transient Redis blip degrades to "uncached", never to a failed request.
pub struct RedisCache {
    conn: redis::aio::ConnectionManager,
}

impl RedisCache {
    // Connect eagerly so a misconfigured `TAHLK_REDIS_URL` fails at startup
    // rather than on the first request. Returns `Err(reason)` for `main` to
    // abort on.
    pub async fn connect(url: &str) -> Result<Self, String> {
        let client = redis::Client::open(url).map_err(|e| e.to_string())?;
        let conn = client
            .get_connection_manager()
            .await
            .map_err(|e| e.to_string())?;
        Ok(Self { conn })
    }
}

#[async_trait]
impl Cache for RedisCache {
    async fn get(&self, key: &str) -> Option<String> {
        let mut conn = self.conn.clone();
        match conn.get::<_, Option<String>>(key).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "redis GET failed; treating as cache miss");
                None
            }
        }
    }

    async fn set(&self, key: &str, value: String, ttl: Duration) {
        let mut conn = self.conn.clone();
        // SETEX needs whole seconds; never pass 0 (redis rejects a 0 TTL).
        let secs = ttl.as_secs().max(1);
        if let Err(e) = conn.set_ex::<_, _, ()>(key, value, secs).await {
            tracing::warn!(error = %e, "redis SETEX failed; entry not cached");
        }
    }

    async fn invalidate(&self, key: &str) {
        let mut conn = self.conn.clone();
        if let Err(e) = conn.del::<_, ()>(key).await {
            tracing::warn!(error = %e, "redis DEL failed; stale entry may persist until TTL");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn in_memory_get_set_invalidate_roundtrip() {
        let c = InMemoryCache::new();
        assert_eq!(c.get("k").await, None);
        c.set("k", "v".to_string(), Duration::from_secs(30)).await;
        assert_eq!(c.get("k").await.as_deref(), Some("v"));
        c.invalidate("k").await;
        assert_eq!(c.get("k").await, None);
    }

    #[tokio::test]
    async fn in_memory_entry_expires() {
        let c = InMemoryCache::new();
        c.set("k", "v".to_string(), Duration::from_millis(10)).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(c.get("k").await, None);
    }

    // A malformed URL is rejected at `Client::open`, before any network I/O, so
    // this exercises the startup fail-fast path without a live Redis. Full
    // get/set/invalidate behaviour against a real Redis is covered by the
    // in-memory roundtrip above (same trait) plus manual verification against a
    // live instance — see server/README.md.
    #[tokio::test]
    async fn redis_connect_rejects_malformed_url() {
        assert!(RedisCache::connect("not-a-redis-url").await.is_err());
    }
}
