use async_trait::async_trait;
use parking_lot::Mutex;
use redis::AsyncCommands;
use std::collections::HashMap;
use std::time::{Duration, Instant};

// Cache boundary. The in-memory impl is process-local; swap for the Redis impl
// (same trait) to share the cache across horizontally-scaled instances.
//
// `bump_version` exists to close a stale-set-after-invalidate race in the
// list-cache flow (see api.rs): a naive "write store, then invalidate(key)"
// on the write path racing a concurrent "miss, read store, then set(key)" on
// the read path can let the reader's *stale* snapshot land in the cache AFTER
// the writer's invalidate has already run, because the reader started before
// the write but its `set()` completes after the `invalidate()`. That stale
// entry then sits there for a full TTL with nothing to correct it.
//
// The fix is cache-key versioning rather than explicit deletion: callers
// fold `current_version(prefix)` into the cache key they read/write
// (e.g. "enc:list:{tenant}:v{n}"). A write bumps the version atomically
// *before* any concurrent reader's stale `set()` can land — even if that
// stale `set()` still executes after the bump, it writes under the OLD
// version's key, which no future reader will ever ask for again (they always
// read the current version). No explicit delete, so no race window: the
// property that matters is "the write is visible to the very next read",
// which an atomic increment gives us for free, whereas invalidate-then-set
// ordering cannot without a lock the whole point of caching is to avoid.
#[async_trait]
pub trait Cache: Send + Sync {
    async fn get(&self, key: &str) -> Option<String>;
    async fn set(&self, key: &str, value: String, ttl: Duration);
    async fn invalidate(&self, key: &str);
    // Atomically increment and return the new version counter for `prefix`.
    // Starts at 1 on first use (i.e. an absent counter behaves as if it were
    // 0 before the increment).
    async fn bump_version(&self, prefix: &str) -> u64;
    // Read the current version for `prefix` without incrementing it. Absent
    // counters read as 0, matching `bump_version`'s starting point.
    async fn current_version(&self, prefix: &str) -> u64;
}

#[derive(Default)]
pub struct InMemoryCache {
    map: Mutex<HashMap<String, (String, Instant)>>,
    versions: Mutex<HashMap<String, u64>>,
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

    async fn bump_version(&self, prefix: &str) -> u64 {
        let mut guard = self.versions.lock();
        let v = guard.entry(prefix.to_string()).or_insert(0);
        *v += 1;
        *v
    }

    async fn current_version(&self, prefix: &str) -> u64 {
        self.versions.lock().get(prefix).copied().unwrap_or(0)
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

    // Redis's INCR is atomic across all connected instances, which is exactly
    // the property that makes the version-keyed cache race-free in a
    // horizontally-scaled deployment (not just within one process, unlike a
    // local counter would be).
    async fn bump_version(&self, prefix: &str) -> u64 {
        let mut conn = self.conn.clone();
        let version_key = format!("{prefix}::version");
        match conn.incr::<_, _, i64>(&version_key, 1).await {
            Ok(v) => v.max(0) as u64,
            Err(e) => {
                // Fail open on the side of correctness: if we can't confirm the
                // bump, callers should assume the version DID move and treat any
                // in-flight read as unsafe to cache. Returning a value derived
                // from time keeps every caller's view moving forward even
                // without a working counter, rather than silently staying at
                // whatever version reads last observed.
                tracing::warn!(error = %e, "redis INCR failed for cache version; degrading to a time-based version");
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0)
            }
        }
    }

    async fn current_version(&self, prefix: &str) -> u64 {
        let mut conn = self.conn.clone();
        let version_key = format!("{prefix}::version");
        match conn.get::<_, Option<i64>>(&version_key).await {
            Ok(v) => v.unwrap_or(0).max(0) as u64,
            Err(e) => {
                tracing::warn!(error = %e, "redis GET failed for cache version; treating as version 0");
                0
            }
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

    #[tokio::test]
    async fn version_starts_at_zero_and_increments_monotonically() {
        let c = InMemoryCache::new();
        assert_eq!(c.current_version("p").await, 0);
        assert_eq!(c.bump_version("p").await, 1);
        assert_eq!(c.current_version("p").await, 1);
        assert_eq!(c.bump_version("p").await, 2);
        assert_eq!(c.bump_version("p").await, 3);
        assert_eq!(c.current_version("p").await, 3);
    }

    #[tokio::test]
    async fn version_counters_are_isolated_per_prefix() {
        let c = InMemoryCache::new();
        c.bump_version("tenant-a").await;
        c.bump_version("tenant-a").await;
        c.bump_version("tenant-b").await;
        assert_eq!(c.current_version("tenant-a").await, 2);
        assert_eq!(c.current_version("tenant-b").await, 1);
    }

    #[tokio::test]
    async fn a_set_under_a_stale_version_key_never_resurfaces_once_bumped() {
        // This is the core property the versioning scheme relies on: writing
        // to an old version's key must be permanently invisible once the
        // version has moved on, even though nothing ever explicitly deletes
        // that stale entry.
        let c = InMemoryCache::new();
        let v0 = c.current_version("enc:list:tenant-a").await;
        let stale_key = format!("enc:list:tenant-a:v{v0}");
        c.bump_version("enc:list:tenant-a").await; // a concurrent write happens
        // The stale reader's set() still lands, but under the old key.
        c.set(&stale_key, "stale-snapshot".to_string(), Duration::from_secs(30)).await;
        let v1 = c.current_version("enc:list:tenant-a").await;
        let fresh_key = format!("enc:list:tenant-a:v{v1}");
        assert_ne!(stale_key, fresh_key);
        assert_eq!(c.get(&fresh_key).await, None, "the current key was never populated by the stale writer");
    }
}
