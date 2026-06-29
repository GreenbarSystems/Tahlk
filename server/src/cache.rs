use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::time::{Duration, Instant};

// Cache boundary. The in-memory impl is process-local; swap for a Redis impl
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
