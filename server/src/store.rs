use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};

use crate::model::{AuditEntry, Encounter};

// Data-access boundary. Every method is tenant-scoped — the handler passes the
// authenticated tenant, and a Postgres impl additionally sets `app.tenant_id`
// so row-level security enforces isolation even if a query forgets the filter.
#[async_trait]
pub trait EncounterStore: Send + Sync {
    async fn list(&self, tenant: &str, limit: usize) -> anyhow::Result<Vec<Encounter>>;
    async fn get(&self, tenant: &str, id: &str) -> anyhow::Result<Option<Encounter>>;
    async fn upsert(&self, tenant: &str, enc: Encounter) -> anyhow::Result<()>;
    async fn append_audit(&self, tenant: &str, entry: AuditEntry) -> anyhow::Result<()>;
    async fn list_audit(&self, tenant: &str, encounter_id: &str) -> anyhow::Result<Vec<AuditEntry>>;
}

// Caps applied by `InMemoryStore` so a misbehaving or malicious tenant can't
// grow the process's memory without bound. This store is the zero-infra
// fallback (see main.rs), not a real database — it has no disk-backed
// eviction, no query planner, nothing to bound memory except these constants.
// Without them, `upsert` and `append_audit` are pure inserts: every unique
// encounter id or every audit call grows a `HashMap`/`Vec` forever, and a
// single noisy tenant (or `RATE_LIMIT_PER_MIN` requests/min sustained for
// long enough) eventually exhausts the process. Real deployments should use
// the Postgres-backed store (see README); these caps just make the fallback
// safe to leave running rather than a guaranteed OOM over time.
//
// Eviction is oldest-first (FIFO by insertion/append order), so a tenant
// bumping into the cap loses their oldest data rather than being rejected —
// consistent with this being a soft, best-effort fallback store rather than a
// durable system of record.
const MAX_ENCOUNTERS_PER_TENANT: usize = 10_000;
const MAX_AUDIT_ENTRIES_PER_ENCOUNTER: usize = 10_000;

// Per-tenant encounter storage: the map for O(1) lookup by id, plus a FIFO
// queue of ids in insertion order so we know which one to evict when the
// tenant is at capacity. `insert_order` only ever contains ids currently in
// `by_id` — entries are removed from the front of the queue exactly when
// they're removed from the map, so the two never drift.
#[derive(Default)]
struct TenantEncounters {
    by_id: HashMap<String, Encounter>,
    insert_order: VecDeque<String>,
}

impl TenantEncounters {
    fn upsert(&mut self, enc: Encounter) {
        let id = enc.id.clone();
        // A re-upsert of an existing id doesn't grow the set, so don't double
        // it in the eviction queue or evict on an update to something we
        // already had.
        let is_new = !self.by_id.contains_key(&id);
        self.by_id.insert(id.clone(), enc);
        if is_new {
            self.insert_order.push_back(id);
            while self.by_id.len() > MAX_ENCOUNTERS_PER_TENANT {
                if let Some(oldest) = self.insert_order.pop_front() {
                    self.by_id.remove(&oldest);
                } else {
                    break;
                }
            }
        }
    }
}

// In-memory implementation — lets the service run with no database. Maps are
// keyed by tenant so isolation holds here too.
#[derive(Default)]
pub struct InMemoryStore {
    encounters: Mutex<HashMap<String, TenantEncounters>>,
    audit: Mutex<HashMap<String, VecDeque<AuditEntry>>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl EncounterStore for InMemoryStore {
    async fn list(&self, tenant: &str, limit: usize) -> anyhow::Result<Vec<Encounter>> {
        let guard = self.encounters.lock();
        let mut rows: Vec<Encounter> = guard
            .get(tenant)
            .map(|t| t.by_id.values().cloned().collect())
            .unwrap_or_default();
        rows.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        rows.truncate(limit);
        Ok(rows)
    }

    async fn get(&self, tenant: &str, id: &str) -> anyhow::Result<Option<Encounter>> {
        Ok(self
            .encounters
            .lock()
            .get(tenant)
            .and_then(|t| t.by_id.get(id).cloned()))
    }

    async fn upsert(&self, tenant: &str, enc: Encounter) -> anyhow::Result<()> {
        self.encounters
            .lock()
            .entry(tenant.to_string())
            .or_default()
            .upsert(enc);
        Ok(())
    }

    async fn append_audit(&self, tenant: &str, entry: AuditEntry) -> anyhow::Result<()> {
        let key = format!("{tenant}::{}", entry.encounter_id);
        let mut guard = self.audit.lock();
        let entries = guard.entry(key).or_default();
        entries.push_back(entry);
        while entries.len() > MAX_AUDIT_ENTRIES_PER_ENCOUNTER {
            entries.pop_front();
        }
        Ok(())
    }

    async fn list_audit(&self, tenant: &str, encounter_id: &str) -> anyhow::Result<Vec<AuditEntry>> {
        let key = format!("{tenant}::{encounter_id}");
        Ok(self
            .audit
            .lock()
            .get(&key)
            .map(|entries| entries.iter().cloned().collect())
            .unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(id: &str) -> Encounter {
        Encounter {
            id: id.to_string(),
            created_at: id.to_string(), // sortable stand-in, not used by these tests
            ..Default::default()
        }
    }

    fn audit_entry(encounter_id: &str, action: &str) -> AuditEntry {
        AuditEntry {
            encounter_id: encounter_id.to_string(),
            action: action.to_string(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn upsert_and_get_roundtrip() {
        let store = InMemoryStore::new();
        store.upsert("tenant-a", enc("e1")).await.unwrap();
        let got = store.get("tenant-a", "e1").await.unwrap();
        assert_eq!(got.map(|e| e.id), Some("e1".to_string()));
    }

    #[tokio::test]
    async fn tenants_are_isolated() {
        let store = InMemoryStore::new();
        store.upsert("tenant-a", enc("e1")).await.unwrap();
        assert!(store.get("tenant-b", "e1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn encounters_beyond_the_cap_evict_the_oldest_first() {
        let store = InMemoryStore::new();
        // Fill one past the cap; e0 (the very first inserted) should be the one
        // evicted, and every id from e1..=e_cap should survive.
        for i in 0..=MAX_ENCOUNTERS_PER_TENANT {
            store.upsert("tenant-a", enc(&format!("e{i}"))).await.unwrap();
        }
        let rows = store.list("tenant-a", MAX_ENCOUNTERS_PER_TENANT + 10).await.unwrap();
        assert_eq!(rows.len(), MAX_ENCOUNTERS_PER_TENANT, "store should never exceed the per-tenant cap");
        assert!(
            store.get("tenant-a", "e0").await.unwrap().is_none(),
            "the oldest encounter should have been evicted"
        );
        assert!(
            store.get("tenant-a", &format!("e{MAX_ENCOUNTERS_PER_TENANT}")).await.unwrap().is_some(),
            "the newest encounter should still be present"
        );
    }

    #[tokio::test]
    async fn re_upserting_an_existing_id_does_not_count_twice_against_the_cap() {
        let store = InMemoryStore::new();
        for i in 0..10 {
            store.upsert("tenant-a", enc(&format!("e{i}"))).await.unwrap();
        }
        // Re-upsert an existing id many times — this must not push anything
        // else out, since it's an update, not a new entry.
        for _ in 0..5 {
            store.upsert("tenant-a", enc("e3")).await.unwrap();
        }
        for i in 0..10 {
            assert!(
                store.get("tenant-a", &format!("e{i}")).await.unwrap().is_some(),
                "e{i} should not have been evicted by re-upserting an existing id"
            );
        }
    }

    #[tokio::test]
    async fn audit_entries_beyond_the_cap_evict_the_oldest_first() {
        let store = InMemoryStore::new();
        for i in 0..=MAX_AUDIT_ENTRIES_PER_ENCOUNTER {
            store
                .append_audit("tenant-a", audit_entry("e1", &format!("action-{i}")))
                .await
                .unwrap();
        }
        let entries = store.list_audit("tenant-a", "e1").await.unwrap();
        assert_eq!(entries.len(), MAX_AUDIT_ENTRIES_PER_ENCOUNTER, "audit log should never exceed the per-encounter cap");
        assert_eq!(
            entries.first().map(|e| e.action.as_str()),
            Some("action-1"),
            "the oldest audit entry (action-0) should have been evicted"
        );
        assert_eq!(
            entries.last().map(|e| e.action.as_str()),
            Some(format!("action-{MAX_AUDIT_ENTRIES_PER_ENCOUNTER}")).as_deref()
        );
    }

    #[tokio::test]
    async fn audit_log_is_scoped_per_tenant_and_encounter() {
        let store = InMemoryStore::new();
        store.append_audit("tenant-a", audit_entry("e1", "signed")).await.unwrap();
        store.append_audit("tenant-b", audit_entry("e1", "signed")).await.unwrap();
        assert_eq!(store.list_audit("tenant-a", "e1").await.unwrap().len(), 1);
        assert_eq!(store.list_audit("tenant-b", "e1").await.unwrap().len(), 1);
        assert_eq!(store.list_audit("tenant-a", "e2").await.unwrap().len(), 0);
    }
}
