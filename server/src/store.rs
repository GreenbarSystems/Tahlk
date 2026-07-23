use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

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
//
// `audit` is nested (tenant -> encounter_id -> entries), not a single map
// keyed by a composite `"{tenant}::{encounter_id}"` string (audit finding,
// Medium: "InMemoryStore has no tenant-isolation defense-in-depth"). A
// composite string key is a real collision hazard here, not just a
// theoretical one: `encounter_id` is an unvalidated URL path segment
// (api.rs's `Path<String>` extractor), so nothing stops it from containing
// `::`. Two different (tenant, encounter_id) pairs can then hash to the
// exact same string — e.g. tenant "acme" + encounter_id "secret::notes"
// produces the identical key "acme::secret::notes" as tenant "acme::secret"
// + encounter_id "notes" — which would let one tenant's audit entries land
// in, or be read from, a bucket a different tenant's request also resolves
// to. Nesting the maps (mirroring `encounters`'s existing, correct
// tenant-keyed design) removes the ambiguity structurally: no string
// encoding, no separator to collide on.
#[derive(Default)]
pub struct InMemoryStore {
    encounters: Mutex<HashMap<String, TenantEncounters>>,
    audit: Mutex<HashMap<String, HashMap<String, VecDeque<AuditEntry>>>>,
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
        let mut guard = self.audit.lock();
        let entries = guard
            .entry(tenant.to_string())
            .or_default()
            .entry(entry.encounter_id.clone())
            .or_default();
        entries.push_back(entry);
        while entries.len() > MAX_AUDIT_ENTRIES_PER_ENCOUNTER {
            entries.pop_front();
        }
        Ok(())
    }

    async fn list_audit(&self, tenant: &str, encounter_id: &str) -> anyhow::Result<Vec<AuditEntry>> {
        Ok(self
            .audit
            .lock()
            .get(tenant)
            .and_then(|by_encounter| by_encounter.get(encounter_id))
            .map(|entries| entries.iter().cloned().collect())
            .unwrap_or_default())
    }
}

// Registry of device_ids that have been through POST /v1/devices/register.
// Follows the same `Arc<dyn Trait>` boundary as `EncounterStore`: an in-memory
// impl here for zero-infra runs, a Postgres impl droppable in later without
// touching the handler. Its purpose is twofold — make registration auditable
// (who/when/how-often) and give a place to hang revocation later — NOT to gate
// issuance: registration is idempotent by device_id (a lost token must be
// re-mintable), so `register` never errors on "already registered".
#[async_trait]
pub trait DeviceStore: Send + Sync {
    // Idempotent: records a first registration or updates an existing device's
    // last-seen/count, returning the (post-update) record for auditing.
    async fn register(&self, device_id: &str) -> anyhow::Result<DeviceRecord>;
    // Lookup used by tests/auditing; not on the request hot path.
    async fn get(&self, device_id: &str) -> anyhow::Result<Option<DeviceRecord>>;
}

// Per-device audit record. `registrations` counts (re-)enrollments so token-loss
// recovery is observable; timestamps are unix milliseconds (matching api.rs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceRecord {
    pub first_registered_at: i64,
    pub last_registered_at: i64,
    pub registrations: u64,
}

// Cap on distinct devices the in-memory registry retains. The register endpoint
// is unauthenticated, so an anonymous caller could otherwise grow this map
// without bound over time (the per-IP rate limiter bounds the *rate*, not the
// lifetime total). Oldest-first eviction is safe here precisely because
// registration is idempotent: an evicted device simply re-registers on its next
// call and gets a fresh record + token, losing only audit history — acceptable
// for the zero-infra fallback (real deployments use a durable Postgres impl).
const MAX_REGISTERED_DEVICES: usize = 100_000;

// `by_id` for O(1) lookup, `insert_order` as a FIFO of ids for eviction. As with
// `TenantEncounters`, `insert_order` only ever holds ids currently in `by_id`.
#[derive(Default)]
struct DeviceRegistry {
    by_id: HashMap<String, DeviceRecord>,
    insert_order: VecDeque<String>,
}

#[derive(Default)]
pub struct InMemoryDeviceStore {
    devices: Mutex<DeviceRegistry>,
}

impl InMemoryDeviceStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl DeviceStore for InMemoryDeviceStore {
    async fn register(&self, device_id: &str) -> anyhow::Result<DeviceRecord> {
        let now = now_ms();
        let mut reg = self.devices.lock();
        if let Some(rec) = reg.by_id.get_mut(device_id) {
            rec.last_registered_at = now;
            rec.registrations += 1;
            return Ok(rec.clone());
        }
        let rec = DeviceRecord {
            first_registered_at: now,
            last_registered_at: now,
            registrations: 1,
        };
        reg.by_id.insert(device_id.to_string(), rec.clone());
        reg.insert_order.push_back(device_id.to_string());
        while reg.by_id.len() > MAX_REGISTERED_DEVICES {
            if let Some(oldest) = reg.insert_order.pop_front() {
                reg.by_id.remove(&oldest);
            } else {
                break;
            }
        }
        Ok(rec)
    }

    async fn get(&self, device_id: &str) -> anyhow::Result<Option<DeviceRecord>> {
        Ok(self.devices.lock().by_id.get(device_id).cloned())
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
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

    // Regression for the composite-string-key collision a nested map
    // structurally eliminates: tenant "acme" + encounter_id "secret::notes"
    // and tenant "acme::secret" + encounter_id "notes" would have hashed to
    // the identical `"acme::secret::notes"` key under the old
    // `format!("{tenant}::{encounter_id}")` scheme, letting one tenant's
    // audit entries be visible to (or overwritten by) a different tenant.
    // encounter_id is an unvalidated URL path segment in api.rs, so `::`
    // reaching this code is a real, reachable input, not a contrived one.
    #[tokio::test]
    async fn tenant_and_encounter_id_containing_the_old_separator_do_not_collide() {
        let store = InMemoryStore::new();
        store
            .append_audit("acme", audit_entry("secret::notes", "victim-entry"))
            .await
            .unwrap();
        store
            .append_audit("acme::secret", audit_entry("notes", "attacker-entry"))
            .await
            .unwrap();

        let victim = store.list_audit("acme", "secret::notes").await.unwrap();
        let attacker = store.list_audit("acme::secret", "notes").await.unwrap();

        assert_eq!(victim.len(), 1, "the victim's own entry must be visible");
        assert_eq!(victim[0].action, "victim-entry");
        assert_eq!(attacker.len(), 1, "the attacker's own entry must be visible");
        assert_eq!(attacker[0].action, "attacker-entry");
        // Neither must see the other's entry — this is the actual isolation
        // property the old composite key could silently violate.
        assert!(!victim.iter().any(|e| e.action == "attacker-entry"));
        assert!(!attacker.iter().any(|e| e.action == "victim-entry"));
    }

    #[tokio::test]
    async fn register_records_a_new_device() {
        let store = InMemoryDeviceStore::new();
        let rec = store.register("dev-1").await.unwrap();
        assert_eq!(rec.registrations, 1);
        assert_eq!(store.get("dev-1").await.unwrap(), Some(rec));
        assert!(store.get("dev-2").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn re_registration_is_idempotent_and_bumps_the_count() {
        let store = InMemoryDeviceStore::new();
        let first = store.register("dev-1").await.unwrap();
        let second = store.register("dev-1").await.unwrap();
        assert_eq!(second.registrations, 2, "re-registration bumps the count, never errors");
        assert_eq!(
            second.first_registered_at, first.first_registered_at,
            "first_registered_at is preserved across re-registration"
        );
    }

    #[tokio::test]
    async fn devices_beyond_the_cap_evict_the_oldest_first() {
        let store = InMemoryDeviceStore::new();
        for i in 0..=MAX_REGISTERED_DEVICES {
            store.register(&format!("dev-{i}")).await.unwrap();
        }
        assert!(
            store.get("dev-0").await.unwrap().is_none(),
            "the oldest device should have been evicted at the cap"
        );
        assert!(
            store.get(&format!("dev-{MAX_REGISTERED_DEVICES}")).await.unwrap().is_some(),
            "the newest device should still be present"
        );
    }
}
