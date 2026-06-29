use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::HashMap;

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

// In-memory implementation — lets the service run with no database. Maps are
// keyed by tenant so isolation holds here too.
#[derive(Default)]
pub struct InMemoryStore {
    encounters: Mutex<HashMap<String, HashMap<String, Encounter>>>,
    audit: Mutex<HashMap<String, Vec<AuditEntry>>>,
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
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default();
        rows.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        rows.truncate(limit);
        Ok(rows)
    }

    async fn get(&self, tenant: &str, id: &str) -> anyhow::Result<Option<Encounter>> {
        Ok(self.encounters.lock().get(tenant).and_then(|m| m.get(id).cloned()))
    }

    async fn upsert(&self, tenant: &str, enc: Encounter) -> anyhow::Result<()> {
        self.encounters
            .lock()
            .entry(tenant.to_string())
            .or_default()
            .insert(enc.id.clone(), enc);
        Ok(())
    }

    async fn append_audit(&self, tenant: &str, entry: AuditEntry) -> anyhow::Result<()> {
        let key = format!("{tenant}::{}", entry.encounter_id);
        self.audit.lock().entry(key).or_default().push(entry);
        Ok(())
    }

    async fn list_audit(&self, tenant: &str, encounter_id: &str) -> anyhow::Result<Vec<AuditEntry>> {
        let key = format!("{tenant}::{encounter_id}");
        Ok(self.audit.lock().get(&key).cloned().unwrap_or_default())
    }
}
