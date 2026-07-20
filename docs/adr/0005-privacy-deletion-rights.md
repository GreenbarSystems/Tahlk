# ADR-0005 — Privacy, Deletion Rights, and Record Retention

**Status:** Planned — 2026-07-20  
**Area:** Data lifecycle, HIPAA PHI disposal, state privacy law (CCPA/CMIA, state medical-record retention statutes)

---

## Context

The 2026-07-14 security audit and subsequent compliance scoring identified state privacy law as the lowest-scoring framework (73/100). The two root causes:

1. **No full-deletion path for clinical records.** `delete_patient` removes only the roster row — linked encounters, note content (in the `kv` table), transcripts, audio files, `note_history`, and `note_audit` PHI all remain. `delete_encounter` correctly removes kv content and audio but leaves `note_history` rows and `note_audit.entry_json` (which contains PHI) as live orphans.

2. **No retention period configuration.** Records are retained indefinitely by default. No tool exists to identify or destroy records that have passed a state-mandated retention deadline, and no destruction act is logged anywhere.

These gaps mean the app cannot:
- Honor a patient's right-to-erasure request (CCPA/CMIA and analogous state statutes)
- Enforce a provider-configured retention policy
- Produce documentation of PHI destruction (required by HIPAA for proper PHI disposal)

---

## Decision

Implement a four-commit privacy and deletion system with the following design principles:

**Tombstone, don't break the audit chain.** `note_audit` and `patient_audit` are append-only by design (HIPAA audit integrity). On PHI destruction, scrub their content fields (`entry_json` → a destruction tombstone JSON) and blind the `encounter_id` column (SHA-256 hash, non-reversible) rather than deleting rows. The chain structure (seq, prev_hash, entry_hash) stays intact. `note_history` contains no PHI (only hashes and action metadata) and is hard-deleted.

**Document every destruction act.** A new append-only `destruction_log` table records every destruction event: who, when, what entity, how many records, under what legal basis. This table has no delete command and satisfies HIPAA's requirement to document PHI disposal.

**Automatic discovery, provider-confirmed destruction.** Silent auto-deletion of medical records is legally risky (litigation holds, state certification requirements). Instead: on every app launch, run a retention check and surface a dismissible banner when records have passed their retention deadline. The provider confirms destruction in one click; the act is logged. A **litigation hold** toggle suppresses the banner when needed.

---

## Schema changes

### New table: `destruction_log` (append-only)

```sql
CREATE TABLE IF NOT EXISTS destruction_log (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at        TEXT NOT NULL,
    provider_id       TEXT NOT NULL DEFAULT '',
    entity_type       TEXT NOT NULL,   -- 'encounter' | 'patient' | 'bulk'
    entity_id         TEXT NOT NULL,   -- original encounter_id or patient_id
    patient_alias     TEXT,            -- captured at destruction time
    legal_basis       TEXT NOT NULL,   -- 'patient_request' | 'provider_request' | 'retention_expired'
    records_scrubbed  INTEGER NOT NULL DEFAULT 0
);
```

No Tauri delete command is ever registered for this table.

### Migration: `patient_id` on `encounters`

```sql
ALTER TABLE encounters ADD COLUMN patient_id TEXT;
```

Applied idempotently in `open_database` via `pragma_table_info` check. Populated on new encounters going forward; historical rows remain NULL and are matched by `patient_alias` fallback on cascade delete.

---

## Implementation

### Commit 1 — Encounter destroy: scrub note_audit, delete note_history, log destruction

**`src-tauri/src/destruction_log.rs`** (new)
- `init_schema(conn)` — creates table, called from `db.rs`
- `append(tx, provider_id, entity_type, entity_id, patient_alias, legal_basis, n)` — internal helper
- `list(conn, limit)` — read-only, for the settings UI
- No delete command

**`src-tauri/src/encounters.rs`** — extend `delete_encounter_row`

Inside the existing transaction, after kv + audio deletion:

```rust
// 1. Count note_audit rows before scrubbing (for destruction_log)
let scrubbed: i64 = tx.query_row(
    "SELECT COUNT(*) FROM note_audit WHERE encounter_id = ?1",
    params![encounter_id], |r| r.get(0)
).unwrap_or(0);

// 2. Scrub note_audit PHI — replace entry_json with tombstone
let tombstone = serde_json::json!({
    "destroyed": true,
    "destroyed_at": now_iso(),
    "legal_basis": reason
}).to_string();
tx.execute(
    "UPDATE note_audit SET entry_json = ?1 WHERE encounter_id = ?2",
    params![tombstone, encounter_id],
)?;

// 3. Blind encounter_id in note_audit (SHA-256 hash, non-reversible)
//    Prevents orphaned ID from being treated as a CCPA "unique identifier"
let blinded = sha256_hex(format!("{}{}", encounter_id, now_iso()));
tx.execute(
    "UPDATE note_audit SET encounter_id = ?1 WHERE encounter_id = ?2",
    params![blinded, encounter_id],
)?;

// 4. Hard-delete note_history — no PHI, version scaffolding only
tx.execute(
    "DELETE FROM note_history WHERE encounter_id = ?1",
    params![encounter_id],
)?;

// 5. Log the destruction act
destruction_log::append(
    &tx, provider_id, "encounter", encounter_id,
    &patient_alias, reason, scrubbed
)?;
```

Add `reason: &str` parameter to `delete_encounter_row`; existing `delete_encounter` Tauri command passes `"provider_request"` as default.

---

### Commit 2 — Patient cascade delete

**`src-tauri/src/db.rs`** — idempotent migration adds `patient_id TEXT` to `encounters`.

**`src-tauri/src/encounters.rs`** — `upsert_encounter` writes `patient_id` when present in the incoming JSON (backwards-compatible; historical rows stay NULL).

**`src-tauri/src/patients.rs`** — extend `delete_patient_conn`

```rust
// Find all encounters linked to this patient (FK or alias fallback)
let encounter_ids: Vec<String> = {
    let mut stmt = conn.prepare(
        "SELECT id FROM encounters
         WHERE patient_id = ?1
            OR (patient_id IS NULL AND patient_alias = (
                SELECT alias FROM patients WHERE id = ?1
            ))"
    )?;
    stmt.query_map(params![id], |r| r.get(0))?
        .filter_map(|r| r.ok())
        .collect()
};

// Destroy each encounter (cascades kv, audio, note_history, note_audit)
for enc_id in &encounter_ids {
    encounters::delete_encounter_row(conn, enc_id, provider_id, "patient_request")?;
}
```

Returns `{ encounters_destroyed: usize }` so the JS confirmation dialog can surface the count.

New Tauri command: **`destroy_patient_records(patient_id, provider_id)`** — same cascade logic as `delete_patient` but exposed separately so the UI can offer two paths:

- **"Remove from roster"** — removes the patient row only; encounters remain (provider keeps clinical history, removes the name linkage)
- **"Delete patient + destroy all records"** — full cascade

---

### Commit 3 — Retention settings + launch-time check + litigation hold

**`src-tauri/src/retention.rs`** (new)

```rust
// Reads/writes settings_v1::retention_years via existing kv path
pub fn get_retention_years(conn: &Connection) -> i64  // default 7
pub fn set_retention_years(conn: &Connection, years: i64) -> Result<()>

// Returns encounters older than the cutoff (signed only; drafts excluded)
pub fn list_candidates(conn: &Connection, cutoff: &str) -> Result<Vec<RetentionCandidate>>
// { id, patient_alias, encounter_date, signed_at }

// Destroys all candidates, returns count
pub fn destroy_eligible(conn: &Connection, provider_id: &str, cutoff: &str) -> Result<usize>

// Litigation hold: settings_v1::litigation_hold_active (bool)
pub fn get_litigation_hold(conn: &Connection) -> bool
pub fn set_litigation_hold(conn: &Connection, active: bool) -> Result<()>
```

All five registered as Tauri commands.

**`src/solo/settingsModal.js`** — new **"Privacy & data retention"** section

- Retention period `<select>`: 1 / 3 / 7 / 10 / Indefinite years (label notes 7 years is the most common US state default for adult medical records)
- Live count: *"N encounters are past the current retention period"* (fetched on section open)
- **"Destroy N eligible records →"** button → confirmation modal listing patient aliases and date ranges → `destroy_eligible` → success toast with count
- **Litigation hold** toggle: when on, suppresses launch-time destruction prompts and writes a `litigation_hold_suppressed` entry to `destruction_log` each time the banner would have fired

**`src/solo/app.js` (or main entry)** — post-auth launch check

```js
// After auth unlock, before rendering main view
const candidates = await retentionRepo.listCandidates();
const litigationHold = await retentionRepo.getLitigationHold();
if (candidates.length > 0 && !litigationHold) {
    showRetentionBanner(candidates.length);
}
```

Banner: *"N clinical records have passed their [7]-year retention period. [Review and destroy →]  [Dismiss]"*  
Dismiss is session-scoped only; the banner re-fires on next launch until records are destroyed or a litigation hold is set.

---

### Commit 4 — Deletion UI + destruction log view

**`src/solo/patientsView.js`** — patient delete confirmation modal

Before the existing "Are you sure?" step, show a pre-confirmation panel:

```
Deleting [JS] will permanently destroy:
  • 14 encounter records
  • 14 transcripts
  • 6 audio files
  • All associated audit content

The destruction will be logged. This cannot be undone.

[ ] I understand this is permanent and irreversible
                                    [Cancel]  [Delete patient + destroy records]
```

Checkbox must be checked before the primary button enables.

**Encounters view** — individual encounter delete

Add a delete icon/button to each encounter card (currently none exists). Signed encounters show an additional warning banner before the confirmation:

*"This is a signed clinical record. Destruction is permanent, irreversible, and will be logged."*

**`src/solo/settingsModal.js`** — destruction log section under **Advanced & troubleshooting**

- Table: last 50 rows from `destruction_log` — date, entity type, patient alias (truncated to first 2 chars + length), legal basis, records count
- Export to CSV button
- Read-only; no clear/delete action

---

## What this closes

| Gap | Commit |
|---|---|
| Patient delete leaves encounters/notes/audio intact | 2 |
| `delete_encounter` leaves PHI in `note_audit.entry_json` | 1 |
| Orphaned `note_history` rows after encounter delete | 1 |
| No documented destruction audit (HIPAA PHI disposal requirement) | 1 (`destruction_log`) |
| `encounter_id` retained in tombstone (CCPA unique-identifier risk) | 1 (SHA-256 blinding) |
| No way to honor patient right-to-erasure | 1 + 2 + 4 |
| No retention period configuration | 3 |
| No mechanism to identify or purge records past retention deadline | 3 |
| No litigation hold capability | 3 |

---

## What this does not close (accepted residual risk)

- `llm_audit` rows are retained after encounter destruction. These contain only metadata (model, endpoint, byte counts, duration, outcome) — no PHI, no content. Not a deletion-right gap.
- `destruction_log` itself is never deletable. This is intentional and legally required — it is the evidence of destruction, not a PHI store.
- True scheduled auto-destruction (without provider confirmation) is not implemented. Provider-confirmed destruction with automatic discovery satisfies most state destruction-certification requirements and avoids the litigation-hold liability of silent auto-deletion.

---

## Rollout

All four commits can ship together as a single release. No feature flag needed — the `destruction_log` table and `patient_id` migration are backwards-compatible. Existing installs receive the migration silently on next launch.

Expected State Privacy Laws score after: **73 → 82**.  
Remaining deductions: no silent auto-purge (accepted), `llm_audit` metadata retention (not PHI, not a gap).
