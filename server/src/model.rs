use serde::{Deserialize, Serialize};

// Encounter mirrors the desktop app's encounters row, with two server-tier
// differences: PHI audio is NOT stored here — `audio_object_key` references an
// encrypted object in object storage — and `updated_at` is a server-assigned
// clock used for last-writer-wins sync. Unknown fields (e.g. the client's
// `audio_path`) are ignored; every field defaults so partial payloads decode.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Encounter {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub provider_id: String,
    #[serde(default)]
    pub encounter_date: String,
    #[serde(default)]
    pub patient_alias: Option<String>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub signed_at: Option<String>,
    #[serde(default)]
    pub signed_hash: Option<String>,
    #[serde(default)]
    pub audio_object_key: Option<String>,
    #[serde(default)]
    pub updated_at: i64,
}

// Append-only audit / hash-chain entry. The server stamps `received_at`; the
// chain fields (content_hash/prev_hash/entry_hash) are computed on the client
// and stored verbatim so tamper-evidence is preserved end to end.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct AuditEntry {
    #[serde(default)]
    pub encounter_id: String,
    #[serde(default)]
    pub actor: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub timestamp: String,
    #[serde(default)]
    pub content_hash: Option<String>,
    #[serde(default)]
    pub prev_hash: Option<String>,
    #[serde(default)]
    pub entry_hash: Option<String>,
    #[serde(default)]
    pub received_at: i64,
}
