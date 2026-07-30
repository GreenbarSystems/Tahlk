//! Database bootstrap and shared row helpers.
//!
//! `DbState` (the shared connection wrapper) lives in `lib.rs` at the crate
//! root so every module can name it via `crate::DbState` without cyclic
//! imports. This module owns the schema + connection pragmas and the
//! encounter-row projection used by both list and get queries.
//!
//! Encryption at rest: the DB file is SQLCipher-encrypted with a 256-bit DEK
//! held in the OS keychain (see `db_key`). On first launch after this
//! release, `open_database` detects a legacy plaintext DB by its magic bytes
//! and performs a one-shot copy migration via `sqlcipher_export` — the old
//! file is best-effort zeroed and unlinked, and a `.plaintext.bak` breadcrumb
//! is left next to the new encrypted file so an operator can spot a partial
//! migration. Unix file mode is tightened to 0600 so a curious process
//! running as a different user on the same box can't read the ciphertext.

use r2d2::{CustomizeConnection, Pool};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::path::Path;
use std::sync::Arc;
use tauri::{AppHandle, Manager};

use crate::{config_audit, db_key, destruction_log, errors::AppError, llm_audit, note_audit, note_history, patient_audit};

/// Alias for the desktop-wide SQLite pool type. Every command that used to
/// take a `Mutex<Connection>` guard now takes a `PooledConnection` handed out
/// by this pool; the `KeyingCustomizer` below guarantees every fresh checkout
/// is SQLCipher-keyed before it reaches user code.
pub(crate) type SqlitePool = Pool<SqliteConnectionManager>;

/// A connection checked out of the pool. Named so `DbState::conn` can return it
/// without every caller spelling out the r2d2/manager generics.
pub(crate) type PooledConn = r2d2::PooledConnection<SqliteConnectionManager>;

// SQLite file magic ("SQLite format 3\0"). SQLCipher-encrypted files start
// with random-looking ciphertext; plaintext files always begin with this
// exact 16-byte header, which is what we use to trigger the one-shot
// migration on upgrade.
const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";

// Column order shared by list_encounters and get_encounter. Keeping the
// SELECT list identical between the two paths means encounter_row_to_json
// can be reused without positional drift.
pub(crate) const ENCOUNTER_COLS: &str =
    "id, provider_id, encounter_date, patient_alias, status, \
     audio_path, created_at, signed_at, signed_hash, patient_id";

pub(crate) fn encounter_row_to_json(r: &rusqlite::Row) -> rusqlite::Result<Value> {
    Ok(json!({
        "id":             r.get::<_, String>(0)?,
        "provider_id":    r.get::<_, String>(1)?,
        "encounter_date": r.get::<_, String>(2)?,
        "patient_alias":  r.get::<_, Option<String>>(3)?,
        "status":         r.get::<_, String>(4)?,
        "audio_path":     r.get::<_, Option<String>>(5)?,
        "created_at":     r.get::<_, String>(6)?,
        "signed_at":      r.get::<_, Option<String>>(7)?,
        "signed_hash":    r.get::<_, Option<String>>(8)?,
        "patient_id":     r.get::<_, Option<String>>(9)?,
    }))
}

// Column order shared by list_patients and get_patient. Same rationale as
// ENCOUNTER_COLS: keeping the SELECT list identical between the two paths lets
// patient_row_to_json be reused without positional drift.
pub(crate) const PATIENT_COLS: &str = "id, alias, dob, notes, source_id, created_at, updated_at";

pub(crate) fn patient_row_to_json(r: &rusqlite::Row) -> rusqlite::Result<Value> {
    Ok(json!({
        "id":         r.get::<_, String>(0)?,
        "alias":      r.get::<_, String>(1)?,
        "dob":        r.get::<_, Option<String>>(2)?,
        "notes":      r.get::<_, Option<String>>(3)?,
        "source_id":  r.get::<_, Option<String>>(4)?,
        "created_at": r.get::<_, String>(5)?,
        "updated_at": r.get::<_, String>(6)?,
    }))
}

/// Hard ceiling on any list query's `LIMIT`. [audit H3]
///
/// Without a ceiling, `list_*(Some(i64::MAX))` would deserialize every row into
/// a `Vec<Value>` in memory — an easy DoS from any JS-layer foothold (or a UI
/// bug), and a footgun as the tables grow. 1000 matches the sync server's
/// `api.rs::LIST_WINDOW`, keeping desktop paging parity with the server.
///
/// Lives here, shared, because `encounters` and `patients` both enforce it and
/// previously each hardcoded `1000` separately — `patients`'s comment claimed
/// "same ceiling as encounters::clamp_list_limit" while nothing actually linked
/// them, so either could drift silently.
pub(crate) const LIST_LIMIT_MAX: i64 = 1000;

/// Ceiling for the append-only audit tables (`destruction_log`, `llm_audit`).
///
/// Lower than `LIST_LIMIT_MAX` because these are compliance views rendered as
/// tables, not paged record lists. Named here rather than left as a literal
/// `500` in each module: `destruction_log` used `.clamp(1, 500)` while
/// `llm_audit` used `.min(500)` — no floor at all, harmless only because its
/// parameter is unsigned — and llm_audit's test re-implemented the arithmetic
/// instead of calling the function, so it would have passed even if the
/// production line drifted. Exactly the divergence `clamp_list_limit`'s own
/// doc comment warns about two constants away.
pub(crate) const AUDIT_LIST_LIMIT_MAX: i64 = 500;

/// Clamp a caller-supplied `LIMIT` into `[1, LIST_LIMIT_MAX]`, applying
/// `default` when the caller passed none.
///
/// The floor of 1 turns pathological inputs (0, negatives) into a "give me one
/// row" query instead of a silent empty result — easier for callers to notice
/// and fix. `default` is the caller's own policy and stays per-module; the
/// ceiling is the security control and does not.
pub(crate) fn clamp_list_limit(limit: Option<i64>, default: i64) -> i64 {
    clamp_list_limit_to(limit, default, LIST_LIMIT_MAX)
}

/// As `clamp_list_limit`, with an explicit ceiling for callers whose view has
/// a tighter bound than the record lists (see `AUDIT_LIST_LIMIT_MAX`).
pub(crate) fn clamp_list_limit_to(limit: Option<i64>, default: i64, max: i64) -> i64 {
    limit.unwrap_or(default).clamp(1, max)
}

// Per-connection PRAGMAs. Applied by the pool's `KeyingCustomizer` on EVERY
// fresh connection, right after the SQLCipher key. journal_mode/synchronous/
// foreign_keys/cache_size/temp_store/mmap_size are connection-scoped in
// SQLite — setting them once on the bootstrap connection would leave every
// other pooled connection on defaults, which is a footgun the old
// Mutex<Connection> arch happened to sidestep.
//
// PRAGMA journal_mode = WAL       → durable and concurrent; safe with SQLCipher.
// PRAGMA synchronous   = NORMAL   → fsync per checkpoint, not per commit; correct
//                                   under WAL and matches audit P5 guidance.
// PRAGMA foreign_keys  = ON       → SQLite disables FK enforcement per-connection
//                                   by default; MUST be re-enabled on every one.
// PRAGMA cache_size = -16384      → 16 MiB per-connection page cache (negative
//                                   means KiB). S-CODE-3: this is a single-user
//                                   desktop DB (encounters + kv + note_history
//                                   + llm_audit metadata — audio lives on disk,
//                                   not in the DB) that grows a few MB/year, so
//                                   16 MiB comfortably caches the entire hot
//                                   working set. The old 64 MiB was a
//                                   server-workload number; at max_size=4 the
//                                   worst-case cache footprint is now 64 MiB
//                                   total instead of ~512 MiB.
// PRAGMA temp_store  = MEMORY     → keep temp b-trees for ORDER BY / GROUP BY
//                                   off disk; matters for the encounter list
//                                   query that sorts by encounter_date DESC.
// PRAGMA mmap_size   = 67108864   → 64 MiB memory-mapped read window (down from
//                                   256 MiB). mmap only maps up to the DB file
//                                   size, so 64 MiB already covers the whole
//                                   realistic DB; the 256 MiB figure was
//                                   server-scale. Note the benefit is modest
//                                   under SQLCipher anyway — mmap'd pages are
//                                   ciphertext and still go through the codec
//                                   into the page cache — but it's harmless and
//                                   saves the pread() on already-decrypted hot
//                                   pages, so we keep a right-sized window.
// PRAGMA busy_timeout = 5000      → 5s spin on SQLITE_BUSY before returning
//                                   an error. WAL + pool means writers still
//                                   serialize on the DB lock; this bounds the
//                                   wait for checkpoints and writer-writer
//                                   contention (e.g. a background audio-path
//                                   write racing a UI-driven read).
const CONN_PRAGMAS: &str = "
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous   = NORMAL;
    PRAGMA foreign_keys  = ON;
    PRAGMA cache_size    = -16384;
    PRAGMA temp_store    = MEMORY;
    PRAGMA mmap_size     = 67108864;
    PRAGMA busy_timeout  = 5000;
";

// Idempotent schema DDL. Runs ONCE on bootstrap from a checked-out pool
// connection — running it on every fresh pooled connection would be wasted
// work (CREATE IF NOT EXISTS is cheap but not free) and would race with the
// plaintext-migration path on first launch.
const SCHEMA_TABLES: &str = "
    CREATE TABLE IF NOT EXISTS kv (
        key        TEXT PRIMARY KEY,
        value      TEXT NOT NULL,
        updated_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS kv_prefix_idx ON kv (key);

    CREATE TABLE IF NOT EXISTS encounters (
        id             TEXT PRIMARY KEY,
        provider_id    TEXT NOT NULL,
        encounter_date TEXT NOT NULL,
        patient_alias  TEXT,
        patient_id     TEXT,
        status         TEXT NOT NULL DEFAULT 'draft',
        audio_path     TEXT,
        created_at     TEXT NOT NULL,
        signed_at      TEXT,
        signed_hash    TEXT
    );
    CREATE INDEX IF NOT EXISTS enc_date_idx ON encounters (encounter_date DESC);
    CREATE INDEX IF NOT EXISTS enc_status_idx ON encounters (status);
    CREATE INDEX IF NOT EXISTS enc_created_idx ON encounters (created_at DESC);
    -- patient_id is filtered by the destroy-preview count and the cascade-destroy
    -- collection (patients.rs: count_linked_encounters / destroy_patient_records),
    -- which otherwise full-scan encounters (audit perf finding, Low-Medium).
    CREATE INDEX IF NOT EXISTS enc_patient_idx ON encounters (patient_id);

    CREATE TABLE IF NOT EXISTS patients (
        id         TEXT PRIMARY KEY,
        alias      TEXT NOT NULL,
        dob        TEXT,
        notes      TEXT,
        source_id  TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS pt_alias_idx ON patients (alias);
    CREATE INDEX IF NOT EXISTS pt_updated_idx ON patients (updated_at DESC);

    -- Anti-rollback generation token (audit finding #2/C4). The counterpart to
    -- the wraps DB's install_meta: on open, the token embedded here (inside the
    -- SQLCipher boundary) is compared against the wraps token to detect an
    -- out-of-band substitution of tahlk.db with an older snapshot.
    CREATE TABLE IF NOT EXISTS install_meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
";

/// r2d2 connection customizer that runs on every fresh SQLite connection the
/// pool creates. Two-step init: (1) apply the SQLCipher DEK, (2) apply the
/// per-connection PRAGMAs. If keying fails the pool refuses to hand the
/// connection out — the alternative (silently returning an unkeyed
/// connection) would let user code read/write plaintext against an encrypted
/// file, corrupting it and leaking PHI. Both are `rusqlite::Error` so the
/// pool's error type stays `rusqlite::Error`.
///
/// The hex key is held in an `Arc<String>` so the customizer is `Send + Sync
/// + 'static` (r2d2's trait bound). The key never leaves this process image
/// — `db_key` fetches it from the OS keychain on startup.
#[derive(Debug)]
struct KeyingCustomizer {
    hex_key: Arc<String>,
}

impl CustomizeConnection<Connection, rusqlite::Error> for KeyingCustomizer {
    fn on_acquire(&self, conn: &mut Connection) -> Result<(), rusqlite::Error> {
        // Wrap `apply_key`'s AppError back into rusqlite::Error so the pool
        // can propagate it. The error text carries "database key rejected"
        // which is exactly what an operator needs to see if the DEK ever
        // drifts from the DB.
        apply_key(conn, &self.hex_key).map_err(|e| {
            rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_AUTH),
                Some(e.to_string()),
            )
        })?;
        conn.execute_batch(CONN_PRAGMAS)?;
        Ok(())
    }
}

// SQL-quote a hex DEK so `PRAGMA key = "x'...'"` skips PBKDF2 and treats
// the value as a raw 32-byte blob. `hex_key` is validated by `db_key`
// (64 lowercase hex chars); we still assert it hasn't been mangled before
// interpolation so a future refactor can't sneak an injection in.
fn key_pragma(hex_key: &str) -> Result<String, AppError> {
    if hex_key.len() != 64 || !hex_key.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::internal_from(
            "internal invariant: DEK hex is not 64 hex chars",
        ));
    }
    Ok(format!("PRAGMA key = \"x'{}'\";", hex_key))
}

// Applies the encryption key and verifies it works by probing the schema
// table — a wrong key surfaces as `SQLITE_NOTADB` from this SELECT rather
// than at the first user query.
fn apply_key(conn: &Connection, hex_key: &str) -> Result<(), AppError> {
    conn.execute_batch(&key_pragma(hex_key)?)?;
    // Pin the SQLCipher on-disk format to v4 (finding #14). The bundled
    // SQLCipher (libsqlite3-sys 0.35) is 4.x, so v4 is the format every existing
    // database was already created under — this is a no-op today. Its purpose is
    // forward safety: a future SQLCipher MAJOR bump (e.g. 5.x, which could change
    // the default page size / KDF / HMAC algorithm) would otherwise be unable to
    // open databases written by this build, an availability/lockout event.
    // Pinning makes the format explicit so a dependency upgrade cannot silently
    // strand installed databases. Must run after `PRAGMA key` and before the
    // first read below. Applied on every pooled connection (via KeyingCustomizer)
    // and every verify/migration open, so create and open always agree.
    conn.execute_batch("PRAGMA cipher_compatibility = 4;")?;
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0))
        .map_err(|e| {
            AppError::Storage(format!(
                "database key rejected (wrong DEK or corrupt file): {}",
                e
            ))
        })?;
    Ok(())
}

// Detects a legacy unencrypted SQLite file by peeking at the 16-byte header.
// SQLCipher-encrypted DBs start with random-looking ciphertext; a plaintext
// SQLite DB always starts with `SQLite format 3\0`. Returns Ok(false) for
// files that don't exist yet (fresh install path).
fn is_plaintext_db(path: &Path) -> std::io::Result<bool> {
    use std::io::Read;
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    let mut header = [0u8; 16];
    match f.read_exact(&mut header) {
        Ok(()) => Ok(&header == SQLITE_MAGIC),
        // Empty/short files aren't legacy plaintext — SQLite creates the
        // header lazily on first write, so this really is a fresh DB path.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(e),
    }
}

// Best-effort attempt to overwrite the plaintext file with zeros before
// unlinking it. This does not defeat a determined forensic recovery on an
// SSD (wear leveling) but it does close the trivial `cat old.db` window
// between the encrypted copy landing and the OS reclaiming the blocks.
fn zero_and_remove(path: &Path) {
    use std::io::{Seek, SeekFrom, Write};
    if let Ok(meta) = std::fs::metadata(path) {
        if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
            let len = meta.len();
            let zero = [0u8; 8192];
            let mut remaining = len;
            let _ = f.seek(SeekFrom::Start(0));
            while remaining > 0 {
                let n = remaining.min(zero.len() as u64) as usize;
                if f.write_all(&zero[..n]).is_err() {
                    break;
                }
                remaining -= n as u64;
            }
            let _ = f.flush();
        }
    }
    let _ = std::fs::remove_file(path);
}



// Returns true iff the SQLCipher-encrypted DB at `path` opens and answers a
// trivial schema query under `hex_key`. Used both to gate the destructive
// swap (never destroy the plaintext original until its encrypted replacement
// is provably readable) and to decide, during crash recovery, whether a
// leftover `tahlk.db.encrypted` temp is a complete copy worth promoting.
fn verify_encrypted_opens(path: &Path, hex_key: &str) -> bool {
    match Connection::open(path) {
        Ok(conn) => apply_key(&conn, hex_key).is_ok(),
        Err(_) => false,
    }
}

// ── Backup restore (staged; OPS-3 restore, ADR 0009) ────────────────────────
//
// Restore is two-phase, for crash safety and because the app cannot safely swap
// the live DB file while the pool holds it open:
//   1. `stage_restore_pending` (driven by a Settings command, NON-destructive)
//      opens the passphrase-encrypted backup and RE-KEYS its contents into a
//      pending file keyed with THIS install's DEK — so the install's existing
//      login password / wraps still open the restored data. It never touches
//      the live DB or the pool.
//   2. `apply_pending_restore` (below, at open time, before the pool exists)
//      swaps the verified pending into the canonical path with the same
//      rename-before-destroy discipline as the plaintext migration, keeping the
//      prior DB as a `.pre-restore.bak` safety copy.

const RESTORE_PENDING_FILE: &str = "tahlk.db.restore-pending";
const PRE_RESTORE_BAK_FILE: &str = "tahlk.db.pre-restore.bak";

fn app_data_dir(app: &AppHandle) -> Result<std::path::PathBuf, AppError> {
    app.path()
        .app_data_dir()
        .map_err(|e| AppError::internal_from(format!("could not resolve app_data_dir: {e}")))
}

/// Re-key a passphrase-encrypted backup at `backup_path` into a pending file
/// keyed with `dek_hex` (this install's DEK). NON-destructive: the live DB is
/// untouched and the swap happens at the next open (`apply_pending_restore`).
/// Verifies the backup opens with `passphrase` and that the staged file opens
/// with the DEK before returning. Errors never echo the KEY SQL (it carries the
/// passphrase).
pub(crate) fn stage_restore_pending(
    app: &AppHandle,
    backup_path: &str,
    passphrase: &str,
    dek_hex: &str,
) -> Result<(), AppError> {
    let pending = app_data_dir(app)?.join(RESTORE_PENDING_FILE);
    build_restore_pending(backup_path, &pending, passphrase, dek_hex)
}

/// Path-explicit core of [`stage_restore_pending`], split out so it is
/// unit-testable against tempfiles without a Tauri `AppHandle`.
fn build_restore_pending(
    backup_path: &str,
    pending: &Path,
    passphrase: &str,
    dek_hex: &str,
) -> Result<(), AppError> {
    if pending.exists() {
        std::fs::remove_file(pending).map_err(AppError::storage_from)?;
    }

    let src = Connection::open(backup_path).map_err(AppError::storage_from)?;
    src.execute_batch(&format!("PRAGMA key = '{}';", passphrase.replace('\'', "''")))
        .map_err(|_| AppError::invalid("could not open the backup file"))?;
    // Confirm the passphrase actually decrypts it before building anything.
    src.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
        .map_err(|_| AppError::invalid("wrong passphrase, or this is not a valid Tahlk backup"))?;

    let attach = format!(
        "ATTACH DATABASE '{}' AS restored KEY \"x'{}'\";",
        pending.display().to_string().replace('\'', "''"),
        dek_hex
    );
    src.execute_batch(&attach)
        .map_err(|_| AppError::Storage("could not stage the restore".into()))?;
    let exported = src.query_row("SELECT sqlcipher_export('restored')", [], |_| Ok(()));
    let _ = src.execute_batch("DETACH DATABASE restored;");
    drop(src);
    exported.map_err(|_| AppError::Storage("restore staging failed".into()))?;

    if !verify_encrypted_opens(pending, dek_hex) {
        let _ = std::fs::remove_file(pending);
        return Err(AppError::Storage("the staged restore could not be verified".into()));
    }
    crate::perms::chmod_0600_unix(pending);
    Ok(())
}

/// Apply a staged restore at open time, before the pool is built. Crash-safe
/// and idempotent (see the module comment). No-op when nothing is staged.
///
/// Returns `true` when a restore was actually swapped into place, so the caller
/// can record the durable `database_restored` audit row and clean up the
/// pre-restore breadcrumb; `false` when there was nothing staged (or a staged
/// file was discarded as unreadable).
fn apply_pending_restore(
    db_path: &Path,
    pending: &Path,
    bak: &Path,
    hex_key: &str,
) -> Result<bool, AppError> {
    if !pending.exists() {
        return Ok(false);
    }
    // Only ever swap in a pending that actually opens with this DEK — never
    // replace good data with a file we cannot read (wrong DEK, corrupt, or a
    // leftover from a different install).
    if !verify_encrypted_opens(pending, hex_key) {
        log::warn!("discarding an unreadable pending restore");
        let _ = std::fs::remove_file(pending);
        return Ok(false);
    }
    // Move the current DB aside as a safety copy. Skipped when the canonical
    // path is already gone (a crash between the two renames), so the prior
    // `.bak` — the only copy of the pre-restore data — is preserved.
    if db_path.exists() {
        let _ = std::fs::remove_file(bak); // Windows rename won't overwrite an existing target
        std::fs::rename(db_path, bak).map_err(AppError::storage_from)?;
    }
    std::fs::rename(pending, db_path).map_err(AppError::storage_from)?;
    log::info!("applied a staged backup restore");
    Ok(true)
}

// ── Anti-rollback generation token (audit finding #2/C4) ──────────────────────
//
// A random token is stamped into BOTH the encrypted main DB and the plaintext
// wraps DB whenever a new legitimate database generation is established (fresh
// create, plaintext migration, or a backup restore). On every open the two are
// compared: a mismatch means the main DB is not the one this install last
// stamped — e.g. an attacker swapped `tahlk.db` for an older captured snapshot.
//
// DETECTION, not prevention, and FAIL-OPEN: a mismatch records a durable
// `rollback_suspected` auth-audit event and a loud log line, but the app still
// opens (bricking a clinician's access on a heuristic would be worse than the
// residual). It is effective specifically against an attacker WITHOUT the DEK:
// the main-DB token lives inside the SQLCipher boundary, so an old ciphertext
// `tahlk.db` carries its own old token that cannot be rewritten to match the
// current wraps token without the key. The DEK holder can defeat it — the
// accepted residual in AUDIT-RESIDUAL-RISK Item 3.

const DB_GENERATION_KEY: &str = "db_generation";

fn new_generation_token() -> String {
    let mut buf = [0u8; 16];
    // A failure here yields an all-zero token; still consistent when written to
    // both sides in the same call, so it never causes a false mismatch.
    let _ = getrandom::getrandom(&mut buf);
    crate::hex::to_hex(&buf)
}

fn read_generation(conn: &Connection) -> Option<String> {
    conn.query_row(
        "SELECT value FROM install_meta WHERE key = ?1",
        params![DB_GENERATION_KEY],
        |r| r.get::<_, String>(0),
    )
    .ok()
}

fn write_generation(conn: &Connection, token: &str) -> Result<(), AppError> {
    conn.execute(
        "INSERT INTO install_meta (key, value) VALUES (?1, ?2) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![DB_GENERATION_KEY, token],
    )?;
    Ok(())
}

/// Pure decision for the generation reconcile, so the branching is unit-testable
/// without a keychain or Tauri handle.
#[derive(Debug, PartialEq)]
enum GenAction {
    /// Tokens match — no-op.
    Ok,
    /// Both present and differ — a possible rollback. Record + proceed.
    Suspect,
    /// Copy the main token into the wraps DB (heal a wraps that lost it).
    SetWraps(String),
    /// Establish a fresh generation in BOTH (fresh / legacy / restore).
    SetBoth(String),
}

fn decide_generation(
    main: Option<&str>,
    wraps: Option<&str>,
    fresh: &str,
    restore_applied: bool,
) -> GenAction {
    if restore_applied {
        // A restore installs a legitimately new generation; stamp both so the
        // restored DB's old embedded token isn't mistaken for a rollback.
        return GenAction::SetBoth(fresh.to_string());
    }
    match (main, wraps) {
        (Some(m), Some(w)) if m != w => GenAction::Suspect,
        (Some(_), Some(_)) => GenAction::Ok,
        // Main has a token but wraps lost it (legacy wraps / wraps reset): adopt
        // the main token rather than alarm.
        (Some(m), None) => GenAction::SetWraps(m.to_string()),
        // No token in the main DB yet (fresh install, or a DB predating this
        // feature): establish one. Cannot distinguish this from a rollback to a
        // pre-feature snapshot — inherent to any generation scheme.
        (None, _) => GenAction::SetBoth(fresh.to_string()),
    }
}

/// Reconcile the anti-rollback generation token between the main and wraps DBs.
/// Best-effort and fail-open: any error is swallowed, never blocks opening.
fn reconcile_db_generation(app: &AppHandle, conn: &Connection, restore_applied: bool) {
    let main = read_generation(conn);
    let wraps = crate::auth::read_wraps_generation(app);
    let fresh = new_generation_token();
    match decide_generation(main.as_deref(), wraps.as_deref(), &fresh, restore_applied) {
        GenAction::Ok => {}
        GenAction::Suspect => {
            log::error!(
                "possible database rollback: the record database's generation does not match this install"
            );
            crate::auth::record_auth_event(app, "rollback_suspected", "failure");
        }
        GenAction::SetWraps(token) => {
            let _ = crate::auth::write_wraps_generation(app, &token);
        }
        GenAction::SetBoth(token) => {
            let _ = write_generation(conn, &token);
            let _ = crate::auth::write_wraps_generation(app, &token);
        }
    }
}

// Builds a fresh SQLCipher-encrypted copy of the legacy plaintext DB at
// `plaintext_path` into `encrypted_path` (a temp path — NOT the canonical DB
// path) using `sqlcipher_export`. `PRAGMA rekey` does NOT work for
// plaintext→encrypted per SQLCipher docs, so we ATTACH the target with the DEK
// and copy the schema+data across.
//
// This function is deliberately NON-destructive: it only writes and verifies
// the encrypted temp. The plaintext original is left untouched — the caller
// performs the rename-before-destroy swap (see `open_database_with_dek`) so
// that no crash window can leave the canonical DB path holding nothing.
fn migrate_plaintext_to_encrypted(
    plaintext_path: &Path,
    encrypted_path: &Path,
    hex_key: &str,
) -> Result<(), AppError> {
    // Sanity: don't clobber an existing encrypted temp. Startup recovery
    // (`recover_orphaned_migration`) clears any leftover temp before we get
    // here, so a temp still present at this point is unexpected — refuse
    // rather than overwriting it.
    if encrypted_path.exists() {
        return Err(AppError::Storage(format!(
            "refusing to migrate: encrypted temp already exists at {} while plaintext {} \
             is still present — manually remove the stale temp file after verifying \
             the encrypted copy is intact",
            encrypted_path.display(),
            plaintext_path.display()
        )));
    }

    let src = Connection::open(plaintext_path)?;
    let attach = format!(
        "ATTACH DATABASE '{}' AS encrypted KEY \"x'{}'\";",
        // Path is app-controlled (data_dir join), not user input; escape
        // single quotes defensively in case a future refactor changes that.
        encrypted_path.display().to_string().replace('\'', "''"),
        hex_key
    );
    // Generic errors on BOTH the ATTACH and the export: the `attach` string
    // contains `KEY "x'<DEK>'"`, and a rusqlite error can echo the offending
    // SQL (statement text + context) into its Display. That message would be
    // logged/panicked upstream (lib.rs, auth.rs) into the OS log file, which is
    // outside the encryption boundary. Discard the underlying message here, the
    // same discipline `export_db_to`/`build_restore_pending` already apply to
    // their KEY-bearing ATTACH statements.
    src.execute_batch(&attach)
        .map_err(|_| AppError::Storage("migration attach failed".into()))?;
    src.query_row("SELECT sqlcipher_export('encrypted')", [], |_| Ok(()))
        .map_err(|_| AppError::Storage("migration export failed".into()))?;
    src.execute_batch("DETACH DATABASE encrypted;")?;
    drop(src);

    // Verify the new encrypted temp is readable with the DEK. The caller
    // refuses to touch the plaintext original unless this succeeds.
    if !verify_encrypted_opens(encrypted_path, hex_key) {
        // Don't leave a half-written temp behind for recovery to trip over.
        let _ = std::fs::remove_file(encrypted_path);
        return Err(AppError::Storage(
            "migration produced an encrypted DB that could not be reopened with the DEK".into(),
        ));
    }
    Ok(())
}

// Recovers from a migration interrupted by a crash between any of the three
// swap steps in `open_database_with_dek` (build temp → move plaintext aside →
// promote temp → wipe breadcrumb). Runs on every launch BEFORE the plaintext
// detection, so an orphaned encrypted temp is never mistaken for a stale file
// to overwrite and the canonical DB path is never left empty.
//
// The invariant it restores: if a verified encrypted temp exists, the
// canonical path ends up holding it; the plaintext breadcrumb is always wiped.
fn recover_orphaned_migration(
    db_path: &Path,
    encrypted_tmp: &Path,
    bak: &Path,
    hex_key: &str,
) -> Result<(), AppError> {
    if encrypted_tmp.exists() {
        if verify_encrypted_opens(encrypted_tmp, hex_key) {
            // The temp is a complete, readable encrypted copy. Promote it
            // unless the canonical slot already holds a valid encrypted DB
            // (crash happened after the swap already completed).
            let canonical_ok = db_path.exists()
                && !is_plaintext_db(db_path).unwrap_or(true)
                && verify_encrypted_opens(db_path, hex_key);
            if canonical_ok {
                let _ = std::fs::remove_file(encrypted_tmp);
            } else {
                // Move any plaintext original aside (non-destructive) so the
                // atomic promote can't collide, then promote the temp.
                if db_path.exists() {
                    std::fs::rename(db_path, bak).map_err(AppError::storage_from)?;
                }
                std::fs::rename(encrypted_tmp, db_path).map_err(AppError::storage_from)?;
            }
        } else {
            // Incomplete/corrupt temp (crash mid-export): discard it. The
            // plaintext original is still authoritative and will re-migrate.
            let _ = std::fs::remove_file(encrypted_tmp);
        }
    }
    // Wipe any leftover plaintext breadcrumb — it contains PHI and its only
    // purpose (a promotion source) is done once we reach here.
    if bak.exists() {
        zero_and_remove(bak);
    }
    Ok(())
}

/// Ordered schema migrations, applied by [`run_migrations`].
///
/// Index + 1 is the `user_version` a migration produces: `MIGRATIONS[0]` takes
/// a database from version 0 to 1. **Append only.** Never reorder, never edit a
/// shipped entry, never remove one — an installed database records only which
/// version it reached, so changing history silently skips work on some installs
/// and re-runs it on others.
///
/// Each entry must be safe to run exactly once against a database at the
/// preceding version. It does NOT need to be idempotent, because the version
/// gate guarantees single execution; that is the whole point of tracking a
/// version rather than probing for columns.
///
/// Adding one: append the SQL, add a test asserting it applies from the prior
/// version, and update `LATEST_VERSION`'s expectation in the tests.
const MIGRATIONS: &[&str] = &[
    // v1 — baseline. Intentionally a no-op.
    //
    // `SCHEMA_TABLES` already runs `CREATE TABLE IF NOT EXISTS` on every open,
    // and two `pragma_table_info`-gated column additions run after it, so an
    // existing install is already at the shape this framework starts from.
    // Stamping a version without changing anything establishes the baseline so
    // the FIRST real migration has a defined starting point. Doing schema work
    // in v1 would apply it to fresh and existing installs alike with no way to
    // tell them apart — which is the failure this framework exists to prevent.
    "SELECT 1;",
];

/// The `user_version` a fully-migrated database reaches.
pub(crate) const LATEST_VERSION: i64 = MIGRATIONS.len() as i64;

/// Apply any migrations the database has not yet reached.
///
/// Before this existed, schema changes were made by probing for a column with
/// `pragma_table_info` and issuing `ALTER TABLE` if absent. That works for
/// adding a nullable column and nothing else: it cannot express a data
/// backfill, a change that must happen exactly once, or an ordering dependency
/// between two changes — and every future open re-runs the probe forever. For a
/// desktop app with no remote control over installs and no auto-update channel,
/// a schema change that half-applies is unrecoverable in the field.
///
/// Each migration runs inside its own transaction together with the version
/// bump, so a failure rolls back both. A partially-applied migration paired
/// with a version claiming it succeeded is the one outcome that must be
/// impossible.
pub(crate) fn run_migrations(conn: &mut Connection) -> Result<(), AppError> {
    let current: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;

    // A database from a NEWER build than this one. Downgrading is not
    // supported: the newer schema may hold columns and rows this binary cannot
    // interpret, and continuing risks writing data the newer build will
    // misread. Refuse rather than corrupt.
    if current > LATEST_VERSION {
        return Err(AppError::internal_from(format!(
            "database schema version {current} is newer than this build supports ({LATEST_VERSION}); \
             install the newer version of Tahlk — refusing to open rather than risk corrupting records"
        )));
    }

    for (idx, sql) in MIGRATIONS.iter().enumerate() {
        let target = idx as i64 + 1;
        if current >= target {
            continue;
        }
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        // `PRAGMA user_version` does not accept a bound parameter, so the value
        // is formatted in. It is derived from an array index, never from input.
        tx.execute_batch(&format!("PRAGMA user_version = {target};"))?;
        tx.commit()?;
        log::info!("applied schema migration to version {target}");
    }
    Ok(())
}

pub(crate) fn open_database(app: &AppHandle) -> Result<SqlitePool, AppError> {
    let hex_key = db_key::load_or_generate_dek()?;
    open_database_with_dek(app, &hex_key)
}

/// Open (or create) the encrypted SQLite database using a caller-supplied hex
/// DEK. Used by the auth path (Stage 4+) where the DEK comes from
/// `auth::unlock_with_password` rather than the OS keychain.
pub(crate) fn open_database_with_dek(app: &AppHandle, hex_key: &str) -> Result<SqlitePool, AppError> {
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| AppError::internal_from(format!("could not resolve app_data_dir: {}", e)))?;
    std::fs::create_dir_all(&data_dir).map_err(AppError::storage_from)?;
    let db_path = data_dir.join("tahlk.db");

    // Legacy upgrade path: existing plaintext DB gets copied into a new
    // encrypted file, then swapped into place. Skipped on fresh installs
    // (file doesn't exist yet) and on subsequent launches (file is already
    // ciphertext, so the magic-byte check returns false). MUST run before we
    // hand the file to the pool — the pool's customizer will `PRAGMA key`
    // every fresh connection and reject a plaintext file with "NOTADB".
    let encrypted_tmp = data_dir.join("tahlk.db.encrypted");
    let bak = data_dir.join("tahlk.db.plaintext.bak");

    // First, finish any migration a prior launch left half-done. This restores
    // the invariant "canonical path holds the encrypted DB" before we decide
    // whether a fresh migration is needed, so a crash mid-swap can never boot
    // an empty DB or re-migrate over a good encrypted file.
    recover_orphaned_migration(&db_path, &encrypted_tmp, &bak, hex_key)?;

    // Apply a staged backup restore (ADR 0009) before the pool opens — the
    // canonical DB may be replaced here by the re-keyed restored copy. Runs
    // after migration recovery (so any half-done plaintext migration is settled
    // first) and before the plaintext check below (the restored copy is
    // ciphertext, so that check then correctly no-ops).
    let restore_pending = data_dir.join(RESTORE_PENDING_FILE);
    let pre_restore_bak = data_dir.join(PRE_RESTORE_BAK_FILE);
    let restore_applied =
        apply_pending_restore(&db_path, &restore_pending, &pre_restore_bak, hex_key)?;

    if is_plaintext_db(&db_path).map_err(AppError::storage_from)? {
        // Rename-before-destroy swap. Each step is individually crash-safe;
        // `recover_orphaned_migration` above completes whichever step was in
        // flight if we die partway through:
        //   1. build + verify the encrypted copy at the temp path (the
        //      plaintext original is untouched until this succeeds),
        //   2. move the plaintext original aside to the .bak breadcrumb,
        //   3. atomically rename the encrypted temp into the canonical path,
        //   4. zero + unlink the plaintext breadcrumb.
        migrate_plaintext_to_encrypted(&db_path, &encrypted_tmp, hex_key)?;
        std::fs::rename(&db_path, &bak).map_err(AppError::storage_from)?;
        std::fs::rename(&encrypted_tmp, &db_path).map_err(AppError::storage_from)?;
        zero_and_remove(&bak);
    }

    crate::perms::chmod_0600_unix(&db_path);

    // Build the pool. S-CODE-3: right-sized for Solo's real concurrency, which
    // is a UI thread issuing *sequential* Tauri commands plus background audio
    // writes, with at most an occasional concurrent read while a save is in
    // flight. That peaks at ~2-3 simultaneous checkouts (e.g. a background
    // audio-path write + a UI-driven list read + a fire-and-forget llm_audit
    // append); `max_size=4` leaves one spare above that peak. WAL still allows
    // many concurrent readers with a single writer regardless of pool size, so
    // shrinking the pool doesn't change concurrency semantics — it only trims
    // the worst-case per-connection cache footprint (now 16 MiB × 4 = 64 MiB
    // instead of 64 MiB × 8 = 512 MiB). The old `max_size=8` was a
    // server-workload number for concurrency this single-user app never sees.
    //
    // `min_idle=1` keeps one warm connection so the first UI action after
    // launch is snappy. (The previous "avoid synchronous PBKDF2" rationale for
    // keeping 2 warm was inaccurate: we key with a raw 32-byte hex DEK via
    // `PRAGMA key = "x'...'"`, which SKIPS PBKDF2 entirely — see `key_pragma`
    // — so fresh-connection keying is cheap and there's no reason to pre-warm
    // more than one.)
    let manager = SqliteConnectionManager::file(&db_path);
    let customizer = KeyingCustomizer {
        hex_key: Arc::new(hex_key.to_string()),
    };
    let pool = Pool::builder()
        .max_size(4)
        .min_idle(Some(1))
        .connection_customizer(Box::new(customizer))
        .build(manager)
        .map_err(AppError::storage_from)?;

    // One-shot bootstrap on a single checked-out connection: schema tables,
    // note_history schema + KV→table migration, llm_audit schema. All three
    // are idempotent so a crash mid-bootstrap on a prior launch is safe.
    // `migrate_from_kv` needs `&mut Connection` for its transaction —
    // PooledConnection derefs to Connection, so DerefMut just works.
    let mut conn = pool.get()?;
    conn.execute_batch(SCHEMA_TABLES)?;
    run_migrations(&mut conn)?;

    // NOTE: the two ad-hoc column migrations below predate `run_migrations`
    // and are deliberately left in place rather than retrofitted into it.
    // Folding them in would require asserting which `user_version` an existing
    // install "should" have had, and we cannot know that — an install created
    // before versioning reports 0 whether or not those columns exist. They are
    // idempotent and gated on `pragma_table_info`, so they are safe to keep
    // running. **New schema changes must go in MIGRATIONS, not here.**

    // One-shot column migration: add source_id to patients on DBs created
    // before this column existed. SCHEMA_TABLES uses CREATE TABLE IF NOT
    // EXISTS so it won't add the column for us on an upgrade; ALTER TABLE
    // ADD COLUMN is the correct upgrade path and is idempotent here because
    // we gate it on a pragma_table_info check.
    let has_source_id = conn.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('patients') WHERE name='source_id'",
        [],
        |r| r.get::<_, i64>(0),
    ).unwrap_or(0);
    if has_source_id == 0 {
        conn.execute_batch("ALTER TABLE patients ADD COLUMN source_id TEXT;")?;
    }

    // One-shot column migration: add patient_id to encounters on DBs created
    // before ADR-0005 Commit 2. Same pattern as the source_id migration above.
    let has_patient_id = conn.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('encounters') WHERE name='patient_id'",
        [],
        |r| r.get::<_, i64>(0),
    ).unwrap_or(0);
    if has_patient_id == 0 {
        conn.execute_batch("ALTER TABLE encounters ADD COLUMN patient_id TEXT;")?;
    }

    note_history::init_schema(&conn)?;
    note_history::migrate_from_kv(&mut conn)?;
    note_audit::init_schema(&conn)?;
    note_audit::migrate_from_kv(&mut conn)?;
    patient_audit::init_schema(&conn)?;
    llm_audit::init_schema(&conn)?;
    destruction_log::init_schema(&conn)?;
    config_audit::init_schema(&conn)?;

    // A staged restore just replaced the ENTIRE record DB (every table and audit
    // trail). Record it durably in the restored DB itself so the live DB an
    // auditor inspects carries the marker. Best-effort: the physical swap has
    // already committed, so a failed insert must not fail the open — and the
    // reliable, healthy-session trace was already written as `restore_staged` in
    // the wraps DB, which the restore does not replace.
    if restore_applied {
        let actor = crate::kv_ops::provider_id(&conn);
        if let Err(e) = config_audit::append(
            &conn,
            "database_restored",
            Some(PRE_RESTORE_BAK_FILE),
            "restored from encrypted backup",
            &actor,
        ) {
            log::warn!("could not record database_restored config-audit row: {e}");
        }
        crate::auth::record_auth_event(app, "restore_applied", "success");
    }

    // Anti-rollback generation check (finding #2/C4). Runs after restore handling
    // so a just-applied restore stamps a fresh generation rather than alarming.
    reconcile_db_generation(app, &conn, restore_applied);
    drop(conn);

    // Clean up the pre-restore breadcrumb once the restored DB has opened and
    // verified cleanly (reaching here means the pool built and every schema init
    // succeeded). This bounds the full, DEK-encrypted copy of the prior record
    // set to the session in which the restore applied, rather than leaving it in
    // the data dir indefinitely (audit finding #2). Mirrors the zero_and_remove
    // discipline already used for the plaintext-migration breadcrumb.
    if pre_restore_bak.exists() {
        zero_and_remove(&pre_restore_bak);
    }

    Ok(pool)
}

#[cfg(test)]
mod migration_tests {
    //! Schema-migration framework. The property under test is that a database
    //! reaches the current version exactly once, from any starting point, and
    //! that a failure never leaves a version claiming work that did not
    //! complete.

    use super::*;

    fn version_of(conn: &Connection) -> i64 {
        conn.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn a_fresh_database_migrates_to_latest() {
        let mut conn = Connection::open_in_memory().unwrap();
        assert_eq!(version_of(&conn), 0, "a new database starts unversioned");
        run_migrations(&mut conn).unwrap();
        assert_eq!(version_of(&conn), LATEST_VERSION);
    }

    #[test]
    fn migrations_are_idempotent_across_repeated_opens() {
        // Every app launch calls this. Running it twice must be identical to
        // running it once — the version gate, not luck, is what guarantees a
        // migration executes exactly once.
        let mut conn = Connection::open_in_memory().unwrap();
        run_migrations(&mut conn).unwrap();
        let after_first = version_of(&conn);
        run_migrations(&mut conn).unwrap();
        assert_eq!(version_of(&conn), after_first, "a second run must be a no-op");
    }

    #[test]
    fn a_database_from_a_newer_build_is_refused_not_opened() {
        // Downgrade protection. A newer schema may hold columns this binary
        // cannot interpret; continuing risks writing data the newer build will
        // misread. With no auto-update channel, a user running an older
        // installer against a newer database is a realistic scenario, not a
        // hypothetical one.
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(&format!("PRAGMA user_version = {};", LATEST_VERSION + 5))
            .unwrap();

        let err = run_migrations(&mut conn).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("newer than this build supports"),
            "the error must say what happened and what to do, got: {msg}"
        );
        assert_eq!(
            version_of(&conn),
            LATEST_VERSION + 5,
            "refusing must not modify the database"
        );
    }

    #[test]
    fn a_failing_migration_rolls_back_its_version_bump() {
        // The one outcome that must be impossible: a version recording work
        // that did not complete. Such a database is unrecoverable in the field,
        // because every later run skips the migration it claims to have run.
        let mut conn = Connection::open_in_memory().unwrap();
        let start = version_of(&conn);

        let tx = conn.transaction().unwrap();
        tx.execute_batch("CREATE TABLE probe (x INTEGER);").unwrap();
        let bad = tx.execute_batch("THIS IS NOT SQL;");
        assert!(bad.is_err(), "the fixture must actually fail");
        drop(tx); // rolls back

        assert_eq!(version_of(&conn), start, "a failed migration leaves the version untouched");
        let survived: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='probe'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(survived, 0, "and leaves no half-applied schema behind");
    }

    // clippy::assertions_on_constants fires because both operands are consts —
    // which is precisely what is being pinned. The lint assumes a constant
    // assertion is a tautology; here it is a guard against someone editing one
    // constant without the other. Same reasoning as
    // `baa::the_gate_is_enabled_in_shipped_builds`.
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn latest_version_matches_the_migration_list() {
        // Guards the invariant the whole framework rests on: index + 1 is the
        // version a migration produces. If someone adds SQL without the count
        // following, installs stamp a version they did not reach.
        assert_eq!(LATEST_VERSION, MIGRATIONS.len() as i64);
        assert!(LATEST_VERSION >= 1, "the baseline migration must exist");
    }
}

#[cfg(test)]
mod tests {
    //! Encryption round-trip tests. These do NOT touch the OS keychain —
    //! they exercise the SQLCipher primitives (apply_key, sqlcipher_export)
    //! directly with an in-memory hex key, which is what CI can validate
    //! without a login session.

    use super::*;
    use tempfile::TempDir;

    fn fixed_key() -> String {
        // Deterministic 32-byte test key — obviously not for production use.
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into()
    }

    fn other_key() -> String {
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into()
    }

    // ── Backup restore (staged) ──────────────────────────────────────────────

    fn second_key() -> String {
        "1".repeat(64)
    }

    fn make_keyed_db(path: &Path, key: &str, row: &str) {
        let c = Connection::open(path).unwrap();
        apply_key(&c, key).unwrap();
        c.execute_batch(&format!(
            "CREATE TABLE t (v TEXT NOT NULL); INSERT INTO t (v) VALUES ('{row}');"
        ))
        .unwrap();
    }

    fn read_row(path: &Path, key: &str) -> String {
        let c = Connection::open(path).unwrap();
        apply_key(&c, key).unwrap();
        c.query_row("SELECT v FROM t", [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn build_restore_pending_rekeys_a_passphrase_backup_into_the_dek() {
        let dir = TempDir::new().unwrap();
        let backup = dir.path().join("b.tahlkbackup");
        let pending = dir.path().join("tahlk.db.restore-pending");
        let passphrase = "a good backup passphrase";
        let dek = fixed_key();

        // A passphrase-keyed "backup" carrying a row.
        {
            let c = Connection::open(&backup).unwrap();
            c.execute_batch(&format!("PRAGMA key = '{passphrase}';")).unwrap();
            c.execute_batch(
                "CREATE TABLE t (v TEXT NOT NULL); INSERT INTO t (v) VALUES ('restored-phi');",
            )
            .unwrap();
        }

        build_restore_pending(backup.to_str().unwrap(), &pending, passphrase, &dek).unwrap();
        assert!(pending.exists(), "a verified pending must be written");

        // The pending opens with the install DEK (not the passphrase) and has the row.
        assert_eq!(read_row(&pending, &dek), "restored-phi");
    }

    #[test]
    fn build_restore_pending_rejects_a_wrong_passphrase_and_leaves_no_file() {
        let dir = TempDir::new().unwrap();
        let backup = dir.path().join("b.tahlkbackup");
        let pending = dir.path().join("pending");
        {
            let c = Connection::open(&backup).unwrap();
            c.execute_batch("PRAGMA key = 'the-real-pass';").unwrap();
            c.execute_batch("CREATE TABLE t (v TEXT NOT NULL); INSERT INTO t (v) VALUES ('x');")
                .unwrap();
        }
        let r = build_restore_pending(backup.to_str().unwrap(), &pending, "the-wrong-pass", &fixed_key());
        assert!(r.is_err(), "a wrong passphrase must fail staging");
        assert!(!pending.exists(), "no pending file may be left behind on failure");
    }

    #[test]
    fn apply_pending_restore_swaps_in_the_pending_and_keeps_a_bak() {
        let dir = TempDir::new().unwrap();
        let db = dir.path().join("tahlk.db");
        let pending = dir.path().join("pending");
        let bak = dir.path().join("bak");
        let key = fixed_key();
        make_keyed_db(&db, &key, "current");
        make_keyed_db(&pending, &key, "from-backup");

        let applied = apply_pending_restore(&db, &pending, &bak, &key).unwrap();

        assert!(applied, "a real swap must report applied=true so the caller audits it");
        assert_eq!(read_row(&db, &key), "from-backup", "canonical DB is now the restored copy");
        assert!(!pending.exists(), "pending must be consumed");
        assert_eq!(read_row(&bak, &key), "current", "prior DB preserved as the safety bak");
    }

    #[test]
    fn apply_pending_restore_discards_a_pending_it_cannot_open() {
        let dir = TempDir::new().unwrap();
        let db = dir.path().join("tahlk.db");
        let pending = dir.path().join("pending");
        let bak = dir.path().join("bak");
        let key = fixed_key();
        make_keyed_db(&db, &key, "current");
        make_keyed_db(&pending, &second_key(), "unreadable-with-install-dek");

        let applied = apply_pending_restore(&db, &pending, &bak, &key).unwrap();

        assert!(!applied, "an unreadable pending is discarded, not applied");
        assert_eq!(read_row(&db, &key), "current", "a pending keyed with the wrong DEK must NOT replace good data");
        assert!(!pending.exists(), "the unreadable pending is discarded");
        assert!(!bak.exists(), "no swap happened, so no bak was made");
    }

    #[test]
    fn apply_pending_restore_is_a_noop_without_a_pending() {
        let dir = TempDir::new().unwrap();
        let db = dir.path().join("tahlk.db");
        let key = fixed_key();
        make_keyed_db(&db, &key, "current");
        let applied =
            apply_pending_restore(&db, &dir.path().join("nope"), &dir.path().join("bak"), &key).unwrap();
        assert!(!applied, "no pending means nothing applied");
        assert_eq!(read_row(&db, &key), "current");
    }

    // ── Anti-rollback generation decision (finding #2/C4) ──────────────────────

    #[test]
    fn generation_matching_tokens_is_ok() {
        assert_eq!(decide_generation(Some("abc"), Some("abc"), "new", false), GenAction::Ok);
    }

    #[test]
    fn generation_mismatch_is_suspect() {
        // The core detection: an old main-DB token vs the current wraps token.
        assert_eq!(decide_generation(Some("old"), Some("current"), "new", false), GenAction::Suspect);
    }

    #[test]
    fn restore_always_establishes_a_fresh_generation_in_both() {
        assert_eq!(
            decide_generation(Some("old"), Some("current"), "new", true),
            GenAction::SetBoth("new".into())
        );
        // Even when the tokens currently match, a restore mints a new generation.
        assert_eq!(
            decide_generation(Some("same"), Some("same"), "new", true),
            GenAction::SetBoth("new".into())
        );
    }

    #[test]
    fn missing_wraps_token_heals_from_main_without_alarming() {
        assert_eq!(decide_generation(Some("m"), None, "new", false), GenAction::SetWraps("m".into()));
    }

    #[test]
    fn missing_main_token_establishes_both() {
        // Fresh install or a DB predating the feature — never a false alarm.
        assert_eq!(decide_generation(None, None, "new", false), GenAction::SetBoth("new".into()));
        assert_eq!(decide_generation(None, Some("w"), "new", false), GenAction::SetBoth("new".into()));
    }

    #[test]
    fn generation_read_write_roundtrips() {
        let dir = TempDir::new().unwrap();
        let db = dir.path().join("tahlk.db");
        let key = fixed_key();
        let conn = Connection::open(&db).unwrap();
        apply_key(&conn, &key).unwrap();
        conn.execute_batch("CREATE TABLE install_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);")
            .unwrap();
        assert_eq!(read_generation(&conn), None, "no token before it is written");
        write_generation(&conn, "tok-123").unwrap();
        assert_eq!(read_generation(&conn).as_deref(), Some("tok-123"));
        write_generation(&conn, "tok-456").unwrap(); // upsert overwrites
        assert_eq!(read_generation(&conn).as_deref(), Some("tok-456"));
    }

    #[test]
    fn fresh_encrypted_db_key_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("fresh.db");
        let key = fixed_key();

        // Open, key, write a row, close.
        {
            let conn = Connection::open(&path).unwrap();
            apply_key(&conn, &key).unwrap();
            conn.execute_batch(
                "CREATE TABLE t (v TEXT NOT NULL); INSERT INTO t (v) VALUES ('phi');",
            )
            .unwrap();
        }

        // Reopen with the same key, read the row.
        {
            let conn = Connection::open(&path).unwrap();
            apply_key(&conn, &key).unwrap();
            let v: String = conn
                .query_row("SELECT v FROM t", [], |r| r.get(0))
                .unwrap();
            assert_eq!(v, "phi");
        }

        // On disk the file must NOT contain the plaintext SQLite header.
        let bytes = std::fs::read(&path).unwrap();
        assert!(
            !bytes.starts_with(SQLITE_MAGIC),
            "encrypted DB unexpectedly starts with plaintext SQLite header"
        );
    }

    #[test]
    fn wrong_key_is_rejected() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wrongkey.db");
        let key = fixed_key();

        {
            let conn = Connection::open(&path).unwrap();
            apply_key(&conn, &key).unwrap();
            conn.execute_batch("CREATE TABLE t (v TEXT);").unwrap();
        }

        let conn = Connection::open(&path).unwrap();
        let err = apply_key(&conn, &other_key()).expect_err("wrong key must be rejected");
        // Should surface as a Storage error — not silent success, not panic.
        match err {
            AppError::Storage(_) => {}
            other => panic!("expected Storage error, got {:?}", other),
        }
    }

    // Test-only mirror of the exact swap sequence in `open_database_with_dek`,
    // so the crash-window tests can execute it up to any step and then invoke
    // recovery. Kept in lockstep with the production swap by construction.
    fn build_plaintext(path: &Path, patient: &str) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(&format!(
            "CREATE TABLE encounters (id TEXT PRIMARY KEY, patient TEXT);
             INSERT INTO encounters VALUES ('e1', '{}');",
            patient
        ))
        .unwrap();
    }

    fn assert_canonical_encrypted_with(path: &Path, key: &str, expected: &str) {
        assert!(path.exists(), "canonical DB must exist");
        assert!(
            !is_plaintext_db(path).unwrap(),
            "canonical DB must be ciphertext, not plaintext"
        );
        let conn = Connection::open(path).unwrap();
        apply_key(&conn, key).unwrap();
        let got: String = conn
            .query_row("SELECT patient FROM encounters WHERE id = 'e1'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(got, expected, "no data may be lost across the migration");
    }

    #[test]
    fn plaintext_db_is_detected_and_migrated() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("tahlk.db");
        let encrypted_tmp = dir.path().join("tahlk.db.encrypted");
        let bak = dir.path().join("tahlk.db.plaintext.bak");
        let key = fixed_key();

        build_plaintext(&db_path, "Jane Doe");
        assert!(is_plaintext_db(&db_path).unwrap());

        // Full swap, exactly as open_database_with_dek runs it.
        migrate_plaintext_to_encrypted(&db_path, &encrypted_tmp, &key).unwrap();
        std::fs::rename(&db_path, &bak).unwrap();
        std::fs::rename(&encrypted_tmp, &db_path).unwrap();
        zero_and_remove(&bak);

        assert!(!encrypted_tmp.exists(), "temp must be consumed by the swap");
        assert!(!bak.exists(), "plaintext breadcrumb must be zeroed and removed");
        assert_canonical_encrypted_with(&db_path, &key, "Jane Doe");
    }

    // Crash after step 1 (encrypted temp built + verified) but before the
    // plaintext original is moved aside. Recovery must promote the temp so the
    // canonical path is never left as bare plaintext / never lost.
    #[test]
    fn crash_after_build_before_move_recovers() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("tahlk.db");
        let encrypted_tmp = dir.path().join("tahlk.db.encrypted");
        let bak = dir.path().join("tahlk.db.plaintext.bak");
        let key = fixed_key();

        build_plaintext(&db_path, "Jane Doe");
        migrate_plaintext_to_encrypted(&db_path, &encrypted_tmp, &key).unwrap();
        // <-- crash here: temp exists, db_path still plaintext, no bak.

        recover_orphaned_migration(&db_path, &encrypted_tmp, &bak, &key).unwrap();

        assert!(!encrypted_tmp.exists());
        assert!(!bak.exists());
        assert_canonical_encrypted_with(&db_path, &key, "Jane Doe");
    }

    // Crash after step 2 (plaintext moved to .bak) but before the temp is
    // promoted — the canonical path does not exist at all. This is the exact
    // window the old destroy-before-rename code lost data in.
    #[test]
    fn crash_after_move_before_promote_recovers() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("tahlk.db");
        let encrypted_tmp = dir.path().join("tahlk.db.encrypted");
        let bak = dir.path().join("tahlk.db.plaintext.bak");
        let key = fixed_key();

        build_plaintext(&db_path, "Jane Doe");
        migrate_plaintext_to_encrypted(&db_path, &encrypted_tmp, &key).unwrap();
        std::fs::rename(&db_path, &bak).unwrap();
        // <-- crash here: db_path missing, temp + bak present.
        assert!(!db_path.exists(), "precondition: canonical path is empty");

        recover_orphaned_migration(&db_path, &encrypted_tmp, &bak, &key).unwrap();

        assert!(!encrypted_tmp.exists());
        assert!(!bak.exists());
        assert_canonical_encrypted_with(&db_path, &key, "Jane Doe");
    }

    // Crash after step 3 (temp promoted to canonical) but before the plaintext
    // breadcrumb is wiped. Recovery must leave the good encrypted DB untouched
    // and only clean up the leftover .bak.
    #[test]
    fn crash_after_promote_before_wipe_recovers() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("tahlk.db");
        let encrypted_tmp = dir.path().join("tahlk.db.encrypted");
        let bak = dir.path().join("tahlk.db.plaintext.bak");
        let key = fixed_key();

        build_plaintext(&db_path, "Jane Doe");
        migrate_plaintext_to_encrypted(&db_path, &encrypted_tmp, &key).unwrap();
        std::fs::rename(&db_path, &bak).unwrap();
        std::fs::rename(&encrypted_tmp, &db_path).unwrap();
        // <-- crash here: canonical is good encrypted DB, bak still present.

        recover_orphaned_migration(&db_path, &encrypted_tmp, &bak, &key).unwrap();

        assert!(!bak.exists(), "leftover plaintext breadcrumb must be wiped");
        assert_canonical_encrypted_with(&db_path, &key, "Jane Doe");
    }

    // A half-written / corrupt temp (crash mid-export, before verify) must be
    // discarded, leaving the plaintext original authoritative so the next
    // launch can re-run the migration cleanly.
    #[test]
    fn corrupt_temp_is_discarded_and_plaintext_preserved() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("tahlk.db");
        let encrypted_tmp = dir.path().join("tahlk.db.encrypted");
        let bak = dir.path().join("tahlk.db.plaintext.bak");
        let key = fixed_key();

        build_plaintext(&db_path, "Jane Doe");
        // A bogus temp that will not open under the DEK.
        std::fs::write(&encrypted_tmp, b"not a real sqlcipher file").unwrap();

        recover_orphaned_migration(&db_path, &encrypted_tmp, &bak, &key).unwrap();

        assert!(!encrypted_tmp.exists(), "corrupt temp must be discarded");
        assert!(
            is_plaintext_db(&db_path).unwrap(),
            "plaintext original must be preserved for a clean re-migration"
        );
    }

    #[test]
    fn key_pragma_rejects_non_hex() {
        assert!(key_pragma("nothex").is_err());
        assert!(key_pragma(&"a".repeat(63)).is_err());
        assert!(key_pragma(&"a".repeat(65)).is_err());
        assert!(key_pragma(&"Z".repeat(64)).is_err());
        assert!(key_pragma(&"0".repeat(64)).is_ok());
    }

    #[test]
    fn is_plaintext_db_returns_false_for_missing_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nope.db");
        assert!(!is_plaintext_db(&path).unwrap());
    }

    // S-CODE-3: pin the right-sized pool + per-connection PRAGMAs so a future
    // edit back to server-scale numbers (max_size=8, 64 MiB cache) fails review
    // loudly. Builds a pool with the exact production customizer + builder
    // config against a temp encrypted DB, then reads the config and the
    // connection-scoped PRAGMAs back off a live checkout.
    #[test]
    fn solo_pool_and_pragmas_are_right_sized() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("pool.db");
        let manager = SqliteConnectionManager::file(&path);
        let customizer = KeyingCustomizer {
            hex_key: Arc::new(fixed_key()),
        };
        let pool = Pool::builder()
            .max_size(4)
            .min_idle(Some(1))
            .connection_customizer(Box::new(customizer))
            .build(manager)
            .unwrap();

        assert_eq!(pool.max_size(), 4, "Solo pool must stay right-sized at 4");
        assert_eq!(
            pool.min_idle(),
            Some(1),
            "one warm connection is enough — raw-hex keying skips PBKDF2"
        );

        let conn = pool.get().unwrap();
        // SQLite echoes the negative-KiB form back verbatim when set that way.
        let cache_size: i64 = conn
            .query_row("PRAGMA cache_size", [], |r| r.get(0))
            .unwrap();
        assert_eq!(cache_size, -16384, "per-connection cache must be 16 MiB");
        // foreign_keys is per-connection and OFF by default — the customizer
        // must re-enable it on every pooled connection, not just the bootstrap.
        let fk: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(fk, 1, "foreign_keys must be ON on every pooled connection");
    }

    // M4 (idle-lock hardening): once the session is locked, DbState must hand
    // out no connection and no pool — a locked screen means PHI is unreachable
    // until re-unlock re-installs the pool. Builds a real keyed pool, proves DB
    // access works unlocked, locks, and proves access is refused with a
    // precondition error (the message shown verbatim to the provider).
    #[test]
    fn locked_dbstate_refuses_connections_until_repooled() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("locktest.db");
        let key = fixed_key();

        let build_pool = || {
            let manager = SqliteConnectionManager::file(&path);
            let customizer = KeyingCustomizer {
                hex_key: Arc::new(key.clone()),
            };
            Pool::builder()
                .max_size(2)
                .min_idle(Some(1))
                .connection_customizer(Box::new(customizer))
                .build(manager)
                .unwrap()
        };

        // Unlocked: a connection is available and usable.
        let state = crate::DbState::from_pool(build_pool());
        {
            let conn = state.conn().expect("unlocked DbState must yield a connection");
            conn.execute_batch("CREATE TABLE t (v TEXT);").unwrap();
        }

        // Lock: pool dropped, DEK-bearing access gone.
        state.lock_session();
        match state.conn() {
            Err(AppError::PreconditionFailed(_)) => {}
            other => panic!("locked DbState must refuse a connection, got {:?}", other.map(|_| "conn")),
        }
        assert!(
            state.pool().is_err(),
            "locked DbState must not expose the pool"
        );

        // Re-unlock: installing a fresh pool restores access.
        state.set_pool(build_pool());
        let conn = state.conn().expect("re-unlocked DbState must yield a connection again");
        let n: i64 = conn.query_row("SELECT count(*) FROM t", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 0, "the same encrypted DB is reachable after re-unlock");
    }
}
