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
use rusqlite::Connection;
use serde_json::{json, Value};
use std::path::Path;
use std::sync::Arc;
use tauri::{AppHandle, Manager};

use crate::{db_key, errors::AppError, llm_audit, note_history, DbState};

/// Alias for the desktop-wide SQLite pool type. Every command that used to
/// take a `Mutex<Connection>` guard now takes a `PooledConnection` handed out
/// by this pool; the `KeyingCustomizer` below guarantees every fresh checkout
/// is SQLCipher-keyed before it reaches user code.
pub(crate) type SqlitePool = Pool<SqliteConnectionManager>;

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
     audio_path, created_at, signed_at, signed_hash";

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
    }))
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
// PRAGMA cache_size = -65536      → 64 MiB per-connection page cache (negative
//                                   means KiB). At max_size=8 that’s ~512 MiB
//                                   worst case; acceptable for a desktop app.
// PRAGMA temp_store  = MEMORY     → keep temp b-trees for ORDER BY / GROUP BY
//                                   off disk; matters for the encounter list
//                                   query that sorts by encounter_date DESC.
// PRAGMA mmap_size   = 268435456  → 256 MiB memory-mapped read window. Lets
//                                   SQLite skip the pread() syscall on hot
//                                   pages. Safe with WAL + SQLCipher (mmap
//                                   reads still go through the codec).
// PRAGMA busy_timeout = 5000      → 5s spin on SQLITE_BUSY before returning
//                                   an error. WAL + pool means writers still
//                                   serialize on the DB lock; this bounds the
//                                   wait for checkpoints and writer-writer
//                                   contention.
const CONN_PRAGMAS: &str = "
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous   = NORMAL;
    PRAGMA foreign_keys  = ON;
    PRAGMA cache_size    = -65536;
    PRAGMA temp_store    = MEMORY;
    PRAGMA mmap_size     = 268435456;
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
        status         TEXT NOT NULL DEFAULT 'draft',
        audio_path     TEXT,
        created_at     TEXT NOT NULL,
        signed_at      TEXT,
        signed_hash    TEXT
    );
    CREATE INDEX IF NOT EXISTS enc_date_idx ON encounters (encounter_date DESC);
    CREATE INDEX IF NOT EXISTS enc_status_idx ON encounters (status);
    CREATE INDEX IF NOT EXISTS enc_created_idx ON encounters (created_at DESC);
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



// Migrates a legacy plaintext SQLite DB at `plaintext_path` into a fresh
// SQLCipher-encrypted DB at `encrypted_path` using `sqlcipher_export`.
// `PRAGMA rekey` does NOT work for plaintext→encrypted per SQLCipher docs,
// so we ATTACH the target with the DEK and copy the schema+data across.
//
// Ordering: we build the encrypted copy first, then destroy the plaintext,
// then rename the encrypted file into place. A crash between the copy and
// the rename leaves both files on disk; the next launch will see the
// plaintext file is gone (or empty) and treat the encrypted file as canonical.
fn migrate_plaintext_to_encrypted(
    plaintext_path: &Path,
    encrypted_path: &Path,
    hex_key: &str,
) -> Result<(), AppError> {
    // Sanity: don't clobber an existing encrypted file. If one exists it
    // means a previous migration succeeded but the plaintext cleanup
    // failed — refuse rather than overwriting good data.
    if encrypted_path.exists() {
        return Err(AppError::Storage(format!(
            "refusing to migrate: encrypted DB already exists at {} while plaintext {} \
             is still present — manually remove the stale plaintext file after verifying \
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
    src.execute_batch(&attach)?;
    src.query_row("SELECT sqlcipher_export('encrypted')", [], |_| Ok(()))
        .map_err(|e| AppError::Storage(format!("sqlcipher_export failed: {}", e)))?;
    src.execute_batch("DETACH DATABASE encrypted;")?;
    drop(src);

    // Verify the new encrypted file is readable with the DEK before we
    // destroy the plaintext original.
    {
        let verify = Connection::open(encrypted_path)?;
        apply_key(&verify, hex_key)?;
    }

    // Leave a breadcrumb next to the DB so an operator investigating a
    // partial upgrade can see what happened, then wipe+unlink the plaintext.
    let bak = plaintext_path.with_extension("db.plaintext.bak");
    // Best-effort: if rename fails (cross-device etc.) fall back to unlink.
    if std::fs::rename(plaintext_path, &bak).is_ok() {
        zero_and_remove(&bak);
    } else {
        zero_and_remove(plaintext_path);
    }
    Ok(())
}

pub(crate) fn open_database(app: &AppHandle) -> Result<SqlitePool, AppError> {
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| AppError::internal_from(format!("could not resolve app_data_dir: {}", e)))?;
    std::fs::create_dir_all(&data_dir).map_err(AppError::storage_from)?;
    let db_path = data_dir.join("tahlk.db");

    let hex_key = db_key::load_or_generate_dek()?;

    // Legacy upgrade path: existing plaintext DB gets copied into a new
    // encrypted file, then swapped into place. Skipped on fresh installs
    // (file doesn't exist yet) and on subsequent launches (file is already
    // ciphertext, so the magic-byte check returns false). MUST run before we
    // hand the file to the pool — the pool's customizer will `PRAGMA key`
    // every fresh connection and reject a plaintext file with "NOTADB".
    if is_plaintext_db(&db_path).map_err(AppError::storage_from)? {
        let encrypted_tmp = data_dir.join("tahlk.db.encrypted");
        migrate_plaintext_to_encrypted(&db_path, &encrypted_tmp, &hex_key)?;
        std::fs::rename(&encrypted_tmp, &db_path).map_err(AppError::storage_from)?;
    }

    crate::perms::chmod_0600_unix(&db_path);

    // Build the pool. `max_size=8` is enough for the desktop workload
    // (streaming SSE + concurrent list/stats/history reads) without
    // over-committing per-connection cache (64 MiB × 8 = 512 MiB worst case).
    // `min_idle=2` keeps a warm connection ready so the first UI action after
    // launch doesn't pay the SQLCipher PBKDF2 cost synchronously.
    let manager = SqliteConnectionManager::file(&db_path);
    let customizer = KeyingCustomizer {
        hex_key: Arc::new(hex_key),
    };
    let pool = Pool::builder()
        .max_size(8)
        .min_idle(Some(2))
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
    note_history::init_schema(&conn)?;
    note_history::migrate_from_kv(&mut conn)?;
    llm_audit::init_schema(&conn)?;
    drop(conn);

    Ok(pool)
}

// Convenience wrapper so `run()` in lib.rs doesn't need to know how DbState
// is constructed from a Pool.
pub(crate) fn new_state(pool: SqlitePool) -> DbState {
    DbState(pool)
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

    #[test]
    fn plaintext_db_is_detected_and_migrated() {
        let dir = TempDir::new().unwrap();
        let plaintext = dir.path().join("legacy.db");
        let encrypted = dir.path().join("legacy.db.encrypted");
        let key = fixed_key();

        // Build a plaintext DB with a recognizable row.
        {
            let conn = Connection::open(&plaintext).unwrap();
            conn.execute_batch(
                "CREATE TABLE encounters (id TEXT PRIMARY KEY, patient TEXT);
                 INSERT INTO encounters VALUES ('e1', 'Jane Doe');",
            )
            .unwrap();
        }

        // File starts with the SQLite magic — detector must agree.
        assert!(is_plaintext_db(&plaintext).unwrap());

        // Run the migration.
        migrate_plaintext_to_encrypted(&plaintext, &encrypted, &key).unwrap();

        // Plaintext file (or its .bak) is gone; encrypted file exists.
        assert!(!plaintext.exists(), "plaintext file must be removed");
        let bak = plaintext.with_extension("db.plaintext.bak");
        assert!(!bak.exists(), "plaintext .bak must be zeroed and removed");
        assert!(encrypted.exists(), "encrypted file must be created");

        // Encrypted file must not start with plaintext SQLite magic.
        let bytes = std::fs::read(&encrypted).unwrap();
        assert!(!bytes.starts_with(SQLITE_MAGIC));

        // And the data must be readable with the DEK.
        let conn = Connection::open(&encrypted).unwrap();
        apply_key(&conn, &key).unwrap();
        let patient: String = conn
            .query_row("SELECT patient FROM encounters WHERE id = 'e1'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(patient, "Jane Doe");
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
}
