//! Tahlk desktop crate root.
//!
//! Modules are split by concern:
//!   - `db`            — SQLite bootstrap, encounter row projection, at-rest encryption.
//!   - `db_key`        — DEK loader (keychain-held 256-bit key for SQLCipher).
//!   - `device`        — device identity + managed-proxy bearer token (mint/refresh).
//!   - `secrets`       — guarded KV namespaces + provider-profile write path.
//!   - `kv`            — generic key/value store commands (secret_* namespace blocked).
//!   - `baa`           — Anthropic BAA acknowledgment gate (audit finding C2).
//!   - `encounters`    — encounter CRUD, sign-off, stats.
//!   - `note_history`  — relational note-history append-log + KV→table migration.
//!   - `note_audit`    — relational record-access/activity audit log + KV→table migration.
//!   - `llm_audit`     — append-only log of Anthropic calls (metadata only, no PHI).
//!   - `audio`         — session audio save/delete with path-traversal hardening.
//!   - `audio_crypto`  — AES-256-GCM at-rest encryption for session audio + migration.
//!   - `whisper`       — local whisper.cpp sidecar transcription.
//!   - `log_safety`    — filename/error redaction for the (unencrypted) app log.
//!   - `lock`           — idle-lock PIN hash storage (OS keychain, never the SQLite kv table).
//!   - `notes`         — managed-proxy streaming note generation (device-token auth, BAA-gated).
//!   - `export`        — data-location lookup + save-as export.
//!   - `patients`       — patient roster CRUD + cascade PHI destruction.
//!   - `patient_audit`  — append-only audit log for patient roster CRUD.
//!   - `retention`      — HIPAA record-retention window + litigation hold + expiration enforcement.
//!   - `time`           — server-side ISO-8601 UTC timestamps for audit rows.
//!   - `hex`            — lowercase hex encode/decode (DEK blob, PIN hash format).
//!   - `keychain`       — shared OS-keychain entry construction (item names stay per-module).
//!
//! `DbState` stays at the crate root so every module can name it via
//! `crate::DbState` without cyclic imports; this file only wires setup and
//! the `generate_handler!` list.

use std::sync::Mutex;
use tauri::Manager;

use crate::errors::AppError;

mod audio;
mod audio_crypto;
mod audit_mac;
mod auth;
mod baa;
mod config_audit;
mod crypto;
mod db;
mod db_key;
mod destruction_log;
mod device;
mod encounters;
mod errors;
mod export;
mod kv;
mod kv_ops;
mod llm_audit;
mod lock;
mod log_safety;
mod hex;
mod keychain;
mod note_audit;
mod note_history;
mod time;
mod notes;
mod patient_audit;
mod patients;
mod perms;
mod retention;
mod secrets;
mod throttle;
mod whisper;

/// Shared SQLite pool state. Every #[tauri::command] that touches the DB
/// checks out a pooled connection via `state.conn()?` — the old
/// `Mutex<Connection>` chokepoint (audit P2) is gone. The pool's
/// `KeyingCustomizer` (see db.rs) guarantees each fresh connection is
/// SQLCipher-keyed before it reaches user code, so this state can be handed
/// out freely across the invoke handler without any keying invariant leaking
/// into every callsite.
///
/// The pool is held in a `Mutex<Option<_>>` (M4, idle-lock hardening): idle
/// lock zeroes the in-memory session DEK and drops the pool here, so that once
/// the screen locks there is no live pool and no key in memory to reach PHI.
/// The pool is re-installed by `auth_unlock_password` after the provider
/// re-enters their password, which re-derives the DEK and reopens the DB. This
/// is preferred over Tauri's `unmanage` (deprecated / unsound — leaves dangling
/// `State` refs); interior mutability lets the single managed instance flip
/// between locked (`None`) and unlocked (`Some(pool)`) safely.
pub(crate) struct DbState(pub(crate) Mutex<Option<db::SqlitePool>>);

impl DbState {
    /// Locked state — no pool. Managed at setup on an auth-configured install
    /// so DB commands return a clean "session locked" precondition (rather than
    /// a Tauri "state not managed" error) until the first unlock.
    pub(crate) fn empty() -> Self {
        DbState(Mutex::new(None))
    }

    /// Unlocked state carrying a live pool. Used on the fresh-install path where
    /// the DB is opened during setup via the keychain DEK.
    pub(crate) fn from_pool(pool: db::SqlitePool) -> Self {
        DbState(Mutex::new(Some(pool)))
    }

    /// Clone out the live pool (an `Arc` bump, cheap), or a precondition error
    /// if the session is locked. The lock guard is released before returning,
    /// so callers may hold the pool across `.await` without pinning the mutex.
    pub(crate) fn pool(&self) -> Result<db::SqlitePool, AppError> {
        self.0
            .lock()
            .expect("DbState mutex poisoned")
            .clone()
            .ok_or_else(|| {
                AppError::precondition(
                    "Your session is locked. Enter your password to unlock and continue.",
                )
            })
    }

    /// Check out a pooled connection, or a precondition error if locked.
    pub(crate) fn conn(&self) -> Result<db::PooledConn, AppError> {
        Ok(self.pool()?.get()?)
    }

    /// Install the pool after an unlock (`auth_unlock_password`).
    pub(crate) fn set_pool(&self, pool: db::SqlitePool) {
        *self.0.lock().expect("DbState mutex poisoned") = Some(pool);
    }

    /// Drop the pool on idle lock. Our reference goes away immediately; any
    /// connection a command is still mid-flight with keeps the underlying pool
    /// alive only until it finishes, after which the pool fully closes.
    pub(crate) fn lock_session(&self) {
        *self.0.lock().expect("DbState mutex poisoned") = None;
    }
}

/// Ceiling on the free-text `provider_id` identity field, so a compromised
/// WebView can't stash arbitrary data in a compliance record under the guise
/// of an actor name.
///
/// At the crate root for the same reason as `DbState`: both `baa::baa_ack_set`
/// and `patients`' audit path cap this same field, and neither module owns the
/// concept (it's the provider's own identity, set at onboarding, used as the
/// audit actor). They previously each hardcoded `256` — `patients`' comment
/// claimed it "matches `baa.rs::baa_ack_set`'s cap" while nothing linked them,
/// so either could drift silently.
pub(crate) const MAX_PROVIDER_ID_BYTES: usize = 256;

pub fn run() {
    tauri::Builder::default()
        // First plugin: stand up file logging before anything else can fail so
        // even a crash during setup lands in the on-disk log. Targets default
        // to Stdout + Webview + the OS log dir (macOS ~/Library/Logs/com.tahlk.app,
        // Windows %LOCALAPPDATA%\com.tahlk.app\logs, Linux ~/.local/share). Info
        // keeps our own diagnostics without drowning them in reqwest/hyper trace.
        .plugin(
            tauri_plugin_log::Builder::new()
                .level(log::LevelFilter::Info)
                .build(),
        )
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .setup(|app| {
            // A GUI process launched from the Start Menu / Finder has no attached
            // terminal, so a `panic!` would otherwise disappear. Route panics to
            // the log file (then chain the default hook so dev builds still print
            // to stderr) — this is the artifact a clinician sends support when the
            // app fails to start.
            let default_hook = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                log::error!("panic: {}", log_safety::cap_len(&info.to_string()));
                default_hook(info);
            }));

            // When auth is already configured the keychain DEK entry has been
            // removed (by auth_set_password) and the DB can only be opened with
            // the DEK unwrapped from the user's password. Defer opening to
            // auth_unlock_password, which runs after the JS auth screen collects
            // the password. On a fresh install (not yet configured), fall through
            // to the keychain path so the first-open setup flow works.
            if !auth::is_auth_configured() {
                // Fail-closed on any DB open error — including keychain unreachable
                // (M1) or wrong-key (tampered / corrupted DEK). We would rather
                // refuse to launch than silently fall back to an unencrypted DB and
                // expose PHI. Log the failure before the panic so the on-disk log
                // names the cause (e.g. "Storage error: ...") even on a GUI launch.
                let pool = db::open_database(app.handle()).unwrap_or_else(|e| {
                    let safe = log_safety::cap_len(&e.to_string());
                    log::error!("failed to open encrypted SQLite database: {safe}");
                    panic!("failed to open encrypted SQLite database: {safe}");
                });

                // One-shot at-rest audio migration: encrypt any legacy plaintext
                // `<id>.wav` files and rewrite their DB paths to `<id>.wav.enc`.
                // Best-effort — a migration hiccup is logged but must not block
                // launch (the DB is already open and the app is usable; a lingering
                // plaintext is a leak we surface in the log, not a hard failure).
                // Runs before we hand the pool to state so it borrows the pool
                // directly. Idempotent/resumable — see audio_crypto.
                match (|| -> Result<usize, errors::AppError> {
                    let conn = pool.get()?;
                    let audio_dir = app
                        .path()
                        .app_data_dir()
                        .map_err(errors::AppError::internal_from)?
                        .join("audio");
                    let key = audio_crypto::audio_key()?;
                    let n = audio_crypto::migrate_plaintext_audio_at_rest(&conn, &audio_dir, &key)?;
                    // Reconcile AFTER the migration, which renames legacy
                    // `.wav` to `.wav.enc` — sweeping first would miss them.
                    // Finds PHI audio whose encounter row is gone, including
                    // the case where a prior destruction died mid-cleanup and
                    // left no record at all.
                    let provider = crate::kv_ops::provider_id(&conn);
                    let orphans = audio::reconcile_orphaned_audio(&conn, &audio_dir, &provider)?;
                    if orphans > 0 {
                        log::warn!("reconciled {orphans} orphaned audio file(s) after prior destruction");
                    }
                    Ok(n)
                })() {
                    Ok(_) => {}
                    Err(e) => log::error!("audio at-rest migration skipped: {}", log_safety::cap_len(&e.to_string())),
                }

                app.manage(DbState::from_pool(pool));
            } else {
                // Auth IS configured — the DB stays locked until the JS auth
                // screen collects the password and calls auth_unlock_password,
                // which installs the pool via DbState::set_pool. Manage an empty
                // (locked) DbState now so DB commands return a "session locked"
                // precondition instead of a Tauri "state not managed" error, and
                // so the same slot can be re-locked/re-unlocked by the idle-lock
                // path for the rest of the process's life.
                app.manage(DbState::empty());
            }

            // Content protection (audit finding: "no window content-protection
            // flag — screen sharing/recording/remote-desktop tools can capture
            // PHI on screen"). Excludes this window from what screen-share,
            // screen-recording, and remote-support tools can capture — on
            // Windows this sets WDA_EXCLUDEFROMCAPTURE, on macOS it sets
            // NSWindowSharingNone. Best-effort: if the main window handle isn't
            // available yet (shouldn't happen at this point in setup) or the
            // platform call fails, log and continue rather than blocking
            // launch — this is defense-in-depth on top of the app's other
            // controls, not the only thing standing between PHI and exposure.
            if let Some(window) = app.get_webview_window("main") {
                // Message says "screen-capture protection", not "content
                // protection", to stay clear of check_log_phi.sh's FORBIDDEN
                // substring list ("content"). The blunt scan can't tell this
                // "content" from note content, and its stated policy is to
                // reword the call rather than carve out an exemption. Reads
                // better anyway — it names the effect, not the Tauri API.
                if let Err(e) = window.set_content_protected(true) {
                    log::error!("failed to enable screen-capture protection: {}", log_safety::cap_len(&e.to_string()));
                }
            } else {
                log::error!("main window not found; screen-capture protection not applied");
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            kv::kv_get,
            kv::kv_set,
            kv::kv_remove,
            kv::kv_list,
            secrets::set_provider_profile,
            baa::baa_ack_status,
            baa::baa_ack_set,
            baa::baa_ack_clear,
            llm_audit::llm_audit_list,
            export::data_location,
            encounters::list_encounters,
            encounters::get_encounter,
            encounters::encounter_stats,
            encounters::mark_encounter_signed,
            encounters::upsert_encounter,
            encounters::delete_encounter,
            audio::save_session_audio,
            audio::delete_session_audio,
            encounters::clear_encounter_audio_path,
            patients::list_patients,
            patients::get_patient,
            patients::upsert_patient,
            patients::delete_patient,
            patients::destroy_patient_records,
            patients::count_patient_encounters,
            patient_audit::patient_audit_list,
            lock::lock_pin_set,
            lock::lock_pin_verify,
            lock::lock_pin_clear,
            lock::lock_pin_is_set,
            note_history::note_history_list,
            note_history::note_history_list_encounter_ids,
            note_history::history_note_generated,
            note_history::history_note_edited,
            note_history::verify_history_macs,
            note_audit::audit_list,
            note_audit::audit_archive_list,
            note_audit::audit_log_record_viewed,
            note_audit::audit_log_note_edited,
            note_audit::audit_log_note_signed,
            note_audit::audit_log_audio_deleted,
            note_audit::audit_log_note_exported,
            note_audit::audit_log_records_listed,
            note_audit::verify_audit_macs,
            whisper::transcribe_audio,
            notes::generate_note,
            export::export_note_to_file,
            export::export_note_pdf_to_file,
            auth::auth_is_configured,
            auth::auth_set_password,
            auth::auth_reset_with_recovery_code,
            auth::auth_unlock_password,
            auth::auth_unlock_recovery,
            auth::auth_change_password,
            auth::auth_generate_recovery_codes,
            auth::auth_nuke_and_reinstall,
            auth::auth_lock_session,
            destruction_log::destruction_log_list,
            destruction_log::destruction_log_note_exported,
            config_audit::config_audit_list,
            note_audit::note_audit_list_encounter_ids,
            retention::retention_get_years,
            retention::retention_set_years,
            retention::retention_hold_get,
            retention::retention_hold_set,
            retention::retention_list_candidates,
            retention::retention_destroy_eligible,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Tauri application");
}
