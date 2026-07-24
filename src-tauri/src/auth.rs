//! First-open authentication and DEK key-wrapping (ADR 0004).
//!
//! Before a provider starts using Tahlk, this module establishes:
//!  - A master password (min 12 chars, not in the vendored 10k-common list)
//!  - Three one-time recovery codes (Crockford base32 + checksum)
//!
//! The database encryption key (DEK) is wrapped under multiple Key-Encryption
//! Keys (KEKs) and stored in `tahlk_auth.db`, a plain SQLite file in the same
//! `app_data_dir` as `tahlk.db`. "Plain" here means not SQLCipher-encrypted
//! (the wraps file cannot use the encrypted DB — that is what it protects).
//! Each row is AES-256-GCM ciphertext: the DEK is only recoverable by
//! someone who knows the password or holds a valid recovery code.
//!
//! ## Key derivation
//!
//! Password KEK: PBKDF2-HMAC-SHA256 at 210,000 iterations (OWASP minimum for
//! this algorithm; matches `lock.rs`'s precedent). A fresh 16-byte random salt
//! is generated per password-set call.
//!
//! Recovery KEK: HKDF-SHA256 from 15 CSPRNG bytes (120 bits of entropy) with a
//! fixed domain-separation label. Those 15 bytes are Crockford-base32-encoded
//! into 24 chars, then a Crockford checksum char is appended, yielding a
//! 25-char code that is shown to the provider and never stored anywhere by this
//! module.
//!
//! ## Wraps DB (`tahlk_auth.db`)
//!
//! Lives in `app_data_dir` alongside `tahlk.db`. Schema:
//! ```sql
//! CREATE TABLE auth_dek_wraps (
//!     id             INTEGER PRIMARY KEY AUTOINCREMENT,
//!     wrap_type      TEXT NOT NULL UNIQUE,
//!     salt_hex       TEXT NOT NULL,
//!     ciphertext_hex TEXT NOT NULL,
//!     created_at     TEXT NOT NULL
//! );
//! ```
//! `wrap_type` values: `"password"`, `"recovery_1"`, `"recovery_2"`,
//! `"recovery_3"`. `salt_hex` carries the PBKDF2 salt for the password row
//! and is empty for recovery rows (recovery KEKs are derived from the code
//! itself — no salt needed given 120-bit entropy). `ciphertext_hex` is
//! `hex(nonce[12] ‖ AES-256-GCM(kek, dek_bytes[32]) ‖ tag[16])`.
//!

use std::num::NonZeroU32;
use std::path::Path;
use std::sync::RwLock;

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::hkdf;
use ring::pbkdf2;
use rusqlite::{params, Connection, OptionalExtension};
use tauri::{AppHandle, Manager, State};

use crate::DbState;

use crate::errors::AppError;
use crate::hex::{from_hex, to_hex};
use crate::time::utc_now_iso;

/// OS keychain item name for the PBKDF2 password hash.
/// Stored format: `"<iterations>:<salt_hex>:<hash_hex>"` (matches `lock.rs`).
pub(crate) const KEYRING_USER: &str = "auth_password_hash";

const PBKDF2_ITERATIONS: u32 = 210_000;
const SALT_LEN: usize = 16;      // PBKDF2 salt bytes
const HASH_LEN: usize = 32;      // PBKDF2 output = AES-256 key size
const DEK_BYTES: usize = 32;     // DEK is 256 bits
const CODE_DATA_LEN: usize = 15; // CSPRNG bytes per recovery code (120 bits)
const CODE_CHARS: usize = 24;    // Crockford chars for 15 bytes (24 × 5 bits = 120 bits)

const PASSWORD_MIN_LEN: usize = 12;
const PASSWORD_MAX_LEN: usize = 128;

/// 10,000 most common passwords (vendored from SecLists), newline-separated.
/// Checked case-insensitively at validate_password time, before any key
/// derivation, so weak passwords are rejected fast.
static COMMON_PASSWORDS: &str = include_str!("../assets/10k-most-common-passwords.txt");

// ─────────────────────────────────────────────────────────────────────────────
// Recovery code type
// ─────────────────────────────────────────────────────────────────────────────

/// A single Crockford base32 recovery code.
/// Internal storage: 25 chars (24 data chars + 1 checksum char).
/// Strip hyphens and uppercase before passing user input to `parse_recovery_code`.
#[derive(Clone)]
pub(crate) struct RecoveryCode(String);

impl RecoveryCode {
    /// The raw 25-character code, no separators.
    ///
    /// `#[cfg(test)]` because production never needs it: codes are shown via
    /// `display()` and consumed via `parse_recovery_code`, which strips
    /// separators itself. Gating it here removes the dead-code warning without
    /// deleting a method twelve tests rely on.
    #[cfg(test)]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    /// Human-display format: `XXXXXX-XXXXXX-XXXXXX-XXXXXX-X` (groups of 6-6-6-6-1).
    pub(crate) fn display(&self) -> String {
        let s = &self.0;
        format!(
            "{}-{}-{}-{}-{}",
            &s[0..6],
            &s[6..12],
            &s[12..18],
            &s[18..24],
            &s[24..]
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Crockford base32
// ─────────────────────────────────────────────────────────────────────────────

/// 32-symbol Crockford alphabet (no I, L, O, U).
const CROCKFORD: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Extended 37-symbol set for the Crockford checksum character.
const CROCKFORD_CHECK: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U";

/// Map one Crockford character (case-insensitive; O→0, I/L→1 per spec) to its
/// 5-bit quintet value. Returns `None` for characters outside the alphabet.
fn crockford_char_to_value(c: u8) -> Option<u8> {
    match c.to_ascii_uppercase() {
        b'0' | b'O' => Some(0),
        b'1' | b'I' | b'L' => Some(1),
        b'2' => Some(2),
        b'3' => Some(3),
        b'4' => Some(4),
        b'5' => Some(5),
        b'6' => Some(6),
        b'7' => Some(7),
        b'8' => Some(8),
        b'9' => Some(9),
        b'A' => Some(10),
        b'B' => Some(11),
        b'C' => Some(12),
        b'D' => Some(13),
        b'E' => Some(14),
        b'F' => Some(15),
        b'G' => Some(16),
        b'H' => Some(17),
        b'J' => Some(18),
        b'K' => Some(19),
        b'M' => Some(20),
        b'N' => Some(21),
        b'P' => Some(22),
        b'Q' => Some(23),
        b'R' => Some(24),
        b'S' => Some(25),
        b'T' => Some(26),
        b'V' => Some(27),
        b'W' => Some(28),
        b'X' => Some(29),
        b'Y' => Some(30),
        b'Z' => Some(31),
        _ => None,
    }
}

/// Encode 15 bytes as 24 Crockford base32 characters.
/// 15 bytes × 8 bits = 120 bits = 24 × 5-bit quintets, processed in three
/// 5-byte blocks (each yielding 8 quintets).
fn crockford_encode(data: &[u8; CODE_DATA_LEN]) -> [u8; CODE_CHARS] {
    let mut out = [0u8; CODE_CHARS];
    for chunk in 0..3 {
        let b = &data[chunk * 5..chunk * 5 + 5];
        let base = chunk * 8;
        out[base] = CROCKFORD[(b[0] >> 3) as usize];
        out[base + 1] = CROCKFORD[((b[0] & 0x07) << 2 | b[1] >> 6) as usize];
        out[base + 2] = CROCKFORD[((b[1] >> 1) & 0x1f) as usize];
        out[base + 3] = CROCKFORD[((b[1] & 0x01) << 4 | b[2] >> 4) as usize];
        out[base + 4] = CROCKFORD[((b[2] & 0x0f) << 1 | b[3] >> 7) as usize];
        out[base + 5] = CROCKFORD[((b[3] >> 2) & 0x1f) as usize];
        out[base + 6] = CROCKFORD[((b[3] & 0x03) << 3 | b[4] >> 5) as usize];
        out[base + 7] = CROCKFORD[(b[4] & 0x1f) as usize];
    }
    out
}

/// Decode 24 Crockford base32 characters back to 15 bytes. Returns `None` if
/// any character is not a valid Crockford symbol (hyphens must be stripped first).
fn crockford_decode(chars: &[u8; CODE_CHARS]) -> Option<[u8; CODE_DATA_LEN]> {
    let mut q = [0u8; CODE_CHARS];
    for (i, &c) in chars.iter().enumerate() {
        q[i] = crockford_char_to_value(c)?;
    }
    let mut out = [0u8; CODE_DATA_LEN];
    for chunk in 0..3 {
        let qi = &q[chunk * 8..chunk * 8 + 8];
        let base = chunk * 5;
        out[base] = (qi[0] << 3) | (qi[1] >> 2);
        out[base + 1] = ((qi[1] & 0x03) << 6) | (qi[2] << 1) | (qi[3] >> 4);
        out[base + 2] = ((qi[3] & 0x0f) << 4) | (qi[4] >> 1);
        out[base + 3] = ((qi[4] & 0x01) << 7) | (qi[5] << 2) | (qi[6] >> 3);
        out[base + 4] = ((qi[6] & 0x07) << 5) | qi[7];
    }
    Some(out)
}

/// Crockford checksum: interpret `data` as a big-endian integer, compute mod 37,
/// map to the 37-symbol check character set.
fn crockford_checksum(data: &[u8; CODE_DATA_LEN]) -> u8 {
    let mut rem: u64 = 0;
    for &byte in data.iter() {
        rem = ((rem << 8) | u64::from(byte)) % 37;
    }
    CROCKFORD_CHECK[rem as usize]
}

/// Generate one recovery code from 15 CSPRNG bytes.
/// Returns the `RecoveryCode` (shown to the user) and the raw seed bytes
/// (used immediately to derive the KEK; never stored after this call returns).
fn generate_recovery_code() -> Result<(RecoveryCode, [u8; CODE_DATA_LEN]), AppError> {
    let mut seed = [0u8; CODE_DATA_LEN];
    getrandom::getrandom(&mut seed).map_err(AppError::internal_from)?;
    let encoded = crockford_encode(&seed);
    let check = crockford_checksum(&seed);
    let mut s = String::with_capacity(CODE_CHARS + 1);
    for &b in &encoded {
        s.push(b as char);
    }
    s.push(check as char);
    Ok((RecoveryCode(s), seed))
}

/// Parse and validate a user-supplied recovery code string.
/// Strips hyphens and spaces, uppercases, checks length (must be 25 chars after
/// stripping) and Crockford checksum. Returns the 15 raw seed bytes on success.
pub(crate) fn parse_recovery_code(input: &str) -> Result<[u8; CODE_DATA_LEN], AppError> {
    let normalized: String = input
        .chars()
        .filter(|&c| c != '-' && c != ' ')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if normalized.len() != CODE_CHARS + 1 {
        return Err(AppError::invalid(format!(
            "recovery code must be {} characters after stripping dashes (got {})",
            CODE_CHARS + 1,
            normalized.len()
        )));
    }
    let bytes = normalized.as_bytes();
    let data_chars: &[u8; CODE_CHARS] = bytes[..CODE_CHARS].try_into().unwrap();
    let check_char = bytes[CODE_CHARS];
    let seed = crockford_decode(data_chars)
        .ok_or_else(|| AppError::invalid("recovery code contains invalid characters"))?;
    if check_char != crockford_checksum(&seed) {
        return Err(AppError::invalid("recovery code checksum mismatch"));
    }
    Ok(seed)
}

// ─────────────────────────────────────────────────────────────────────────────
// KEK derivation
// ─────────────────────────────────────────────────────────────────────────────

/// Derive a 32-byte Key-Encryption Key from a password and salt using
/// PBKDF2-HMAC-SHA256 at `PBKDF2_ITERATIONS` iterations.
/// Iteration count matches `lock.rs` (210,000 — OWASP minimum for this algorithm).
pub(crate) fn derive_kek(password: &str, salt: &[u8]) -> Result<[u8; HASH_LEN], AppError> {
    let nz = NonZeroU32::new(PBKDF2_ITERATIONS)
        .ok_or_else(|| AppError::internal_from("PBKDF2 iteration count must be nonzero"))?;
    let mut kek = [0u8; HASH_LEN];
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, nz, salt, password.as_bytes(), &mut kek);
    Ok(kek)
}

/// Derive a 32-byte KEK from a recovery code's 15-byte seed via HKDF-SHA256.
/// No PBKDF2 stretching is needed: the seed already has 120 bits of entropy.
fn derive_recovery_kek(seed: &[u8; CODE_DATA_LEN]) -> Result<[u8; HASH_LEN], AppError> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"tahlk-recovery-kek-v1");
    let prk = salt.extract(seed.as_ref());
    let mut kek = [0u8; HASH_LEN];
    prk.expand(&[b"kek" as &[u8]], hkdf::HKDF_SHA256)
        .map_err(|_| AppError::internal_from("recovery KEK HKDF expand failed"))?
        .fill(&mut kek)
        .map_err(|_| AppError::internal_from("recovery KEK HKDF fill failed"))?;
    Ok(kek)
}

// ─────────────────────────────────────────────────────────────────────────────
// DEK wrap / unwrap
// ─────────────────────────────────────────────────────────────────────────────

/// Wrap (encrypt) the 32-byte DEK under a KEK using AES-256-GCM.
/// Returns `nonce[12] ‖ ciphertext[32] ‖ tag[16]` = 60 bytes total.
/// A fresh random nonce is drawn per call — never reuse (key, nonce) pairs.
pub(crate) fn wrap_dek(kek: &[u8; HASH_LEN], dek: &[u8; DEK_BYTES]) -> Result<Vec<u8>, AppError> {
    let unbound =
        UnboundKey::new(&AES_256_GCM, kek).map_err(|_| AppError::internal_from("wrap_dek: bad key"))?;
    let sealing = LessSafeKey::new(unbound);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes).map_err(AppError::internal_from)?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut buf = dek.to_vec();
    sealing
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut buf)
        .map_err(|_| AppError::internal_from("wrap_dek: seal failed"))?;

    let mut out = Vec::with_capacity(NONCE_LEN + buf.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&buf);
    Ok(out)
}

/// Unwrap (decrypt + authenticate) a wrapped DEK blob produced by `wrap_dek`.
/// Returns the 32-byte DEK on success. Fails if the blob is too short, if the
/// GCM tag does not validate (wrong key, corruption, tampering), or if the
/// decrypted length is not exactly `DEK_BYTES`.
pub(crate) fn unwrap_dek(kek: &[u8; HASH_LEN], wrapped: &[u8]) -> Result<[u8; DEK_BYTES], AppError> {
    let min_len = NONCE_LEN + DEK_BYTES + AES_256_GCM.tag_len();
    if wrapped.len() < min_len {
        return Err(AppError::invalid("wrapped DEK blob is too short"));
    }
    let (nonce_bytes, ciphertext) = wrapped.split_at(NONCE_LEN);
    let mut nonce_arr = [0u8; NONCE_LEN];
    nonce_arr.copy_from_slice(nonce_bytes);
    let nonce = Nonce::assume_unique_for_key(nonce_arr);

    let unbound =
        UnboundKey::new(&AES_256_GCM, kek).map_err(|_| AppError::internal_from("unwrap_dek: bad key"))?;
    let opening = LessSafeKey::new(unbound);
    let mut buf = ciphertext.to_vec();
    let plaintext = opening
        .open_in_place(nonce, Aad::empty(), &mut buf)
        .map_err(|_| AppError::invalid("unwrap_dek: authentication failed — wrong key or corrupted blob"))?;

    if plaintext.len() != DEK_BYTES {
        return Err(AppError::internal_from(format!(
            "unwrapped DEK has wrong length: expected {DEK_BYTES}, got {}",
            plaintext.len()
        )));
    }
    let mut out = [0u8; DEK_BYTES];
    out.copy_from_slice(plaintext);
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// Password validation
// ─────────────────────────────────────────────────────────────────────────────

/// Validate a candidate master password. Rejects:
///   - Shorter than `PASSWORD_MIN_LEN` (12 chars)
///   - Longer than `PASSWORD_MAX_LEN` (128 chars — paste-in-wrong-field guard)
///   - Present in the vendored 10k-common-passwords list (case-insensitive)
pub(crate) fn validate_password(password: &str) -> Result<(), AppError> {
    if password.len() < PASSWORD_MIN_LEN {
        return Err(AppError::invalid(format!(
            "password must be at least {PASSWORD_MIN_LEN} characters"
        )));
    }
    if password.len() > PASSWORD_MAX_LEN {
        return Err(AppError::invalid(format!(
            "password exceeds {PASSWORD_MAX_LEN} characters"
        )));
    }
    let lower = password.to_ascii_lowercase();
    if COMMON_PASSWORDS.lines().any(|line| line.trim() == lower) {
        return Err(AppError::invalid(
            "this password appears in a list of commonly used passwords — choose a more unique one",
        ));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Password hash (OS keychain)
// ─────────────────────────────────────────────────────────────────────────────

fn keyring_entry() -> Result<keyring::Entry, AppError> {
    crate::keychain::entry(KEYRING_USER)
}

/// Derive and format the keychain-stored password hash.
/// Format: `"<iterations>:<salt_hex>:<hash_hex>"` — matches `lock.rs`'s precedent
/// so the iteration count travels with the hash and a future increase doesn't
/// break verification of an already-set password.
fn hash_password(password: &str) -> Result<String, AppError> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::getrandom(&mut salt).map_err(AppError::internal_from)?;
    let nz = NonZeroU32::new(PBKDF2_ITERATIONS)
        .ok_or_else(|| AppError::internal_from("PBKDF2 iteration count must be nonzero"))?;
    let mut hash = [0u8; HASH_LEN];
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, nz, &salt, password.as_bytes(), &mut hash);
    Ok(format!("{PBKDF2_ITERATIONS}:{}:{}", to_hex(&salt), to_hex(&hash)))
}

/// Verify `password` against the stored PBKDF2 hash from the OS keychain.
/// Returns `Ok(false)` — not an error — for missing entry, malformed entry, or
/// wrong password. Uses `ring::pbkdf2::verify` for constant-time comparison.
fn verify_password_hash(password: &str) -> Result<bool, AppError> {
    let stored = match keyring_entry()?.get_password() {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    let parts: Vec<&str> = stored.splitn(3, ':').collect();
    if parts.len() != 3 {
        return Ok(false);
    }
    let Ok(iterations) = parts[0].parse::<u32>() else { return Ok(false) };
    let Some(nz) = NonZeroU32::new(iterations) else { return Ok(false) };
    let Some(salt) = from_hex(parts[1]) else { return Ok(false) };
    let Some(expected) = from_hex(parts[2]) else { return Ok(false) };
    Ok(
        pbkdf2::verify(pbkdf2::PBKDF2_HMAC_SHA256, nz, &salt, password.as_bytes(), &expected)
            .is_ok(),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Wraps DB
// ─────────────────────────────────────────────────────────────────────────────

fn init_wraps_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS auth_dek_wraps (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            wrap_type      TEXT NOT NULL UNIQUE,
            salt_hex       TEXT NOT NULL,
            ciphertext_hex TEXT NOT NULL,
            created_at     TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS auth_audit (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            event      TEXT NOT NULL,
            outcome    TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS auth_audit_created_idx
            ON auth_audit (created_at DESC);",
    )
}

// ── Authentication-event audit trail (HIPAA §164.312(b), audit finding H1) ──
//
// Before this, every credential-verification path (password unlock, recovery
// unlock, PIN verify, password change/reset, recovery-code regeneration, the
// irreversible nuke) was rate-limited but never *recorded*: the single most
// security-critical event in the app — who unlocked the DEK that protects
// 100% of the PHI, when, and how many times it was guessed wrong — left no
// durable trace (`throttle.rs` state is in-memory only, wiped on restart).
//
// This log lives in the plain `tahlk_auth.db` wraps DB, NOT the SQLCipher
// `tahlk.db`, for a structural reason: a *failed* unlock happens precisely
// while the encrypted DB is still locked, so it could never be recorded there.
// The wraps DB is always openable, so both success and failure land. It is
// deliberately metadata-only (timestamp, event, outcome) — no password, no
// PHI, no provider identity — so persisting it to an unencrypted file next to
// the wraps table (already `chmod 0600`) adds no sensitive material to protect.

/// Valid `event` values. Validated at the append boundary so a bug can't stuff
/// an arbitrary string into a compliance record.
pub(crate) const AUTH_AUDIT_EVENTS: &[&str] = &[
    "password_set",             // first-open / post-nuke setup
    "unlock_password",          // startup or idle-resume password unlock
    "unlock_recovery",          // forgot-password recovery-code unlock
    "password_changed",         // Settings: change master password
    "password_reset_recovery",  // forgot-password: reset via recovery code
    "recovery_codes_regenerated", // Settings: regenerate all three codes
    "pin_verify",               // idle-lock PIN verification
    "session_locked",           // idle-lock activation (auto-logoff)
    "nuke_reinstall",           // irreversible wipe attempt
];

/// Valid `outcome` values.
pub(crate) const AUTH_AUDIT_OUTCOMES: &[&str] = &["success", "failure", "throttled", "refused"];

/// Appends one authentication-event row. Takes `&Connection` so it can be
/// unit-tested against a bare in-memory SQLite without a Tauri harness.
pub(crate) fn append_auth_event(conn: &Connection, event: &str, outcome: &str) -> Result<(), AppError> {
    debug_assert!(AUTH_AUDIT_EVENTS.contains(&event), "append_auth_event: unvalidated event: {event}");
    debug_assert!(AUTH_AUDIT_OUTCOMES.contains(&outcome), "append_auth_event: unvalidated outcome: {outcome}");
    conn.execute(
        "INSERT INTO auth_audit (created_at, event, outcome) VALUES (?1, ?2, ?3)",
        params![utc_now_iso(), event, outcome],
    )?;
    Ok(())
}

/// Best-effort recorder called from the auth/lock command entry points. Opens
/// the wraps DB and appends one row. Deliberately fire-and-forget: a failed
/// audit write is logged (metadata only — never PHI) but NOT propagated, for
/// the same reason `notes::record_llm_call` refuses to propagate — masking the
/// real auth result the caller came in with (an unlock success or failure)
/// behind an audit-plumbing error would be worse than a missing row. Note that
/// a *successful* `nuke_reinstall` is intentionally never recorded here: it
/// destroys `tahlk_auth.db` by design, so the meaningful auditable nuke events
/// are the failed/refused/throttled attempts, which DO persist.
pub(crate) fn record_auth_event(app: &AppHandle, event: &str, outcome: &str) {
    let path = match wraps_db_path(app) {
        Ok(p) => p,
        Err(e) => {
            log::warn!("auth_audit: could not resolve wraps path for {event}/{outcome}: {e}");
            return;
        }
    };
    match open_wraps_db(&path) {
        Ok(conn) => {
            if let Err(e) = append_auth_event(&conn, event, outcome) {
                log::warn!("auth_audit: failed to record {event}/{outcome}: {e}");
            }
        }
        Err(e) => log::warn!("auth_audit: could not open wraps DB for {event}/{outcome}: {e}"),
    }
}

/// Success/failure outcome string for the common `Result`-returning commands.
fn outcome_str<T>(r: &Result<T, AppError>) -> &'static str {
    if r.is_ok() { "success" } else { "failure" }
}

/// #[tauri::command] — list recent authentication events (newest first) for the
/// provider's own review / an auditor's post-incident inspection. Metadata only.
/// Capped so the query stays bounded even on a long-lived install.
#[tauri::command]
pub(crate) fn auth_audit_list(app: AppHandle) -> Result<Vec<serde_json::Value>, AppError> {
    let path = wraps_db_path(&app)?;
    let conn = open_wraps_db(&path)?;
    let mut stmt = conn.prepare(
        "SELECT created_at, event, outcome FROM auth_audit ORDER BY id DESC LIMIT 500",
    )?;
    let rows = stmt
        .query_map([], |r| {
            Ok(serde_json::json!({
                "createdAt": r.get::<_, String>(0)?,
                "event":     r.get::<_, String>(1)?,
                "outcome":   r.get::<_, String>(2)?,
            }))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Open (or create) the wraps DB at `path`. Creates parent directories if
/// needed, initialises the schema, and tightens Unix file permissions to 0600.
pub(crate) fn open_wraps_db(path: &Path) -> Result<Connection, AppError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(AppError::storage_from)?;
    }
    let conn = Connection::open(path)?;
    init_wraps_schema(&conn)?;
    crate::perms::chmod_0600_unix(path);
    Ok(conn)
}

fn wraps_db_path(app: &AppHandle) -> Result<std::path::PathBuf, AppError> {
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| AppError::internal_from(format!("could not resolve app_data_dir: {e}")))?;
    Ok(data_dir.join("tahlk_auth.db"))
}

// ─────────────────────────────────────────────────────────────────────────────
// High-level auth operations (take &Path, no AppHandle — testable without Tauri)
// ─────────────────────────────────────────────────────────────────────────────

/// The DEK for the current unlocked session, hex-encoded.
///
/// Once auth is configured, `auth_set_password` deletes the keychain DEK entry
/// so the wrapped copy in `tahlk_auth.db` is the only route to the key. Anything
/// that needs the DEK *after* that point — notably `audio_crypto::audio_key`,
/// which derives the audio-at-rest key from it — must read the unwrapped value
/// from here rather than from the keychain, because the keychain no longer has
/// it and `db_key::load_or_generate_dek` would otherwise mint a replacement.
///
/// `RwLock<Option<_>>` rather than `OnceLock`: `auth_nuke_and_reinstall`
/// followed by a fresh `auth_set_password` in the same process legitimately
/// produces a *different* DEK, and a write-once cell would silently retain the
/// stale one.
///
/// Held as hex to match the existing DEK plumbing (`to_hex` at the unlock
/// sites, `PRAGMA key = "x'..'"`, `derive_audio_key(&str)`); this adds no
/// plaintext-key exposure the process did not already have.
static SESSION_DEK_HEX: RwLock<Option<String>> = RwLock::new(None);

/// Throttle scopes. Kept distinct so a lockout on the destructive path cannot
/// lock a provider out of their own records, and vice versa.
const THROTTLE_UNLOCK: &str = "auth_unlock";
const THROTTLE_NUKE: &str = "auth_nuke";

/// Record the unwrapped DEK for this session. Called from every path that
/// legitimately obtains it: first-time setup, password unlock, recovery unlock,
/// and password change.
pub(crate) fn set_session_dek_hex(hex: &str) {
    if let Ok(mut slot) = SESSION_DEK_HEX.write() {
        *slot = Some(hex.to_string());
    }
}

/// The current session's DEK hex, or `None` before unlock.
pub(crate) fn session_dek_hex() -> Option<String> {
    SESSION_DEK_HEX.read().ok().and_then(|s| s.clone())
}

/// Zero the in-memory session DEK. Called by the idle-lock path (M4) so the
/// key no longer lives in process memory once the screen locks; re-unlock
/// (`auth_unlock_password`) re-derives and re-publishes it.
pub(crate) fn clear_session_dek() {
    if let Ok(mut slot) = SESSION_DEK_HEX.write() {
        *slot = None;
    }
}

/// Returns true if the `auth_password_hash` keychain item exists.
pub(crate) fn is_auth_configured() -> bool {
    keyring_entry()
        .and_then(|e| e.get_password().map_err(AppError::internal_from))
        .is_ok()
}


/// Set the master password for the first time (or after a full reset).
///
/// Validates the password, wraps `dek` under one password KEK and three
/// recovery KEKs, writes all four rows to `tahlk_auth.db` in a single
/// transaction, then stores the password hash in the OS keychain.
///
/// Returns three recovery codes — the caller MUST display them to the user.
/// They are NEVER stored by this module.
///
/// `dek` is the raw 32-byte DEK. Callers holding a hex DEK from
/// `db_key::load_or_generate_dek()` must decode it first with `from_hex`.
pub(crate) fn set_password(
    password: &str,
    dek: &[u8; DEK_BYTES],
    wraps_db_path: &Path,
) -> Result<[RecoveryCode; 3], AppError> {
    validate_password(password)?;

    // Derive password KEK.
    let mut pw_salt = [0u8; SALT_LEN];
    getrandom::getrandom(&mut pw_salt).map_err(AppError::internal_from)?;
    let pw_kek = derive_kek(password, &pw_salt)?;
    let pw_wrapped = wrap_dek(&pw_kek, dek)?;

    // Generate recovery codes and wrap DEK under each recovery KEK.
    let (rc1, seed1) = generate_recovery_code()?;
    let (rc2, seed2) = generate_recovery_code()?;
    let (rc3, seed3) = generate_recovery_code()?;
    let rw1 = wrap_dek(&derive_recovery_kek(&seed1)?, dek)?;
    let rw2 = wrap_dek(&derive_recovery_kek(&seed2)?, dek)?;
    let rw3 = wrap_dek(&derive_recovery_kek(&seed3)?, dek)?;

    // Write all four rows atomically.
    let mut conn = open_wraps_db(wraps_db_path)?;
    let now = utc_now_iso();
    {
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT OR REPLACE INTO auth_dek_wraps (wrap_type, salt_hex, ciphertext_hex, created_at) \
             VALUES ('password', ?1, ?2, ?3)",
            params![to_hex(&pw_salt), to_hex(&pw_wrapped), now],
        )?;
        for (wrap_type, wrapped) in [
            ("recovery_1", &rw1),
            ("recovery_2", &rw2),
            ("recovery_3", &rw3),
        ] {
            tx.execute(
                "INSERT OR REPLACE INTO auth_dek_wraps (wrap_type, salt_hex, ciphertext_hex, created_at) \
                 VALUES (?1, '', ?2, ?3)",
                params![wrap_type, to_hex(wrapped), now],
            )?;
        }
        tx.commit()?;
    }

    // Keychain write is last: if it fails, the wraps DB is already committed
    // and the caller can retry (set_password will overwrite via INSERT OR REPLACE).
    let hash_str = hash_password(password)?;
    keyring_entry()?.set_password(&hash_str).map_err(AppError::internal_from)?;

    Ok([rc1, rc2, rc3])
}

/// Verify `password` and return the unwrapped DEK from `tahlk_auth.db`.
/// Returns `InvalidInput` on wrong password, `Storage` if the wraps DB row is
/// missing or corrupt.
pub(crate) fn unlock_with_password(
    password: &str,
    wraps_db_path: &Path,
) -> Result<[u8; DEK_BYTES], AppError> {
    if !verify_password_hash(password)? {
        return Err(AppError::invalid("incorrect password"));
    }
    let conn = open_wraps_db(wraps_db_path)?;
    let row: Option<(String, String)> = conn
        .query_row(
            "SELECT salt_hex, ciphertext_hex FROM auth_dek_wraps WHERE wrap_type = 'password'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (salt_hex, ciph_hex) = row.ok_or_else(|| {
        AppError::Storage("no password wrap row found — auth DB may be corrupt".into())
    })?;
    let salt = from_hex(&salt_hex).ok_or_else(|| AppError::Storage("invalid salt hex".into()))?;
    let wrapped =
        from_hex(&ciph_hex).ok_or_else(|| AppError::Storage("invalid ciphertext hex".into()))?;
    let kek = derive_kek(password, &salt)?;
    unwrap_dek(&kek, &wrapped)
}

/// Try each recovery row in turn; return the DEK on the first that authenticates
/// with the provided code's derived KEK. Returns `InvalidInput` if no row
/// matches (wrong code, or all codes exhausted / replaced).
///
/// After a successful recovery unlock the caller should prompt for a new
/// password and call `change_password` so the lost password row is replaced.
pub(crate) fn unlock_with_recovery_code(
    code_input: &str,
    wraps_db_path: &Path,
) -> Result<[u8; DEK_BYTES], AppError> {
    let seed = parse_recovery_code(code_input)?;
    let kek = derive_recovery_kek(&seed)?;

    let conn = open_wraps_db(wraps_db_path)?;
    let mut stmt = conn.prepare(
        "SELECT ciphertext_hex FROM auth_dek_wraps \
         WHERE wrap_type IN ('recovery_1','recovery_2','recovery_3') ORDER BY id",
    )?;
    let rows: Vec<String> = stmt
        .query_map([], |r| r.get(0))?
        .filter_map(|r| r.ok())
        .collect();

    for hex in &rows {
        if let Some(wrapped) = from_hex(hex) {
            if let Ok(dek) = unwrap_dek(&kek, &wrapped) {
                return Ok(dek);
            }
        }
    }
    Err(AppError::invalid(
        "recovery code is incorrect or has already been replaced",
    ))
}

/// Change the master password.
///
/// Verifies the old password, re-wraps the DEK under the new password KEK, and
/// updates the keychain hash. Recovery code rows are left untouched.
pub(crate) fn change_password(
    old_password: &str,
    new_password: &str,
    wraps_db_path: &Path,
) -> Result<(), AppError> {
    // Verify + unwrap before any writes so we hold the DEK before mutating.
    let dek = unlock_with_password(old_password, wraps_db_path)?;
    validate_password(new_password)?;

    let mut new_salt = [0u8; SALT_LEN];
    getrandom::getrandom(&mut new_salt).map_err(AppError::internal_from)?;
    let new_kek = derive_kek(new_password, &new_salt)?;
    let new_wrapped = wrap_dek(&new_kek, &dek)?;

    let conn = open_wraps_db(wraps_db_path)?;
    conn.execute(
        "UPDATE auth_dek_wraps SET salt_hex = ?1, ciphertext_hex = ?2, created_at = ?3 \
         WHERE wrap_type = 'password'",
        params![to_hex(&new_salt), to_hex(&new_wrapped), utc_now_iso()],
    )?;

    let hash_str = hash_password(new_password)?;
    keyring_entry()?.set_password(&hash_str).map_err(AppError::internal_from)?;
    Ok(())
}

/// Regenerate all three recovery codes. Requires the current password to unwrap
/// the DEK for re-wrapping. Returns the three new codes — display them to the
/// provider. Old codes are atomically replaced.
pub(crate) fn generate_new_recovery_codes(
    current_password: &str,
    wraps_db_path: &Path,
) -> Result<[RecoveryCode; 3], AppError> {
    let dek = unlock_with_password(current_password, wraps_db_path)?;

    let (rc1, seed1) = generate_recovery_code()?;
    let (rc2, seed2) = generate_recovery_code()?;
    let (rc3, seed3) = generate_recovery_code()?;
    let rw1 = wrap_dek(&derive_recovery_kek(&seed1)?, &dek)?;
    let rw2 = wrap_dek(&derive_recovery_kek(&seed2)?, &dek)?;
    let rw3 = wrap_dek(&derive_recovery_kek(&seed3)?, &dek)?;

    let mut conn = open_wraps_db(wraps_db_path)?;
    let now = utc_now_iso();
    {
        let tx = conn.transaction()?;
        for (wrap_type, wrapped) in [
            ("recovery_1", &rw1),
            ("recovery_2", &rw2),
            ("recovery_3", &rw3),
        ] {
            tx.execute(
                "UPDATE auth_dek_wraps \
                 SET salt_hex = '', ciphertext_hex = ?1, created_at = ?2 \
                 WHERE wrap_type = ?3",
                params![to_hex(wrapped), now, wrap_type],
            )?;
        }
        tx.commit()?;
    }
    Ok([rc1, rc2, rc3])
}

// `migrate_from_plaintext_dek` lived here and was removed as dead code.
//
// It was never wired in: absent from the generate_handler! list and never
// called from lib.rs::setup. The legacy plaintext-DEK path needs no separate
// migration because `auth_set_password` already IS one — it calls
// load_or_generate_dek (picking up the existing keychain DEK), wraps that same
// value under the new password, and deletes the old entry. An upgrading user
// has a keychain DEK and no auth_password_hash, so is_auth_configured() is
// false, lib.rs opens the DB through the keychain path, and first-open setup
// performs the migration as a side effect of setting a password.
//
// Its only callers were its own tests, and its `wraps_db_has_password` helper
// existed solely to make one of those tests pass on a dev machine whose
// keychain already had a real entry. Keeping an unreachable branch that writes
// key material is worse than deleting it.

/// Permanent, irreversible reset: deletes the wraps DB, the password hash
/// keychain item, the DEK keychain item, and the main encrypted database.
/// The next launch treats the device as a fresh install.
///
/// This is the "forgot password, no recovery codes" nuclear option.
pub(crate) fn nuke_and_reinstall(
    wraps_db_path: &Path,
    main_db_path: &Path,
) -> Result<(), AppError> {
    if wraps_db_path.exists() {
        std::fs::remove_file(wraps_db_path).map_err(AppError::storage_from)?;
    }
    if let Ok(entry) = keyring_entry() {
        let _ = entry.delete_credential();
    }
    if let Ok(entry) = crate::keychain::entry(crate::db_key::KEYRING_USER) {
        let _ = entry.delete_credential();
    }
    if main_db_path.exists() {
        std::fs::remove_file(main_db_path).map_err(AppError::storage_from)?;
    }
    Ok(())
}

/// Forgot-password reset via a recovery code. Derives the DEK from `code`,
/// then re-wraps it under `new_password` and 3 fresh recovery codes.
/// All prior recovery rows are atomically replaced; the caller must surface
/// the returned codes to the provider (re-run Screen C in the JS flow).
pub(crate) fn reset_password_with_recovery_code(
    code: &str,
    new_password: &str,
    wraps_db_path: &Path,
) -> Result<[RecoveryCode; 3], AppError> {
    let dek = unlock_with_recovery_code(code, wraps_db_path)?;
    // set_password uses INSERT OR REPLACE, so this atomically overwrites all
    // 4 rows (password + 3 recovery) and updates auth_password_hash.
    set_password(new_password, &dek, wraps_db_path)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tauri commands
// ─────────────────────────────────────────────────────────────────────────────

/// Returns true only when auth has been configured (password set on this device).
/// When false, the JS startup flow runs the first-open setup instead.
#[tauri::command]
pub(crate) fn auth_is_configured() -> bool {
    is_auth_configured()
}

/// First-open or post-nuke setup: sets the master password and returns the
/// three recovery codes (display strings) for the provider to store securely.
/// Deletes the keychain DEK entry so that `db.rs::open_database` (which reads
/// from the keychain) can no longer bypass the auth gate — the auth DEK in
/// `tahlk_auth.db` becomes the only route to the database key.
#[tauri::command]
pub(crate) fn auth_set_password(app: AppHandle, password: String) -> Result<Vec<String>, AppError> {
    let r = (|| -> Result<Vec<String>, AppError> {
        let dek_hex = crate::db_key::load_or_generate_dek()?;
        let dek_vec =
            from_hex(&dek_hex).ok_or_else(|| AppError::internal_from("DEK hex malformed"))?;
        let mut dek = [0u8; DEK_BYTES];
        dek.copy_from_slice(&dek_vec);
        let path = wraps_db_path(&app)?;
        let codes = set_password(&password, &dek, &path)?;

        // Publish the DEK for this session BEFORE the keychain entry is deleted
        // below. Without this, audio_crypto::audio_key() would look for a keychain
        // entry that no longer exists and db_key would mint a fresh random DEK —
        // silently orphaning every previously-encrypted .wav.enc on this device.
        crate::auth::set_session_dek_hex(&dek_hex);

        // Remove the keychain DEK so subsequent launches must go through the auth
        // path. Best-effort: a delete failure leaves the keychain as a fallback
        // but is logged; the wrapped copy is what guards forward security.
        if let Ok(entry) = crate::keychain::entry(crate::db_key::KEYRING_USER) {
            if let Err(e) = entry.delete_credential() {
                log::warn!("auth_set_password: could not remove keychain DEK: {e}");
            }
        }

        Ok(codes.iter().map(|c| c.display()).collect())
    })();
    record_auth_event(&app, "password_set", outcome_str(&r));
    r
}

/// Startup (and idle-lock re-)unlock via master password. Verifies the
/// password, unwraps the DEK, opens `tahlk.db` with that key, runs post-open
/// migrations, and installs the pool into the managed `DbState`. After this
/// command returns `Ok`, all DB-backed commands become available for the
/// session. This is also the path the idle-lock overlay drives to re-open the
/// DB after `auth_lock_session` dropped the pool and zeroed the DEK.
#[tauri::command]
pub(crate) fn auth_unlock_password(
    app: AppHandle,
    state: State<DbState>,
    password: String,
) -> Result<(), AppError> {
    let path = wraps_db_path(&app)?;
    crate::throttle::check(THROTTLE_UNLOCK).inspect_err(|_| {
        record_auth_event(&app, "unlock_password", "throttled");
    })?;
    let dek = unlock_with_password(&password, &path).inspect_err(|_| {
        crate::throttle::record_failure(THROTTLE_UNLOCK);
        record_auth_event(&app, "unlock_password", "failure");
    })?;
    crate::throttle::record_success(THROTTLE_UNLOCK);
    let hex_key = to_hex(&dek);
    // Publish before the audio migration below, which calls audio_key().
    set_session_dek_hex(&hex_key);

    let pool = crate::db::open_database_with_dek(&app, &hex_key).inspect_err(|e| {
        log::error!(
            "auth_unlock_password: failed to open database: {}",
            crate::log_safety::cap_len(&e.to_string())
        );
    })?;

    // Audio at-rest migration — same best-effort logic as lib.rs::setup().
    if let Err(e) = (|| -> Result<usize, AppError> {
        let conn = pool.get()?;
        let audio_dir = app
            .path()
            .app_data_dir()
            .map_err(AppError::internal_from)?
            .join("audio");
        let key = crate::audio_crypto::audio_key()?;
        let n = crate::audio_crypto::migrate_plaintext_audio_at_rest(&conn, &audio_dir, &key)?;
        // Same reconciliation as the pre-auth path in lib.rs::setup: find PHI
        // audio whose encounter row is gone and either finish the disposal or
        // record that it could not be finished.
        let provider = crate::kv_ops::provider_id(&conn);
        let orphans = crate::audio::reconcile_orphaned_audio(&conn, &audio_dir, &provider)?;
        if orphans > 0 {
            log::warn!("reconciled {orphans} orphaned audio file(s) after prior destruction");
        }
        Ok(n)
    })() {
        log::error!(
            "audio at-rest migration skipped post-auth: {}",
            crate::log_safety::cap_len(&e.to_string())
        );
    }

    state.set_pool(pool);
    record_auth_event(&app, "unlock_password", "success");
    Ok(())
}

/// Idle-lock trigger (M4). Drops the DB connection pool and zeroes the
/// in-memory session DEK so that, once the screen locks, no live pool and no
/// key remain in the process to reach PHI. The provider must re-enter their
/// password (via `auth_unlock_password`) to re-derive the DEK and reopen the
/// DB — the JS overlay drives exactly that flow. Ordered pool-first so a
/// caller mid-checkout can't grab a connection after the DEK is gone.
#[tauri::command]
pub(crate) fn auth_lock_session(app: AppHandle, state: State<DbState>) {
    state.lock_session();
    clear_session_dek();
    // Auto-logoff is a §164.312(a)(2)(iii) safeguard activation — record it so
    // the audit trail shows the session was actually locked, not just that the
    // control is configured.
    record_auth_event(&app, "session_locked", "success");
}

/// Unlock via a recovery code (forgot-password flow). Returns nothing to JS;
/// the provider must immediately be prompted for a new password via
/// `auth_change_password`.
#[tauri::command]
pub(crate) fn auth_unlock_recovery(app: AppHandle, code: String) -> Result<(), AppError> {
    let path = wraps_db_path(&app)?;
    crate::throttle::check(THROTTLE_UNLOCK).inspect_err(|_| {
        record_auth_event(&app, "unlock_recovery", "throttled");
    })?;
    let dek = unlock_with_recovery_code(&code, &path).inspect_err(|_| {
        crate::throttle::record_failure(THROTTLE_UNLOCK);
        record_auth_event(&app, "unlock_recovery", "failure");
    })?;
    crate::throttle::record_success(THROTTLE_UNLOCK);
    set_session_dek_hex(&to_hex(&dek));
    record_auth_event(&app, "unlock_recovery", "success");
    Ok(())
}

/// Change the master password. Requires the current (old) password to unwrap
/// the DEK before re-wrapping under the new password.
#[tauri::command]
pub(crate) fn auth_change_password(
    app: AppHandle,
    old_password: String,
    new_password: String,
) -> Result<(), AppError> {
    let path = wraps_db_path(&app)?;
    let r = change_password(&old_password, &new_password, &path);
    record_auth_event(&app, "password_changed", outcome_str(&r));
    r
}

/// Forgot-password reset via a recovery code. Wraps the DEK under a new
/// password; returns three new recovery code display strings. Old codes
/// (including the two unused ones) are permanently replaced.
#[tauri::command]
pub(crate) fn auth_reset_with_recovery_code(
    app: AppHandle,
    code: String,
    new_password: String,
) -> Result<Vec<String>, AppError> {
    let path = wraps_db_path(&app)?;
    let r = reset_password_with_recovery_code(&code, &new_password, &path);
    record_auth_event(&app, "password_reset_recovery", outcome_str(&r));
    let codes = r?;
    Ok(codes.iter().map(|c| c.display()).collect())
}

/// Regenerate all three recovery codes. Requires the current password.
/// Returns the new display strings — old codes are immediately invalidated.
#[tauri::command]
pub(crate) fn auth_generate_recovery_codes(
    app: AppHandle,
    password: String,
) -> Result<Vec<String>, AppError> {
    let path = wraps_db_path(&app)?;
    let r = generate_new_recovery_codes(&password, &path);
    record_auth_event(&app, "recovery_codes_regenerated", outcome_str(&r));
    let codes = r?;
    Ok(codes.iter().map(|c| c.display()).collect())
}

/// Permanently wipe all auth data and the main encrypted database. Irreversible.
/// For the "forgot password AND no recovery codes" scenario only.
///
/// Requires `credential` to be either the current master password or a valid
/// recovery code (audit finding C4).
///
/// If the provider has forgotten both their password and all recovery codes,
/// they cannot use this in-app path. They must manually delete the app data
/// directory from the operating system's file manager.
#[tauri::command]
pub(crate) fn auth_nuke_and_reinstall(app: AppHandle, credential: String) -> Result<(), AppError> {
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| AppError::internal_from(format!("could not resolve app_data_dir: {e}")))?;
    let wraps = data_dir.join("tahlk_auth.db");
    let main_db = data_dir.join("tahlk.db");

    match nuke_authorization(
        wraps.exists(),
        main_db.exists(),
        crate::db_key::dek_entry_exists(),
    ) {
        // Verify before destroying anything. Password first (common case),
        // then recovery code. Both perform AES-GCM decryption against the
        // wraps DB — if both fail, reject.
        NukeAuthorization::VerifyCredential => {
            // Throttled on its own scope: unlimited guesses against an
            // irreversible destruction of every record on the device is the
            // sharpest brute-force target in the app, and it must not share a
            // counter with the ordinary unlock screen (locking one should not
            // lock the other).
            crate::throttle::check(THROTTLE_NUKE).inspect_err(|_| {
                record_auth_event(&app, "nuke_reinstall", "throttled");
            })?;
            let pass_ok = unlock_with_password(&credential, &wraps).is_ok();
            let code_ok = !pass_ok && unlock_with_recovery_code(&credential, &wraps).is_ok();
            if !pass_ok && !code_ok {
                crate::throttle::record_failure(THROTTLE_NUKE);
                // A wrong-credential wipe attempt is exactly the attack signal
                // this log exists to preserve — record it before returning.
                // (A *successful* nuke is intentionally not recorded: it deletes
                // this very wraps DB, so only the failed/refused attempts persist.)
                record_auth_event(&app, "nuke_reinstall", "failure");
                return Err(AppError::precondition(
                    "That is not your current password or a valid recovery code. \
                     Confirm with one of them to erase this device.",
                ));
            }
            crate::throttle::record_success(THROTTLE_NUKE);
        }
        NukeAuthorization::Refuse => {
            record_auth_event(&app, "nuke_reinstall", "refused");
            return Err(AppError::invalid(
                "this device holds patient data that predates password setup, so there is no \
                 credential to verify against — Tahlk will not destroy it from inside the app. \
                 Remove the application data folder using your operating system's file manager \
                 if you intend to erase it.",
            ));
        }
        NukeAuthorization::AllowUnauthenticated => {}
    }

    nuke_and_reinstall(&wraps, &main_db)
}

/// What the nuke command is permitted to do, given what exists on disk.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NukeAuthorization {
    /// Auth is configured — the caller must prove they hold the credential.
    VerifyCredential,
    /// Protected data exists but there is no credential to check it against.
    Refuse,
    /// Genuinely nothing to destroy; let a fresh install reset itself.
    AllowUnauthenticated,
}

/// Decide whether an unauthenticated nuke may proceed.
///
/// The original guard skipped verification whenever the wraps DB was absent,
/// on the premise that "no wraps DB" means "nothing protected yet". That
/// premise is false, and falsely in the worst direction:
///
///   * Tahlk 0.1.1 shipped before ADR-0004 introduced auth. Every install
///     predating it has a fully populated, PHI-bearing `tahlk.db` and no
///     `tahlk_auth.db` at all — so the entire pre-upgrade installed base could
///     be wiped by `auth_nuke_and_reinstall("")` from a compromised WebView,
///     which is exactly the scenario C4's credential check was added to close.
///   * The same holds for any install where the user has not yet finished
///     first-open setup but the legacy keychain-DEK path has already opened a
///     database.
///
/// So absence of the wraps DB is not evidence of absence of data. The main DB
/// and the keychain DEK are both checked, and either one present means refuse
/// rather than bypass. Pure function so the policy is testable without a Tauri
/// harness or a real filesystem.
pub(crate) fn nuke_authorization(
    wraps_exists: bool,
    main_db_exists: bool,
    keychain_dek_exists: bool,
) -> NukeAuthorization {
    if wraps_exists {
        return NukeAuthorization::VerifyCredential;
    }
    if main_db_exists || keychain_dek_exists {
        return NukeAuthorization::Refuse;
    }
    NukeAuthorization::AllowUnauthenticated
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_dek() -> [u8; DEK_BYTES] {
        [0x42u8; DEK_BYTES]
    }

    fn temp_wraps() -> (TempDir, std::path::PathBuf) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("tahlk_auth.db");
        (dir, path)
    }

    // ── Crockford encode / decode ────────────────────────────────────────────

    #[test]
    fn crockford_encode_decode_roundtrip() {
        let data: [u8; CODE_DATA_LEN] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66,
        ];
        let encoded = crockford_encode(&data);
        let decoded = crockford_decode(&encoded).expect("decode must succeed");
        assert_eq!(data, decoded);
    }

    #[test]
    fn crockford_encode_all_zeros_roundtrip() {
        let data = [0u8; CODE_DATA_LEN];
        let encoded = crockford_encode(&data);
        assert_eq!(crockford_decode(&encoded).unwrap(), data);
    }

    #[test]
    fn crockford_encode_all_ff_roundtrip() {
        let data = [0xffu8; CODE_DATA_LEN];
        let encoded = crockford_encode(&data);
        assert_eq!(crockford_decode(&encoded).unwrap(), data);
    }

    #[test]
    fn crockford_encode_produces_only_alphabet_chars() {
        let data = [0xffu8; CODE_DATA_LEN];
        let encoded = crockford_encode(&data);
        for &c in &encoded {
            assert!(
                CROCKFORD.contains(&c),
                "unexpected char: 0x{:02x} ({})",
                c,
                c as char
            );
        }
    }

    #[test]
    fn crockford_decode_accepts_lowercase() {
        let data = [0xabu8; CODE_DATA_LEN];
        let encoded_upper = crockford_encode(&data);
        let lower: Vec<u8> = encoded_upper.iter().map(|&c| c.to_ascii_lowercase()).collect();
        let lower_arr: [u8; CODE_CHARS] = lower.try_into().unwrap();
        assert_eq!(crockford_decode(&lower_arr).unwrap(), data);
    }

    #[test]
    fn crockford_decode_accepts_letter_o_as_zero() {
        // All-zeros data encodes to all '0' chars; substituting 'O' must decode identically.
        let data = [0u8; CODE_DATA_LEN];
        let mut encoded = crockford_encode(&data);
        encoded[0] = b'O';
        let decoded = crockford_decode(&encoded).expect("O should decode as 0");
        assert_eq!(decoded, data);
    }

    #[test]
    fn crockford_decode_rejects_invalid_char() {
        let mut chars = crockford_encode(&[0u8; CODE_DATA_LEN]);
        chars[3] = b'!';
        assert!(crockford_decode(&chars).is_none());
    }

    #[test]
    fn crockford_checksum_is_deterministic() {
        let data = [0xabu8; CODE_DATA_LEN];
        assert_eq!(crockford_checksum(&data), crockford_checksum(&data));
    }

    #[test]
    fn crockford_checksum_differs_for_different_data() {
        // All-zeros gives remainder 0 → '0'; all-0xff cycles through the field
        // and won't be 0 (verified by inspection — see comment in crockford_checksum).
        let z = crockford_checksum(&[0u8; CODE_DATA_LEN]);
        let f = crockford_checksum(&[0xffu8; CODE_DATA_LEN]);
        assert_ne!(z, f, "checksums for distinct inputs should differ");
    }

    #[test]
    fn crockford_check_chars_are_in_extended_set() {
        for &c in CROCKFORD_CHECK {
            // Every check symbol is printable ASCII.
            assert!(c.is_ascii() && !c.is_ascii_control());
        }
    }

    // ── Recovery code generation / parsing ───────────────────────────────────

    #[test]
    fn recovery_code_raw_length_is_25() {
        let (code, _) = generate_recovery_code().unwrap();
        assert_eq!(code.as_str().len(), 25);
    }

    #[test]
    fn recovery_code_data_chars_are_crockford_and_check_is_extended() {
        let (code, _) = generate_recovery_code().unwrap();
        let s = code.as_str();
        for &c in &s.as_bytes()[..CODE_CHARS] {
            assert!(CROCKFORD.contains(&c));
        }
        assert!(CROCKFORD_CHECK.contains(&s.as_bytes()[CODE_CHARS]));
    }

    #[test]
    fn parse_recovery_code_round_trips_raw() {
        let (code, seed) = generate_recovery_code().unwrap();
        let parsed = parse_recovery_code(code.as_str()).unwrap();
        assert_eq!(parsed, seed);
    }

    #[test]
    fn parse_recovery_code_round_trips_display_with_dashes() {
        let (code, seed) = generate_recovery_code().unwrap();
        let display = code.display(); // "XXXXXX-XXXXXX-XXXXXX-XXXXXX-X"
        let parsed = parse_recovery_code(&display).unwrap();
        assert_eq!(parsed, seed);
    }

    #[test]
    fn parse_recovery_code_accepts_lowercase_with_dashes() {
        let (code, seed) = generate_recovery_code().unwrap();
        let lower_dashes = code.display().to_ascii_lowercase();
        let parsed = parse_recovery_code(&lower_dashes).unwrap();
        assert_eq!(parsed, seed);
    }

    #[test]
    fn parse_recovery_code_rejects_wrong_checksum() {
        let (code, _) = generate_recovery_code().unwrap();
        let mut s = code.as_str().to_string();
        let last = s.pop().unwrap();
        // Replace checksum with a different character from the extended set.
        let replacement = if last == '0' { '1' } else { '0' };
        s.push(replacement);
        let err = parse_recovery_code(&s).unwrap_err();
        assert!(matches!(err, AppError::InvalidInput(_)));
    }

    #[test]
    fn parse_recovery_code_rejects_wrong_length() {
        assert!(parse_recovery_code("TOOSHORT").is_err());
        assert!(parse_recovery_code(&"A".repeat(26)).is_err());
    }

    #[test]
    fn parse_recovery_code_rejects_invalid_chars() {
        // 25 chars but with '!' which is not in the Crockford alphabet.
        let s = format!("{}!", "A".repeat(24));
        assert!(parse_recovery_code(&s).is_err());
    }

    #[test]
    fn two_generated_codes_have_distinct_seeds() {
        let (_, s1) = generate_recovery_code().unwrap();
        let (_, s2) = generate_recovery_code().unwrap();
        assert_ne!(s1, s2, "random seeds must differ across calls");
    }

    // ── Password validation ──────────────────────────────────────────────────

    #[test]
    fn validate_password_rejects_too_short() {
        assert!(validate_password("short9!").is_err());
        assert!(validate_password(&"a".repeat(PASSWORD_MIN_LEN - 1)).is_err());
    }

    #[test]
    fn validate_password_accepts_min_length_strong() {
        // 12-char password that isn't in the common list.
        assert!(validate_password("Tr0ub4dor&3!").is_ok());
    }

    #[test]
    fn validate_password_rejects_too_long() {
        assert!(validate_password(&"Aa1!".repeat(33)).is_err()); // 132 chars
    }

    #[test]
    fn validate_password_rejects_common_passwords() {
        // "unbelievable" is exactly 12 chars and is in the vendored 10k list.
        assert!(validate_password("unbelievable").is_err());
        // Case-insensitive: "UNBELIEVABLE" must also be rejected.
        assert!(validate_password("UNBELIEVABLE").is_err());
    }

    #[test]
    fn common_passwords_list_is_loaded_and_non_empty() {
        assert!(!COMMON_PASSWORDS.is_empty());
        assert!(
            COMMON_PASSWORDS.lines().count() >= 1000,
            "common passwords list seems truncated"
        );
    }

    // ── PBKDF2 parameter parity ──────────────────────────────────────────────

    #[test]
    fn pbkdf2_parameters_match_lock_rs_constants() {
        // Pin these so a drift in lock.rs or auth.rs surfaces as a test failure.
        // Both modules must use 210,000 iterations (OWASP minimum for PBKDF2-HMAC-SHA256).
        assert_eq!(PBKDF2_ITERATIONS, 210_000);
        assert_eq!(SALT_LEN, 16);
        assert_eq!(HASH_LEN, 32);
    }

    // ── KEK derivation ───────────────────────────────────────────────────────

    #[test]
    fn derive_kek_is_deterministic() {
        let salt = [0x11u8; SALT_LEN];
        let k1 = derive_kek("test-password-here!!", &salt).unwrap();
        let k2 = derive_kek("test-password-here!!", &salt).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn derive_kek_differs_on_different_salt() {
        let k1 = derive_kek("same-password!!!!!", &[0x01u8; SALT_LEN]).unwrap();
        let k2 = derive_kek("same-password!!!!!", &[0x02u8; SALT_LEN]).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn derive_kek_differs_on_different_password() {
        let salt = [0u8; SALT_LEN];
        let k1 = derive_kek("password-alpha-one!!", &salt).unwrap();
        let k2 = derive_kek("password-alpha-two!!", &salt).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn derive_recovery_kek_is_deterministic() {
        let seed = [0x77u8; CODE_DATA_LEN];
        let k1 = derive_recovery_kek(&seed).unwrap();
        let k2 = derive_recovery_kek(&seed).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn derive_recovery_kek_differs_from_password_kek_on_same_bytes() {
        // Even if someone used 15 identical bytes as both a password and a seed,
        // the domain separation labels make the KEKs distinct.
        let salt = [0x77u8; SALT_LEN];
        let pw_kek = derive_kek("same-data-here-kek!!", &salt).unwrap();
        let seed = [0x77u8; CODE_DATA_LEN];
        let rc_kek = derive_recovery_kek(&seed).unwrap();
        assert_ne!(pw_kek, rc_kek);
    }

    // ── DEK wrap / unwrap ────────────────────────────────────────────────────

    #[test]
    fn wrap_unwrap_roundtrip() {
        let kek = [0x42u8; HASH_LEN];
        let dek = test_dek();
        let wrapped = wrap_dek(&kek, &dek).unwrap();
        // nonce(12) + plaintext(32) + tag(16) = 60 bytes.
        assert_eq!(wrapped.len(), NONCE_LEN + DEK_BYTES + AES_256_GCM.tag_len());
        assert_eq!(unwrap_dek(&kek, &wrapped).unwrap(), dek);
    }

    #[test]
    fn wrap_produces_different_blobs_for_same_input() {
        let kek = [0x42u8; HASH_LEN];
        let w1 = wrap_dek(&kek, &test_dek()).unwrap();
        let w2 = wrap_dek(&kek, &test_dek()).unwrap();
        assert_ne!(w1[..NONCE_LEN], w2[..NONCE_LEN], "nonces must differ");
        assert_ne!(w1, w2);
    }

    #[test]
    fn unwrap_rejects_wrong_key() {
        let kek = [0x42u8; HASH_LEN];
        let wrong = [0x43u8; HASH_LEN];
        let wrapped = wrap_dek(&kek, &test_dek()).unwrap();
        assert!(unwrap_dek(&wrong, &wrapped).is_err());
    }

    #[test]
    fn unwrap_rejects_tampered_ciphertext() {
        let kek = [0x42u8; HASH_LEN];
        let mut wrapped = wrap_dek(&kek, &test_dek()).unwrap();
        let last = wrapped.len() - 1;
        wrapped[last] ^= 0x01;
        assert!(unwrap_dek(&kek, &wrapped).is_err());
    }

    #[test]
    fn unwrap_rejects_tampered_nonce() {
        let kek = [0x42u8; HASH_LEN];
        let mut wrapped = wrap_dek(&kek, &test_dek()).unwrap();
        wrapped[0] ^= 0xff;
        assert!(unwrap_dek(&kek, &wrapped).is_err());
    }

    #[test]
    fn unwrap_rejects_too_short_blob() {
        let kek = [0x42u8; HASH_LEN];
        assert!(unwrap_dek(&kek, &[0u8; 4]).is_err());
        assert!(unwrap_dek(&kek, &[]).is_err());
    }

    // ── set_password + unlock ────────────────────────────────────────────────

    #[test]
    fn set_password_writes_exactly_four_rows() {
        let (_dir, path) = temp_wraps();
        set_password("Correct-Horse-Battery97!", &test_dek(), &path).unwrap();
        let conn = open_wraps_db(&path).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM auth_dek_wraps", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 4);
    }

    #[test]
    fn set_password_returns_three_distinct_codes() {
        let (_dir, path) = temp_wraps();
        let codes = set_password("Correct-Horse-Battery97!", &test_dek(), &path).unwrap();
        assert_eq!(codes.len(), 3);
        for code in &codes {
            assert_eq!(code.as_str().len(), 25);
        }
        assert_ne!(codes[0].as_str(), codes[1].as_str());
        assert_ne!(codes[1].as_str(), codes[2].as_str());
        assert_ne!(codes[0].as_str(), codes[2].as_str());
    }

    #[test]
    fn set_password_rejects_weak_password() {
        let (_dir, path) = temp_wraps();
        assert!(set_password("short", &test_dek(), &path).is_err());
    }

    #[test]
    fn recovery_codes_each_unwrap_the_dek() {
        let (_dir, path) = temp_wraps();
        let dek = test_dek();
        let codes = set_password("Correct-Horse-Battery97!", &dek, &path).unwrap();
        for code in &codes {
            let seed = parse_recovery_code(code.as_str()).unwrap();
            let kek = derive_recovery_kek(&seed).unwrap();
            let conn = open_wraps_db(&path).unwrap();
            // Try all three recovery rows.
            let mut found = false;
            for row_type in ["recovery_1", "recovery_2", "recovery_3"] {
                let hex: Option<String> = conn
                    .query_row(
                        "SELECT ciphertext_hex FROM auth_dek_wraps WHERE wrap_type = ?1",
                        params![row_type],
                        |r| r.get(0),
                    )
                    .optional()
                    .unwrap();
                if let Some(h) = hex {
                    if let Some(wrapped) = from_hex(&h) {
                        if let Ok(recovered) = unwrap_dek(&kek, &wrapped) {
                            assert_eq!(recovered, dek);
                            found = true;
                            break;
                        }
                    }
                }
            }
            assert!(found, "code {} should match one recovery row", code.as_str());
        }
    }

    #[test]
    fn unlock_with_wrong_kek_fails() {
        let (_dir, path) = temp_wraps();
        set_password("Correct-Horse-Battery97!", &test_dek(), &path).unwrap();
        let wrong_kek = [0x99u8; HASH_LEN];
        let conn = open_wraps_db(&path).unwrap();
        let (salt_hex, ciph_hex): (String, String) = conn
            .query_row(
                "SELECT salt_hex, ciphertext_hex FROM auth_dek_wraps WHERE wrap_type = 'password'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        // Sanity-check the row is there, then confirm wrong KEK fails.
        assert!(!salt_hex.is_empty());
        let wrapped = from_hex(&ciph_hex).unwrap();
        assert!(unwrap_dek(&wrong_kek, &wrapped).is_err());
    }

    #[test]
    fn unlock_with_bogus_recovery_code_fails() {
        let (_dir, path) = temp_wraps();
        set_password("Correct-Horse-Battery97!", &test_dek(), &path).unwrap();
        let (bogus_code, _) = generate_recovery_code().unwrap();
        assert!(unlock_with_recovery_code(bogus_code.as_str(), &path).is_err());
    }

    // ── Migration ────────────────────────────────────────────────────────────

    // ── Nuke authorization (H-13) ───────────────────────────────────────

    #[test]
    fn a_configured_install_must_prove_the_credential() {
        assert_eq!(
            nuke_authorization(true, true, false),
            NukeAuthorization::VerifyCredential
        );
        // Even with no main DB — the wraps DB alone means auth is configured.
        assert_eq!(
            nuke_authorization(true, false, false),
            NukeAuthorization::VerifyCredential
        );
    }

    #[test]
    fn a_pre_auth_install_holding_patient_data_is_refused_not_bypassed() {
        // The regression. Tahlk 0.1.1 shipped before auth existed, so every
        // install predating it has a PHI-bearing tahlk.db and NO wraps DB.
        // The old guard read that as "nothing protected" and destroyed it
        // without any credential.
        assert_eq!(
            nuke_authorization(false, true, false),
            NukeAuthorization::Refuse,
            "a database with no credential to check against must not be destroyable in-app"
        );
        // Same conclusion from the keychain DEK alone: the main DB may have
        // been moved or renamed, but a DEK means a database existed.
        assert_eq!(
            nuke_authorization(false, false, true),
            NukeAuthorization::Refuse
        );
        assert_eq!(
            nuke_authorization(false, true, true),
            NukeAuthorization::Refuse
        );
    }

    #[test]
    fn a_genuinely_empty_device_may_reset_itself() {
        // The only case the unauthenticated path is for: nothing exists, so
        // there is nothing to protect and a fresh install can clear itself.
        assert_eq!(
            nuke_authorization(false, false, false),
            NukeAuthorization::AllowUnauthenticated
        );
    }

    // The three migrate_from_plaintext_dek tests were removed with the
    // function itself — see the note where it was defined. The behaviour they
    // covered (an existing keychain DEK being wrapped under a new password,
    // and the codes then unwrapping it) is exercised through the real path by
    // `recovery_codes_each_unwrap_the_dek` and `set_password_writes_exactly_
    // four_rows`, which drive `set_password` directly.

    // ── Change password (wrapped-layer) ─────────────────────────────────────

    #[test]
    fn re_wrapping_dek_with_new_kek_succeeds() {
        // change_password verifies the stored hash via keychain, which is not
        // available in unit tests. Test the wrapped-layer logic directly:
        // wrap, unwrap with old KEK, re-wrap with new KEK, confirm new KEK opens.
        let dek = test_dek();
        let old_salt = [0x01u8; SALT_LEN];
        let old_kek = derive_kek("OldP4ssword-Alpha!!", &old_salt).unwrap();
        let old_wrapped = wrap_dek(&old_kek, &dek).unwrap();
        let recovered = unwrap_dek(&old_kek, &old_wrapped).unwrap();
        assert_eq!(recovered, dek);

        let new_salt = [0x02u8; SALT_LEN];
        let new_kek = derive_kek("NewP4ssword-Beta!!!", &new_salt).unwrap();
        let new_wrapped = wrap_dek(&new_kek, &recovered).unwrap();
        assert_eq!(unwrap_dek(&new_kek, &new_wrapped).unwrap(), dek);
        // Old KEK must no longer open the new blob.
        assert!(unwrap_dek(&old_kek, &new_wrapped).is_err());
    }

    // ── Nuke ─────────────────────────────────────────────────────────────────

    #[test]
    fn nuke_removes_wraps_db_and_main_db() {
        let dir = TempDir::new().unwrap();
        let wraps_path = dir.path().join("tahlk_auth.db");
        let main_path = dir.path().join("tahlk.db");
        std::fs::write(&wraps_path, b"stub").unwrap();
        std::fs::write(&main_path, b"stub").unwrap();
        nuke_and_reinstall(&wraps_path, &main_path).unwrap();
        assert!(!wraps_path.exists(), "wraps DB must be deleted");
        assert!(!main_path.exists(), "main DB must be deleted");
    }

    // ── Session DEK lifecycle (M4 idle-lock) ─────────────────────────────────

    #[test]
    fn clear_session_dek_removes_the_in_memory_key() {
        // Serialized implicitly: this is the only test touching SESSION_DEK_HEX.
        set_session_dek_hex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        assert!(session_dek_hex().is_some(), "DEK must be present after publish");
        clear_session_dek();
        assert!(
            session_dek_hex().is_none(),
            "idle lock must zero the in-memory session DEK so it cannot be read until re-unlock"
        );
    }

    #[test]
    fn nuke_is_idempotent_on_missing_files() {
        let dir = TempDir::new().unwrap();
        // Neither file exists — nuke should succeed silently.
        let wraps_path = dir.path().join("tahlk_auth.db");
        let main_path = dir.path().join("tahlk.db");
        assert!(nuke_and_reinstall(&wraps_path, &main_path).is_ok());
    }

    // ── Authentication-event audit trail (H1, §164.312(b)) ───────────────────

    // Read the audit rows the same way `auth_audit_list` does, but against a
    // bare Connection (the #[tauri::command] needs an AppHandle we don't have
    // in a unit test). Newest-first, mirroring the command's ORDER BY id DESC.
    fn list_events(conn: &Connection) -> Vec<(String, String)> {
        let mut stmt = conn
            .prepare("SELECT event, outcome FROM auth_audit ORDER BY id DESC")
            .unwrap();
        stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    #[test]
    fn open_wraps_db_creates_the_auth_audit_table() {
        // The audit table must be created by the same schema init every wraps-DB
        // open runs, so existing installs get it on their next unlock.
        let (_dir, path) = temp_wraps();
        let conn = open_wraps_db(&path).unwrap();
        // A bare count query only succeeds if the table exists.
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM auth_audit", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "a fresh wraps DB has an empty audit trail");
    }

    #[test]
    fn append_auth_event_records_event_and_outcome() {
        let (_dir, path) = temp_wraps();
        let conn = open_wraps_db(&path).unwrap();
        append_auth_event(&conn, "unlock_password", "failure").unwrap();
        let rows = list_events(&conn);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0], ("unlock_password".to_string(), "failure".to_string()));
    }

    #[test]
    fn auth_audit_rows_are_metadata_only_timestamped() {
        // No PHI, no credential — just a UTC timestamp, event, outcome.
        let (_dir, path) = temp_wraps();
        let conn = open_wraps_db(&path).unwrap();
        append_auth_event(&conn, "pin_verify", "success").unwrap();
        let created_at: String = conn
            .query_row("SELECT created_at FROM auth_audit LIMIT 1", [], |r| r.get(0))
            .unwrap();
        assert!(created_at.ends_with('Z'), "timestamp must be UTC ISO-8601: {created_at}");
    }

    #[test]
    fn auth_audit_lists_newest_first() {
        let (_dir, path) = temp_wraps();
        let conn = open_wraps_db(&path).unwrap();
        append_auth_event(&conn, "password_set", "success").unwrap();
        append_auth_event(&conn, "unlock_password", "failure").unwrap();
        append_auth_event(&conn, "unlock_password", "success").unwrap();
        let rows = list_events(&conn);
        // ORDER BY id DESC → most recent first.
        let events: Vec<&str> = rows.iter().map(|(e, _)| e.as_str()).collect();
        assert_eq!(events, vec!["unlock_password", "unlock_password", "password_set"]);
        assert_eq!(rows[0].1, "success");
        assert_eq!(rows[1].1, "failure");
    }

    #[test]
    fn every_wired_event_and_outcome_is_on_its_allowlist() {
        // Guards against a call site passing a string that isn't in the
        // allowlist (which would debug_assert-panic in tests / slip an
        // unvalidated value into the record in release). These are the exact
        // pairs the auth.rs / lock.rs command sites emit.
        for (event, outcome) in [
            ("password_set", "success"),
            ("unlock_password", "throttled"),
            ("unlock_password", "failure"),
            ("unlock_password", "success"),
            ("unlock_recovery", "success"),
            ("password_changed", "failure"),
            ("password_reset_recovery", "success"),
            ("recovery_codes_regenerated", "success"),
            ("pin_verify", "failure"),
            ("session_locked", "success"),
            ("nuke_reinstall", "refused"),
        ] {
            assert!(AUTH_AUDIT_EVENTS.contains(&event), "event off allowlist: {event}");
            assert!(AUTH_AUDIT_OUTCOMES.contains(&outcome), "outcome off allowlist: {outcome}");
        }
    }
}
