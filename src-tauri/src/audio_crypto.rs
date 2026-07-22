//! At-rest encryption for session audio (.wav) files.
//!
//! HIPAA §164.312(a)(2)(iv) requires PHI to be encrypted at rest. The DB is
//! already SQLCipher-encrypted (see `db.rs`), but raw session audio was
//! landing on disk as plaintext `.wav` — this module closes that gap.
//!
//! ## Key derivation
//!
//! We do NOT reuse the SQLCipher DEK directly. Instead we HKDF-SHA256 a
//! *separate* 256-bit audio key from the DEK, with a fixed, domain-separating
//! `info` string (`HKDF_INFO`) that is distinct from any DB usage. The DEK is
//! never passed to `PRAGMA key` and to AES-GCM under the same bytes, so a
//! weakness or compromise confined to one usage does not hand an attacker the
//! other. The DEK stays the single root of trust in the OS keychain; this is
//! pure key separation, no new secret to store.
//!
//! ## File format
//!
//! Each encrypted file is:
//!
//! ```text
//! ┌───────────────┬────────────────────────────────────┐
//! │ nonce (12 B)  │ ciphertext ‖ GCM auth tag (16 B)    │
//! └───────────────┴────────────────────────────────────┘
//! ```
//!
//! A fresh random 96-bit nonce is generated per file (per encrypt call) and
//! prepended. AES-256-GCM's authentication tag is appended by `ring` in place.
//! Decryption validates the tag: a corrupted or tampered file fails with an
//! error rather than returning garbage plaintext.

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::hkdf;

use crate::errors::AppError;

/// Domain-separation label for HKDF. MUST stay distinct from any string used
/// to derive or apply the SQLCipher DB key, so the audio key is
/// cryptographically independent from the DB key even though both descend
/// from the same DEK. Changing this string would orphan every already-
/// encrypted `.wav.enc` file (they'd no longer decrypt) — treat it as a
/// stable on-disk format constant.
const HKDF_INFO: &[u8] = b"tahlk-audio-at-rest-key-v1";

/// AES-256 key length in bytes.
const KEY_LEN: usize = 32;

/// Decode a 64-char lowercase-hex DEK into its 32 raw bytes. The DEK format is
/// validated upstream by `db_key` (64 hex chars); we re-check here so this
/// module is safe to call in isolation (tests, migration) without assuming a
/// caller already validated.
fn dek_hex_to_bytes(dek_hex: &str) -> Result<[u8; KEY_LEN], AppError> {
    if dek_hex.len() != KEY_LEN * 2 || !dek_hex.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::internal_from(
            "audio key derivation: DEK is not 64 hex chars",
        ));
    }
    let mut out = [0u8; KEY_LEN];
    for (i, chunk) in dek_hex.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16).unwrap() as u8;
        let lo = (chunk[1] as char).to_digit(16).unwrap() as u8;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

/// Derive the 256-bit audio-at-rest key from the SQLCipher DEK via
/// HKDF-SHA256 with the domain-separating [`HKDF_INFO`] label.
///
/// The DEK is used as the HKDF input keying material (IKM). We use an empty
/// salt: the IKM is already a full-entropy 256-bit CSPRNG key (not a
/// low-entropy password), so HKDF-Extract's salt provides no additional
/// security here — RFC 5869 explicitly permits an empty salt for high-entropy
/// IKM. The `info` label is what makes this key distinct from the DB usage.
pub(crate) fn derive_audio_key(dek_hex: &str) -> Result<[u8; KEY_LEN], AppError> {
    let ikm = dek_hex_to_bytes(dek_hex)?;
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
    let prk = salt.extract(&ikm);
    // `HKDF_SHA256` doubles as the output KeyType; its len() is 32, exactly
    // the AES-256 key size we want.
    let okm = prk
        .expand(&[HKDF_INFO], hkdf::HKDF_SHA256)
        .map_err(|_| AppError::internal_from("audio key HKDF expand failed"))?;
    let mut key = [0u8; KEY_LEN];
    okm.fill(&mut key)
        .map_err(|_| AppError::internal_from("audio key HKDF fill failed"))?;
    Ok(key)
}

/// Convenience: resolve the DEK and derive the audio-at-rest key in one step.
/// This is the entry point the audio commands and the startup migration use —
/// they never touch the DEK bytes directly.
///
/// Source order matters, and getting it wrong destroys PHI:
///
///  1. The unlocked session DEK, once auth is configured. `auth_set_password`
///     deletes the keychain DEK entry, so from that point the wrapped copy in
///     `tahlk_auth.db` is the only route to the key.
///  2. The keychain, on installs where auth has not been configured yet (the
///     legacy path in `lib.rs::setup`, which still opens the DB that way).
///
/// Previously this called `db_key::load_or_generate_dek()` unconditionally.
/// After `auth_set_password` removed the keychain entry, that call fell through
/// to its *generate* branch and minted a brand-new random DEK — so every
/// `.wav.enc` written before the user set a password became permanently
/// undecryptable, silently, on the first launch afterwards. `load_or_generate_dek`
/// now refuses to generate once auth is configured, so this cannot recur even
/// if a future caller bypasses the session DEK.
pub(crate) fn audio_key() -> Result<[u8; KEY_LEN], AppError> {
    if let Some(hex) = crate::auth::session_dek_hex() {
        return derive_audio_key(&hex);
    }
    derive_audio_key(&crate::db_key::load_or_generate_dek()?)
}

/// Encrypt `plaintext` with AES-256-GCM under `key`. Returns
/// `nonce ‖ ciphertext ‖ tag` (see module docs for the layout). A fresh
/// random 96-bit nonce is drawn per call — never reuse a (key, nonce) pair,
/// which GCM's security absolutely depends on.
pub(crate) fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>, AppError> {
    let unbound = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_| AppError::internal_from("audio encrypt: bad key"))?;
    let sealing = LessSafeKey::new(unbound);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes).map_err(AppError::internal_from)?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    // seal_in_place appends the 16-byte tag to `buf`.
    let mut buf = plaintext.to_vec();
    sealing
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut buf)
        .map_err(|_| AppError::internal_from("audio encrypt: seal failed"))?;

    let mut out = Vec::with_capacity(NONCE_LEN + buf.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&buf);
    Ok(out)
}

/// Decrypt a `nonce ‖ ciphertext ‖ tag` blob produced by [`encrypt`]. Fails
/// (rather than returning garbage) if the file is too short to hold a nonce +
/// tag, or if the GCM auth tag does not validate — i.e. any corruption or
/// tampering is detected. Decryption errors are `Storage` so a damaged file on
/// disk surfaces the same class as other on-disk failures.
pub(crate) fn decrypt(key: &[u8; KEY_LEN], data: &[u8]) -> Result<Vec<u8>, AppError> {
    // Must contain at least the nonce plus a GCM tag; a shorter blob is
    // truncated/corrupt.
    if data.len() < NONCE_LEN + AES_256_GCM.tag_len() {
        return Err(AppError::Storage(
            "encrypted audio file is too short to be valid".into(),
        ));
    }
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let mut nonce_arr = [0u8; NONCE_LEN];
    nonce_arr.copy_from_slice(nonce_bytes);
    let nonce = Nonce::assume_unique_for_key(nonce_arr);

    let unbound = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_| AppError::internal_from("audio decrypt: bad key"))?;
    let opening = LessSafeKey::new(unbound);

    let mut buf = ciphertext.to_vec();
    let plaintext = opening
        .open_in_place(nonce, Aad::empty(), &mut buf)
        .map_err(|_| {
            AppError::Storage("encrypted audio failed authentication (corrupt or tampered)".into())
        })?;
    Ok(plaintext.to_vec())
}

/// One-shot startup migration: encrypt any legacy plaintext `<id>.wav` files
/// in `audio_dir` in place, rewriting the DB `audio_path` to the new
/// `<id>.wav.enc` name. Runs once per launch; a no-op after everything is
/// encrypted (nothing but `.wav.enc` files remain).
///
/// ## Ordering (crash-safe)
///
/// For each plaintext file: **write encrypted → update DB → delete plaintext**.
/// The plaintext original is removed ONLY after the encrypted copy is on disk
/// AND the DB column is updated, so a crash at any point never loses audio:
///   * crash after write, before update  → next run re-encrypts (same plaintext,
///     harmless overwrite), updates, deletes.
///   * crash after update, before delete → next run re-encrypts, the UPDATE
///     matches 0 rows (already migrated), deletes the leftover plaintext.
///
/// The migration is therefore idempotent and resumable — re-running after full
/// completion does nothing because no bare `.wav` files remain.
///
/// ## Signed-encounter freeze bypass (narrow, one-time)
///
/// `enforce_signed_immutability` freezes `audio_path` on signed rows to stop a
/// post-sign swap that would repoint provenance at a different recording. This
/// migration needs to update `audio_path` on signed rows too, so it uses a
/// DEDICATED `UPDATE ... WHERE audio_path = <old>` statement — NOT the general
/// `upsert_encounter` path — that ONLY rewrites the `.wav` → `.wav.enc`
/// extension suffix on the SAME file. It never repoints to a different file
/// (the WHERE clause matches the exact prior path, the SET value is that same
/// path plus `.enc`), so the provenance guarantee the freeze protects is
/// preserved: the signed note still references the identical recording bytes,
/// now merely stored encrypted. This is the only sanctioned bypass.
pub(crate) fn migrate_plaintext_audio_at_rest(
    conn: &rusqlite::Connection,
    audio_dir: &std::path::Path,
    key: &[u8; KEY_LEN],
) -> Result<usize, AppError> {
    // Fresh install (or audio never recorded): nothing to walk.
    if !audio_dir.exists() {
        return Ok(0);
    }
    let entries = match std::fs::read_dir(audio_dir) {
        Ok(e) => e,
        Err(e) => {
            log::error!("audio at-rest migration: cannot read audio dir: {}", crate::log_safety::cap_len(&e.to_string()));
            return Ok(0);
        }
    };

    let mut migrated = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };
        // Skip already-encrypted files and anything that isn't a bare `.wav`.
        if name.ends_with(".wav.enc") || !name.ends_with(".wav") {
            continue;
        }

        // --- write encrypted copy ---
        let plaintext = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                log::error!("audio at-rest migration: read {} failed: {}", crate::log_safety::redact_filename(name), crate::log_safety::cap_len(&e.to_string()));
                continue;
            }
        };
        let ciphertext = match encrypt(key, &plaintext) {
            Ok(c) => c,
            Err(e) => {
                log::error!("audio at-rest migration: encrypt {} failed: {}", crate::log_safety::redact_filename(name), crate::log_safety::cap_len(&e.to_string()));
                continue;
            }
        };
        let enc_path = path.with_file_name(format!("{name}.enc"));
        if let Err(e) = std::fs::write(&enc_path, &ciphertext) {
            log::error!("audio at-rest migration: write {}.enc failed: {}", crate::log_safety::redact_filename(name), crate::log_safety::cap_len(&e.to_string()));
            continue;
        }
        crate::perms::chmod_0600_unix(&enc_path);

        // --- update DB (dedicated freeze-bypass UPDATE; suffix-only rewrite) ---
        let old_path = path.to_string_lossy().into_owned();
        let new_path = enc_path.to_string_lossy().into_owned();
        if let Err(e) = conn.execute(
            "UPDATE encounters SET audio_path = ?1 WHERE audio_path = ?2",
            rusqlite::params![new_path, old_path],
        ) {
            // Leave the plaintext in place so a later run can retry the whole
            // step — never delete before the DB is consistent.
            log::error!("audio at-rest migration: DB update for {} failed: {}", crate::log_safety::redact_filename(name), crate::log_safety::cap_len(&e.to_string()));
            continue;
        }

        // --- delete plaintext ONLY after write + update both succeeded ---
        if let Err(e) = std::fs::remove_file(&path) {
            // The encrypted copy and DB row are already correct; a lingering
            // plaintext is a leak we log, and the next run will retry the
            // delete (re-encrypt is a harmless overwrite).
            log::error!("audio at-rest migration: delete plaintext {} failed: {}", crate::log_safety::redact_filename(name), crate::log_safety::cap_len(&e.to_string()));
            continue;
        }
        migrated += 1;
    }
    if migrated > 0 {
        log::info!("audio at-rest migration: encrypted {migrated} legacy .wav file(s)");
    }
    Ok(migrated)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dek() -> String {
        // Deterministic 32-byte test DEK (hex) — not a production key.
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into()
    }

    #[test]
    fn roundtrip_recovers_plaintext() {
        let key = derive_audio_key(&test_dek()).unwrap();
        let plaintext = b"RIFF....fake wav audio bytes with \x00\x01\x02 binary";
        let blob = encrypt(&key, plaintext).unwrap();
        // Ciphertext must not equal plaintext, and must carry nonce + tag overhead.
        assert_ne!(&blob[NONCE_LEN..], &plaintext[..]);
        assert_eq!(blob.len(), NONCE_LEN + plaintext.len() + AES_256_GCM.tag_len());
        let recovered = decrypt(&key, &blob).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn empty_plaintext_roundtrips() {
        let key = derive_audio_key(&test_dek()).unwrap();
        let blob = encrypt(&key, b"").unwrap();
        assert_eq!(blob.len(), NONCE_LEN + AES_256_GCM.tag_len());
        assert_eq!(decrypt(&key, &blob).unwrap(), b"");
    }

    #[test]
    fn tampered_ciphertext_fails_authentication() {
        let key = derive_audio_key(&test_dek()).unwrap();
        let mut blob = encrypt(&key, b"sensitive audio").unwrap();
        // Flip a bit in the ciphertext body (past the nonce). GCM's tag must
        // catch it — decryption returns Err, never garbage plaintext.
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        let err = decrypt(&key, &blob).unwrap_err();
        assert!(matches!(err, AppError::Storage(_)));
    }

    #[test]
    fn tampered_nonce_fails_authentication() {
        let key = derive_audio_key(&test_dek()).unwrap();
        let mut blob = encrypt(&key, b"sensitive audio").unwrap();
        blob[0] ^= 0xff; // corrupt the nonce
        assert!(decrypt(&key, &blob).is_err());
    }

    #[test]
    fn wrong_key_fails_authentication() {
        let key = derive_audio_key(&test_dek()).unwrap();
        let other = derive_audio_key(
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        )
        .unwrap();
        let blob = encrypt(&key, b"sensitive audio").unwrap();
        assert!(decrypt(&other, &blob).is_err());
    }

    #[test]
    fn short_blob_is_rejected() {
        let key = derive_audio_key(&test_dek()).unwrap();
        // Fewer bytes than nonce + tag can never be a valid file.
        assert!(decrypt(&key, &[0u8; 4]).is_err());
        assert!(decrypt(&key, &[]).is_err());
    }

    #[test]
    fn distinct_nonces_across_calls() {
        // Two encryptions of identical plaintext must differ (random nonce),
        // proving we don't reuse a (key, nonce) pair.
        let key = derive_audio_key(&test_dek()).unwrap();
        let a = encrypt(&key, b"same input").unwrap();
        let b = encrypt(&key, b"same input").unwrap();
        assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN], "nonces must differ per call");
        assert_ne!(a, b, "ciphertext must differ when nonce differs");
    }

    #[test]
    fn audio_key_is_distinct_from_dek_and_deterministic() {
        let dek = test_dek();
        let k1 = derive_audio_key(&dek).unwrap();
        let k2 = derive_audio_key(&dek).unwrap();
        assert_eq!(k1, k2, "derivation must be deterministic for a given DEK");
        // The derived key must not simply echo the DEK bytes.
        let dek_bytes = dek_hex_to_bytes(&dek).unwrap();
        assert_ne!(k1, dek_bytes, "audio key must be HKDF-separated from the DEK");
    }

    // ── audio_key source-of-truth (regression: silent PHI loss) ─────────────
    //
    // `auth_set_password` deletes the keychain DEK entry by design. While
    // `audio_key()` still resolved through `db_key::load_or_generate_dek()`,
    // that deletion sent it down the *generate* branch, minting a brand-new
    // random DEK — so every `.wav.enc` written before the user set a password
    // became permanently undecryptable, with no error surfaced, on the first
    // launch afterwards. These pin the resolution order.

    // Deliberately ONE test, not three. `SESSION_DEK_HEX` is process-global and
    // the test harness runs tests in parallel, so separate cases that each
    // publish a session DEK race each other — a split version passed a full run
    // and failed under `--exact` filtering. Sequencing the whole scenario in a
    // single test makes the assertions deterministic.
    #[test]
    fn audio_key_resolves_from_session_dek_and_survives_password_setup() {
        // 1. Resolution order: with a session DEK published, audio_key() must
        //    derive from it and never consult the keychain.
        crate::auth::set_session_dek_hex(&test_dek());
        let before = audio_key().expect("audio_key must resolve from the session DEK");
        assert_eq!(
            before,
            derive_audio_key(&test_dek()).unwrap(),
            "audio_key must derive from the unlocked session DEK, not the keychain"
        );

        // Encrypt as a pre-auth install would.
        let blob = encrypt(&before, b"RIFF....session audio").unwrap();

        // 2. auth_set_password wraps the SAME DEK bytes it read from the
        //    keychain and republishes them before deleting the entry, so the
        //    audio key is unchanged. This is why no re-encryption migration is
        //    needed — and precisely what the old keychain lookup broke.
        crate::auth::set_session_dek_hex(&test_dek());
        let after = audio_key().unwrap();
        assert_eq!(after, before, "audio key must not change across password setup");
        assert_eq!(
            decrypt(&after, &blob).unwrap(),
            b"RIFF....session audio",
            "audio encrypted before password setup must still decrypt afterwards"
        );

        // 3. The damage the old path caused, asserted so the cost is explicit:
        //    a regenerated DEK yields a key that cannot authenticate existing
        //    blobs. Under the bug this is what every .wav.enc on the device hit.
        let regenerated = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
        crate::auth::set_session_dek_hex(regenerated);
        let minted = audio_key().unwrap();
        assert_ne!(minted, before);
        assert!(
            decrypt(&minted, &blob).is_err(),
            "a regenerated DEK must not be able to read audio written under the old one"
        );

        // Leave the global as this module's test DEK, not the throwaway one.
        crate::auth::set_session_dek_hex(&test_dek());
    }

    #[test]
    fn rejects_malformed_dek() {
        assert!(derive_audio_key("nothex").is_err());
        assert!(derive_audio_key(&"a".repeat(63)).is_err());
        assert!(derive_audio_key(&"Z".repeat(64)).is_err());
    }

    // ── Startup migration ──────────────────────────────────────────────────

    use rusqlite::{params, Connection};

    fn migration_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE encounters (
                id             TEXT PRIMARY KEY,
                provider_id    TEXT NOT NULL,
                encounter_date TEXT NOT NULL,
                patient_alias  TEXT,
                status         TEXT NOT NULL DEFAULT 'draft',
                audio_path     TEXT,
                created_at     TEXT NOT NULL,
                signed_at      TEXT,
                signed_hash    TEXT
            );",
        )
        .unwrap();
        conn
    }

    fn audio_path_of(conn: &Connection, id: &str) -> Option<String> {
        conn.query_row(
            "SELECT audio_path FROM encounters WHERE id = ?1",
            params![id],
            |r| r.get(0),
        )
        .unwrap()
    }

    // A SIGNED encounter's plaintext .wav is migrated to .wav.enc, the DB
    // audio_path is rewritten (freeze bypass), the plaintext is deleted, and
    // the encrypted copy decrypts back to the original bytes. This is the core
    // scenario: the signed-row freeze must NOT block the suffix-only rewrite.
    #[test]
    fn migration_encrypts_signed_row_and_rewrites_path() {
        let dir = tempfile::tempdir().unwrap();
        let audio_dir = dir.path();
        let key = derive_audio_key(&test_dek()).unwrap();

        let wav = audio_dir.join("enc-signed.wav");
        let original = b"RIFF plaintext signed audio \x00\x01";
        std::fs::write(&wav, original).unwrap();
        let old_path = wav.to_string_lossy().into_owned();

        let conn = migration_db();
        conn.execute(
            "INSERT INTO encounters (id, provider_id, encounter_date, status, audio_path, \
                                     created_at, signed_at, signed_hash) \
             VALUES ('enc-signed','prov-1','2026-07-04','signed', ?1, \
                     '2026-07-04T10:00:00Z','2026-07-04T10:30:00Z','deadbeef')",
            params![old_path],
        )
        .unwrap();

        let n = migrate_plaintext_audio_at_rest(&conn, audio_dir, &key).unwrap();
        assert_eq!(n, 1, "exactly one file migrated");

        // Plaintext gone, encrypted present.
        assert!(!wav.exists(), "plaintext .wav must be deleted");
        let enc = audio_dir.join("enc-signed.wav.enc");
        assert!(enc.exists(), ".wav.enc must be created");

        // DB path rewritten to the encrypted file — suffix-only change.
        let new_path = audio_path_of(&conn, "enc-signed").unwrap();
        assert_eq!(new_path, enc.to_string_lossy());
        assert_eq!(new_path, format!("{old_path}.enc"));

        // Encrypted copy decrypts to the exact original bytes.
        let recovered = decrypt(&key, &std::fs::read(&enc).unwrap()).unwrap();
        assert_eq!(recovered, original);
    }

    // Running the migration a second time is a no-op: after the first pass no
    // bare .wav files remain, so nothing is re-migrated and the DB is stable.
    #[test]
    fn migration_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let audio_dir = dir.path();
        let key = derive_audio_key(&test_dek()).unwrap();

        let wav = audio_dir.join("enc-1.wav");
        std::fs::write(&wav, b"body").unwrap();
        let old_path = wav.to_string_lossy().into_owned();

        let conn = migration_db();
        conn.execute(
            "INSERT INTO encounters (id, provider_id, encounter_date, status, audio_path, created_at) \
             VALUES ('enc-1','prov-1','2026-07-04','draft', ?1, '2026-07-04T10:00:00Z')",
            params![old_path],
        )
        .unwrap();

        let first = migrate_plaintext_audio_at_rest(&conn, audio_dir, &key).unwrap();
        assert_eq!(first, 1);
        let path_after_first = audio_path_of(&conn, "enc-1").unwrap();

        // Second run: nothing left to do.
        let second = migrate_plaintext_audio_at_rest(&conn, audio_dir, &key).unwrap();
        assert_eq!(second, 0, "second run must migrate nothing");
        assert_eq!(
            audio_path_of(&conn, "enc-1").unwrap(),
            path_after_first,
            "idempotent run must not change the stored path"
        );
    }

    // A pre-existing .wav.enc (e.g. interrupted after write, before delete)
    // plus a lingering plaintext .wav: the resume pass re-encrypts, keeps the
    // DB consistent, and removes the plaintext. Simulates crash recovery.
    #[test]
    fn migration_resumes_after_partial_interruption() {
        let dir = tempfile::tempdir().unwrap();
        let audio_dir = dir.path();
        let key = derive_audio_key(&test_dek()).unwrap();

        let wav = audio_dir.join("enc-2.wav");
        std::fs::write(&wav, b"resume body").unwrap();
        // Pretend a prior run already wrote the encrypted copy AND updated the
        // DB, then crashed before deleting the plaintext.
        let enc = audio_dir.join("enc-2.wav.enc");
        std::fs::write(&enc, encrypt(&key, b"resume body").unwrap()).unwrap();
        let new_path = enc.to_string_lossy().into_owned();

        let conn = migration_db();
        conn.execute(
            "INSERT INTO encounters (id, provider_id, encounter_date, status, audio_path, created_at) \
             VALUES ('enc-2','prov-1','2026-07-04','draft', ?1, '2026-07-04T10:00:00Z')",
            params![new_path],
        )
        .unwrap();

        let n = migrate_plaintext_audio_at_rest(&conn, audio_dir, &key).unwrap();
        assert_eq!(n, 1, "the lingering plaintext is cleaned up");
        assert!(!wav.exists(), "plaintext must be removed on resume");
        assert!(enc.exists());
        // DB path unchanged (already pointed at .wav.enc); still decryptable.
        assert_eq!(audio_path_of(&conn, "enc-2").unwrap(), new_path);
        let recovered = decrypt(&key, &std::fs::read(&enc).unwrap()).unwrap();
        assert_eq!(recovered, b"resume body");
    }

    // Empty audio dir / no files → zero migrated, no error.
    #[test]
    fn migration_noop_on_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let key = derive_audio_key(&test_dek()).unwrap();
        let conn = migration_db();
        assert_eq!(
            migrate_plaintext_audio_at_rest(&conn, dir.path(), &key).unwrap(),
            0
        );
    }
}
