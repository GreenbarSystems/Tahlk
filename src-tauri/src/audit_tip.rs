//! External tip anchor for tail-truncation detection on the note-history chain.
//!
//! The per-entry keyed MAC ([`crate::audit_mac`]) defeats SUBSTITUTION and EDIT
//! of the audit chains, but not TRUNCATION of the newest entries — a MAC-valid
//! prefix of a chain is still a MAC-valid chain, so dropping the trailing rows
//! (e.g. removing a `signed` attestation to make a signed note look like a
//! draft, or removing a post-sign modification record) is invisible to
//! in-chain verification. Detecting a dropped tail requires an anchor stored
//! OUTSIDE the database, so that truncating the DB does not also truncate the
//! anchor.
//!
//! This module keeps that anchor: when an encounter is signed, its note-history
//! chain tip — `(max seq, that row's chain_mac)` — is recorded in a sidecar
//! file (`audit_tips.v1` in the app data dir), and the whole file is
//! authenticated with an HMAC keyed by the same keychain-derived key
//! [`crate::audit_mac`] uses (domain-separated by a fixed tag). On opening a
//! signed note, the recorded tip is compared against the chain's current tip;
//! a mismatch means the chain was truncated or otherwise altered after sign-off.
//! Signed history chains are terminal (no legitimate post-sign appends), so the
//! tip is written once and never legitimately changes until the encounter is
//! destroyed, at which point its entry is removed.
//!
//! ## Threat boundary — stated honestly
//!
//! This raises the bar for tail-truncation via vectors that do NOT hold the
//! MAC key: DB-only tampering, a partial backup/restore, silent row-dropping
//! corruption, and (where the OS keychain ACLs the key away, e.g. macOS) a
//! sandboxed co-process. It does NOT — and on a local-first single-user app
//! fundamentally cannot — detect tampering by a party who holds the keychain
//! DEK (the record owner, or a full same-user compromise), because that party
//! can re-derive the key and re-author both the chain and this anchor. It is
//! defense-in-depth, not a root of trust.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use ring::hmac;
use serde::{Deserialize, Serialize};

/// Absolute path to the sidecar file, set once at startup ([`init`]).
static TIPS_PATH: OnceLock<PathBuf> = OnceLock::new();
/// Serializes read-modify-write on the sidecar. Appends are user-driven and
/// effectively serial on a single-user desktop, but the connection pool allows
/// concurrent commands, so guard the file explicitly.
static FILE_LOCK: Mutex<()> = Mutex::new(());

/// Domain-separation tag prefixed to the MAC input so reusing
/// `audit_mac`'s key here can never be confused with a per-entry chain MAC.
const DOMAIN_TAG: &[u8] = b"tahlk-audit-tip-file-v1\n";
const FILE_VERSION: u32 = 1;

#[derive(Serialize, Deserialize, Clone)]
struct Tip {
    seq: i64,
    /// The tip row's `chain_mac`, or `""` when that row was stored unanchored
    /// (NULL) — see `audit_mac::compute_best_effort`.
    mac: String,
}

#[derive(Serialize, Deserialize)]
struct TipFile {
    v: u32,
    tips: BTreeMap<String, Tip>,
    mac: String,
}

/// Result of loading the sidecar: absent (first run), present-and-authenticated,
/// or present-but-unreadable/failed-authentication (damage or tampering).
enum Loaded {
    Absent,
    Present(BTreeMap<String, Tip>),
    Corrupt,
}

/// Outcome of checking one encounter's current chain tip against the anchor.
pub(crate) enum TipCheck {
    /// No anchor recorded for this encounter (a legacy signed note from before
    /// this feature, or a best-effort write that failed at sign-off) —
    /// truncation cannot be checked, and this is NOT reported as tampering.
    NoAnchor,
    /// The current chain tip matches the recorded anchor.
    Match,
    /// The current chain tip differs from the anchor — the chain was truncated
    /// or otherwise modified after sign-off.
    Mismatch,
    /// The sidecar itself is missing its path, unreadable, or failed
    /// authentication — the anchor is unavailable, checked separately.
    Unavailable,
}

/// Record the sidecar path. Call once at startup, before any sign-off/verify.
pub(crate) fn init(app_data_dir: &Path) {
    let _ = TIPS_PATH.set(app_data_dir.join("audit_tips.v1"));
}

/// HMAC of the serialized tips map, domain-tagged. `None` only on the
/// practically-impossible serialization failure of a `BTreeMap<String, Tip>`.
fn file_mac(key: &hmac::Key, tips: &BTreeMap<String, Tip>) -> Option<String> {
    let body = serde_json::to_vec(tips).ok()?;
    let mut input = Vec::with_capacity(DOMAIN_TAG.len() + body.len());
    input.extend_from_slice(DOMAIN_TAG);
    input.extend_from_slice(&body);
    Some(crate::hex::to_hex(hmac::sign(key, &input).as_ref()))
}

/// Load and authenticate the sidecar at `path`. Path-explicit so it is unit
/// testable without the global or the keychain.
fn load_from(path: &Path, key: &hmac::Key) -> Loaded {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Loaded::Absent,
        Err(_) => return Loaded::Corrupt,
    };
    let file: TipFile = match serde_json::from_slice(&bytes) {
        Ok(f) => f,
        Err(_) => return Loaded::Corrupt,
    };
    if file.v != FILE_VERSION {
        return Loaded::Corrupt;
    }
    match file_mac(key, &file.tips) {
        // Plain compare is fine: this is an at-rest artifact verified locally,
        // not an online MAC oracle, so MAC-compare timing is not a concern.
        Some(expected) if expected == file.mac => Loaded::Present(file.tips),
        _ => Loaded::Corrupt,
    }
}

/// Authenticate and atomically write the tips map to `path` (temp + rename on
/// the same directory/filesystem). Returns whether the write succeeded.
fn store_to(path: &Path, key: &hmac::Key, tips: &BTreeMap<String, Tip>) -> bool {
    let Some(mac) = file_mac(key, tips) else { return false };
    let file = TipFile { v: FILE_VERSION, tips: tips.clone(), mac };
    let Ok(data) = serde_json::to_vec(&file) else { return false };
    let tmp = path.with_extension("tmp");
    if std::fs::write(&tmp, &data).is_err() {
        return false;
    }
    std::fs::rename(&tmp, path).is_ok()
}

/// Resolve the key + path, run `f` under the file lock. `f` receives the loaded
/// state and the resolved key/path. Returns `None` if the key or path is
/// unavailable.
fn with_store<T>(f: impl FnOnce(&Path, &hmac::Key, Loaded) -> T) -> Option<T> {
    let _guard = FILE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = TIPS_PATH.get()?;
    let key = crate::audit_mac::mac_key().ok()?;
    let loaded = load_from(path, &key);
    Some(f(path, &key, loaded))
}

/// Record (or update) the note-history tip for a just-signed encounter.
/// Best-effort — a sidecar failure is logged and must never fail sign-off.
/// A corrupt/tampered existing file is NOT overwritten (that would erase
/// evidence); the failure is logged instead.
pub(crate) fn record_signed_tip(encounter_id: &str, seq: i64, mac: Option<&str>) {
    let done = with_store(|path, key, loaded| {
        let mut tips = match loaded {
            Loaded::Present(t) => t,
            Loaded::Absent => BTreeMap::new(),
            Loaded::Corrupt => {
                log::error!("audit-tip: sidecar failed authentication; refusing to overwrite");
                return false;
            }
        };
        tips.insert(
            encounter_id.to_string(),
            Tip { seq, mac: mac.unwrap_or_default().to_string() },
        );
        store_to(path, key, &tips)
    });
    if done != Some(true) {
        log::error!("audit-tip: signed-note tip not anchored (truncation detection unavailable for this note)");
    }
}

/// Remove an encounter's anchor when it is destroyed. Best-effort. Called from
/// inside the destroy transaction; on a (rare) rollback the anchor is merely
/// lost, which downgrades to `NoAnchor` (no false tamper alarm), never up.
pub(crate) fn remove_tip(encounter_id: &str) {
    let _ = with_store(|path, key, loaded| {
        if let Loaded::Present(mut tips) = loaded {
            if tips.remove(encounter_id).is_some() {
                store_to(path, key, &tips);
            }
        }
    });
}

/// Compare an encounter's current chain tip `(cur_seq, cur_mac)` against the
/// recorded anchor.
pub(crate) fn check_tip(encounter_id: &str, cur_seq: i64, cur_mac: Option<&str>) -> TipCheck {
    match with_store(|_, _, loaded| match loaded {
        Loaded::Present(tips) => match tips.get(encounter_id) {
            Some(t) if t.seq == cur_seq && t.mac.as_str() == cur_mac.unwrap_or_default() => TipCheck::Match,
            Some(_) => TipCheck::Mismatch,
            None => TipCheck::NoAnchor,
        },
        Loaded::Absent => TipCheck::NoAnchor,
        Loaded::Corrupt => TipCheck::Unavailable,
    }) {
        Some(v) => v,
        None => TipCheck::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    //! Exercise the file authentication + tip-compare logic directly with a
    //! fixed key and a temp path — no keychain, no global state.

    use super::*;

    fn test_key() -> hmac::Key {
        hmac::Key::new(hmac::HMAC_SHA256, &[0x33u8; 32])
    }

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("tahlk_tip_test_{name}.json"))
    }

    fn map_of(pairs: &[(&str, i64, &str)]) -> BTreeMap<String, Tip> {
        pairs
            .iter()
            .map(|(id, seq, mac)| (id.to_string(), Tip { seq: *seq, mac: mac.to_string() }))
            .collect()
    }

    #[test]
    fn store_then_load_round_trips() {
        let path = temp_path("roundtrip");
        let _ = std::fs::remove_file(&path);
        let key = test_key();
        let tips = map_of(&[("enc-1", 3, "mac-abc"), ("enc-2", 1, "")]);
        assert!(store_to(&path, &key, &tips));
        match load_from(&path, &key) {
            Loaded::Present(loaded) => {
                assert_eq!(loaded.len(), 2);
                assert_eq!(loaded["enc-1"].seq, 3);
                assert_eq!(loaded["enc-1"].mac, "mac-abc");
                assert_eq!(loaded["enc-2"].mac, "");
            }
            _ => panic!("expected Present"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn absent_file_is_not_corrupt() {
        let path = temp_path("absent-nonexistent");
        let _ = std::fs::remove_file(&path);
        assert!(matches!(load_from(&path, &test_key()), Loaded::Absent));
    }

    #[test]
    fn tampered_file_fails_authentication() {
        let path = temp_path("tampered");
        let _ = std::fs::remove_file(&path);
        let key = test_key();
        store_to(&path, &key, &map_of(&[("enc-1", 5, "mac-x")]));
        // Attacker edits the tip (e.g. lowers seq to match a truncated chain)
        // without the key — the file MAC no longer matches.
        let raw = std::fs::read_to_string(&path).unwrap().replace("\"seq\":5", "\"seq\":2");
        std::fs::write(&path, raw).unwrap();
        assert!(matches!(load_from(&path, &key), Loaded::Corrupt));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn wrong_key_fails_authentication() {
        let path = temp_path("wrongkey");
        let _ = std::fs::remove_file(&path);
        store_to(&path, &test_key(), &map_of(&[("enc-1", 1, "m")]));
        let other = hmac::Key::new(hmac::HMAC_SHA256, &[0x44u8; 32]);
        assert!(matches!(load_from(&path, &other), Loaded::Corrupt));
        let _ = std::fs::remove_file(&path);
    }

    // The pure tip-compare, factored to mirror check_tip's logic against a
    // known map (check_tip itself needs the global path + keychain).
    fn verdict(tips: &BTreeMap<String, Tip>, id: &str, seq: i64, mac: Option<&str>) -> TipCheck {
        match tips.get(id) {
            Some(t) if t.seq == seq && t.mac.as_str() == mac.unwrap_or_default() => TipCheck::Match,
            Some(_) => TipCheck::Mismatch,
            None => TipCheck::NoAnchor,
        }
    }

    #[test]
    fn tip_compare_detects_truncation_and_matches() {
        let tips = map_of(&[("enc-1", 3, "mac-c")]);
        // Intact: DB tip equals the anchor.
        assert!(matches!(verdict(&tips, "enc-1", 3, Some("mac-c")), TipCheck::Match));
        // Truncated tail: the signed row (seq 3) was dropped, so the DB tip is
        // now seq 2 with a different mac.
        assert!(matches!(verdict(&tips, "enc-1", 2, Some("mac-b")), TipCheck::Mismatch));
        // Post-sign append: a new row past the anchored tip.
        assert!(matches!(verdict(&tips, "enc-1", 4, Some("mac-d")), TipCheck::Mismatch));
        // No anchor for this encounter.
        assert!(matches!(verdict(&tips, "enc-other", 1, Some("x")), TipCheck::NoAnchor));
    }

    #[test]
    fn null_mac_tip_matches_empty() {
        let tips = map_of(&[("enc-1", 1, "")]);
        assert!(matches!(verdict(&tips, "enc-1", 1, None), TipCheck::Match));
        assert!(matches!(verdict(&tips, "enc-1", 1, Some("")), TipCheck::Match));
    }
}
