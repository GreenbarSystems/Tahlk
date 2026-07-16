//! Database encryption key (DEK) — keychain-held, 256-bit random.
//!
//! The DEK is generated on first launch via a CSPRNG (`getrandom`), stored
//! in the OS secure store next to the Anthropic key, and passed to SQLCipher
//! as a 64-character hex blob so `PRAGMA key = "x'HEX'"` bypasses PBKDF2 —
//! no passphrase, no key derivation, deterministic startup.
//!
//! Threat model: the DEK never touches disk in plaintext form. If the OS
//! keychain is compromised the DB is too; that is an accepted trade-off vs.
//! prompting the clinician for a passphrase on every launch. FDE at the OS
//! level (FileVault/BitLocker) is a recommended complementary control, not
//! a substitute — device theft plus keychain export is the residual risk.

use crate::errors::AppError;
use crate::hex::to_hex;

/// This module's own keychain item name. Deliberately distinct from
/// `secrets`'s and `lock`'s — see `keychain.rs`'s module doc.
pub(crate) const KEYRING_USER: &str = "db_encryption_key";
const KEY_BYTES: usize = 32; // 256-bit AES key
const KEY_HEX_LEN: usize = KEY_BYTES * 2;

fn keyring_entry() -> Result<keyring::Entry, AppError> {
    crate::keychain::entry(KEYRING_USER)
}

fn is_valid_hex_key(s: &str) -> bool {
    s.len() == KEY_HEX_LEN && s.bytes().all(|c| c.is_ascii_hexdigit())
}

/// Load the DEK from the OS keychain, generating and persisting a fresh one
/// on first launch. Returns the 64-character hex string ready to hand to
/// `PRAGMA key = "x'..'"`.
///
/// Fails closed: if the keychain is unreachable or returns garbage, this
/// returns an error. Callers must NOT fall back to plaintext.
pub(crate) fn load_or_generate_dek() -> Result<String, AppError> {
    let entry = keyring_entry()?;

    // Existing DEK path — validate strictly. A malformed keychain entry
    // (truncated, non-hex) means either a bug or tampering; refuse rather
    // than silently regenerating (which would orphan the encrypted DB).
    match entry.get_password() {
        Ok(existing) if is_valid_hex_key(&existing) => return Ok(existing),
        Ok(bad) if !bad.is_empty() => {
            return Err(AppError::internal_from(format!(
                "database encryption key in keychain is malformed (len={}); \
                 refusing to open database — restore keychain or reset app data",
                bad.len()
            )));
        }
        _ => { /* no entry yet — fall through to generation */ }
    }

    // First-launch: generate a fresh 256-bit key.
    let mut buf = [0u8; KEY_BYTES];
    getrandom::getrandom(&mut buf).map_err(AppError::internal_from)?;
    let hex = to_hex(&buf);
    entry.set_password(&hex).map_err(AppError::internal_from)?;
    Ok(hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: hex encoding is covered by `hex::tests::hex_roundtrip`, which
    // asserts the same lowercase/zero-padding properties on a superset of
    // these inputs. Testing it from here would be testing another module's
    // function.

    #[test]
    fn valid_hex_key_gate() {
        assert!(is_valid_hex_key(&"a".repeat(64)));
        assert!(is_valid_hex_key(&"0123456789abcdef".repeat(4)));
        assert!(!is_valid_hex_key(&"a".repeat(63)));
        assert!(!is_valid_hex_key(&"a".repeat(65)));
        assert!(!is_valid_hex_key(&"Z".repeat(64))); // non-hex char
        assert!(!is_valid_hex_key(""));
    }

    // Round-trips a DEK through the real OS secure store to confirm the
    // keyring backend works on this platform. Uses a dedicated service name
    // and cleans up after itself, so it never touches a real saved key.
    //
    // Ignored in CI because headless Linux runners have no D-Bus session
    // and Secret Service errors out at `keyring::Entry::new`. Run manually
    // on a workstation (macOS Keychain, Windows Credential Manager, or a
    // Linux desktop with gnome-keyring/kwallet):
    //     cargo test --lib -- --ignored db_key::tests::keyring_roundtrip_dek
    #[test]
    #[ignore]
    fn keyring_roundtrip_dek() {
        let entry = keyring::Entry::new("com.tahlk.app.test", "dek_roundtrip").unwrap();
        let hex = to_hex(&[0xab; 32]);
        entry.set_password(&hex).unwrap();
        assert_eq!(entry.get_password().unwrap(), hex);
        entry.delete_credential().unwrap();
    }
}
