//! Shared OS-keychain entry construction.
//!
//! Two modules hold a secret in the OS secure store (Keychain /
//! Credential Manager / Secret Service), and each had its own copy of the
//! service constant plus an identical `keyring_entry()` wrapper:
//!   - `db_key.rs`    → the SQLCipher database encryption key (DEK)
//!   - `lock.rs`      → the idle-lock PIN hash
//!
//! (The retired Anthropic BYOK key used to be a third; managed mode holds no
//! user-supplied credential — the device proxy token lives in the `kv` table,
//! guarded like a secret, not in the OS keychain.)
//!
//! Only the *service* name and the constructor are shared here. **Each
//! module keeps its own item/user constant** (`db_encryption_key`,
//! `lock_pin_hash`) rather than centralizing them: those distinct names are
//! what keep the secrets in separate keychain items, so one being read,
//! rotated, or cleared cannot touch another. That separation is a security
//! boundary, not incidental structure — do not consolidate the user constants
//! here.

use crate::errors::AppError;

/// Keychain service name, shared by every Tahlk secret. Matches the app's
/// bundle identifier so the items group under one entry in the OS keychain
/// UI. Changing this orphans every existing stored secret.
pub(crate) const SERVICE: &str = "com.tahlk.app";

/// Build a keychain entry for one item under Tahlk's service. `user` is the
/// caller's own item constant — see the module doc on why those stay put.
pub(crate) fn entry(user: &str) -> Result<keyring::Entry, AppError> {
    keyring::Entry::new(SERVICE, user).map_err(AppError::internal_from)
}

#[cfg(test)]
mod tests {
    /// The item names must stay distinct — if any two collided, one secret
    /// would silently overwrite another in the OS keychain (e.g. setting a
    /// lock PIN would clobber the DEK and lock the user out of their own
    /// database). This pins that invariant at the one place that can see all
    /// of them.
    #[test]
    fn every_keychain_item_name_is_distinct() {
        let names = [
            crate::db_key::KEYRING_USER,
            crate::lock::KEYRING_USER,
        ];
        for (i, a) in names.iter().enumerate() {
            assert!(!a.is_empty(), "keychain item name must not be empty");
            for b in &names[i + 1..] {
                assert_ne!(a, b, "two keychain items share the name {a} — they would collide");
            }
        }
    }
}
