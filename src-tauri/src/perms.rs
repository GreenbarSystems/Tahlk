//! Filesystem permission helpers.
//!
//! Every file this app creates that either holds PHI (audio, transcript
//! scratch, encrypted DB) or acts as a keychain-adjacent artifact must be
//! restricted to the owning user on Unix. `File::create` defaults to `0644`
//! on Unix, which lets any other local user (or a curious backup daemon)
//! read the raw bytes. Audit M1 traced this back to `audio.wav` and the
//! transcript `.txt` scratch file; the same rule already applied to the
//! encrypted DB via an ad-hoc helper in `db.rs`, so we centralize it here
//! and reuse it everywhere.
//!
//! Windows: NTFS ACLs are handled at the app-data-dir level by the OS user
//! profile, so this helper is a no-op there.

use std::path::Path;

/// Best-effort chmod to `0600` on Unix; no-op on Windows.
///
/// Errors are intentionally swallowed. If the file has already been unlinked
/// or the FS doesn't support permissions (network mounts, temp filesystems),
/// there's nothing sensible to do at the call site \u2014 the file will still
/// exist with the earlier default mode, which is no worse than the pre-fix
/// state. Callers must not rely on this for security-critical enforcement:
/// this is defense-in-depth on top of app-data-dir permissions.
pub(crate) fn chmod_0600_unix(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(path, perms);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path; // suppress unused-var warning on Windows
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    // Verify the helper actually flips the mode to 0600 on Unix. Uses a
    // tempfile so parallel tests don't collide.
    #[test]
    fn chmod_0600_unix_sets_owner_only_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("phi_audio.wav");
        std::fs::write(&path, b"fake audio").unwrap();

        // Sanity: default write above lands somewhere in the 0644 family,
        // which is exactly the problem we're fixing.
        let before = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_ne!(before, 0o600, "test setup produced 0600 already; nothing to prove");

        chmod_0600_unix(&path);

        let after = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(after, 0o600, "expected 0600, got {:o}", after);
    }

    // Missing path must not panic \u2014 callers use this on RAII cleanup paths
    // where the file may already be gone.
    #[test]
    fn chmod_0600_unix_ignores_missing_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does_not_exist.wav");
        // No assertion \u2014 the test passes if the call doesn't panic.
        chmod_0600_unix(&path);
    }
}
