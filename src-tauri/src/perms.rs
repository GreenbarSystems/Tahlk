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

// L9 (optional hardening): create-then-chmod (the chmod_0600_unix pattern
// below) has a brief window between the file's creation with the process
// umask's default mode (typically 0644 — world/group-readable) and the
// chmod call narrowing it to 0600. For files we control the creation of
// ourselves (unlike the whisper.cpp sidecar's .txt output, which we don't),
// write_0600_unix opens with O_CREAT and mode 0600 in a single syscall via
// OpenOptions::mode(), closing that window entirely rather than narrowing
// it after the fact.
#[cfg(unix)]
pub(crate) async fn write_0600_unix(
    path: &Path,
    contents: &[u8],
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .await?;
    file.write_all(contents).await?;
    file.flush().await
}

#[cfg(not(unix))]
pub(crate) async fn write_0600_unix(
    path: &Path,
    contents: &[u8],
) -> std::io::Result<()> {
    tokio::fs::write(path, contents).await
}

/// Best-effort chmod to `0600` on Unix; no-op on Windows.
///
/// Errors are intentionally swallowed. If the file has already been unlinked
/// or the FS doesn't support permissions (network mounts, temp filesystems),
/// there's nothing sensible to do at the call site — the file will still
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

    // Missing path must not panic — callers use this on RAII cleanup paths
    // where the file may already be gone.
    #[test]
    fn chmod_0600_unix_ignores_missing_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does_not_exist.wav");
        // No assertion — the test passes if the call doesn't panic.
        chmod_0600_unix(&path);
    }

    // L9: write_0600_unix must create the file at 0600 directly — not at
    // the umask-derived default and then narrow it. There's no intermediate
    // state to observe in a single-process test (the whole point is that
    // there's only one syscall), so this pins the *result*: immediately
    // after the await returns, the mode is already 0600.
    #[tokio::test]
    async fn write_0600_unix_creates_the_file_at_owner_only_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("phi_scratch.wav");

        write_0600_unix(&path, b"fake plaintext audio").await.unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600 immediately on creation, got {:o}", mode);
    }

    #[tokio::test]
    async fn write_0600_unix_writes_the_exact_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("phi_scratch.wav");
        let payload = b"some fake wav bytes, not really PCM";

        write_0600_unix(&path, payload).await.unwrap();

        let on_disk = std::fs::read(&path).unwrap();
        assert_eq!(on_disk, payload);
    }

    // Overwriting an existing file (e.g. a retried transcription reusing the
    // same random suffix — astronomically unlikely but not impossible)
    // must truncate rather than append or leave old bytes trailing, since
    // `.truncate(true)` is set explicitly.
    #[tokio::test]
    async fn write_0600_unix_truncates_a_preexisting_longer_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("phi_scratch.wav");
        std::fs::write(&path, b"this is a much longer preexisting payload").unwrap();

        write_0600_unix(&path, b"short").await.unwrap();

        let on_disk = std::fs::read(&path).unwrap();
        assert_eq!(on_disk, b"short");
    }
}
