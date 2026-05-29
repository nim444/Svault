//! Owner-only file + directory writes for at-rest-sensitive material.
//!
//! On Unix this means mode `0600` (files) / `0700` (dirs), written atomically.
//! On Windows there is no mode, so we strip inherited ACLs and grant only the
//! current user via `icacls` (best-effort). Used for `recovery.enc`, export
//! bundles, the session key file, and the `.svault/` tree (findings #14, #16,
//! and the Windows half of #4).

use std::path::Path;

/// Write `data` to `path` so only the owner can read or write it.
pub fn write_owner_only(path: &Path, data: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(data)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data)?;
        restrict_to_owner(path);
    }
    Ok(())
}

/// Create `dir` (and parents) and make it owner-only traversable.
pub fn create_dir_owner_only(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    restrict_to_owner(dir);
    Ok(())
}

/// Windows: best-effort owner-only ACL via `icacls` (no-op if it fails). Mode
/// bits don't exist on Windows, so this is the closest equivalent to `0600`.
#[cfg(windows)]
fn restrict_to_owner(path: &Path) {
    if let Ok(user) = std::env::var("USERNAME") {
        let _ = std::process::Command::new("icacls")
            .arg(path)
            .arg("/inheritance:r")
            .arg("/grant:r")
            .arg(format!("{user}:F"))
            .output();
    }
}

/// Non-Windows, non-Unix targets (none shipped today): nothing to restrict.
#[cfg(all(not(unix), not(windows)))]
fn restrict_to_owner(_path: &Path) {}
