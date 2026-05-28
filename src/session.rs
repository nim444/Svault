/// File-based lock/unlock simulation for MVP.
///
/// The passphrase is stored in .svault/<name>/.session (mode 0600).
/// This is NOT the production daemon — that's Step 3.
/// Purpose: simulate the unlock-once-use-many-times UX.

use anyhow::Result;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn session_path(vault_dir: &Path) -> PathBuf {
    vault_dir.join(".session")
}

/// Store passphrase and mark vault as unlocked.
/// File is created atomically with mode 0600 — never visible at permissive permissions.
pub fn unlock(vault_dir: &Path, passphrase: &str) -> Result<()> {
    let path = session_path(vault_dir);

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true).create(true).truncate(true)
            .mode(0o600)
            .open(&path)?;
        f.write_all(passphrase.as_bytes())?;
    }

    #[cfg(not(unix))]
    std::fs::write(&path, passphrase)?;

    Ok(())
}

/// Clear the session — vault is locked.
pub fn lock(vault_dir: &Path) -> Result<()> {
    let path = session_path(vault_dir);
    if path.exists() {
        // Overwrite with zeros before deleting
        let len = std::fs::metadata(&path)?.len() as usize;
        std::fs::write(&path, vec![0u8; len])?;
        std::fs::remove_file(&path)?;
    }
    Ok(())
}

/// Returns true if the vault has an active session.
pub fn is_unlocked(vault_dir: &Path) -> bool {
    session_path(vault_dir).exists()
}

/// Read cached passphrase from session file.
pub fn get_passphrase(vault_dir: &Path) -> Option<String> {
    let path = session_path(vault_dir);
    std::fs::read_to_string(&path).ok().map(|s| s.trim().to_string())
}

/// Lock all vaults in .svault/
pub fn lock_all(svault_dir: &Path) -> Result<usize> {
    let mut count = 0;
    let Ok(entries) = std::fs::read_dir(svault_dir) else {
        return Ok(0);
    };
    for entry in entries.flatten() {
        let vault_dir = entry.path();
        if vault_dir.is_dir() && session_path(&vault_dir).exists() {
            lock(&vault_dir)?;
            count += 1;
        }
    }
    Ok(count)
}
