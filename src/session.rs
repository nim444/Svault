/// File-based lock/unlock simulation for MVP.
///
/// The passphrase is stored in .svault/<name>/.session (mode 0600).
/// This is NOT the production daemon — that's Step 3.
/// Purpose: simulate the unlock-once-use-many-times UX.
use anyhow::Result;
use std::path::{Path, PathBuf};

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
            .write(true)
            .create(true)
            .truncate(true)
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
    std::fs::read_to_string(&path)
        .ok()
        .map(|s| s.trim().to_string())
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn unlock_caches_then_lock_clears() {
        let dir = TempDir::new().unwrap();
        let vault_dir = dir.path().join("v");
        std::fs::create_dir_all(&vault_dir).unwrap();

        assert!(!is_unlocked(&vault_dir));

        unlock(&vault_dir, "my-pass").unwrap();
        assert!(is_unlocked(&vault_dir));
        assert_eq!(get_passphrase(&vault_dir).as_deref(), Some("my-pass"));

        lock(&vault_dir).unwrap();
        assert!(!is_unlocked(&vault_dir));
        assert_eq!(get_passphrase(&vault_dir), None);
    }

    #[test]
    fn lock_all_locks_every_unlocked_vault() {
        let svault = TempDir::new().unwrap();
        let a = svault.path().join("a");
        let b = svault.path().join("b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        unlock(&a, "pa").unwrap();
        unlock(&b, "pb").unwrap();

        assert_eq!(lock_all(svault.path()).unwrap(), 2);
        assert!(!is_unlocked(&a));
        assert!(!is_unlocked(&b));
        // Nothing left to lock the second time.
        assert_eq!(lock_all(svault.path()).unwrap(), 0);
    }
}
