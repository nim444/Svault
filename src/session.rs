/// File-based lock/unlock for the no-daemon path.
///
/// The session caches the vault's **derived key** (32 bytes, hex-encoded) in
/// `.svault/<name>/.session` (mode 0600 on Unix) — never the passphrase. This
/// is deliberate (finding #4): a stolen `.session` lets an attacker open this
/// one vault (same as before), but it no longer leaks the reusable passphrase,
/// which may protect other vaults or services. The daemon (keys in memory, no
/// file) remains the preferred path when it's running; this is the fallback.
use anyhow::Result;
use std::path::{Path, PathBuf};

fn session_path(vault_dir: &Path) -> PathBuf {
    vault_dir.join(".session")
}

/// Cache the derived key (hex) and mark the vault unlocked. Written atomically
/// with mode 0600 on Unix so it's never world-readable.
pub fn unlock_with_key(vault_dir: &Path, key: &[u8; 32]) -> Result<()> {
    let path = session_path(vault_dir);
    let encoded = hex::encode(key);

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
        f.write_all(encoded.as_bytes())?;
    }

    #[cfg(not(unix))]
    std::fs::write(&path, &encoded)?;

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

/// Returns true if the vault has an active session holding a usable key. A
/// `.session` that exists but doesn't decode to a 32-byte key (e.g. a stale
/// pre-0.6 file that cached a passphrase) counts as locked, so status and the
/// prompt paths agree.
pub fn is_unlocked(vault_dir: &Path) -> bool {
    get_key(vault_dir).is_some()
}

/// Read the cached derived key from the session file. Returns `None` if the
/// file is missing or doesn't hold a valid 32-byte hex key (e.g. a stale
/// pre-0.6 session that cached a passphrase) — the caller then treats the vault
/// as locked and re-prompts.
pub fn get_key(vault_dir: &Path) -> Option<[u8; 32]> {
    let path = session_path(vault_dir);
    let contents = std::fs::read_to_string(&path).ok()?;
    let bytes = hex::decode(contents.trim()).ok()?;
    bytes.try_into().ok()
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
    fn unlock_caches_key_then_lock_clears() {
        let dir = TempDir::new().unwrap();
        let vault_dir = dir.path().join("v");
        std::fs::create_dir_all(&vault_dir).unwrap();

        assert!(!is_unlocked(&vault_dir));

        let key = [7u8; 32];
        unlock_with_key(&vault_dir, &key).unwrap();
        assert!(is_unlocked(&vault_dir));
        assert_eq!(get_key(&vault_dir), Some(key));

        lock(&vault_dir).unwrap();
        assert!(!is_unlocked(&vault_dir));
        assert_eq!(get_key(&vault_dir), None);
    }

    #[test]
    fn session_never_contains_a_passphrase() {
        // The on-disk session must be a hex-encoded key, not the passphrase.
        let dir = TempDir::new().unwrap();
        let vault_dir = dir.path().join("v");
        std::fs::create_dir_all(&vault_dir).unwrap();
        unlock_with_key(&vault_dir, &[0xABu8; 32]).unwrap();
        let raw = std::fs::read_to_string(session_path(&vault_dir)).unwrap();
        assert_eq!(raw.trim(), "ab".repeat(32));
        // A stale passphrase-style session is rejected as not-a-key.
        std::fs::write(session_path(&vault_dir), "hunter2").unwrap();
        assert_eq!(get_key(&vault_dir), None);
    }

    #[test]
    fn lock_all_locks_every_unlocked_vault() {
        let svault = TempDir::new().unwrap();
        let a = svault.path().join("a");
        let b = svault.path().join("b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        unlock_with_key(&a, &[1u8; 32]).unwrap();
        unlock_with_key(&b, &[2u8; 32]).unwrap();

        assert_eq!(lock_all(svault.path()).unwrap(), 2);
        assert!(!is_unlocked(&a));
        assert!(!is_unlocked(&b));
        // Nothing left to lock the second time.
        assert_eq!(lock_all(svault.path()).unwrap(), 0);
    }
}
