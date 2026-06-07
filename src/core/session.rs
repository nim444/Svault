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
use std::time::{SystemTime, UNIX_EPOCH};

/// Default hard re-auth cap: a cached session is unconditionally invalid once it
/// is this old, regardless of activity. The master, keyring, and per-vault file
/// sessions all honor it, and the daemon uses it as its in-memory hard cap
/// default. This bounds the window in which an already-unlocked vault (e.g. one
/// an AI was prompted into via the CLI) can be read before the master must be
/// re-entered. Configurable via the keyring's `lock.max_unlocked_secs` (clamped
/// to [`MIN_SESSION_CAP_SECS`]..=[`MAX_SESSION_CAP_SECS`]); the cap that applied
/// at unlock time is stamped into each session file, so reads never need the
/// (possibly locked) keyring to decide expiry.
pub const MAX_SESSION_SECS: u64 = 6 * 60 * 60;

/// Floor for a configured re-auth cap — below this, unlocks churn constantly.
pub const MIN_SESSION_CAP_SECS: u64 = 15 * 60;
/// Ceiling for a configured re-auth cap — an unlocked store never outlives a week.
pub const MAX_SESSION_CAP_SECS: u64 = 7 * 24 * 60 * 60;

/// Clamp a configured cap into the supported range.
pub fn clamp_session_cap(secs: u64) -> u64 {
    secs.clamp(MIN_SESSION_CAP_SECS, MAX_SESSION_CAP_SECS)
}

/// The re-auth cap currently in force for NEW sessions: the keyring's
/// `lock.max_unlocked_secs` (clamped) when the keyring is unlocked, else the
/// built-in default. Reads of existing sessions use the cap stamped into the
/// session file instead, so a locked keyring never blocks an expiry decision.
pub fn effective_session_cap() -> u64 {
    crate::core::keyring::open_from_session()
        .map(|kr| clamp_session_cap(kr.data.lock.max_unlocked_secs))
        .unwrap_or(MAX_SESSION_SECS)
}

fn session_path(vault_dir: &Path) -> PathBuf {
    vault_dir.join(".session")
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Overwrite a session file with zeros and delete it. Used by `lock` and on
/// expiry so a cached key never lingers on disk.
pub fn secure_remove(path: &Path) -> std::io::Result<()> {
    if path.exists() {
        if let Ok(meta) = std::fs::metadata(path) {
            let _ = std::fs::write(path, vec![0u8; meta.len() as usize]);
        }
        std::fs::remove_file(path)?;
    }
    Ok(())
}

/// Write a session payload — `"<unlocked_at_unix_secs> <cap_secs>\n<hex_key>"` —
/// owner-only (mode 0600 on Unix, an icacls owner-only ACL on Windows, #4). The
/// timestamp + cap are what let reads enforce the re-auth cap. Never stores a
/// passphrase. The cap is resolved from the keyring config when it is unlocked
/// (see [`effective_session_cap`]); use [`write_session_key_with_cap`] when the
/// caller already holds the applicable cap.
pub fn write_session_key(path: &Path, key: &[u8; 32]) -> Result<()> {
    write_session_key_with_cap(path, key, effective_session_cap())
}

/// [`write_session_key`] with an explicit cap (already clamped by the caller or
/// clamped here). Used by the keyring's own unlock, which can read its config
/// directly with the key in hand before any session exists.
pub fn write_session_key_with_cap(path: &Path, key: &[u8; 32], cap_secs: u64) -> Result<()> {
    let cap = clamp_session_cap(cap_secs);
    let payload = format!("{} {}\n{}", now_secs(), cap, hex::encode(key));
    crate::core::secfile::write_owner_only(path, payload.as_bytes())?;
    Ok(())
}

/// Read the cached key from a session file, or `None` if it is missing,
/// malformed (e.g. a pre-timestamp or pre-0.6 file), or older than its stamped
/// re-auth cap (pre-cap files fall back to [`MAX_SESSION_SECS`]). An expired
/// file is best-effort removed so status and prompt paths agree that the store
/// is locked.
pub fn read_session_key(path: &Path) -> Option<[u8; 32]> {
    let contents = std::fs::read_to_string(path).ok()?;
    let (ts_line, hex_key) = contents.trim().split_once('\n')?;
    let mut parts = ts_line.split_whitespace();
    let unlocked_at: u64 = parts.next()?.parse().ok()?;
    let cap: u64 = parts
        .next()
        .and_then(|c| c.parse().ok())
        .map(clamp_session_cap)
        .unwrap_or(MAX_SESSION_SECS);
    if now_secs().saturating_sub(unlocked_at) >= cap {
        let _ = secure_remove(path);
        return None;
    }
    hex::decode(hex_key.trim()).ok()?.try_into().ok()
}

/// Cache the derived key and mark the vault unlocked. Owner-only, timestamped so
/// it expires after [`MAX_SESSION_SECS`].
pub fn unlock_with_key(vault_dir: &Path, key: &[u8; 32]) -> Result<()> {
    write_session_key(&session_path(vault_dir), key)
}

/// Clear the session — vault is locked.
pub fn lock(vault_dir: &Path) -> Result<()> {
    secure_remove(&session_path(vault_dir))?;
    Ok(())
}

/// Returns true if the vault has an active, non-expired session holding a usable
/// key. A `.session` that is missing, malformed (e.g. a stale pre-0.6 file that
/// cached a passphrase), or past the hard cap counts as locked, so status and
/// the prompt paths agree.
pub fn is_unlocked(vault_dir: &Path) -> bool {
    get_key(vault_dir).is_some()
}

/// Read the cached derived key from the session file. Returns `None` if the file
/// is missing, malformed, or older than [`MAX_SESSION_SECS`] — the caller then
/// treats the vault as locked and re-prompts.
pub fn get_key(vault_dir: &Path) -> Option<[u8; 32]> {
    read_session_key(&session_path(vault_dir))
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
        // The on-disk session is "<unix_secs>\n<hex_key>" — never the passphrase.
        let dir = TempDir::new().unwrap();
        let vault_dir = dir.path().join("v");
        std::fs::create_dir_all(&vault_dir).unwrap();
        unlock_with_key(&vault_dir, &[0xABu8; 32]).unwrap();
        let raw = std::fs::read_to_string(session_path(&vault_dir)).unwrap();
        let (_ts, key) = raw.trim().split_once('\n').unwrap();
        assert_eq!(key, "ab".repeat(32));
        // A stale passphrase-style session (no timestamp line) is not-a-key.
        std::fs::write(session_path(&vault_dir), "hunter2").unwrap();
        assert_eq!(get_key(&vault_dir), None);
    }

    #[test]
    fn session_expires_past_the_hard_cap() {
        let dir = TempDir::new().unwrap();
        let vault_dir = dir.path().join("v");
        std::fs::create_dir_all(&vault_dir).unwrap();
        unlock_with_key(&vault_dir, &[5u8; 32]).unwrap();
        assert!(is_unlocked(&vault_dir));

        // Backdate the unlock timestamp to just past the hard cap.
        let path = session_path(&vault_dir);
        let stale = now_secs().saturating_sub(MAX_SESSION_SECS + 1);
        std::fs::write(&path, format!("{}\n{}", stale, "05".repeat(32))).unwrap();

        // Reads back as locked, and the expired file is cleaned up.
        assert_eq!(get_key(&vault_dir), None);
        assert!(!is_unlocked(&vault_dir));
        assert!(!path.exists());
    }

    #[test]
    fn session_honors_its_stamped_cap() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".session");

        // A configured 1h cap is stamped into the file and enforced on read.
        write_session_key_with_cap(&path, &[9u8; 32], 3600).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.starts_with(&format!("{} 3600\n", raw.split(' ').next().unwrap())));
        assert_eq!(read_session_key(&path), Some([9u8; 32]));

        // Backdate past the stamped cap (but well under the 6h default): expired.
        let stale = now_secs() - 3601;
        std::fs::write(&path, format!("{stale} 3600\n{}", "09".repeat(32))).unwrap();
        assert_eq!(read_session_key(&path), None);
        assert!(!path.exists());

        // An out-of-range stamped cap is clamped on read.
        std::fs::write(
            &path,
            format!("{} 999999999\n{}", now_secs(), "09".repeat(32)),
        )
        .unwrap();
        let stale = now_secs() - (MAX_SESSION_CAP_SECS + 1);
        std::fs::write(&path, format!("{stale} 999999999\n{}", "09".repeat(32))).unwrap();
        assert_eq!(read_session_key(&path), None);

        // A pre-cap (legacy) file falls back to the 6h default.
        let fresh = now_secs() - (MAX_SESSION_SECS - 60);
        std::fs::write(&path, format!("{fresh}\n{}", "09".repeat(32))).unwrap();
        assert_eq!(read_session_key(&path), Some([9u8; 32]));
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
