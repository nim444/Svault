//! Shared helpers for the vault-facing commands. Vaults are identified across the
//! GUI by their **leaf** (directory name) — stable and matching how the daemon
//! keys them — while `meta.name` is only a display label.

use std::path::{Path, PathBuf};

use crate::error::CmdResult;
use svault_cli::core::policy::Tier;
use svault_cli::core::{keyring, master, vault, vault::Vault};

/// Directory leaf (the vault's id) for a path.
pub fn leaf(dir: &Path) -> String {
    dir.file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The master, from the cached login session. Every vault read/write needs it:
/// we re-derive the vault's data key from the master keyslot rather than relying
/// on the daemon (which never hands the raw key back).
pub fn require_master() -> CmdResult<master::Master> {
    master::open_from_session().ok_or_else(|| "master is locked — sign in again".to_string())
}

/// Resolve a vault leaf to its directory, erroring if it isn't a known vault.
pub fn dir_for(leaf_id: &str) -> CmdResult<PathBuf> {
    vault::list_vault_dirs()
        .into_iter()
        .find(|d| leaf(d) == leaf_id)
        .ok_or_else(|| format!("vault '{leaf_id}' not found"))
}

/// Open a vault for reading/writing by re-deriving its data key from the master.
pub fn open_vault(leaf_id: &str) -> CmdResult<(PathBuf, Vault)> {
    let dir = dir_for(leaf_id)?;
    let m = require_master()?;
    if !master::vault_has_keyslot(&dir) {
        return Err(format!("vault '{leaf_id}' is not wrapped under the master"));
    }
    let dek = m.unwrap_dek(&dir).map_err(|e| e.to_string())?;
    let v = Vault::open_with_key(&dir, dek).map_err(|e| e.to_string())?;
    Ok((dir, v))
}

/// Open the keyring for read/write, creating it on first use. The keyring is a
/// keyslot store opened under the master (no separate passphrase); this mirrors
/// `keyring init` + `keyring unlock` and caches the session.
pub fn open_or_init_keyring() -> CmdResult<keyring::Keyring> {
    if let Some(kr) = keyring::open_from_session() {
        return Ok(kr);
    }
    let m = require_master()?;
    if keyring::exists() {
        let dek = m.unwrap_keyring_dek().map_err(|e| e.to_string())?;
        keyring::unlock_session(dek.bytes()).map_err(|e| e.to_string())?;
        keyring::open_from_session().ok_or_else(|| "could not open the keyring".to_string())
    } else {
        let dek = master::new_dek();
        let kr = keyring::Keyring::init_with_key(dek).map_err(|e| e.to_string())?;
        m.wrap_keyring_dek(kr.key()).map_err(|e| e.to_string())?;
        keyring::unlock_session(kr.key().bytes()).map_err(|e| e.to_string())?;
        Ok(kr)
    }
}

/// Parse a tier label; defaults to low on an unknown value.
pub fn parse_tier(s: &str) -> Tier {
    match s.trim().to_lowercase().as_str() {
        "high" => Tier::High,
        "medium" | "med" => Tier::Medium,
        _ => Tier::Low,
    }
}
