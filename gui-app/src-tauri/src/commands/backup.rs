//! Backup & recovery (10). Export/import move a vault as an encrypted, checksummed
//! bundle; recovery codes re-attach a vault or reset a forgotten master.

use serde::Serialize;

use crate::commands::common::{dir_for, leaf, open_vault, require_master};
use crate::error::{emsg, CmdResult};

use svault_ai::core::meta::VaultMeta;
use svault_ai::core::vault::Vault;
use svault_ai::core::{master, portable, recovery, secfile, session, usage, vault};

/// Export a vault to an encrypted bundle at `path` (owner-only — it carries the
/// wrapped key).
#[tauri::command]
pub fn export_vault(leaf_id: String, path: String) -> CmdResult<()> {
    let dir = dir_for(&leaf_id)?;
    let meta = VaultMeta::load_unverified(&dir).map_err(emsg)?;
    let json = portable::build_bundle(&dir, &meta.name, &meta.storage).map_err(emsg)?;
    secfile::write_owner_only(std::path::Path::new(&path), json.as_bytes()).map_err(emsg)?;
    usage::human(&dir, "export", None);
    Ok(())
}

/// Import a bundle and re-attach it to this machine's master using its recovery
/// code. Returns the (possibly suffixed) imported vault name.
#[tauri::command]
pub fn import_vault(
    path: String,
    name: Option<String>,
    recovery_code: String,
) -> CmdResult<String> {
    let raw = std::fs::read_to_string(&path).map_err(emsg)?;
    let bundle = portable::parse_bundle(&raw).map_err(emsg)?;
    let base = vault::svault_dir();
    let desired = name.unwrap_or_else(|| bundle.name.clone());
    let target = portable::unique_vault_name(&base, &desired);

    portable::import_bundle_as(&raw, &base, &target).map_err(emsg)?;
    let dir = base.join(&target);

    if !recovery::exists(&dir) {
        let _ = std::fs::remove_dir_all(&dir);
        return Err("bundle has no recovery file — cannot attach to your master".into());
    }
    let dek = match recovery::unlock_with_code(&dir, &recovery_code) {
        Ok(k) => k,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(emsg(e));
        }
    };
    let v = Vault::open_with_key(&dir, dek).map_err(emsg)?;
    if target != bundle.name {
        let mut meta = v.meta.clone();
        meta.name = target.clone();
        v.save_meta(&meta).map_err(emsg)?;
    }
    let m = require_master()?;
    m.wrap_dek(&dir, v.key()).map_err(emsg)?;
    let _ = session::unlock_with_key(&dir, v.key().bytes());
    usage::human(&dir, "import", None);
    Ok(target)
}

/// Reset a forgotten master using the master recovery code, then set a new
/// passphrase. The signed-out "lost passphrase" path.
#[tauri::command]
pub fn recover_master(code: String, new_passphrase: String) -> CmdResult<()> {
    master::recover(&code, &new_passphrase).map_err(emsg)?;
    Ok(())
}

#[derive(Serialize)]
pub struct RecoveryStatus {
    pub vault_leaf: String,
    pub vault_name: String,
    pub has_code: bool,
}

#[tauri::command]
pub fn recovery_status() -> Vec<RecoveryStatus> {
    vault::list_vault_dirs()
        .into_iter()
        .map(|dir| {
            let name = VaultMeta::load_unverified(&dir)
                .map(|m| m.name)
                .unwrap_or_else(|_| leaf(&dir));
            RecoveryStatus {
                vault_leaf: leaf(&dir),
                vault_name: name,
                has_code: recovery::exists(&dir),
            }
        })
        .collect()
}

/// Rotate a vault's recovery code: generate a new one, re-wrap the data key under
/// it, invalidating the old. Shown once.
#[tauri::command]
pub fn rotate_code(leaf_id: String) -> CmdResult<String> {
    let (dir, v) = open_vault(&leaf_id)?;
    let code = recovery::generate_code();
    recovery::write(&dir, v.key(), &code).map_err(emsg)?;
    usage::human(&dir, "recovery.rotate", None);
    Ok(code)
}
