//! Pending approvals (09). Sealed secrets await a human; an agent can never
//! self-clear. "Approve & unseal" clears the seal (mirrors `svault approve`);
//! "Keep denied" is a frontend dismiss (no state change).

use serde::Serialize;

use crate::commands::common::{leaf, open_vault};
use crate::error::{emsg, CmdResult};

use svault_ai::core::meta::VaultMeta;
use svault_ai::core::{master, usage, vault};

#[derive(Serialize)]
pub struct PendingItem {
    pub vault_leaf: String,
    pub vault_name: String,
    pub secret: String,
    pub scope: String,
    pub tier: String,
    pub sealed_at: String,
    pub trigger: String,
    pub last_caller: String,
    pub denials: u32,
}

/// Every sealed secret across all vaults.
#[tauri::command]
pub fn pending() -> CmdResult<Vec<PendingItem>> {
    let m = master::open_from_session().ok_or("master is locked — sign in again")?;
    let mut out = Vec::new();

    for dir in vault::list_vault_dirs() {
        if !master::vault_has_keyslot(&dir) {
            continue;
        }
        let Ok(dek) = m.unwrap_dek(&dir) else {
            continue;
        };
        let Ok(v) = vault::Vault::open_with_key(&dir, dek) else {
            continue;
        };
        if v.policy.seals.is_empty() {
            continue;
        }
        let vault_name = VaultMeta::load_unverified(&dir)
            .map(|m| m.name)
            .unwrap_or_else(|_| leaf(&dir));
        for (secret, seal) in &v.policy.seals {
            let rule = v.policy.classify(secret).cloned().unwrap_or_default();
            out.push(PendingItem {
                vault_leaf: leaf(&dir),
                vault_name: vault_name.clone(),
                secret: secret.clone(),
                scope: rule.scope,
                tier: rule.tier.to_string(),
                sealed_at: seal.sealed_at.clone(),
                trigger: seal.trigger.clone(),
                last_caller: seal.last_caller.clone(),
                denials: seal.denials,
            });
        }
    }
    Ok(out)
}

/// Clear a seal so agents may request the secret again. Human-only.
#[tauri::command]
pub fn approve_unseal(leaf_id: String, secret: String) -> CmdResult<()> {
    let (dir, v) = open_vault(&leaf_id)?;
    if !v.policy.seals.contains_key(&secret) {
        return Err(format!("'{secret}' is not sealed"));
    }
    let mut policy = v.policy.clone();
    policy.seals.remove(&secret);
    v.save_policy(&policy).map_err(emsg)?;
    usage::human(&dir, "seal.cleared", Some(&secret));
    Ok(())
}
