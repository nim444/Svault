//! Vault list (03) and vault config (04) commands. All policy fields are written
//! into the vault's AES-256-GCM-encrypted policy (inside `vault.enc`); only the
//! non-sensitive metadata lands in the signed `meta.yaml`.

use serde::{Deserialize, Serialize};

use crate::commands::common::{dir_for, leaf, open_vault, parse_tier, require_master};
use crate::error::{emsg, CmdResult};

use svault_ai::core::meta::{AccessConfig, AllowAgent, LoginMethod, VaultMeta, VaultSettings};
use svault_ai::core::policy::VaultPolicyData;
use svault_ai::core::{master, recovery, session, usage, vault, vault::Vault};
use svault_ai::daemon::client;

#[derive(Serialize)]
pub struct VaultSummary {
    pub leaf: String,
    pub name: String,
    pub description: String,
    pub storage: String,
    pub created_at: String,
    pub unlocked: bool,
    pub secret_count: usize,
    pub default_tier: String,
    pub allow_agent: String,
    pub judge_enabled: bool,
    pub assigned_judge: Option<String>,
    pub sealed_count: usize,
    pub last_activity: Option<i64>,
}

/// The create/edit form. `allow_agent_mode` is "none" | "list" | "all"; the list
/// is used only in "list" mode.
#[derive(Deserialize)]
pub struct VaultForm {
    pub name: String,
    pub description: String,
    pub allow_agent_mode: String,
    #[serde(default)]
    pub allow_agent_list: Vec<String>,
    pub rate_limit: String,
    pub autolock: bool,
    pub autolock_timer: String,
    pub login_method: String,
    pub default_tier: String,
    pub judge_enabled: bool,
    #[serde(default)]
    pub assigned_judge: Option<String>,
}

/// The edit form pre-fill: the same fields read back from an existing vault.
#[derive(Serialize)]
pub struct VaultFormData {
    pub leaf: String,
    pub name: String,
    pub description: String,
    pub allow_agent_mode: String,
    pub allow_agent_list: Vec<String>,
    pub rate_limit: String,
    pub autolock: bool,
    pub autolock_timer: String,
    pub login_method: String,
    pub default_tier: String,
    pub judge_enabled: bool,
    pub assigned_judge: Option<String>,
}

#[derive(Serialize)]
pub struct CreateResult {
    /// One-time vault recovery code — shown once, never stored in plaintext.
    pub recovery_code: String,
}

fn allow_agent_display(a: &AllowAgent) -> String {
    a.to_string()
}

fn allow_agent_from(mode: &str, list: &[String]) -> AllowAgent {
    match mode {
        "all" => AllowAgent::Bool(true),
        "list" => AllowAgent::List(list.to_vec()),
        _ => AllowAgent::Bool(false),
    }
}

fn allow_agent_to_mode(a: &AllowAgent) -> (String, Vec<String>) {
    match a {
        AllowAgent::Bool(true) => ("all".into(), vec![]),
        AllowAgent::Bool(false) => ("none".into(), vec![]),
        AllowAgent::List(l) => ("list".into(), l.clone()),
    }
}

fn login_method_from(s: &str) -> LoginMethod {
    match s {
        "yubikey" => LoginMethod::Yubikey,
        _ => LoginMethod::Passphrase,
    }
}

#[tauri::command]
pub fn list_vaults() -> CmdResult<Vec<VaultSummary>> {
    let unlocked_set = unlocked_leaves();
    let m = require_master()?;
    let mut out = Vec::new();

    for dir in vault::list_vault_dirs() {
        let l = leaf(&dir);
        let meta = match VaultMeta::load_unverified(&dir) {
            Ok(m) => m,
            Err(_) => continue,
        };
        // Decrypt the policy via the master keyslot for the rich columns.
        let policy = master::vault_has_keyslot(&dir)
            .then(|| m.unwrap_dek(&dir).ok())
            .flatten()
            .and_then(|dek| Vault::open_with_key(&dir, dek).ok())
            .map(|v| v.policy);

        let (secret_count, default_tier, allow_agent, judge_enabled, assigned_judge, sealed_count) =
            match &policy {
                Some(p) => (
                    p.secrets.iter().filter(|(n, _)| n.as_str() != "*").count(),
                    p.default_tier.to_string(),
                    allow_agent_display(&p.access.allow_agent),
                    p.judge.enabled.unwrap_or(false),
                    p.judge.judge.clone(),
                    p.seals.len(),
                ),
                None => (0, "low".into(), "—".into(), false, None, 0),
            };

        let last_activity = usage::recent(&dir, 1)
            .first()
            .and_then(|e| e.timestamp())
            .map(|t| t.timestamp());

        out.push(VaultSummary {
            leaf: l.clone(),
            name: meta.name,
            description: meta.description,
            storage: meta.storage,
            created_at: meta.created_at,
            unlocked: unlocked_set.contains(&l),
            secret_count,
            default_tier,
            allow_agent,
            judge_enabled,
            assigned_judge,
            sealed_count,
            last_activity,
        });
    }
    out.sort_by_key(|v| v.name.to_lowercase());
    Ok(out)
}

fn unlocked_leaves() -> Vec<String> {
    let mut names = client::unlocked_vaults();
    for dir in vault::list_vault_dirs() {
        let l = leaf(&dir);
        if !names.contains(&l) && session::is_unlocked(&dir) {
            names.push(l);
        }
    }
    names
}

#[tauri::command]
pub fn create_vault(form: VaultForm) -> CmdResult<CreateResult> {
    let name = form.name.trim().to_string();
    if name.is_empty() {
        return Err("vault name is required".into());
    }
    let vault_dir = vault::svault_dir().join(&name);
    if vault_dir.exists() {
        return Err(format!("a vault named '{name}' already exists"));
    }

    let m = require_master()?;

    let meta = VaultMeta::new(
        name.clone(),
        form.description.trim().to_string(),
        VaultSettings {
            autolock: form.autolock,
            autolock_timer: form.autolock_timer.clone(),
            login_method: login_method_from(&form.login_method),
        },
    );
    let mut policy = VaultPolicyData {
        access: AccessConfig {
            allow_agent: allow_agent_from(&form.allow_agent_mode, &form.allow_agent_list),
            rate_limit: form.rate_limit.clone(),
        },
        default_tier: parse_tier(&form.default_tier),
        ..VaultPolicyData::default()
    };
    policy.judge.enabled = Some(form.judge_enabled);
    policy.judge.judge = form.assigned_judge.clone();

    let dek = master::new_dek();
    let v = Vault::init_with_key(&vault_dir, dek, meta, policy).map_err(emsg)?;
    m.wrap_dek(&vault_dir, v.key()).map_err(emsg)?;

    // Cache the key so the new vault shows unlocked: daemon if up, else session.
    let l = leaf(&vault_dir);
    match client::unlock_with_key(&l, v.key().bytes()) {
        Some(Ok(())) => {}
        _ => session::unlock_with_key(&vault_dir, v.key().bytes()).map_err(emsg)?,
    }

    let recovery_code = recovery::generate_code();
    recovery::write(&vault_dir, v.key(), &recovery_code).map_err(emsg)?;
    usage::human(&vault_dir, "vault.create", None);

    Ok(CreateResult { recovery_code })
}

#[tauri::command]
pub fn vault_settings(leaf_id: String) -> CmdResult<VaultFormData> {
    let (_dir, v) = open_vault(&leaf_id)?;
    let (mode, list) = allow_agent_to_mode(&v.policy.access.allow_agent);
    Ok(VaultFormData {
        leaf: leaf_id,
        name: v.meta.name.clone(),
        description: v.meta.description.clone(),
        allow_agent_mode: mode,
        allow_agent_list: list,
        rate_limit: v.policy.access.rate_limit.clone(),
        autolock: v.meta.settings.autolock,
        autolock_timer: v.meta.settings.autolock_timer.clone(),
        login_method: v.meta.settings.login_method.to_string().replace(' ', "_"),
        default_tier: v.policy.default_tier.to_string(),
        judge_enabled: v.policy.judge.enabled.unwrap_or(false),
        assigned_judge: v.policy.judge.judge.clone(),
    })
}

#[tauri::command]
pub fn save_settings(leaf_id: String, form: VaultForm) -> CmdResult<()> {
    let (dir, v) = open_vault(&leaf_id)?;
    let mut meta = v.meta.clone();
    let mut policy = v.policy.clone();

    meta.description = form.description.trim().to_string();
    meta.settings.autolock = form.autolock;
    meta.settings.autolock_timer = form.autolock_timer.clone();
    meta.settings.login_method = login_method_from(&form.login_method);

    policy.access.allow_agent = allow_agent_from(&form.allow_agent_mode, &form.allow_agent_list);
    policy.access.rate_limit = form.rate_limit.clone();
    policy.default_tier = parse_tier(&form.default_tier);
    policy.judge.enabled = Some(form.judge_enabled);
    policy.judge.judge = form.assigned_judge.clone();

    v.save_meta(&meta).map_err(emsg)?;
    v.save_policy(&policy).map_err(emsg)?;
    usage::human(&dir, "settings.update", None);
    Ok(())
}

#[tauri::command]
pub fn unlock_vault(leaf_id: String) -> CmdResult<()> {
    let dir = dir_for(&leaf_id)?;
    let m = require_master()?;
    if !master::vault_has_keyslot(&dir) {
        return Err("vault is not wrapped under the master".into());
    }
    let dek = m.unwrap_dek(&dir).map_err(emsg)?;
    match client::unlock_with_key(&leaf_id, dek.bytes()) {
        Some(Ok(())) => {}
        Some(Err(e)) => return Err(emsg(e)),
        None => session::unlock_with_key(&dir, dek.bytes()).map_err(emsg)?,
    }
    usage::human(&dir, "unlock", None);
    Ok(())
}

#[tauri::command]
pub fn lock_vault(leaf_id: String) -> CmdResult<()> {
    let dir = dir_for(&leaf_id)?;
    match client::lock(&leaf_id) {
        Some(_) => {}
        None => session::lock(&dir).map_err(emsg)?,
    }
    Ok(())
}

/// Delete a vault: lock it, then remove its directory. Destructive and
/// confirm-gated in the UI. The vault's secrets are gone for good.
#[tauri::command]
pub fn delete_vault(leaf_id: String) -> CmdResult<()> {
    let dir = dir_for(&leaf_id)?;
    let _ = client::lock(&leaf_id);
    let _ = session::lock(&dir);
    std::fs::remove_dir_all(&dir).map_err(emsg)?;
    Ok(())
}
