//! Secrets management (05). Secret **values** are encrypted into `vault.enc` and
//! never logged; classification (scope/tier/description/conditions) lives in the
//! encrypted policy. Reveal is the human path (no judge) — the human already
//! holds the master.

use serde::{Deserialize, Serialize};

use crate::commands::common::{leaf, open_vault, parse_tier};
use crate::error::{emsg, CmdResult};

use svault_cli::core::policy::{AccessWindow, SecretRule};
use svault_cli::core::{audit, usage};
use svault_cli::daemon::client;

#[derive(Serialize)]
pub struct SecretSummary {
    pub name: String,
    pub scope: String,
    pub tier: String,
    pub require_reason: bool,
    pub description: String,
    pub callers: Vec<String>,
    pub windows: Vec<String>,
    pub sealed: bool,
    pub last_read: Option<i64>,
}

#[derive(Deserialize)]
pub struct SecretForm {
    pub name: String,
    /// New/updated value. Required on add; on edit, `None`/empty leaves it as-is.
    #[serde(default)]
    pub value: Option<String>,
    pub scope: String,
    pub tier: String,
    #[serde(default)]
    pub require_reason: bool,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub windows: Vec<String>,
    #[serde(default)]
    pub require_callers: Vec<String>,
}

#[tauri::command]
pub fn list_secrets(leaf_id: String) -> CmdResult<Vec<SecretSummary>> {
    let (dir, v) = open_vault(&leaf_id)?;
    let names = v.list_secret_names().map_err(emsg)?;
    let since = chrono::DateTime::<chrono::Utc>::from_timestamp(0, 0).unwrap();

    let mut out = Vec::new();
    for name in names {
        let rule = v.policy.classify(&name).cloned().unwrap_or_default();
        let last_read = audit::recent_for_secret(&dir, &name, since)
            .unwrap_or_default()
            .iter()
            .filter_map(|e| e.timestamp())
            .map(|t| t.timestamp())
            .max();
        out.push(SecretSummary {
            scope: rule.scope,
            tier: rule.tier.to_string(),
            require_reason: rule.require_reason,
            description: rule.description,
            callers: rule.require_callers,
            windows: rule.windows.iter().map(|w| w.to_string()).collect(),
            sealed: v.policy.seals.contains_key(&name),
            last_read,
            name,
        });
    }
    out.sort_by_key(|s| s.name.to_lowercase());
    Ok(out)
}

/// Build a SecretRule from a form, validating any time-window specs up front.
fn rule_from(form: &SecretForm) -> CmdResult<SecretRule> {
    let windows = form
        .windows
        .iter()
        .filter(|s| !s.trim().is_empty())
        .map(|s| AccessWindow::parse(s))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("invalid window: {e}"))?;
    Ok(SecretRule {
        scope: form.scope.trim().to_string(),
        tier: parse_tier(&form.tier),
        require_reason: form.require_reason,
        description: form.description.trim().to_string(),
        windows,
        require_callers: form
            .require_callers
            .iter()
            .filter(|c| !c.trim().is_empty())
            .map(|c| c.trim().to_string())
            .collect(),
    })
}

#[tauri::command]
pub fn add_secret(leaf_id: String, form: SecretForm) -> CmdResult<()> {
    let name = form.name.trim().to_string();
    if name.is_empty() || name == "*" {
        return Err("a secret name is required".into());
    }
    let value = form
        .value
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or("a value is required")?;

    let (dir, v) = open_vault(&leaf_id)?;
    if v.list_secret_names().map_err(emsg)?.contains(&name) {
        return Err(format!("a secret named '{name}' already exists"));
    }
    let rule = rule_from(&form)?;
    v.add_secret(&name, value).map_err(emsg)?;

    let mut policy = v.policy.clone();
    policy.secrets.insert(name.clone(), rule);
    v.save_policy(&policy).map_err(emsg)?;
    usage::human(&dir, "secret.add", Some(&name));
    Ok(())
}

#[tauri::command]
pub fn edit_secret(leaf_id: String, form: SecretForm) -> CmdResult<()> {
    let name = form.name.trim().to_string();
    let (dir, v) = open_vault(&leaf_id)?;
    if !v.list_secret_names().map_err(emsg)?.contains(&name) {
        return Err(format!("secret '{name}' not found"));
    }
    let rule = rule_from(&form)?;

    // Only overwrite the value when a new non-empty one was supplied.
    if let Some(value) = form.value.as_deref().filter(|s| !s.is_empty()) {
        v.add_secret(&name, value).map_err(emsg)?;
    }
    let mut policy = v.policy.clone();
    policy.secrets.insert(name.clone(), rule);
    v.save_policy(&policy).map_err(emsg)?;
    usage::human(&dir, "secret.update", Some(&name));
    Ok(())
}

#[tauri::command]
pub fn remove_secret(leaf_id: String, name: String) -> CmdResult<()> {
    let (dir, v) = open_vault(&leaf_id)?;
    let removed = v.remove_secret(&name).map_err(emsg)?;
    if !removed {
        return Err(format!("secret '{name}' not found"));
    }
    let mut policy = v.policy.clone();
    policy.secrets.remove(&name);
    policy.seals.remove(&name);
    v.save_policy(&policy).map_err(emsg)?;
    usage::human(&dir, "secret.remove", Some(&name));
    Ok(())
}

/// Reveal a secret's value — the human path (no judge). Prefers the daemon (so
/// the read is audited there) and falls back to opening the vault directly.
#[tauri::command]
pub fn reveal_secret(leaf_id: String, name: String) -> CmdResult<String> {
    let dir = crate::commands::common::dir_for(&leaf_id)?;
    if let Some(outcome) = client::get(&leaf(&dir), &name) {
        match outcome {
            client::GetOutcome::Value(value) => {
                usage::human(&dir, "secret.get", Some(&name));
                return Ok(value);
            }
            client::GetOutcome::NotFound => return Err(format!("secret '{name}' not found")),
            client::GetOutcome::NotUnlocked => {} // fall through to direct open
        }
    }
    let (_dir, v) = open_vault(&leaf_id)?;
    match v.get_secret(&name).map_err(emsg)? {
        Some(value) => {
            usage::human(&dir, "secret.get", Some(&name));
            Ok((*value).clone())
        }
        None => Err(format!("secret '{name}' not found")),
    }
}
