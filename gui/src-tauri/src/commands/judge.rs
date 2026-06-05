//! Judge & Policy screen (06) — judge registry + live test bench. All judge
//! config lives in the encrypted keyring; the live test runs the real model.

use serde::{Deserialize, Serialize};

use crate::commands::common::{open_or_init_keyring, parse_tier};
use crate::error::{emsg, CmdResult};

use svault_cli::core::judge::{self, JudgeContext, JudgeVerdict};
use svault_cli::core::keyring::{self, JudgeDef};
use svault_cli::core::{usage, vault};

/// Record a global (vault-independent) provider/judge config change to
/// `.svault/usage.log` so it shows in the Audit screen's activity view — the
/// same pattern the TUI uses for judge changes. Best-effort, never blocks.
fn log_global(action: &str, target: &str) {
    usage::human(&vault::svault_dir(), action, Some(target));
}

#[derive(Serialize)]
pub struct KeyringState {
    pub exists: bool,
    pub unlocked: bool,
    pub judge_enabled: bool,
    pub mcp_enabled: bool,
    pub default_judge: Option<String>,
    pub judge_count: usize,
    pub provider_count: usize,
}

#[derive(Serialize)]
pub struct ProviderInfo {
    pub name: String,
    pub kind: String,
    pub base_url: String,
    pub has_key: bool,
    pub enabled: bool,
    pub is_default: bool,
    /// Judges currently drawing their key from this provider.
    pub used_by: Vec<String>,
}

#[derive(Serialize)]
pub struct ProviderKind {
    pub kind: String,
    pub base_url: String,
    /// Whether this kind works without an API key (local endpoints).
    pub key_optional: bool,
}

#[derive(Deserialize)]
pub struct ProviderFormInput {
    pub name: String,
    pub kind: String,
    /// Blank = the kind's default base URL.
    #[serde(default)]
    pub base_url: String,
    /// New API key. Blank leaves the existing key unchanged on edit.
    #[serde(default)]
    pub api_key: String,
}

#[derive(Serialize)]
pub struct JudgeInfo {
    pub name: String,
    pub model: String,
    pub allow_threshold: u8,
    pub high_threshold: u8,
    pub criteria: String,
    pub has_key: bool,
    pub is_default: bool,
    pub provider: Option<String>,
}

#[derive(Deserialize)]
pub struct JudgeFormInput {
    pub name: String,
    pub model: String,
    pub allow_threshold: u8,
    pub high_threshold: u8,
    pub criteria: String,
    /// New API key. `None`/empty leaves the existing key unchanged on edit.
    #[serde(default)]
    pub api_key: Option<String>,
    /// Named provider this judge draws its key from. `None` = own key.
    #[serde(default)]
    pub provider: Option<String>,
}

#[derive(Deserialize)]
pub struct JudgeTestInput {
    pub judge: Option<String>,
    pub reason: String,
    pub scope: String,
    pub secret: String,
    pub caller: String,
    pub tier: String,
    #[serde(default)]
    pub secret_description: String,
}

#[derive(Serialize)]
pub struct JudgeTestResult {
    pub verdict: String, // "allow" | "deny" | "unavailable"
    pub score: Option<u8>,
    pub rationale: String,
    pub model: String,
    pub allow_threshold: u8,
    pub high_threshold: u8,
}

#[tauri::command]
pub fn keyring_state() -> KeyringState {
    match keyring::open_from_session() {
        Some(kr) => KeyringState {
            exists: true,
            unlocked: true,
            judge_enabled: kr.data.judge_enabled,
            mcp_enabled: kr.data.mcp_enabled,
            default_judge: kr.data.default_judge.clone(),
            judge_count: kr.data.judges.len(),
            provider_count: kr.data.providers.len(),
        },
        None => KeyringState {
            exists: keyring::exists(),
            unlocked: false,
            judge_enabled: false,
            mcp_enabled: true,
            default_judge: None,
            judge_count: 0,
            provider_count: 0,
        },
    }
}

#[tauri::command]
pub fn judge_list() -> CmdResult<Vec<JudgeInfo>> {
    let kr = open_or_init_keyring()?;
    let default = kr.data.default_judge.clone();
    let mut out: Vec<JudgeInfo> = kr
        .data
        .judges
        .iter()
        .map(|(name, def)| JudgeInfo {
            name: name.clone(),
            model: def.model.clone(),
            allow_threshold: def.allow_threshold,
            high_threshold: def.high_threshold,
            criteria: def.criteria.clone(),
            has_key: kr.data.judge_has_key(def),
            is_default: default.as_deref() == Some(name.as_str()),
            provider: def.provider.clone(),
        })
        .collect();
    out.sort_by_key(|j| j.name.to_lowercase());
    Ok(out)
}

/// Add or update a named judge. The first judge added becomes the default.
#[tauri::command]
pub fn judge_save(form: JudgeFormInput) -> CmdResult<()> {
    let name = form.name.trim().to_string();
    if name.is_empty() {
        return Err("a judge name is required".into());
    }
    let mut kr = open_or_init_keyring()?;
    let existing = kr.data.judges.get(&name).cloned();
    let mut def = existing.clone().unwrap_or_default();
    def.model = form.model.trim().to_string();
    def.allow_threshold = form.allow_threshold;
    def.high_threshold = form.high_threshold;
    def.criteria = form.criteria;
    if let Some(key) = form.api_key.as_deref().filter(|s| !s.is_empty()) {
        def.api_key = key.to_string();
    }
    def.provider = form
        .provider
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    if let Some(p) = def.provider.as_deref() {
        if !kr.data.providers.contains_key(p) {
            return Err(format!("no provider named '{p}'"));
        }
    }
    kr.data.judges.insert(name.clone(), def);
    if kr.data.default_judge.is_none() {
        kr.data.default_judge = Some(name.clone());
    }
    kr.save().map_err(emsg)?;
    log_global(
        if existing.is_some() {
            "judge.update"
        } else {
            "judge.add"
        },
        &name,
    );
    Ok(())
}

#[tauri::command]
pub fn judge_remove(name: String) -> CmdResult<()> {
    let mut kr = open_or_init_keyring()?;
    kr.data.judges.remove(&name);
    if kr.data.default_judge.as_deref() == Some(name.as_str()) {
        kr.data.default_judge = kr.data.judges.keys().next().cloned();
    }
    kr.save().map_err(emsg)?;
    log_global("judge.remove", &name);
    Ok(())
}

#[tauri::command]
pub fn judge_set_default(name: String) -> CmdResult<()> {
    let mut kr = open_or_init_keyring()?;
    if !kr.data.judges.contains_key(&name) {
        return Err(format!("no judge named '{name}'"));
    }
    kr.data.default_judge = Some(name.clone());
    kr.save().map_err(emsg)?;
    log_global("judge.default", &name);
    Ok(())
}

/// Global AI-judge on/off switch.
#[tauri::command]
pub fn judge_toggle(enabled: bool) -> CmdResult<()> {
    let mut kr = open_or_init_keyring()?;
    kr.data.judge_enabled = enabled;
    kr.save().map_err(emsg)?;
    log_global(
        if enabled {
            "judge.enable"
        } else {
            "judge.disable"
        },
        "global",
    );
    Ok(())
}

#[tauri::command]
pub async fn judge_test(input: JudgeTestInput) -> CmdResult<JudgeTestResult> {
    let kr = open_or_init_keyring()?;
    let target = input
        .judge
        .clone()
        .or_else(|| kr.data.default_judge.clone())
        .ok_or("no judge to test — add one or set a default")?;
    let def: &JudgeDef = kr
        .data
        .judges
        .get(&target)
        .ok_or_else(|| format!("no judge named '{target}'"))?;
    let rt = judge::JudgeRuntime::from_def(&kr.data.materialize_judge(def)).ok_or(
        "this judge has no API key — pick a provider, set a key, or export $SVAULT_OPENROUTER_KEY",
    )?;
    let model = rt.model.clone();
    let allow_threshold = rt.allow_threshold;
    let high_threshold = rt.high_threshold;
    let ctx = JudgeContext {
        caller: &input.caller,
        scope: &input.scope,
        reason: &input.reason,
        secret: &input.secret,
        tier: parse_tier(&input.tier),
        vault: "test",
        vault_description: "",
        secret_description: &input.secret_description,
        recent: "no prior requests in the last hour",
    };
    let (verdict, score, rationale) = match judge::evaluate(&rt, &model, &ctx) {
        JudgeVerdict::Allow { score, rationale } => ("allow", Some(score), rationale),
        JudgeVerdict::Deny { score, rationale } => ("deny", Some(score), rationale),
        JudgeVerdict::Unavailable { err } => ("unavailable", None, err),
    };
    Ok(JudgeTestResult {
        verdict: verdict.to_string(),
        score,
        rationale,
        model,
        allow_threshold,
        high_threshold,
    })
}

/// Names of defined judges — for the vault-config "assigned judge" picker.
#[tauri::command]
pub fn judge_names() -> Vec<String> {
    keyring::open_from_session()
        .map(|kr| kr.data.judges.keys().cloned().collect())
        .unwrap_or_default()
}

// ── AI providers ──────────────────────────────────────────────────────────

/// The provider kinds the GUI offers, with their default base URLs.
#[tauri::command]
pub fn provider_kinds() -> Vec<ProviderKind> {
    keyring::PROVIDER_KINDS
        .iter()
        .map(|k| ProviderKind {
            kind: k.to_string(),
            base_url: keyring::provider_kind_base_url(k)
                .unwrap_or_default()
                .to_string(),
            key_optional: *k == "local",
        })
        .collect()
}

#[tauri::command]
pub fn provider_list() -> CmdResult<Vec<ProviderInfo>> {
    let kr = open_or_init_keyring()?;
    let default = kr.data.default_provider.clone();
    Ok(kr
        .data
        .providers
        .iter()
        .map(|(name, p)| ProviderInfo {
            name: name.clone(),
            kind: p.kind.clone(),
            base_url: p.base_url.clone(),
            has_key: !p.api_key.is_empty(),
            enabled: p.enabled,
            is_default: default.as_deref() == Some(name.as_str()),
            used_by: kr
                .data
                .judges
                .iter()
                .filter(|(_, d)| d.provider.as_deref() == Some(name.as_str()))
                .map(|(n, _)| n.clone())
                .collect(),
        })
        .collect())
}

/// Add or update a named provider. An empty `api_key` leaves the existing key
/// unchanged on edit (the GUI never reads keys back); only `local` providers
/// may end up keyless. The first provider added becomes the default.
#[tauri::command]
pub fn provider_save(form: ProviderFormInput) -> CmdResult<()> {
    let name = form.name.trim().to_string();
    if name.is_empty() {
        return Err("a provider name is required".into());
    }
    let kind = form.kind.trim().to_string();
    if !keyring::PROVIDER_KINDS.contains(&kind.as_str()) {
        return Err(format!(
            "unknown provider kind '{kind}' — use one of: {}",
            keyring::PROVIDER_KINDS.join(", ")
        ));
    }
    let mut kr = open_or_init_keyring()?;
    let mut def = kr.data.providers.get(&name).cloned().unwrap_or_default();
    def.kind = kind.clone();
    def.base_url = if form.base_url.trim().is_empty() {
        keyring::provider_kind_base_url(&kind)
            .unwrap_or_default()
            .to_string()
    } else {
        form.base_url.trim().trim_end_matches('/').to_string()
    };
    if !form.api_key.trim().is_empty() {
        def.api_key = form.api_key.trim().to_string();
    }
    if def.api_key.is_empty() && kind != "local" {
        return Err("an API key is required for this provider kind".into());
    }
    let updating = kr.data.providers.contains_key(&name);
    let first = kr.data.providers.is_empty();
    kr.data.providers.insert(name.clone(), def);
    if first || kr.data.default_provider.is_none() {
        kr.data.default_provider = Some(name.clone());
    }
    kr.save().map_err(emsg)?;
    log_global(
        if updating {
            "provider.update"
        } else {
            "provider.add"
        },
        &name,
    );
    Ok(())
}

/// Enable/disable a provider. Disabled providers lend no credentials, so their
/// judges fall back to the static tier rules (enforced in core).
#[tauri::command]
pub fn provider_toggle(name: String, enabled: bool) -> CmdResult<()> {
    let mut kr = open_or_init_keyring()?;
    let def = kr
        .data
        .providers
        .get_mut(&name)
        .ok_or_else(|| format!("no provider named '{name}'"))?;
    def.enabled = enabled;
    kr.save().map_err(emsg)?;
    log_global(
        if enabled {
            "provider.enable"
        } else {
            "provider.disable"
        },
        &name,
    );
    Ok(())
}

#[tauri::command]
pub fn provider_set_default(name: String) -> CmdResult<()> {
    let mut kr = open_or_init_keyring()?;
    if !kr.data.providers.contains_key(&name) {
        return Err(format!("no provider named '{name}'"));
    }
    kr.data.default_provider = Some(name.clone());
    kr.save().map_err(emsg)?;
    log_global("provider.default", &name);
    Ok(())
}

/// Live model list from the provider's `/models` endpoint, for the judge
/// form's model picker. Network only; falls back to free text in the UI.
#[tauri::command]
pub async fn provider_models(name: String) -> CmdResult<Vec<String>> {
    let kr = open_or_init_keyring()?;
    let p = kr
        .data
        .providers
        .get(&name)
        .ok_or_else(|| format!("no provider named '{name}'"))?;
    judge::list_models(&p.kind, &p.base_url, &p.api_key).map_err(emsg)
}

/// Remove a provider. Refused while a judge still references it.
#[tauri::command]
pub fn provider_remove(name: String) -> CmdResult<()> {
    let mut kr = open_or_init_keyring()?;
    if let Some(judge) = kr
        .data
        .judges
        .iter()
        .find(|(_, d)| d.provider.as_deref() == Some(name.as_str()))
        .map(|(n, _)| n.clone())
    {
        return Err(format!(
            "provider '{name}' is used by judge '{judge}' — reassign or remove that judge first"
        ));
    }
    kr.data.providers.remove(&name);
    if kr.data.default_provider.as_deref() == Some(name.as_str()) {
        kr.data.default_provider = kr.data.providers.keys().next().cloned();
    }
    kr.save().map_err(emsg)?;
    log_global("provider.remove", &name);
    Ok(())
}
