//! Judge & Policy screen (06) — judge registry + live test bench. All judge
//! config lives in the encrypted keyring; the live test runs the real model.

use serde::{Deserialize, Serialize};

use crate::commands::common::{open_or_init_keyring, parse_tier};
use crate::error::{emsg, CmdResult};

use svault_cli::core::judge::{self, JudgeContext, JudgeVerdict};
use svault_cli::core::keyring::{self, JudgeDef};

#[derive(Serialize)]
pub struct KeyringState {
    pub exists: bool,
    pub unlocked: bool,
    pub judge_enabled: bool,
    pub mcp_enabled: bool,
    pub default_judge: Option<String>,
    pub judge_count: usize,
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
        },
        None => KeyringState {
            exists: keyring::exists(),
            unlocked: false,
            judge_enabled: false,
            mcp_enabled: true,
            default_judge: None,
            judge_count: 0,
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
            has_key: !def.api_key.is_empty(),
            is_default: default.as_deref() == Some(name.as_str()),
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
    kr.data.judges.insert(name.clone(), def);
    if kr.data.default_judge.is_none() {
        kr.data.default_judge = Some(name);
    }
    kr.save().map_err(emsg)
}

#[tauri::command]
pub fn judge_remove(name: String) -> CmdResult<()> {
    let mut kr = open_or_init_keyring()?;
    kr.data.judges.remove(&name);
    if kr.data.default_judge.as_deref() == Some(name.as_str()) {
        kr.data.default_judge = kr.data.judges.keys().next().cloned();
    }
    kr.save().map_err(emsg)
}

#[tauri::command]
pub fn judge_set_default(name: String) -> CmdResult<()> {
    let mut kr = open_or_init_keyring()?;
    if !kr.data.judges.contains_key(&name) {
        return Err(format!("no judge named '{name}'"));
    }
    kr.data.default_judge = Some(name);
    kr.save().map_err(emsg)
}

/// Global AI-judge on/off switch.
#[tauri::command]
pub fn judge_toggle(enabled: bool) -> CmdResult<()> {
    let mut kr = open_or_init_keyring()?;
    kr.data.judge_enabled = enabled;
    kr.save().map_err(emsg)
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
    let rt = judge::JudgeRuntime::from_def(def)
        .ok_or("this judge has no API key — set one, or export $SVAULT_OPENROUTER_KEY")?;
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
