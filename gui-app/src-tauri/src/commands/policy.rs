//! Judge & Policy screen (06) — the read-only policy surface and caller-access
//! views. Everything here is read from the vault's decrypted, encrypted-at-rest
//! policy; nothing is mutated.

use serde::Serialize;

use crate::commands::common::open_vault;
use crate::error::CmdResult;

use svault_cli::core::audit;
use svault_cli::core::policy::{SEAL_DENY_THRESHOLD, SEAL_WINDOW_SECS};

#[derive(Serialize)]
pub struct CallerRuleInfo {
    pub name: String,
    pub scopes: Vec<String>,
    pub rate_limit: String,
}

#[derive(Serialize)]
pub struct ConditionInfo {
    pub secret: String,
    pub windows: Vec<String>,
    pub callers: Vec<String>,
}

#[derive(Serialize)]
pub struct SealInfo {
    pub secret: String,
    pub trigger: String,
    pub last_caller: String,
    pub denials: u32,
    pub sealed_at: String,
}

#[derive(Serialize)]
pub struct TierGate {
    pub tier: String,
    pub gate: String,
}

#[derive(Serialize)]
pub struct PolicySurface {
    pub rate_limit: String,
    pub allow_agent: String,
    pub default_tier: String,
    pub callers: Vec<CallerRuleInfo>,
    pub conditioned: Vec<ConditionInfo>,
    pub tier_gates: Vec<TierGate>,
    pub seal_threshold: usize,
    pub seal_window_secs: i64,
}

fn conditioned(policy: &svault_cli::core::policy::VaultPolicyData) -> Vec<ConditionInfo> {
    policy
        .secrets
        .iter()
        .filter(|(n, r)| {
            n.as_str() != "*" && (!r.windows.is_empty() || !r.require_callers.is_empty())
        })
        .map(|(n, r)| ConditionInfo {
            secret: n.clone(),
            windows: r.windows.iter().map(|w| w.to_string()).collect(),
            callers: r.require_callers.clone(),
        })
        .collect()
}

#[tauri::command]
pub fn policy_surface(leaf_id: String) -> CmdResult<PolicySurface> {
    let (_dir, v) = open_vault(&leaf_id)?;
    let p = &v.policy;
    Ok(PolicySurface {
        rate_limit: p.access.rate_limit.clone(),
        allow_agent: p.access.allow_agent.to_string(),
        default_tier: p.default_tier.to_string(),
        callers: p
            .callers
            .iter()
            .map(|(name, r)| CallerRuleInfo {
                name: name.clone(),
                scopes: r.scopes.clone(),
                rate_limit: r.rate_limit.clone(),
            })
            .collect(),
        conditioned: conditioned(p),
        tier_gates: vec![
            TierGate {
                tier: "low".into(),
                gate: "audit only (unless 'always judge' is set)".into(),
            },
            TierGate {
                tier: "medium".into(),
                gate: "AI judge (fail-open, audit-flagged)".into(),
            },
            TierGate {
                tier: "high".into(),
                gate: "AI judge (fail-closed); human-only when judge off".into(),
            },
        ],
        seal_threshold: SEAL_DENY_THRESHOLD,
        seal_window_secs: SEAL_WINDOW_SECS,
    })
}

#[derive(Serialize)]
pub struct CallerAccess {
    pub defined: bool,
    pub scopes: Vec<String>,
    pub rate_limit: String,
    pub accessible: Vec<AccessRow>,
    pub conditioned: Vec<ConditionInfo>,
    pub seals: Vec<SealInfo>,
    pub audit_total: usize,
    pub audit_denied: usize,
}

#[derive(Serialize)]
pub struct AccessRow {
    pub secret: String,
    pub scope: String,
    pub tier: String,
}

#[tauri::command]
pub fn caller_access(leaf_id: String, caller: String) -> CmdResult<CallerAccess> {
    let (dir, v) = open_vault(&leaf_id)?;
    let p = &v.policy;
    let rule = p.caller(&caller);

    let accessible = p
        .accessible(&caller)
        .into_iter()
        .map(|(secret, scope, tier)| AccessRow {
            secret,
            scope,
            tier: tier.to_string(),
        })
        .collect();

    let seals = p
        .seals
        .iter()
        .map(|(secret, s)| SealInfo {
            secret: secret.clone(),
            trigger: s.trigger.clone(),
            last_caller: s.last_caller.clone(),
            denials: s.denials,
            sealed_at: s.sealed_at.clone(),
        })
        .collect();

    let mut total = 0usize;
    let mut denied = 0usize;
    for e in audit::all(&dir).unwrap_or_default() {
        if e.caller == caller {
            total += 1;
            if e.decision == "deny" {
                denied += 1;
            }
        }
    }

    Ok(CallerAccess {
        defined: rule.is_some(),
        scopes: rule.map(|r| r.scopes.clone()).unwrap_or_default(),
        rate_limit: rule.map(|r| r.rate_limit.clone()).unwrap_or_default(),
        accessible,
        conditioned: conditioned(p),
        seals,
        audit_total: total,
        audit_denied: denied,
    })
}
