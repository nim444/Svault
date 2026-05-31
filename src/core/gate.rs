//! The combined access gate: base policy + tier + AI judge.
//!
//! [`policy::evaluate`] makes the base decision (reason, scope, caller, rate).
//! This module layers the **tier + judge gate** on top so the daemon and the CLI
//! fallback share one decision path:
//!
//! - **low** — allowed (judge consulted only if the secret is `require_reason`).
//! - **medium** — judge consulted when active; **fail-open** (allow + flag) if the
//!   judge is unavailable; allowed-and-flagged when the judge is off.
//! - **high** — judge consulted when active; **fail-closed** (deny) if unavailable;
//!   **human-only** (deny) when the judge is off — the pre-0.9.0 behaviour.

use std::path::Path;

use anyhow::Result;
use zeroize::Zeroizing;

use crate::core::judge::{self, JudgeContext, JudgeRuntime, JudgeVerdict};
use crate::core::policy::{self, Decision, Tier, VaultPolicyData};
use crate::core::vault::Vault;
use crate::core::{audit, keyring, usage};

const HIGH_HUMAN_ONLY: &str =
    "high-sensitivity secret — a human must retrieve it via 'svault secret get'";

/// The single, opaque message returned to a *caller* on any denial. The real
/// reason (judge score + rationale, scope/caller mismatch, rate limit, …) is
/// recorded in the audit log for the human — never sent back to the agent, so a
/// caller can't learn what to change to make a denied request pass. The CLI
/// prefixes this with a `denied:` label, so the constant itself omits it.
pub const GENERIC_DENY: &str = "request not authorized for this secret";

/// The gate's verdict: the final decision plus a short note for the audit log
/// (the judge score/rationale, or why it was denied).
pub struct Verdict {
    pub decision: Decision,
    pub note: String,
}

impl Verdict {
    pub fn allowed(&self) -> bool {
        matches!(self.decision, Decision::Allow(_))
    }
    pub fn tier(&self) -> Tier {
        self.decision.tier()
    }
}

/// Authorize a structured request. `policy` is `None` when there's no policy
/// file; `judge` is `None` when the judge is globally disabled / unconfigured.
pub fn authorize(
    policy: &VaultPolicyData,
    req: &policy::Request,
    judge: Option<&JudgeRuntime>,
) -> Verdict {
    let base = policy::evaluate(policy, req);
    let tier = base.tier();
    if let Decision::Deny(_, why) = &base {
        let note = why.clone();
        return Verdict {
            decision: base,
            note,
        };
    }

    // Per-vault opt-out: policy.judge.enabled = Some(false) disables it here even
    // when a global runtime exists.
    let vault_enabled = policy.judge.enabled.unwrap_or(true);
    let active = judge.is_some() && vault_enabled;
    let rule = policy.classify(req.secret);
    let require_reason = rule.map(|r| r.require_reason).unwrap_or(false);

    // Should we actually call the model? Low tier skips it unless require_reason.
    let consult = active && (tier != Tier::Low || require_reason);

    if !consult {
        return match tier {
            Tier::Low => allow(tier, "ok"),
            Tier::Medium => allow(tier, "elevated (judge off)"),
            // Judge off and high tier → human-only, the pre-0.9.0 rule.
            Tier::High if !active => deny(tier, HIGH_HUMAN_ONLY),
            Tier::High => allow(tier, "ok"),
        };
    }

    let rt = judge.expect("active implies Some");
    let model = rt.model.clone();
    let recent = recent_summary(req.vault_dir, req.caller);
    let ctx = JudgeContext {
        caller: req.caller,
        scope: req.scope,
        reason: req.reason,
        secret: req.secret,
        tier,
        vault: req.vault,
        vault_description: req.vault_description,
        secret_description: rule.map(|r| r.description.as_str()).unwrap_or(""),
        recent: &recent,
    };
    let verdict = judge::evaluate(rt, &model, &ctx);
    let threshold = if tier == Tier::High {
        rt.high_threshold
    } else {
        rt.allow_threshold
    };
    let fail_open = tier != Tier::High;

    match verdict {
        JudgeVerdict::Allow { score, rationale } if score >= threshold => Verdict {
            decision: Decision::Allow(tier),
            note: format!("judge allow ({score}): {rationale}"),
        },
        JudgeVerdict::Allow { score, rationale } | JudgeVerdict::Deny { score, rationale } => {
            Verdict {
                decision: Decision::Deny(tier, format!("judge denied (score {score})")),
                note: format!("judge deny ({score}): {rationale}"),
            }
        }
        JudgeVerdict::Unavailable { err } => {
            if fail_open {
                Verdict {
                    decision: Decision::Allow(tier),
                    note: format!("judge-unavailable (fail-open): {err}"),
                }
            } else {
                Verdict {
                    decision: Decision::Deny(
                        tier,
                        "AI judge unavailable — high-tier access fails closed".to_string(),
                    ),
                    note: format!("judge-unavailable (fail-closed): {err}"),
                }
            }
        }
    }
}

/// Structured outcome of a gated agent request against an already-unlocked vault.
/// `Denied` carries no reason — the caller only ever gets [`GENERIC_DENY`]; the
/// real rationale lives in the audit log.
pub enum GatedGet {
    Granted {
        value: Zeroizing<String>,
        tier: Tier,
    },
    Denied,
    NotFound,
}

/// Run the full agent gate against an already-open, **unlocked** vault: resolve
/// the vault's judge from the keyring, [`authorize`], record the audit entry
/// (with the full reason) and a usage event (tagged with the process surface —
/// `cli` / `mcp`), then fetch the value on allow. Does no prompting, printing, or
/// process exit, so both the CLI local-fallback path and the MCP server can share
/// one enforcement path.
pub fn gated_get(
    vault: &Vault,
    vault_dir: &Path,
    caller: &str,
    secret: &str,
    scope: &str,
    reason: &str,
) -> Result<GatedGet> {
    // The vault's assigned judge (or the keyring default); None when the keyring
    // is locked, the judge is off, or it has no key — the gate then applies the
    // static tier rules.
    let judge = keyring::open_from_session().and_then(|kr| {
        kr.data
            .resolve_judge(vault.policy.judge.judge.as_deref())
            .and_then(|(_n, def)| JudgeRuntime::from_def(def))
    });
    let req = policy::Request {
        vault: &vault.meta.name,
        vault_description: &vault.meta.description,
        vault_dir,
        secret,
        scope,
        reason,
        caller,
    };
    let verdict = authorize(&vault.policy, &req, judge.as_ref());
    let decision_str = if verdict.allowed() { "allow" } else { "deny" };
    // Audit keeps the full reason; the caller only ever sees a generic denial.
    audit::record(
        vault_dir,
        &audit::Entry::now(
            caller,
            secret,
            scope,
            &verdict.tier().to_string(),
            decision_str,
            &verdict.note,
            reason,
        ),
    )?;
    usage::agent(
        vault_dir,
        caller,
        &format!("get.{decision_str}"),
        Some(secret),
    );
    if !verdict.allowed() {
        return Ok(GatedGet::Denied);
    }
    match vault.get_secret(secret)? {
        Some(value) => Ok(GatedGet::Granted {
            value,
            tier: verdict.tier(),
        }),
        None => Ok(GatedGet::NotFound),
    }
}

fn allow(tier: Tier, note: &str) -> Verdict {
    Verdict {
        decision: Decision::Allow(tier),
        note: note.to_string(),
    }
}

fn deny(tier: Tier, why: &str) -> Verdict {
    Verdict {
        decision: Decision::Deny(tier, why.to_string()),
        note: why.to_string(),
    }
}

/// A short, model-friendly summary of the caller's recent activity, fed to the
/// judge as a burst/anomaly signal.
pub fn recent_summary(vault_dir: &Path, caller: &str) -> String {
    let since = chrono::Utc::now() - chrono::Duration::hours(1);
    let entries = crate::core::audit::recent(vault_dir, caller, since).unwrap_or_default();
    if entries.is_empty() {
        return "no prior requests in the last hour".to_string();
    }
    let allowed = entries.iter().filter(|e| e.decision == "allow").count();
    let denied = entries.len() - allowed;
    format!(
        "{} request(s) in the last hour ({allowed} allowed, {denied} denied)",
        entries.len()
    )
}
