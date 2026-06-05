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
use crate::core::policy::{
    self, Decision, Seal, Tier, VaultPolicyData, SEAL_DENY_THRESHOLD, SEAL_WINDOW_SECS,
};
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
    // A sealed secret denies every gated agent get until a human clears it
    // (`svault approve`). Checked first so it overrides everything; the caller
    // still only ever sees the generic message.
    if let Some(seal) = policy.seals.get(req.secret) {
        let tier = policy
            .classify(req.secret)
            .map(|r| r.tier)
            .unwrap_or_default();
        return Verdict {
            decision: Decision::Deny(tier, format!("sealed: {}", seal.trigger)),
            note: format!("sealed at {} ({})", seal.sealed_at, seal.trigger),
        };
    }

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
            .map(|(_n, def)| kr.data.materialize_judge(def))
            .and_then(|def| JudgeRuntime::from_def(&def))
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
        maybe_seal(vault, vault_dir, secret, verdict.tier(), caller);
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

/// Seal a secret after sustained abuse. Call on a **denied** gated get against an
/// already-open vault (the enforcement path holds the vault key). When a
/// medium/high secret has accumulated [`SEAL_DENY_THRESHOLD`] denials within
/// [`SEAL_WINDOW_SECS`] (across any caller), persist a [`Seal`] into the encrypted
/// policy so every later agent get is denied until a human clears it. Returns
/// whether it sealed this call. Low-tier secrets never seal (they auto-allow, so
/// there is nothing to grind against), and an already-sealed secret short-circuits
/// so the `vault.enc` rewrite happens only on the rare seal transition.
pub fn maybe_seal(vault: &Vault, vault_dir: &Path, secret: &str, tier: Tier, caller: &str) -> bool {
    if tier == Tier::Low || vault.policy.seals.contains_key(secret) {
        return false;
    }
    let since = chrono::Utc::now() - chrono::Duration::seconds(SEAL_WINDOW_SECS);
    let denials = audit::recent_for_secret(vault_dir, secret, since)
        .map(|es| es.iter().filter(|e| e.decision == "deny").count())
        .unwrap_or(0);
    if denials < SEAL_DENY_THRESHOLD {
        return false;
    }
    let mut policy = vault.policy.clone();
    policy.seals.insert(
        secret.to_string(),
        Seal {
            sealed_at: chrono::Utc::now().to_rfc3339(),
            trigger: format!("{denials} denials in {SEAL_WINDOW_SECS}s"),
            last_caller: caller.to_string(),
            denials: denials as u32,
        },
    );
    if vault.save_policy(&policy).is_ok() {
        usage::agent(vault_dir, caller, "secret.sealed", Some(secret));
        true
    } else {
        false
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::meta::{VaultMeta, VaultSettings};
    use crate::core::policy::{SecretRule, VaultPolicyData};
    use tempfile::TempDir;

    fn vault_with_secret(dir: &TempDir, tier: Tier) -> (Vault, std::path::PathBuf) {
        let vault_dir = dir.path().join("v");
        let mut policy = VaultPolicyData::default();
        policy.secrets.insert(
            "API_KEY".into(),
            SecretRule {
                scope: "api".into(),
                tier,
                ..Default::default()
            },
        );
        let meta = VaultMeta::new("v".into(), "d".into(), VaultSettings::default());
        let v = Vault::init(&vault_dir, "Str0ng!Pass#99", meta, policy).unwrap();
        v.add_secret("API_KEY", "s3cr3t").unwrap();
        (v, vault_dir)
    }

    fn seed_denials(vault_dir: &Path, secret: &str, n: usize) {
        for _ in 0..n {
            audit::record(
                vault_dir,
                &audit::Entry::now(
                    "attacker", secret, "api", "medium", "deny", "nope", "probe me",
                ),
            )
            .unwrap();
        }
    }

    #[test]
    fn repeated_denials_seal_a_medium_secret() {
        let dir = TempDir::new().unwrap();
        let (v, vault_dir) = vault_with_secret(&dir, Tier::Medium);
        seed_denials(&vault_dir, "API_KEY", SEAL_DENY_THRESHOLD);

        assert!(gate_maybe_seal(&v, &vault_dir));
        // Persisted into the encrypted policy.
        let reopened = Vault::open(&vault_dir, "Str0ng!Pass#99").unwrap();
        assert!(reopened.policy.seals.contains_key("API_KEY"));
        // Already sealed → no re-seal.
        assert!(!gate_maybe_seal(&reopened, &vault_dir));
    }

    #[test]
    fn low_tier_never_seals() {
        let dir = TempDir::new().unwrap();
        let (v, vault_dir) = vault_with_secret(&dir, Tier::Low);
        seed_denials(&vault_dir, "API_KEY", SEAL_DENY_THRESHOLD + 3);
        assert!(!maybe_seal(
            &v,
            &vault_dir,
            "API_KEY",
            Tier::Low,
            "attacker"
        ));
    }

    #[test]
    fn under_threshold_does_not_seal() {
        let dir = TempDir::new().unwrap();
        let (v, vault_dir) = vault_with_secret(&dir, Tier::Medium);
        seed_denials(&vault_dir, "API_KEY", SEAL_DENY_THRESHOLD - 1);
        assert!(!gate_maybe_seal(&v, &vault_dir));
    }

    #[test]
    fn sealed_secret_denies_an_otherwise_allowable_request() {
        let dir = TempDir::new().unwrap();
        let mut policy = VaultPolicyData::default();
        policy.secrets.insert(
            "API_KEY".into(),
            SecretRule {
                scope: "api".into(),
                tier: Tier::Medium,
                ..Default::default()
            },
        );
        // Without a seal the request allows; with one it denies.
        let req = policy::Request {
            vault: "v",
            vault_description: "",
            vault_dir: dir.path(),
            secret: "API_KEY",
            scope: "api",
            reason: "legitimate use of the api key",
            caller: "claude",
        };
        assert!(authorize(&policy, &req, None).allowed());
        policy.seals.insert(
            "API_KEY".into(),
            Seal {
                sealed_at: chrono::Utc::now().to_rfc3339(),
                trigger: "5 denials in 300s".into(),
                last_caller: "attacker".into(),
                denials: 5,
            },
        );
        assert!(!authorize(&policy, &req, None).allowed());
    }

    fn gate_maybe_seal(v: &Vault, vault_dir: &Path) -> bool {
        maybe_seal(v, vault_dir, "API_KEY", Tier::Medium, "attacker")
    }
}
