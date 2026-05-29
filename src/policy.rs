//! The policy engine — the gate behind `svault get`.
//!
//! A structured request (`secret`, `scope`, `reason`, `caller`) is run through
//! a pipeline: reason required -> capability (scope) check -> sensitivity tier
//! -> rate limit -> burst detection. The verdict is an [`Decision`], and the
//! caller (main) records it to the audit log either way.
//!
//! Policy lives in a committable `svault.policy.yaml` at the project root. When
//! that file is absent we fall back to the per-vault `allow_agent` / `rate_limit`
//! fields in `meta.yaml`, so Step 1 behavior is preserved and the policy file
//! stays optional-but-recommended.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::audit;
use crate::meta::{AllowAgent, VaultMeta};

pub const POLICY_FILE: &str = "svault.policy.yaml";

/// Burst window: more than [`BURST_MAX`] allowed requests inside this many
/// seconds is treated as anomalous regardless of the configured rate limit.
const BURST_WINDOW_SECS: i64 = 10;
const BURST_MAX: usize = 5;

/// Sensitivity of a secret. Drives what the engine does on a match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// Auto-allow.
    #[default]
    Low,
    /// Allow, but the audit entry is flagged as elevated.
    Medium,
    /// Never handed to an agent — denied and logged. Humans use `secret get`.
    High,
}

impl std::fmt::Display for Tier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Tier::Low => "low",
            Tier::Medium => "medium",
            Tier::High => "high",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallerRule {
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default = "default_rate_limit")]
    pub rate_limit: String,
}

fn default_rate_limit() -> String {
    "5/hour".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRule {
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub tier: Tier,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VaultPolicy {
    #[serde(default)]
    pub secrets: HashMap<String, SecretRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub callers: HashMap<String, CallerRule>,
    #[serde(default)]
    pub vaults: HashMap<String, VaultPolicy>,
}

fn default_version() -> u32 {
    1
}

impl Policy {
    /// Resolve a caller, falling back to the `default` caller when present.
    pub fn caller(&self, name: &str) -> Option<&CallerRule> {
        self.callers
            .get(name)
            .or_else(|| self.callers.get("default"))
    }

    /// The (vault, secret, scope, tier) tuples this caller may retrieve, for
    /// `svault policy check`. High-tier secrets are excluded (agents can't get
    /// them) and the `"*"` wildcard is skipped since it can't be enumerated.
    pub fn accessible(&self, caller: &str) -> Vec<(String, String, String, Tier)> {
        let Some(rule) = self.caller(caller) else {
            return vec![];
        };
        let mut out = Vec::new();
        for (vname, vp) in &self.vaults {
            for (sname, sr) in &vp.secrets {
                if sname == "*" {
                    continue;
                }
                if sr.tier != Tier::High && rule.scopes.iter().any(|s| s == &sr.scope) {
                    out.push((vname.clone(), sname.clone(), sr.scope.clone(), sr.tier));
                }
            }
        }
        out.sort();
        out
    }
}

/// Find and parse `svault.policy.yaml`, searching the current directory and
/// walking up to the filesystem root. Returns `None` when no file is found or
/// it fails to parse (the engine then runs in fallback mode).
pub fn load() -> Option<Policy> {
    let path = find_policy_file()?;
    let content = std::fs::read_to_string(path).ok()?;
    serde_yaml::from_str(&content).ok()
}

/// Absolute path to the policy file if one exists at or above the CWD.
pub fn find_policy_file() -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let candidate = dir.join(POLICY_FILE);
        if candidate.is_file() {
            return Some(candidate);
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// Parse a rate-limit string like `20/hour` into a count and a window.
pub fn rate_limit_parse(s: &str) -> Option<(u32, Duration)> {
    let (n, unit) = s.split_once('/')?;
    let n: u32 = n.trim().parse().ok()?;
    let secs = match unit.trim().to_lowercase().as_str() {
        "s" | "sec" | "secs" | "second" | "seconds" => 1,
        "m" | "min" | "mins" | "minute" | "minutes" => 60,
        "h" | "hr" | "hour" | "hours" => 3600,
        "d" | "day" | "days" => 86_400,
        _ => return None,
    };
    Some((n, Duration::from_secs(secs)))
}

/// A structured secret request.
pub struct Request<'a> {
    pub vault: &'a str,
    pub vault_dir: &'a Path,
    pub secret: &'a str,
    pub scope: &'a str,
    pub reason: &'a str,
    pub caller: &'a str,
}

/// The engine's verdict. Carries the secret's tier so the audit entry is
/// accurate even on a denial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow(Tier),
    Deny(Tier, String),
}

impl Decision {
    pub fn tier(&self) -> Tier {
        match self {
            Decision::Allow(t) | Decision::Deny(t, _) => *t,
        }
    }
    #[cfg(test)]
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow(_))
    }
}

/// Run the pipeline. `policy` is `None` in fallback mode; `meta` supplies the
/// fallback allow/deny + rate limit and is otherwise unused.
pub fn evaluate(policy: Option<&Policy>, meta: &VaultMeta, req: &Request) -> Decision {
    // Reason is required in every mode.
    if let Err(msg) = check_reason(req.reason) {
        return Decision::Deny(Tier::Low, msg);
    }
    match policy {
        Some(p) => evaluate_with_policy(p, req),
        None => evaluate_fallback(meta, req),
    }
}

fn check_reason(reason: &str) -> Result<(), String> {
    let r = reason.trim();
    if r.len() < 10 {
        return Err("a reason of at least 10 characters is required".to_string());
    }
    let placeholders = [
        "testtest",
        "asdfasdf",
        "no reason",
        "because",
        "placeholder",
    ];
    let lower = r.to_lowercase();
    if placeholders.contains(&lower.as_str()) {
        return Err(
            "reason looks like a placeholder — explain why the secret is needed".to_string(),
        );
    }
    Ok(())
}

fn evaluate_with_policy(p: &Policy, req: &Request) -> Decision {
    let Some(caller) = p.caller(req.caller) else {
        return Decision::Deny(Tier::Low, format!("unknown caller '{}'", req.caller));
    };

    // Classify the secret: explicit entry, then the vault's "*" wildcard.
    let rule = p
        .vaults
        .get(req.vault)
        .and_then(|v| v.secrets.get(req.secret).or_else(|| v.secrets.get("*")));
    let Some(rule) = rule else {
        return Decision::Deny(
            Tier::Low,
            format!("secret '{}' is not classified in the policy", req.secret),
        );
    };
    let tier = rule.tier;

    // Capability: the declared scope must match the secret's scope, and the
    // caller must hold that scope.
    if req.scope != rule.scope {
        return Decision::Deny(
            tier,
            format!(
                "scope '{}' does not match the secret's scope '{}'",
                req.scope, rule.scope
            ),
        );
    }
    if !caller.scopes.iter().any(|s| s == req.scope) {
        return Decision::Deny(
            tier,
            format!(
                "caller '{}' is not granted scope '{}'",
                req.caller, req.scope
            ),
        );
    }

    // Sensitivity tier.
    if tier == Tier::High {
        return Decision::Deny(
            tier,
            "high-sensitivity secret — a human must retrieve it via 'svault secret get'"
                .to_string(),
        );
    }

    if let Some(msg) = rate_and_burst(req, &caller.rate_limit) {
        return Decision::Deny(tier, msg);
    }
    Decision::Allow(tier)
}

fn evaluate_fallback(meta: &VaultMeta, req: &Request) -> Decision {
    let allowed = match &meta.access.allow_agent {
        AllowAgent::Bool(b) => *b,
        AllowAgent::List(agents) => agents.iter().any(|a| a == req.caller),
    };
    if !allowed {
        return Decision::Deny(
            Tier::Low,
            format!(
                "agent '{}' is not permitted by this vault's allow_agent setting",
                req.caller
            ),
        );
    }
    if let Some(msg) = rate_and_burst(req, &meta.access.rate_limit) {
        return Decision::Deny(Tier::Low, msg);
    }
    Decision::Allow(Tier::Low)
}

/// Returns `Some(reason)` when the request should be denied for rate or burst,
/// counting prior *allowed* requests for this caller from the audit log.
fn rate_and_burst(req: &Request, rate_limit: &str) -> Option<String> {
    let now = Utc::now();

    if let Some((n, window)) = rate_limit_parse(rate_limit) {
        if let Ok(w) = chrono::Duration::from_std(window) {
            if allowed_count(req.vault_dir, req.caller, now - w) >= n as usize {
                return Some(format!("rate limit exceeded ({rate_limit})"));
            }
        }
    }

    let burst_since = now - chrono::Duration::seconds(BURST_WINDOW_SECS);
    if allowed_count(req.vault_dir, req.caller, burst_since) >= BURST_MAX {
        return Some(format!(
            "burst detected (>= {BURST_MAX} requests in {BURST_WINDOW_SECS}s)"
        ));
    }
    None
}

fn allowed_count(vault_dir: &Path, caller: &str, since: DateTime<Utc>) -> usize {
    audit::recent(vault_dir, caller, since)
        .map(|entries| entries.iter().filter(|e| e.decision == "allow").count())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::Entry;
    use crate::meta::{AccessConfig, AllowAgent, VaultMeta, VaultSettings};
    use tempfile::TempDir;

    fn parse(yaml: &str) -> Policy {
        serde_yaml::from_str(yaml).expect("policy yaml")
    }

    fn sample() -> Policy {
        parse(
            r#"
version: 1
callers:
  claude:
    scopes: [database, api]
    rate_limit: 2/hour
  default:
    scopes: []
    rate_limit: 5/hour
vaults:
  proj:
    secrets:
      DB_URL: { scope: database, tier: low }
      DB_PW: { scope: database, tier: high }
      API_KEY: { scope: api, tier: medium }
"#,
        )
    }

    fn req<'a>(dir: &'a Path, secret: &'a str, scope: &'a str, caller: &'a str) -> Request<'a> {
        Request {
            vault: "proj",
            vault_dir: dir,
            secret,
            scope,
            reason: "run the database migration",
            caller,
        }
    }

    #[test]
    fn rate_limit_parsing() {
        assert_eq!(
            rate_limit_parse("20/hour"),
            Some((20, Duration::from_secs(3600)))
        );
        assert_eq!(
            rate_limit_parse("5/min"),
            Some((5, Duration::from_secs(60)))
        );
        assert_eq!(
            rate_limit_parse("1/day"),
            Some((1, Duration::from_secs(86_400)))
        );
        assert_eq!(rate_limit_parse("nonsense"), None);
        assert_eq!(rate_limit_parse("10/decade"), None);
    }

    #[test]
    fn allow_when_scope_matches_and_held() {
        let dir = TempDir::new().unwrap();
        let p = sample();
        let d = evaluate(
            Some(&p),
            &dummy_meta(),
            &req(dir.path(), "DB_URL", "database", "claude"),
        );
        assert_eq!(d, Decision::Allow(Tier::Low));
    }

    #[test]
    fn medium_tier_is_allowed() {
        let dir = TempDir::new().unwrap();
        let p = sample();
        let d = evaluate(
            Some(&p),
            &dummy_meta(),
            &req(dir.path(), "API_KEY", "api", "claude"),
        );
        assert_eq!(d, Decision::Allow(Tier::Medium));
    }

    #[test]
    fn high_tier_is_denied() {
        let dir = TempDir::new().unwrap();
        let p = sample();
        let d = evaluate(
            Some(&p),
            &dummy_meta(),
            &req(dir.path(), "DB_PW", "database", "claude"),
        );
        assert!(!d.is_allow());
        assert_eq!(d.tier(), Tier::High);
    }

    #[test]
    fn scope_not_held_is_denied() {
        let dir = TempDir::new().unwrap();
        let p = sample();
        // "default" caller holds no scopes.
        let d = evaluate(
            Some(&p),
            &dummy_meta(),
            &req(dir.path(), "DB_URL", "database", "default"),
        );
        assert!(!d.is_allow());
    }

    #[test]
    fn wrong_scope_for_secret_is_denied() {
        let dir = TempDir::new().unwrap();
        let p = sample();
        let d = evaluate(
            Some(&p),
            &dummy_meta(),
            &req(dir.path(), "DB_URL", "api", "claude"),
        );
        assert!(!d.is_allow());
    }

    #[test]
    fn unknown_caller_without_default_is_denied() {
        let dir = TempDir::new().unwrap();
        let p = parse(
            r#"
version: 1
callers:
  claude: { scopes: [api], rate_limit: 5/hour }
vaults:
  proj:
    secrets:
      API_KEY: { scope: api, tier: low }
"#,
        );
        let d = evaluate(
            Some(&p),
            &dummy_meta(),
            &req(dir.path(), "API_KEY", "api", "ghost"),
        );
        assert!(!d.is_allow());
    }

    #[test]
    fn unclassified_secret_is_denied() {
        let dir = TempDir::new().unwrap();
        let p = sample();
        let d = evaluate(
            Some(&p),
            &dummy_meta(),
            &req(dir.path(), "MYSTERY", "database", "claude"),
        );
        assert!(!d.is_allow());
    }

    #[test]
    fn short_reason_is_denied() {
        let dir = TempDir::new().unwrap();
        let p = sample();
        let mut r = req(dir.path(), "DB_URL", "database", "claude");
        r.reason = "fix";
        assert!(!evaluate(Some(&p), &dummy_meta(), &r).is_allow());
    }

    #[test]
    fn rate_limit_exceeded_is_denied() {
        let dir = TempDir::new().unwrap();
        let p = sample(); // claude is 2/hour
        for _ in 0..2 {
            audit::record(
                dir.path(),
                &Entry::now("claude", "DB_URL", "database", "low", "allow", "ok", "seed"),
            )
            .unwrap();
        }
        let d = evaluate(
            Some(&p),
            &dummy_meta(),
            &req(dir.path(), "DB_URL", "database", "claude"),
        );
        assert!(!d.is_allow());
    }

    #[test]
    fn burst_is_denied() {
        let dir = TempDir::new().unwrap();
        let p = parse(
            r#"
version: 1
callers:
  fast: { scopes: [api], rate_limit: 1000/hour }
vaults:
  proj:
    secrets:
      API_KEY: { scope: api, tier: low }
"#,
        );
        for _ in 0..BURST_MAX {
            audit::record(
                dir.path(),
                &Entry::now("fast", "API_KEY", "api", "low", "allow", "ok", "seed"),
            )
            .unwrap();
        }
        let d = evaluate(
            Some(&p),
            &dummy_meta(),
            &req(dir.path(), "API_KEY", "api", "fast"),
        );
        assert!(!d.is_allow());
    }

    #[test]
    fn fallback_respects_allow_agent() {
        let dir = TempDir::new().unwrap();
        let yes = meta_with(AllowAgent::Bool(true));
        let no = meta_with(AllowAgent::Bool(false));
        let listed = meta_with(AllowAgent::List(vec!["claude".to_string()]));

        assert!(evaluate(None, &yes, &req(dir.path(), "X", "any", "claude")).is_allow());
        assert!(!evaluate(None, &no, &req(dir.path(), "X", "any", "claude")).is_allow());
        assert!(evaluate(None, &listed, &req(dir.path(), "X", "any", "claude")).is_allow());
        assert!(!evaluate(None, &listed, &req(dir.path(), "X", "any", "stranger")).is_allow());
    }

    fn dummy_meta() -> VaultMeta {
        meta_with(AllowAgent::Bool(true))
    }

    fn meta_with(allow: AllowAgent) -> VaultMeta {
        VaultMeta::new(
            "proj".to_string(),
            String::new(),
            AccessConfig {
                allow_agent: allow,
                rate_limit: "1000/hour".to_string(),
            },
            VaultSettings::default(),
        )
    }
}
