//! The policy engine — the base of the gate behind `svault get`.
//!
//! A structured request (`secret`, `scope`, `reason`, `caller`) is run through
//! the base pipeline here: reason required -> classification (from the signed
//! `meta.yaml`) -> scope match -> caller capability -> rate limit / burst. The
//! verdict is a [`Decision`] carrying the secret's tier; the **tier + AI-judge
//! gate** is then applied by [`crate::gate`] so the daemon and the CLI fallback
//! share one decision path. Enforcement lives in the daemon (the choke point).
//!
//! Per-secret classification (scope/tier/`require_reason`) lives in the
//! HMAC-signed `meta.yaml`. The committable `svault.policy.yaml` holds only the
//! caller definitions; its discovery is anchored to the project root and a
//! present-but-unparseable file [fails closed](PolicyLoad::Error). When neither
//! a classification nor a policy file applies, caller authorization falls back to
//! the vault's `allow_agent` / `rate_limit`.

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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecretRule {
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub tier: Tier,
    /// When set, the AI judge is always consulted for this secret (even at
    /// `low` tier) — i.e. the caller must justify the request and have it
    /// scored. Off by default; the reason is still required for any agent get.
    #[serde(default)]
    pub require_reason: bool,
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

    /// Secrets in `meta` this caller may retrieve, for `svault policy check`.
    /// High-tier and the `"*"` wildcard are skipped. Classification now lives in
    /// the signed `meta.yaml`, so this reads from there rather than the policy
    /// file.
    pub fn accessible(&self, caller: &str, meta: &VaultMeta) -> Vec<(String, String, Tier)> {
        let Some(rule) = self.caller(caller) else {
            return vec![];
        };
        let mut out = Vec::new();
        for (sname, sr) in &meta.secrets {
            if sname == "*" {
                continue;
            }
            if sr.tier != Tier::High && rule.scopes.iter().any(|s| s == &sr.scope) {
                out.push((sname.clone(), sr.scope.clone(), sr.tier));
            }
        }
        out.sort();
        out
    }
}

/// Outcome of trying to load `svault.policy.yaml`.
pub enum PolicyLoad {
    /// No policy file at or below the project root — run in fallback mode.
    Absent,
    /// Parsed successfully.
    Loaded(Box<Policy>),
    /// A policy file exists but couldn't be read/parsed. The gate **fails
    /// closed** on this — a typo must not silently downgrade to allow-all (N-2).
    Error(String),
}

/// Find and parse `svault.policy.yaml`. Searches from the CWD upward but **stops
/// at the project root** (the first directory containing a `.svault/`), so an
/// agent can't `cd` somewhere with a permissive ancestor policy (#5). A present
/// but unparseable file is reported as [`PolicyLoad::Error`] (fail closed, N-2).
pub fn load() -> PolicyLoad {
    let Ok(cwd) = std::env::current_dir() else {
        return PolicyLoad::Absent;
    };
    let Some(path) = find_policy_file(&cwd) else {
        return PolicyLoad::Absent;
    };
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => return PolicyLoad::Error(format!("cannot read {}: {e}", path.display())),
    };
    match serde_yaml::from_str::<Policy>(&content) {
        Ok(p) => PolicyLoad::Loaded(Box::new(p)),
        Err(e) => PolicyLoad::Error(format!("invalid {}: {e}", path.display())),
    }
}

/// Path to `svault.policy.yaml` at or above `start`, never searching past the
/// project root (the directory that holds `.svault/`).
pub fn find_policy_file(start: &Path) -> Option<PathBuf> {
    let mut dir = start.to_path_buf();
    loop {
        let candidate = dir.join(POLICY_FILE);
        if candidate.is_file() {
            return Some(candidate);
        }
        // Don't search above the project root.
        if dir.join(crate::vault::SVAULT_DIR).is_dir() {
            return None;
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

/// Run the base policy pipeline: reason -> classification (from the signed
/// meta) -> scope match -> caller capability -> rate/burst. Returns `Allow(tier)`
/// or `Deny`. The **tier + AI-judge gate is applied separately** by
/// [`crate::gate`] so the same decision path serves the daemon and the CLI
/// fallback. `policy` is `None` when there's no policy file (caller authorization
/// then falls back to the vault's `allow_agent`).
pub fn evaluate(policy: Option<&Policy>, meta: &VaultMeta, req: &Request) -> Decision {
    // Reason is required for every agent request.
    if let Err(msg) = check_reason(req.reason) {
        return Decision::Deny(Tier::Low, msg);
    }
    match meta.classify(req.secret) {
        Some(rule) => evaluate_classified(policy, meta, req, rule),
        // No per-secret classification: legacy fallback (allow_agent, tier low).
        None => evaluate_fallback(meta, req),
    }
}

fn evaluate_classified(
    policy: Option<&Policy>,
    meta: &VaultMeta,
    req: &Request,
    rule: &SecretRule,
) -> Decision {
    let tier = rule.tier;

    // The declared scope must match the secret's classified scope.
    if req.scope != rule.scope {
        return Decision::Deny(
            tier,
            format!(
                "scope '{}' does not match the secret's scope '{}'",
                req.scope, rule.scope
            ),
        );
    }

    // Caller authorization + the rate limit to enforce. With a policy file the
    // caller must hold the scope; without one we fall back to allow_agent.
    let rate_limit = match policy {
        Some(p) => {
            let Some(caller) = p.caller(req.caller) else {
                return Decision::Deny(tier, format!("unknown caller '{}'", req.caller));
            };
            if !caller.scopes.iter().any(|s| s == req.scope) {
                return Decision::Deny(
                    tier,
                    format!(
                        "caller '{}' is not granted scope '{}'",
                        req.caller, req.scope
                    ),
                );
            }
            caller.rate_limit.clone()
        }
        None => {
            let allowed = match &meta.access.allow_agent {
                AllowAgent::Bool(b) => *b,
                AllowAgent::List(agents) => agents.iter().any(|a| a == req.caller),
            };
            if !allowed {
                return Decision::Deny(
                    tier,
                    format!(
                        "agent '{}' is not permitted by this vault's allow_agent setting",
                        req.caller
                    ),
                );
            }
            meta.access.rate_limit.clone()
        }
    };

    if let Some(msg) = rate_and_burst(req, &rate_limit) {
        return Decision::Deny(tier, msg);
    }
    // High tier is NOT auto-denied here anymore — the gate decides (judge-gated
    // when the judge is on, human-only when it's off).
    Decision::Allow(tier)
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

    /// Callers only — classification now lives in the (signed) meta.
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
"#,
        )
    }

    fn rule(scope: &str, tier: Tier) -> SecretRule {
        SecretRule {
            scope: scope.to_string(),
            tier,
            require_reason: false,
        }
    }

    /// A meta carrying the per-secret classification the tests gate on.
    fn classified_meta() -> VaultMeta {
        let mut m = meta_with(AllowAgent::Bool(true));
        m.secrets
            .insert("DB_URL".into(), rule("database", Tier::Low));
        m.secrets
            .insert("DB_PW".into(), rule("database", Tier::High));
        m.secrets
            .insert("API_KEY".into(), rule("api", Tier::Medium));
        m
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
        let d = evaluate(
            Some(&sample()),
            &classified_meta(),
            &req(dir.path(), "DB_URL", "database", "claude"),
        );
        assert_eq!(d, Decision::Allow(Tier::Low));
    }

    #[test]
    fn medium_tier_is_allowed() {
        let dir = TempDir::new().unwrap();
        let d = evaluate(
            Some(&sample()),
            &classified_meta(),
            &req(dir.path(), "API_KEY", "api", "claude"),
        );
        assert_eq!(d, Decision::Allow(Tier::Medium));
    }

    #[test]
    fn high_tier_passes_base_policy() {
        // The base policy no longer auto-denies high — the gate does. evaluate
        // returns Allow(High) so the tier+judge gate can decide.
        let dir = TempDir::new().unwrap();
        let d = evaluate(
            Some(&sample()),
            &classified_meta(),
            &req(dir.path(), "DB_PW", "database", "claude"),
        );
        assert_eq!(d, Decision::Allow(Tier::High));
    }

    #[test]
    fn scope_not_held_is_denied() {
        let dir = TempDir::new().unwrap();
        // "default" caller holds no scopes.
        let d = evaluate(
            Some(&sample()),
            &classified_meta(),
            &req(dir.path(), "DB_URL", "database", "default"),
        );
        assert!(!d.is_allow());
    }

    #[test]
    fn wrong_scope_for_secret_is_denied() {
        let dir = TempDir::new().unwrap();
        let d = evaluate(
            Some(&sample()),
            &classified_meta(),
            &req(dir.path(), "DB_URL", "api", "claude"),
        );
        assert!(!d.is_allow());
    }

    #[test]
    fn unknown_caller_without_default_is_denied() {
        let dir = TempDir::new().unwrap();
        let p = parse("version: 1\ncallers:\n  claude: { scopes: [api], rate_limit: 5/hour }\n");
        let d = evaluate(
            Some(&p),
            &classified_meta(),
            &req(dir.path(), "API_KEY", "api", "ghost"),
        );
        assert!(!d.is_allow());
    }

    #[test]
    fn unclassified_secret_falls_back_to_allow_agent() {
        let dir = TempDir::new().unwrap();
        // No classification for "MYSTERY" → fallback. allow_agent=true → allow,
        // allow_agent=false → deny.
        let yes = classified_meta();
        let no = meta_with(AllowAgent::Bool(false));
        assert!(evaluate(
            Some(&sample()),
            &yes,
            &req(dir.path(), "MYSTERY", "database", "claude")
        )
        .is_allow());
        assert!(!evaluate(
            Some(&sample()),
            &no,
            &req(dir.path(), "MYSTERY", "database", "claude")
        )
        .is_allow());
    }

    #[test]
    fn short_reason_is_denied() {
        let dir = TempDir::new().unwrap();
        let mut r = req(dir.path(), "DB_URL", "database", "claude");
        r.reason = "fix";
        assert!(!evaluate(Some(&sample()), &classified_meta(), &r).is_allow());
    }

    #[test]
    fn rate_limit_exceeded_is_denied() {
        let dir = TempDir::new().unwrap();
        for _ in 0..2 {
            audit::record(
                dir.path(),
                &Entry::now("claude", "DB_URL", "database", "low", "allow", "ok", "seed"),
            )
            .unwrap();
        }
        let d = evaluate(
            Some(&sample()), // claude is 2/hour
            &classified_meta(),
            &req(dir.path(), "DB_URL", "database", "claude"),
        );
        assert!(!d.is_allow());
    }

    #[test]
    fn burst_is_denied() {
        let dir = TempDir::new().unwrap();
        let p = parse("version: 1\ncallers:\n  fast: { scopes: [api], rate_limit: 1000/hour }\n");
        let mut m = meta_with(AllowAgent::Bool(true));
        m.secrets.insert("API_KEY".into(), rule("api", Tier::Low));
        for _ in 0..BURST_MAX {
            audit::record(
                dir.path(),
                &Entry::now("fast", "API_KEY", "api", "low", "allow", "ok", "seed"),
            )
            .unwrap();
        }
        let d = evaluate(Some(&p), &m, &req(dir.path(), "API_KEY", "api", "fast"));
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
