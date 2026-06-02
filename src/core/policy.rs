//! The policy engine — the base of the gate behind `svault get`.
//!
//! A structured request (`secret`, `scope`, `reason`, `caller`) runs through the
//! base pipeline here: reason required, classification lookup, scope match,
//! caller capability, rate limit / burst. The verdict is a [`Decision`] carrying
//! the secret's tier; the tier + AI-judge gate is then applied by [`crate::core::gate`]
//! so the daemon and the CLI fallback share one decision path. Enforcement lives
//! in the daemon (the choke point).
//!
//! All policy — per-secret classification (scope/tier/`require_reason`), caller
//! rules, access fallback — lives in [`VaultPolicyData`], stored AES-256-GCM
//! **encrypted** inside `vault.enc`. It is unreadable at rest (no recon) and only
//! in memory once the vault is unlocked. When a secret has no classification,
//! caller authorization falls back to the vault's `allow_agent` / `rate_limit`.

use chrono::{DateTime, Datelike, Local, NaiveTime, Utc, Weekday};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use crate::core::audit;
use crate::core::meta::{AccessConfig, AllowAgent, VaultJudgeConfig};

/// Burst window: more than [`BURST_MAX`] allowed requests inside this many
/// seconds is treated as anomalous regardless of the configured rate limit.
const BURST_WINDOW_SECS: i64 = 10;
const BURST_MAX: usize = 5;

/// Caller-agnostic burst ceiling: more than this many *allowed* reads of a
/// single secret inside [`BURST_WINDOW_SECS`], counted across **every** caller,
/// is denied. The per-caller [`BURST_MAX`] and rate limit are keyed on the
/// self-asserted `--caller` string, so an abuser could evade them by rotating
/// caller names; this ceiling can't be sidestepped that way (it mirrors the
/// caller-agnostic seal detector). Set above [`BURST_MAX`] so a few legitimate
/// distinct callers reading the same secret don't trip it.
const SECRET_BURST_MAX: usize = 10;

/// Seal trigger: this many denials for one secret inside [`SEAL_WINDOW_SECS`]
/// seals it (medium/high only) and escalates to a human. The seal then denies
/// every gated agent get until a human clears it — the agent can never
/// self-clear. A human still reads the secret directly via `svault secret get`.
pub const SEAL_DENY_THRESHOLD: usize = 5;
pub const SEAL_WINDOW_SECS: i64 = 300;

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
    /// Optional human note on what this secret is for (e.g. "production Stripe
    /// charge key"). Travels in the signed `meta.yaml` and is handed to the AI
    /// judge as context so it can tell whether a stated reason actually fits the
    /// secret. Never a secret value.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// Conditional access: allowed time windows (local time). Empty = any time.
    /// When set, a request outside every window is denied with the same generic
    /// message, so a caller cannot read the window and wait for it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub windows: Vec<AccessWindow>,
    /// Conditional access: when non-empty, only these callers may retrieve the
    /// secret (a per-secret hard requirement, on top of scope/caller rules).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub require_callers: Vec<String>,
}

/// An allowed access window for a secret, evaluated in **local machine time**.
/// Parsed from a compact spec like `mon-fri 09:00-18:00`, `fri 10:00-12:00`, or
/// `09:00-17:00` (no day = any day). Same-day only: `start` is inclusive, `end`
/// exclusive, and `start` must be before `end` (no cross-midnight spans).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessWindow {
    /// Allowed weekdays as lowercase `mon`..`sun`. Empty = any day.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub days: Vec<String>,
    /// Inclusive start, `HH:MM` 24h local.
    pub start: String,
    /// Exclusive end, `HH:MM` 24h local.
    pub end: String,
}

const DAY_ORDER: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

fn weekday_short(wd: Weekday) -> &'static str {
    match wd {
        Weekday::Mon => "mon",
        Weekday::Tue => "tue",
        Weekday::Wed => "wed",
        Weekday::Thu => "thu",
        Weekday::Fri => "fri",
        Weekday::Sat => "sat",
        Weekday::Sun => "sun",
    }
}

fn parse_hhmm(s: &str) -> Result<NaiveTime, String> {
    let (h, m) = s
        .trim()
        .split_once(':')
        .ok_or_else(|| format!("'{s}' is not HH:MM"))?;
    let h: u32 = h.trim().parse().map_err(|_| format!("bad hour in '{s}'"))?;
    let m: u32 = m
        .trim()
        .parse()
        .map_err(|_| format!("bad minute in '{s}'"))?;
    NaiveTime::from_hms_opt(h, m, 0).ok_or_else(|| format!("'{s}' is out of range"))
}

fn parse_days(part: &str) -> Result<Vec<String>, String> {
    let part = part.trim();
    if part.is_empty() {
        return Ok(vec![]);
    }
    let idx = |d: &str| DAY_ORDER.iter().position(|x| *x == d);
    if let Some((a, b)) = part.split_once('-') {
        let (a, b) = (a.trim(), b.trim());
        let (ai, bi) = (
            idx(a).ok_or_else(|| format!("unknown day '{a}'"))?,
            idx(b).ok_or_else(|| format!("unknown day '{b}'"))?,
        );
        if ai > bi {
            return Err(format!("day range '{part}' is reversed"));
        }
        return Ok(DAY_ORDER[ai..=bi].iter().map(|s| s.to_string()).collect());
    }
    let mut out = Vec::new();
    for d in part.split(',') {
        let d = d.trim();
        if idx(d).is_none() {
            return Err(format!("unknown day '{d}'"));
        }
        out.push(d.to_string());
    }
    Ok(out)
}

impl AccessWindow {
    /// Parse a compact spec like `mon-fri 09:00-18:00` (day part optional).
    pub fn parse(spec: &str) -> Result<AccessWindow, String> {
        let spec = spec.trim().to_lowercase();
        if spec.is_empty() {
            return Err("empty window".to_string());
        }
        let (days_part, time_part) = match spec.rsplit_once(char::is_whitespace) {
            Some((d, t)) => (d.trim(), t.trim()),
            None => ("", spec.as_str()),
        };
        let (start_s, end_s) = time_part
            .split_once('-')
            .ok_or_else(|| format!("'{time_part}' is not a HH:MM-HH:MM range"))?;
        let start = parse_hhmm(start_s)?;
        let end = parse_hhmm(end_s)?;
        if start >= end {
            return Err("window start must be before end (no cross-midnight spans)".to_string());
        }
        Ok(AccessWindow {
            days: parse_days(days_part)?,
            start: start.format("%H:%M").to_string(),
            end: end.format("%H:%M").to_string(),
        })
    }

    /// True if `now` (local) falls on an allowed day and inside `[start, end)`.
    pub fn is_open(&self, now: DateTime<Local>) -> bool {
        if !self.days.is_empty() && !self.days.iter().any(|d| d == weekday_short(now.weekday())) {
            return false;
        }
        let (Ok(start), Ok(end)) = (parse_hhmm(&self.start), parse_hhmm(&self.end)) else {
            return false;
        };
        let t = now.time();
        t >= start && t < end
    }
}

impl std::fmt::Display for AccessWindow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.days.is_empty() {
            write!(f, "{}-{}", self.start, self.end)
        } else {
            write!(f, "{} {}-{}", self.days.join(","), self.start, self.end)
        }
    }
}

/// A sealed secret — set by the gate after [`SEAL_DENY_THRESHOLD`] denials within
/// [`SEAL_WINDOW_SECS`]. Stored AES-256-GCM encrypted inside `vault.enc` (an agent
/// can't read or clear it without the master). Denies every gated agent get until
/// a human clears it via `svault approve`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seal {
    /// RFC 3339 UTC timestamp of when the seal was set.
    pub sealed_at: String,
    /// Short human-readable cause (e.g. "5 denials in 300s").
    pub trigger: String,
    /// The caller string on the request that tripped the seal.
    pub last_caller: String,
    /// How many denials led to the seal.
    pub denials: u32,
}

/// The complete per-vault policy surface, stored **AES-256-GCM encrypted** inside
/// `vault.enc` (not in the plaintext `meta.yaml`). Because it is encrypted under
/// the vault key, a same-UID agent can't *read* it at rest to plan a request that
/// passes (no recon), nor *tamper* with a tier/scope/caller without the
/// passphrase. It is only in memory once the vault is unlocked.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VaultPolicyData {
    /// Per-secret classification (scope, tier, require_reason, description). A
    /// `"*"` entry, if present, is the default classification for any unlisted
    /// secret.
    #[serde(default)]
    pub secrets: BTreeMap<String, SecretRule>,
    /// Fallback access (allow_agent + rate_limit) used when no caller rules are
    /// defined.
    #[serde(default)]
    pub access: AccessConfig,
    /// Per-vault AI-judge overrides (inherit the global config when unset).
    #[serde(default)]
    pub judge: VaultJudgeConfig,
    /// Default tier applied to a secret added without an explicit one.
    #[serde(default)]
    pub default_tier: Tier,
    /// Caller definitions (which agent holds which scopes, at what rate limit).
    /// Formerly the committable `svault.policy.yaml`; now per-vault and encrypted.
    #[serde(default)]
    pub callers: BTreeMap<String, CallerRule>,
    /// Sealed secrets (anomaly-escalated, awaiting human approval), keyed by
    /// secret name. Set by the gate, cleared only by a human (`svault approve`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub seals: BTreeMap<String, Seal>,
}

impl VaultPolicyData {
    /// The classification for `secret`: an explicit entry, else the `"*"`
    /// default, else `None` (the vault has no classification for it).
    pub fn classify(&self, secret: &str) -> Option<&SecretRule> {
        self.secrets.get(secret).or_else(|| self.secrets.get("*"))
    }

    /// Resolve a caller, falling back to the `default` caller when present.
    pub fn caller(&self, name: &str) -> Option<&CallerRule> {
        self.callers
            .get(name)
            .or_else(|| self.callers.get("default"))
    }

    /// Secrets this caller may retrieve, for `svault policy check`. High-tier and
    /// the `"*"` wildcard are skipped.
    pub fn accessible(&self, caller: &str) -> Vec<(String, String, Tier)> {
        let Some(rule) = self.caller(caller) else {
            return vec![];
        };
        let mut out = Vec::new();
        for (sname, sr) in &self.secrets {
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
    /// The vault's public description — handed to the AI judge as the vault's
    /// purpose (so a reason that doesn't fit can be denied). Not used by the
    /// base policy pipeline.
    pub vault_description: &'a str,
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

/// Run the base policy pipeline (reason, then classification, scope match,
/// caller capability, rate/burst). Returns `Allow(tier)` or `Deny`. The tier and
/// AI-judge gate is applied separately by [`crate::core::gate`] so the same decision
/// path serves the daemon and the CLI fallback. All policy comes from the
/// decrypted [`VaultPolicyData`]; caller authorization falls back to
/// `access.allow_agent` when no caller rules are defined.
pub fn evaluate(policy: &VaultPolicyData, req: &Request) -> Decision {
    // Reason is required for every agent request.
    if let Err(msg) = check_reason(req.reason) {
        return Decision::Deny(Tier::Low, msg);
    }
    match policy.classify(req.secret) {
        Some(rule) => evaluate_classified(policy, req, rule),
        // No per-secret classification: fallback (allow_agent, tier low).
        None => evaluate_fallback(policy, req),
    }
}

fn evaluate_classified(policy: &VaultPolicyData, req: &Request, rule: &SecretRule) -> Decision {
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

    // Caller authorization + the rate limit to enforce. When caller rules are
    // defined the caller must hold the scope; otherwise we fall back to the
    // vault's allow_agent setting.
    let rate_limit = if policy.callers.is_empty() {
        let allowed = match &policy.access.allow_agent {
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
        policy.access.rate_limit.clone()
    } else {
        let Some(caller) = policy.caller(req.caller) else {
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
    };

    // Conditional access (0.9.9): required callers and time windows. Both deny
    // with a normal Decision, so the caller only ever sees the generic message
    // and can't read the window or the required-caller list to game it.
    if !rule.require_callers.is_empty() && !rule.require_callers.iter().any(|c| c == req.caller) {
        return Decision::Deny(
            tier,
            "caller not in this secret's required-caller list".to_string(),
        );
    }
    if !rule.windows.is_empty() {
        let now = Local::now();
        if !rule.windows.iter().any(|w| w.is_open(now)) {
            return Decision::Deny(
                tier,
                "outside this secret's allowed access window".to_string(),
            );
        }
    }

    if let Some(msg) = rate_and_burst(req, &rate_limit) {
        return Decision::Deny(tier, msg);
    }
    // High tier is NOT auto-denied here — the gate decides (judge-gated when the
    // judge is on, human-only when it's off).
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

fn evaluate_fallback(policy: &VaultPolicyData, req: &Request) -> Decision {
    let allowed = match &policy.access.allow_agent {
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
    if let Some(msg) = rate_and_burst(req, &policy.access.rate_limit) {
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

    // Caller-agnostic backstop: the per-caller checks above key on the
    // self-asserted `--caller`, so an abuser can rotate caller names to dodge
    // them. Count allowed reads of THIS secret across every caller — a ceiling
    // here can't be evaded by cycling identities (same idea as the seal
    // detector, which counts denials per-secret across callers).
    if allowed_count_for_secret(req.vault_dir, req.secret, burst_since) >= SECRET_BURST_MAX {
        return Some(format!(
            "secret burst detected (>= {SECRET_BURST_MAX} reads in {BURST_WINDOW_SECS}s across all callers)"
        ));
    }
    None
}

fn allowed_count(vault_dir: &Path, caller: &str, since: DateTime<Utc>) -> usize {
    audit::recent(vault_dir, caller, since)
        .map(|entries| entries.iter().filter(|e| e.decision == "allow").count())
        .unwrap_or(0)
}

/// Allowed reads of `secret` since `since`, counted across **every** caller —
/// the rotation-proof companion to [`allowed_count`].
fn allowed_count_for_secret(vault_dir: &Path, secret: &str, since: DateTime<Utc>) -> usize {
    audit::recent_for_secret(vault_dir, secret, since)
        .map(|entries| entries.iter().filter(|e| e.decision == "allow").count())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::audit::Entry;
    use crate::core::meta::{AccessConfig, AllowAgent};
    use tempfile::TempDir;

    fn rule(scope: &str, tier: Tier) -> SecretRule {
        SecretRule {
            scope: scope.to_string(),
            tier,
            ..SecretRule::default()
        }
    }

    fn caller(scopes: &[&str], rate: &str) -> CallerRule {
        CallerRule {
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            rate_limit: rate.to_string(),
        }
    }

    /// Policy with caller rules + per-secret classification.
    fn classified_policy() -> VaultPolicyData {
        let mut p = VaultPolicyData::default();
        p.callers
            .insert("claude".into(), caller(&["database", "api"], "2/hour"));
        p.callers.insert("default".into(), caller(&[], "5/hour"));
        p.secrets
            .insert("DB_URL".into(), rule("database", Tier::Low));
        p.secrets
            .insert("DB_PW".into(), rule("database", Tier::High));
        p.secrets
            .insert("API_KEY".into(), rule("api", Tier::Medium));
        p
    }

    /// Fallback policy (no caller rules) — only allow_agent + rate_limit apply.
    fn fallback_policy(allow: AllowAgent) -> VaultPolicyData {
        VaultPolicyData {
            access: AccessConfig {
                allow_agent: allow,
                rate_limit: "1000/hour".to_string(),
            },
            ..VaultPolicyData::default()
        }
    }

    fn req<'a>(dir: &'a Path, secret: &'a str, scope: &'a str, caller: &'a str) -> Request<'a> {
        Request {
            vault: "proj",
            vault_description: "",
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
            &classified_policy(),
            &req(dir.path(), "DB_URL", "database", "claude"),
        );
        assert_eq!(d, Decision::Allow(Tier::Low));
    }

    #[test]
    fn medium_tier_is_allowed() {
        let dir = TempDir::new().unwrap();
        let d = evaluate(
            &classified_policy(),
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
            &classified_policy(),
            &req(dir.path(), "DB_PW", "database", "claude"),
        );
        assert_eq!(d, Decision::Allow(Tier::High));
    }

    #[test]
    fn scope_not_held_is_denied() {
        let dir = TempDir::new().unwrap();
        // "default" caller holds no scopes.
        let d = evaluate(
            &classified_policy(),
            &req(dir.path(), "DB_URL", "database", "default"),
        );
        assert!(!d.is_allow());
    }

    #[test]
    fn wrong_scope_for_secret_is_denied() {
        let dir = TempDir::new().unwrap();
        let d = evaluate(
            &classified_policy(),
            &req(dir.path(), "DB_URL", "api", "claude"),
        );
        assert!(!d.is_allow());
    }

    #[test]
    fn unknown_caller_without_default_is_denied() {
        let dir = TempDir::new().unwrap();
        let mut p = VaultPolicyData::default();
        p.callers
            .insert("claude".into(), caller(&["api"], "5/hour"));
        p.secrets
            .insert("API_KEY".into(), rule("api", Tier::Medium));
        let d = evaluate(&p, &req(dir.path(), "API_KEY", "api", "ghost"));
        assert!(!d.is_allow());
    }

    #[test]
    fn unclassified_secret_falls_back_to_allow_agent() {
        let dir = TempDir::new().unwrap();
        // No classification for "MYSTERY" → fallback to allow_agent regardless of
        // caller rules. allow_agent=true → allow, allow_agent=false → deny.
        let yes = classified_policy(); // access defaults to allow_agent=true
        let no = fallback_policy(AllowAgent::Bool(false));
        assert!(evaluate(&yes, &req(dir.path(), "MYSTERY", "database", "claude")).is_allow());
        assert!(!evaluate(&no, &req(dir.path(), "MYSTERY", "database", "claude")).is_allow());
    }

    #[test]
    fn short_reason_is_denied() {
        let dir = TempDir::new().unwrap();
        let mut r = req(dir.path(), "DB_URL", "database", "claude");
        r.reason = "fix";
        assert!(!evaluate(&classified_policy(), &r).is_allow());
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
            &classified_policy(), // claude is 2/hour
            &req(dir.path(), "DB_URL", "database", "claude"),
        );
        assert!(!d.is_allow());
    }

    #[test]
    fn burst_is_denied() {
        let dir = TempDir::new().unwrap();
        let mut p = VaultPolicyData::default();
        p.callers
            .insert("fast".into(), caller(&["api"], "1000/hour"));
        p.secrets.insert("API_KEY".into(), rule("api", Tier::Low));
        for _ in 0..BURST_MAX {
            audit::record(
                dir.path(),
                &Entry::now("fast", "API_KEY", "api", "low", "allow", "ok", "seed"),
            )
            .unwrap();
        }
        let d = evaluate(&p, &req(dir.path(), "API_KEY", "api", "fast"));
        assert!(!d.is_allow());
    }

    #[test]
    fn caller_rotation_cannot_evade_the_per_secret_burst_ceiling() {
        // An abuser rotating the self-asserted caller stays under the per-caller
        // BURST_MAX for each name, but the caller-agnostic SECRET_BURST_MAX counts
        // allowed reads of the secret across every caller and still trips.
        let dir = TempDir::new().unwrap();
        let mut p = VaultPolicyData::default();
        // Each rotated caller is well under its own per-caller burst.
        for n in 0..SECRET_BURST_MAX {
            let who = format!("rot{n}");
            p.callers.insert(who.clone(), caller(&["api"], "1000/hour"));
            audit::record(
                dir.path(),
                &Entry::now(&who, "API_KEY", "api", "low", "allow", "ok", "seed"),
            )
            .unwrap();
        }
        p.secrets.insert("API_KEY".into(), rule("api", Tier::Low));
        // A fresh, never-before-seen caller would pass every per-caller check,
        // yet the secret has already been read SECRET_BURST_MAX times.
        p.callers
            .insert("newcomer".into(), caller(&["api"], "1000/hour"));
        let d = evaluate(&p, &req(dir.path(), "API_KEY", "api", "newcomer"));
        assert!(
            !d.is_allow(),
            "per-secret ceiling should deny across callers"
        );
    }

    #[test]
    fn window_parse_round_trips() {
        let w = AccessWindow::parse("mon-fri 09:00-18:00").unwrap();
        assert_eq!(w.days, vec!["mon", "tue", "wed", "thu", "fri"]);
        assert_eq!((w.start.as_str(), w.end.as_str()), ("09:00", "18:00"));
        assert_eq!(w.to_string(), "mon,tue,wed,thu,fri 09:00-18:00");

        // No day = any day; single day; comma list; loose hours zero-pad.
        assert!(AccessWindow::parse("09:00-17:00").unwrap().days.is_empty());
        assert_eq!(
            AccessWindow::parse("fri 10:00-12:00").unwrap().days,
            vec!["fri"]
        );
        assert_eq!(
            AccessWindow::parse("mon,wed,fri 9:00-17:30").unwrap().days,
            vec!["mon", "wed", "fri"]
        );
        assert_eq!(AccessWindow::parse("8:05-9:00").unwrap().start, "08:05");

        // Rejected: bad day, reversed range, reversed time, missing range.
        assert!(AccessWindow::parse("funday 09:00-10:00").is_err());
        assert!(AccessWindow::parse("fri-mon 09:00-10:00").is_err());
        assert!(AccessWindow::parse("18:00-09:00").is_err());
        assert!(AccessWindow::parse("mon-fri 0900").is_err());
    }

    #[test]
    fn window_is_open_respects_day_and_time() {
        use chrono::TimeZone;
        let w = AccessWindow::parse("mon 09:00-12:00").unwrap();
        // 2026-06-01 is a Monday.
        let inside = Local.with_ymd_and_hms(2026, 6, 1, 10, 30, 0).unwrap();
        let before = Local.with_ymd_and_hms(2026, 6, 1, 8, 59, 0).unwrap();
        let at_end = Local.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap(); // exclusive
        let tuesday = Local.with_ymd_and_hms(2026, 6, 2, 10, 30, 0).unwrap();
        assert!(w.is_open(inside));
        assert!(!w.is_open(before));
        assert!(!w.is_open(at_end));
        assert!(!w.is_open(tuesday));

        // No-day window is open any day inside the time range.
        let anyday = AccessWindow::parse("09:00-12:00").unwrap();
        assert!(anyday.is_open(tuesday));
    }

    #[test]
    fn required_caller_is_enforced() {
        let dir = TempDir::new().unwrap();
        let mut p = VaultPolicyData::default();
        let mut r = rule("api", Tier::Low);
        r.require_callers = vec!["ci".to_string()];
        p.secrets.insert("API_KEY".into(), r);

        assert!(evaluate(&p, &req(dir.path(), "API_KEY", "api", "ci")).is_allow());
        assert!(!evaluate(&p, &req(dir.path(), "API_KEY", "api", "claude")).is_allow());
    }

    #[test]
    fn out_of_window_is_denied() {
        let dir = TempDir::new().unwrap();
        let mut p = VaultPolicyData::default();
        let mut r = rule("api", Tier::Low);
        // A window that can never contain "now" within the same day: a 1-minute
        // slot. We assert the deny path by using a window far from any plausible
        // run time is brittle, so instead drive both branches via is_open above
        // and here assert that an impossible day set denies.
        r.windows = vec![AccessWindow {
            days: vec!["xxx".to_string()], // never matches a real weekday
            start: "00:00".to_string(),
            end: "23:59".to_string(),
        }];
        p.secrets.insert("API_KEY".into(), r);
        assert!(!evaluate(&p, &req(dir.path(), "API_KEY", "api", "claude")).is_allow());
    }

    #[test]
    fn fallback_respects_allow_agent() {
        let dir = TempDir::new().unwrap();
        let yes = fallback_policy(AllowAgent::Bool(true));
        let no = fallback_policy(AllowAgent::Bool(false));
        let listed = fallback_policy(AllowAgent::List(vec!["claude".to_string()]));

        assert!(evaluate(&yes, &req(dir.path(), "X", "any", "claude")).is_allow());
        assert!(!evaluate(&no, &req(dir.path(), "X", "any", "claude")).is_allow());
        assert!(evaluate(&listed, &req(dir.path(), "X", "any", "claude")).is_allow());
        assert!(!evaluate(&listed, &req(dir.path(), "X", "any", "stranger")).is_allow());
    }
}
