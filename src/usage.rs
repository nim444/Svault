//! Usage log — an append-only timeline of what happens to a vault, by whom.
//!
//! One JSON object per line in `.svault/<vault>/usage.log`. Unlike `audit.log`
//! (which is specialized for policy decisions and rate-limit counting), this is
//! a general activity stream: who did what, when. It distinguishes **human**
//! actions (the CLI/TUI used by a person) from **agent** actions (the policy-
//! gated `svault get` path), so the data can later feed usage analysis.
//!
//! It never stores secret *values* — only the action, the secret's name where
//! relevant, the actor kind, and an actor id (system user, or the agent caller).
//! The file is gitignored (written by `Vault::init`) and owner-only (mode 0600).

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const HUMAN: &str = "human";
pub const AGENT: &str = "agent";

/// One usage event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub ts: String,
    /// "human" or "agent".
    pub actor: String,
    /// System username for humans, the `--caller` value for agents.
    pub actor_id: String,
    /// A short action key, e.g. `unlock`, `secret.reveal`, `get.allow`.
    pub action: String,
    /// The thing acted on (usually a secret name), when relevant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

impl Event {
    fn new(actor: &str, actor_id: &str, action: &str, target: Option<&str>) -> Self {
        Self {
            ts: Utc::now().to_rfc3339(),
            actor: actor.to_string(),
            actor_id: actor_id.to_string(),
            action: action.to_string(),
            target: target.map(|t| t.to_string()),
        }
    }

    /// An action taken by a person via the CLI or TUI.
    pub fn human(action: &str, target: Option<&str>) -> Self {
        Self::new(HUMAN, &current_user(), action, target)
    }

    /// An action taken by an AI agent through the policy-gated `get` path.
    pub fn agent(caller: &str, action: &str, target: Option<&str>) -> Self {
        Self::new(AGENT, caller, action, target)
    }

    pub fn timestamp(&self) -> Option<DateTime<Utc>> {
        DateTime::parse_from_rfc3339(&self.ts)
            .ok()
            .map(|t| t.with_timezone(&Utc))
    }
}

/// Best guess at the current human's identity for labeling events.
pub fn current_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| HUMAN.to_string())
}

fn usage_path(vault_dir: &Path) -> PathBuf {
    vault_dir.join("usage.log")
}

/// Make sure the vault's local `.gitignore` lists the session + log files, so
/// they can never be committed — even for a vault created before usage logging
/// existed (whose `.gitignore` predates the `usage.log` line). Best-effort.
fn ensure_gitignored(vault_dir: &Path) {
    const NEEDED: [&str; 3] = [".session", "audit.log", "usage.log"];
    let gi = vault_dir.join(".gitignore");
    let existing = std::fs::read_to_string(&gi).unwrap_or_default();
    let have: std::collections::HashSet<&str> = existing.lines().map(str::trim).collect();
    let missing: Vec<&str> = NEEDED
        .iter()
        .copied()
        .filter(|n| !have.contains(n))
        .collect();
    if missing.is_empty() {
        return;
    }
    let mut content = existing;
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    for n in missing {
        content.push_str(n);
        content.push('\n');
    }
    let _ = std::fs::write(&gi, content);
}

/// Append one event as a JSON line (owner-only on unix). Best-effort: callers in
/// the UI ignore the error so logging can never block the actual operation.
pub fn record(vault_dir: &Path, event: &Event) -> Result<()> {
    let path = usage_path(vault_dir);
    // On the first event for this vault, make sure the log is gitignored before
    // we create it (covers vaults whose .gitignore predates usage logging).
    if !path.exists() {
        ensure_gitignored(vault_dir);
    }
    let mut line = serde_json::to_string(event)?;
    line.push('\n');

    use std::io::Write;
    #[cfg(unix)]
    let mut f = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)?
    };
    #[cfg(not(unix))]
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;

    f.write_all(line.as_bytes())?;
    Ok(())
}

/// Convenience: record a human event, ignoring any I/O error.
pub fn human(vault_dir: &Path, action: &str, target: Option<&str>) {
    let _ = record(vault_dir, &Event::human(action, target));
}

/// Convenience: record an agent event, ignoring any I/O error.
pub fn agent(vault_dir: &Path, caller: &str, action: &str, target: Option<&str>) {
    let _ = record(vault_dir, &Event::agent(caller, action, target));
}

/// The most recent `limit` events, newest first. Empty when the log is absent.
/// Malformed lines are skipped rather than failing the whole read.
pub fn recent(vault_dir: &Path, limit: usize) -> Vec<Event> {
    let Ok(content) = std::fs::read_to_string(usage_path(vault_dir)) else {
        return Vec::new();
    };
    let mut events: Vec<Event> = content
        .lines()
        .filter_map(|l| serde_json::from_str::<Event>(l.trim()).ok())
        .collect();
    events.reverse();
    events.truncate(limit);
    events
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn human_and_agent_events_record_and_read_newest_first() {
        let dir = TempDir::new().unwrap();
        let vd = dir.path();

        human(vd, "unlock", None);
        human(vd, "secret.reveal", Some("STRIPE_KEY"));
        agent(vd, "claude", "get.allow", Some("DB_URL"));

        let events = recent(vd, 10);
        assert_eq!(events.len(), 3);
        // Newest first.
        assert_eq!(events[0].actor, AGENT);
        assert_eq!(events[0].actor_id, "claude");
        assert_eq!(events[0].action, "get.allow");
        assert_eq!(events[0].target.as_deref(), Some("DB_URL"));
        assert_eq!(events[2].action, "unlock");
        assert!(events[2].target.is_none());
    }

    #[test]
    fn recent_limit_caps_results() {
        let dir = TempDir::new().unwrap();
        for _ in 0..5 {
            human(dir.path(), "secret.list", None);
        }
        assert_eq!(recent(dir.path(), 3).len(), 3);
    }

    #[test]
    fn recent_on_missing_log_is_empty() {
        let dir = TempDir::new().unwrap();
        assert!(recent(dir.path(), 10).is_empty());
    }

    #[test]
    fn first_event_adds_usage_log_to_a_stale_gitignore() {
        let dir = TempDir::new().unwrap();
        // Simulate an old vault whose .gitignore predates usage logging.
        std::fs::write(dir.path().join(".gitignore"), ".session\naudit.log\n").unwrap();

        human(dir.path(), "unlock", None);

        let gi = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
        assert!(gi.contains("usage.log"), "usage.log must be ignored: {gi}");
        // Existing lines are preserved, not clobbered.
        assert!(gi.contains(".session") && gi.contains("audit.log"));
    }

    #[test]
    fn target_is_omitted_from_json_when_none() {
        let e = Event::human("lock", None);
        let json = serde_json::to_string(&e).unwrap();
        assert!(!json.contains("target"));
    }
}
