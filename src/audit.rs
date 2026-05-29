//! Append-only audit log for policy decisions.
//!
//! One JSON object per line in `.svault/<vault>/audit.log`. The log records
//! every structured `svault get` request — allowed or denied — and is the data
//! source for rate-limit counting, burst detection, and `svault policy check`.
//!
//! The file is gitignored (written by `Vault::init`) and never holds secret
//! values — only the secret's name, the caller, and the decision.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// One audit record. `decision` is "allow" or "deny"; `rule` is a short,
/// human-readable explanation of why.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub ts: String,
    pub caller: String,
    pub secret: String,
    pub scope: String,
    pub tier: String,
    /// Surface the request came through: "cli" / "mcp" / etc. (see [`crate::usage::Source`]).
    #[serde(default = "unknown_source")]
    pub source: String,
    pub decision: String,
    pub rule: String,
    pub reason: String,
}

fn unknown_source() -> String {
    String::new()
}

impl Entry {
    /// Build an entry stamped with the current time (RFC 3339, UTC).
    #[allow(clippy::too_many_arguments)]
    pub fn now(
        caller: &str,
        secret: &str,
        scope: &str,
        tier: &str,
        decision: &str,
        rule: &str,
        reason: &str,
    ) -> Self {
        Self {
            ts: Utc::now().to_rfc3339(),
            caller: caller.to_string(),
            secret: secret.to_string(),
            scope: scope.to_string(),
            tier: tier.to_string(),
            source: crate::usage::source().as_str().to_string(),
            decision: decision.to_string(),
            rule: rule.to_string(),
            reason: reason.to_string(),
        }
    }

    /// Parse the timestamp back into a `DateTime`, if it is valid RFC 3339.
    pub fn timestamp(&self) -> Option<DateTime<Utc>> {
        DateTime::parse_from_rfc3339(&self.ts)
            .ok()
            .map(|t| t.with_timezone(&Utc))
    }
}

fn audit_path(vault_dir: &Path) -> PathBuf {
    vault_dir.join("audit.log")
}

/// Append one entry as a JSON line. Creates the file with mode 0600 on unix,
/// mirroring the session file so audit history is owner-only.
pub fn record(vault_dir: &Path, entry: &Entry) -> Result<()> {
    let path = audit_path(vault_dir);
    let mut line = serde_json::to_string(entry)?;
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

/// Read all entries for `caller` with a timestamp at or after `since`.
/// Returns an empty vec when the log does not exist yet. Malformed lines are
/// skipped rather than failing the whole read.
pub fn recent(vault_dir: &Path, caller: &str, since: DateTime<Utc>) -> Result<Vec<Entry>> {
    let path = audit_path(vault_dir);
    let Ok(content) = std::fs::read_to_string(&path) else {
        return Ok(vec![]);
    };

    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<Entry>(line) {
            if entry.caller == caller && entry.timestamp().is_some_and(|t| t >= since) {
                out.push(entry);
            }
        }
    }
    Ok(out)
}

/// Read every well-formed entry in the log (any caller, any time). Used by
/// `svault policy check` to summarize activity.
pub fn all(vault_dir: &Path) -> Result<Vec<Entry>> {
    let path = audit_path(vault_dir);
    let Ok(content) = std::fs::read_to_string(&path) else {
        return Ok(vec![]);
    };
    Ok(content
        .lines()
        .filter_map(|l| serde_json::from_str::<Entry>(l.trim()).ok())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn record_then_recent_roundtrip() {
        let dir = TempDir::new().unwrap();
        let vault_dir = dir.path();

        record(
            vault_dir,
            &Entry::now(
                "claude",
                "DB_URL",
                "database",
                "low",
                "allow",
                "ok",
                "run migration",
            ),
        )
        .unwrap();
        record(
            vault_dir,
            &Entry::now(
                "claude", "DB_URL", "database", "low", "allow", "ok", "again",
            ),
        )
        .unwrap();
        record(
            vault_dir,
            &Entry::now("other", "API_KEY", "api", "low", "allow", "ok", "use api"),
        )
        .unwrap();

        let since = Utc::now() - chrono::Duration::hours(1);
        let got = recent(vault_dir, "claude", since).unwrap();
        assert_eq!(got.len(), 2);
        assert!(got.iter().all(|e| e.caller == "claude"));

        // `all` sees every caller.
        assert_eq!(all(vault_dir).unwrap().len(), 3);
    }

    #[test]
    fn recent_filters_by_time() {
        let dir = TempDir::new().unwrap();
        let vault_dir = dir.path();
        record(
            vault_dir,
            &Entry::now("c", "S", "misc", "low", "allow", "ok", "reason here"),
        )
        .unwrap();

        // A window starting in the future excludes the just-written entry.
        let future = Utc::now() + chrono::Duration::hours(1);
        assert!(recent(vault_dir, "c", future).unwrap().is_empty());
    }

    #[test]
    fn recent_on_missing_log_is_empty() {
        let dir = TempDir::new().unwrap();
        let since = Utc::now() - chrono::Duration::hours(1);
        assert!(recent(dir.path(), "anyone", since).unwrap().is_empty());
    }
}
