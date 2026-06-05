//! Audit timeline (08) and the data behind the MCP live log. Every daemon/CLI/GUI
//! decision is read straight from each vault's append-only audit log. The **real**
//! denial reason and the unforgeable peer UID appear here — even though the agent
//! only ever got a generic message.

use serde::{Deserialize, Serialize};

use crate::commands::common::leaf;
use crate::error::{emsg, CmdResult};

use svault_ai::core::meta::VaultMeta;
use svault_ai::core::{audit, vault};

#[derive(Serialize)]
pub struct AuditEvent {
    pub vault_leaf: String,
    pub vault_name: String,
    pub ts: String,
    pub unix: Option<i64>,
    pub caller: String,
    pub peer_uid: Option<u32>,
    pub secret: String,
    pub scope: String,
    pub tier: String,
    pub source: String,
    pub decision: String,
    pub rule: String,
    pub reason: String,
}

#[derive(Deserialize, Default)]
pub struct AuditFilter {
    /// "all" | "allowed" | "denied" | "judge"
    #[serde(default)]
    pub result: Option<String>,
    /// Restrict to one vault leaf.
    #[serde(default)]
    pub vault: Option<String>,
    /// Restrict to one caller.
    #[serde(default)]
    pub caller: Option<String>,
    /// Restrict to one source (e.g. "mcp" for the live log).
    #[serde(default)]
    pub source: Option<String>,
    /// Cap the number of (newest-first) events returned.
    #[serde(default)]
    pub limit: Option<usize>,
}

fn matches(e: &AuditEvent, f: &AuditFilter) -> bool {
    if let Some(r) = f.result.as_deref() {
        let ok = match r {
            "allowed" => e.decision == "allow",
            "denied" => e.decision == "deny",
            "judge" => e.rule.to_lowercase().contains("judge"),
            _ => true,
        };
        if !ok {
            return false;
        }
    }
    if let Some(c) = f.caller.as_deref() {
        if !c.is_empty() && e.caller != c {
            return false;
        }
    }
    if let Some(s) = f.source.as_deref() {
        if !s.is_empty() && e.source != s {
            return false;
        }
    }
    true
}

#[tauri::command]
pub fn audit_events(filter: AuditFilter) -> CmdResult<Vec<AuditEvent>> {
    let dirs = match filter.vault.as_deref().filter(|v| !v.is_empty()) {
        Some(v) => vec![crate::commands::common::dir_for(v)?],
        None => vault::list_vault_dirs(),
    };

    let mut out: Vec<AuditEvent> = Vec::new();
    for dir in &dirs {
        let l = leaf(dir);
        let vname = VaultMeta::load_unverified(dir)
            .map(|m| m.name)
            .unwrap_or_else(|_| l.clone());
        for e in audit::all(dir).unwrap_or_default() {
            let ev = AuditEvent {
                vault_leaf: l.clone(),
                vault_name: vname.clone(),
                unix: e.timestamp().map(|t| t.timestamp()),
                ts: e.ts,
                caller: e.caller,
                peer_uid: e.peer_uid,
                secret: e.secret,
                scope: e.scope,
                tier: e.tier,
                source: e.source,
                decision: e.decision,
                rule: e.rule,
                reason: e.reason,
            };
            if matches(&ev, &filter) {
                out.push(ev);
            }
        }
    }
    // Newest first.
    out.sort_by_key(|e| std::cmp::Reverse(e.unix));
    if let Some(limit) = filter.limit {
        out.truncate(limit);
    }
    Ok(out)
}

/// Distinct caller names across all (or one) vault's audit logs — for the filter
/// dropdown.
#[tauri::command]
pub fn audit_callers() -> Vec<String> {
    let mut set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for dir in vault::list_vault_dirs() {
        for e in audit::all(&dir).unwrap_or_default() {
            if !e.caller.is_empty() {
                set.insert(e.caller);
            }
        }
    }
    set.into_iter().collect()
}

/// Export a vault's audit log to a file path chosen by the user.
#[tauri::command]
pub fn export_log(leaf_id: String, path: String) -> CmdResult<()> {
    let dir = crate::commands::common::dir_for(&leaf_id)?;
    let events = audit::all(&dir).unwrap_or_default();
    let json = serde_json::to_string_pretty(&events).map_err(emsg)?;
    std::fs::write(&path, json).map_err(emsg)?;
    Ok(())
}
