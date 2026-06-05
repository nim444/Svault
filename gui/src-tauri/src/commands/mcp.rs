//! MCP screen (07) — the agent door. Connected-agents view (derived from the
//! audit trail), the enable switch (stored in the keyring, enforced by the MCP
//! server), and the per-client wiring config.

use std::collections::HashMap;

use serde::Serialize;

use crate::commands::common::open_or_init_keyring;
use crate::error::{emsg, CmdResult};

use svault_cli::core::{audit, keyring, usage, vault};

#[derive(Serialize)]
pub struct ConnectedAgent {
    pub caller: String,
    pub peer_uid: Option<u32>,
    pub last_call: Option<i64>,
    pub calls_today: usize,
}

/// Derive the connected-agents table from audit entries stamped `source = mcp`,
/// grouped by caller. (The MCP server is stdio per-client, so "connected" means
/// "has called through the door".)
#[tauri::command]
pub fn connected_agents() -> Vec<ConnectedAgent> {
    let start_of_day = chrono::Local::now()
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .and_then(|d| d.and_local_timezone(chrono::Local).single())
        .map(|d| d.with_timezone(&chrono::Utc));

    let mut by_caller: HashMap<String, ConnectedAgent> = HashMap::new();
    for dir in vault::list_vault_dirs() {
        for e in audit::all(&dir).unwrap_or_default() {
            if e.source != "mcp" {
                continue;
            }
            let ts = e.timestamp().map(|t| t.timestamp());
            let entry = by_caller.entry(e.caller.clone()).or_insert(ConnectedAgent {
                caller: e.caller.clone(),
                peer_uid: e.peer_uid,
                last_call: None,
                calls_today: 0,
            });
            if e.peer_uid.is_some() {
                entry.peer_uid = e.peer_uid;
            }
            if ts > entry.last_call {
                entry.last_call = ts;
            }
            if let (Some(t), Some(sod)) = (e.timestamp(), start_of_day) {
                if t >= sod {
                    entry.calls_today += 1;
                }
            }
        }
    }
    let mut out: Vec<_> = by_caller.into_values().collect();
    out.sort_by_key(|a| std::cmp::Reverse(a.last_call));
    out
}

/// Toggle the MCP door. Enforced server-side in `svault_get_secret`.
#[tauri::command]
pub fn mcp_toggle(enabled: bool) -> CmdResult<()> {
    let mut kr = open_or_init_keyring()?;
    kr.data.mcp_enabled = enabled;
    kr.save().map_err(emsg)?;
    usage::human(
        &vault::svault_dir(),
        if enabled { "mcp.enable" } else { "mcp.disable" },
        Some("global"),
    );
    Ok(())
}

#[tauri::command]
pub fn mcp_enabled() -> bool {
    keyring::open_from_session()
        .map(|kr| kr.data.mcp_enabled)
        .unwrap_or(true)
}

/// The `.mcp.json` snippet for a given client. `bin` is the path the GUI knows
/// the `svault` binary lives at (the bundled sidecar, or just "svault" on PATH).
#[tauri::command]
pub fn mcp_config_snippet(bin: String, caller: String) -> String {
    let caller = if caller.trim().is_empty() {
        "my-agent".to_string()
    } else {
        caller
    };
    serde_json::json!({
        "mcpServers": {
            "svault": {
                "command": bin,
                "args": ["mcp"],
                "env": { "SVAULT_CALLER": caller }
            }
        }
    })
    .to_string()
}

/// Merge the Svault MCP server into a `.mcp.json` at `path` without clobbering
/// other servers. Creates the file if absent.
#[tauri::command]
pub fn write_mcp_config(path: String, bin: String, caller: String) -> CmdResult<()> {
    let snippet: serde_json::Value =
        serde_json::from_str(&mcp_config_snippet(bin, caller)).map_err(emsg)?;

    let mut root: serde_json::Value = match std::fs::read_to_string(&path) {
        Ok(s) if !s.trim().is_empty() => serde_json::from_str(&s).map_err(emsg)?,
        _ => serde_json::json!({}),
    };
    if !root.is_object() {
        return Err("existing .mcp.json is not a JSON object".into());
    }
    let servers = root
        .as_object_mut()
        .unwrap()
        .entry("mcpServers")
        .or_insert_with(|| serde_json::json!({}));
    if let (Some(servers), Some(svault)) = (
        servers.as_object_mut(),
        snippet["mcpServers"]["svault"].as_object(),
    ) {
        servers.insert(
            "svault".to_string(),
            serde_json::Value::Object(svault.clone()),
        );
    }
    std::fs::write(&path, serde_json::to_string_pretty(&root).map_err(emsg)?).map_err(emsg)?;
    Ok(())
}

/// The store path shown on the wiring tab (`SVAULT_HOME/.svault`).
#[tauri::command]
pub fn store_path() -> String {
    vault::svault_dir().to_string_lossy().into_owned()
}
