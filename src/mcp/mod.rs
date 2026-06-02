//! MCP frontend — a local [Model Context Protocol] server (`svault mcp`).
//!
//! Exposes Svault's gated secret access to MCP-aware agents (Claude Code, Cursor,
//! VS Code, …) over **stdio**, speaking newline-delimited JSON-RPC 2.0. It is a
//! thin frontend: every secret request runs through the same enforcement path as
//! `svault get` — the daemon's policy + AI-judge gate when the daemon is up, or
//! the in-process gate against the session-cached key otherwise ([`gate::gated_get`]).
//!
//! Security model — the server **never prompts for or sees the master passphrase**.
//! It serves only from already-unlocked state (daemon memory or the `0600` session
//! key, exactly like the CLI's agent path). A locked vault returns an error telling
//! a human to run `svault unlock`; the agent cannot unlock, and high-tier secrets
//! may be human-only. Denials are generic ([`gate::GENERIC_DENY`]) — the real
//! reason stays in the audit log, stamped `source = mcp`.
//!
//! Tools: [`svault_list_vaults`](TOOL_LIST_VAULTS) and
//! [`svault_get_secret`](TOOL_GET_SECRET). The server's `instructions` (returned
//! from `initialize`) are the **capability descriptor**: they tell an agent *how*
//! to request a secret without revealing the decision criteria (tiers, thresholds,
//! judge prompts stay encrypted and server-side).
//!
//! [Model Context Protocol]: https://modelcontextprotocol.io

use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde_json::{json, Value};

use crate::core::crypto::VaultKey;
use crate::core::vault::{list_vault_dirs, Vault};
use crate::core::{gate, session, usage};
use crate::daemon::client::{self, GatedOutcome};

/// MCP protocol revision we implement. Stable and broadly supported by clients.
const PROTOCOL_VERSION: &str = "2024-11-05";

pub const TOOL_LIST_VAULTS: &str = "svault_list_vaults";
pub const TOOL_GET_SECRET: &str = "svault_get_secret";

/// The capability descriptor handed to agents on `initialize`. Advertises the
/// request *interface* and its consequences — never the decision criteria.
const INSTRUCTIONS: &str = "\
Svault gates access to secrets for AI agents. To retrieve a secret, call \
`svault_get_secret` with: `name` (the secret's name), `scope` (its category, e.g. \
\"database\"), and `reason` (a concise, truthful justification for needing it now). \
Optionally pass `vault` (required only if several vaults exist) and `caller` (your \
agent identity). Low-sensitivity secrets are returned directly; medium/high ones are \
evaluated by a policy engine and an AI judge against your stated reason — a vague, \
mismatched, or fabricated reason is denied with a generic message and no value. \
High-sensitivity secrets may be human-only. Some secrets are further restricted to \
certain callers or times, or may be temporarily sealed after repeated denials; in every \
such case you get the same generic denial and only a human can change it, so do not retry \
in a loop. If a vault is locked, the call returns an error asking a human to run `svault \
unlock`; you cannot unlock it yourself. Use `svault_list_vaults` to discover vaults and \
their lock state. Every request is audited — never invent a reason to pass the gate.";

/// Run the MCP server over stdio until EOF. Tags this process as the `mcp`
/// surface so audit/usage records are stamped accordingly.
pub fn run() -> Result<()> {
    usage::set_source(usage::Source::Mcp);
    let stdin = io::stdin();
    let stdout = io::stdout();
    serve(stdin.lock(), stdout.lock())?;
    Ok(())
}

/// The transport loop: read one JSON-RPC message per line, dispatch it, and write
/// the response (if any) as a single line. Notifications (no `id`) get no reply.
/// All diagnostics go to stderr — stdout is the protocol channel and must carry
/// only JSON-RPC messages.
pub fn serve<R: BufRead, W: Write>(reader: R, mut writer: W) -> io::Result<()> {
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(&line) {
            Ok(req) => dispatch(&req),
            // Parse error: reply with a JSON-RPC parse error (id unknown → null).
            Err(e) => Some(error(Value::Null, -32700, &format!("parse error: {e}"))),
        };
        if let Some(resp) = response {
            writeln!(writer, "{}", serde_json::to_string(&resp).unwrap())?;
            writer.flush()?;
        }
    }
    Ok(())
}

/// Dispatch one parsed JSON-RPC message. Returns `Some(response)` for a request,
/// `None` for a notification (no `id`).
pub fn dispatch(req: &Value) -> Option<Value> {
    let id = req.get("id").cloned();
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");

    // A message with no `id` is a notification — we never respond to it.
    let is_notification = id.is_none();
    if is_notification {
        // Recognized notifications (e.g. notifications/initialized) are simply
        // acknowledged by doing nothing; unknown ones are ignored too.
        return None;
    }
    let id = id.unwrap();

    match method {
        "initialize" => Some(ok(id, initialize_result())),
        "ping" => Some(ok(id, json!({}))),
        "tools/list" => Some(ok(id, json!({ "tools": tool_specs() }))),
        "tools/call" => Some(handle_tools_call(id, req.get("params"))),
        other => Some(error(id, -32601, &format!("method not found: {other}"))),
    }
}

fn initialize_result() -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": { "tools": {} },
        "serverInfo": {
            "name": "svault",
            "version": env!("CARGO_PKG_VERSION"),
        },
        "instructions": INSTRUCTIONS,
    })
}

/// JSON Schemas for the exposed tools (the request interface agents see).
fn tool_specs() -> Value {
    json!([
        {
            "name": TOOL_LIST_VAULTS,
            "description": "List Svault vaults available on this machine and whether each is currently unlocked. Returns a JSON array of { name, unlocked }.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        },
        {
            "name": TOOL_GET_SECRET,
            "description": "Request a secret through Svault's policy + AI-judge gate. Returns the secret value if allowed, or an error (denied / not found / vault locked). Medium/high-sensitivity secrets are judged against your `reason`; provide a truthful, specific justification.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name":   { "type": "string", "description": "The secret's name." },
                    "scope":  { "type": "string", "description": "The secret's category, e.g. \"database\" or \"payments\"." },
                    "reason": { "type": "string", "description": "A concise, truthful justification for needing the secret now." },
                    "vault":  { "type": "string", "description": "Vault name. Optional; required only if more than one vault exists." },
                    "caller": { "type": "string", "description": "Your agent identity (defaults to $SVAULT_CALLER or \"default\")." }
                },
                "required": ["name", "scope", "reason"],
                "additionalProperties": false
            }
        }
    ])
}

fn handle_tools_call(id: Value, params: Option<&Value>) -> Value {
    let Some(params) = params else {
        return error(id, -32602, "missing params");
    };
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let args = params.get("arguments").cloned().unwrap_or(json!({}));

    let result = match name {
        TOOL_LIST_VAULTS => call_list_vaults(),
        TOOL_GET_SECRET => call_get_secret(&args),
        other => Err((-32602, format!("unknown tool: {other}"))),
    };
    match result {
        Ok(tool_result) => ok(id, tool_result),
        Err((code, message)) => error(id, code, &message),
    }
}

// ── Tools ────────────────────────────────────────────────────────────────────

/// `svault_list_vaults` — names + lock state, no keys needed.
fn call_list_vaults() -> Result<Value, (i64, String)> {
    let held = client::unlocked_vaults();
    let vaults: Vec<Value> = list_vault_dirs()
        .iter()
        .map(|dir| {
            let name = leaf(dir);
            let unlocked = held.iter().any(|n| n == &name) || session::is_unlocked(dir);
            json!({ "name": name, "unlocked": unlocked })
        })
        .collect();
    let text = serde_json::to_string_pretty(&Value::Array(vaults)).unwrap();
    Ok(tool_text(&text, false))
}

/// `svault_get_secret` — the gated agent path. Daemon first (the enforced choke
/// point), then the in-process gate against the session key; never prompts.
fn call_get_secret(args: &Value) -> Result<Value, (i64, String)> {
    let name = required_str(args, "name")?;
    let scope = required_str(args, "scope")?;
    let reason = required_str(args, "reason")?;
    let caller = args
        .get("caller")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| std::env::var("SVAULT_CALLER").ok())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "default".to_string());

    let vault_arg = args.get("vault").and_then(Value::as_str);
    let dir = match resolve_vault_dir(vault_arg) {
        Ok(d) => d,
        Err(e) => return Ok(tool_text(&e, true)),
    };
    let leaf_name = leaf(&dir);

    // 1) Daemon path — the enforced choke point (policy + judge + peer-UID audit).
    if let Some(outcome) = client::get_gated(&leaf_name, &name, &caller, &scope, &reason) {
        match outcome {
            GatedOutcome::Granted(value, _tier) => {
                usage::agent(&dir, &caller, "get.allow", Some(&name));
                return Ok(secret_text(&value));
            }
            GatedOutcome::Denied(_why) => {
                usage::agent(&dir, &caller, "get.deny", Some(&name));
                return Ok(tool_text(gate::GENERIC_DENY, true));
            }
            GatedOutcome::NotFound => {
                return Ok(tool_text(&format!("secret '{name}' not found"), true));
            }
            // Daemon up but this vault isn't unlocked there — try the session.
            GatedOutcome::NotUnlocked => {}
        }
    }

    // 2) Session path — same gate, run in-process against the cached key. No
    //    prompting: MCP never asks a human for a passphrase.
    if let Some(key) = session::get_key(&dir) {
        let vault = match Vault::open_with_key(&dir, VaultKey::from_bytes(key)) {
            Ok(v) => v,
            Err(e) => {
                return Ok(tool_text(
                    &format!("cannot open vault '{leaf_name}': {e}"),
                    true,
                ))
            }
        };
        return match gate::gated_get(&vault, &dir, &caller, &name, &scope, &reason) {
            Ok(gate::GatedGet::Granted { value, .. }) => Ok(secret_text(&value)),
            Ok(gate::GatedGet::Denied) => Ok(tool_text(gate::GENERIC_DENY, true)),
            Ok(gate::GatedGet::NotFound) => {
                Ok(tool_text(&format!("secret '{name}' not found"), true))
            }
            Err(e) => Err((-32603, format!("{e}"))),
        };
    }

    // 3) Locked everywhere — a human must unlock first; the agent can't.
    Ok(tool_text(
        &format!("vault '{leaf_name}' is locked — a human must run `svault unlock` before secrets can be served"),
        true,
    ))
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn leaf(dir: &Path) -> String {
    dir.file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default()
}

/// Resolve the target vault dir: by name, or the only vault when unspecified.
fn resolve_vault_dir(vault_arg: Option<&str>) -> Result<PathBuf, String> {
    let dirs = list_vault_dirs();
    match vault_arg {
        Some(name) => dirs
            .into_iter()
            .find(|d| leaf(d) == name)
            .ok_or_else(|| format!("no vault named '{name}'")),
        None => match dirs.len() {
            0 => Err("no vaults exist — a human must create one with `svault create`".to_string()),
            1 => Ok(dirs.into_iter().next().unwrap()),
            _ => Err("multiple vaults exist — pass \"vault\" to choose one".to_string()),
        },
    }
}

/// A required non-empty string argument, or a JSON-RPC invalid-params error.
fn required_str(args: &Value, key: &str) -> Result<String, (i64, String)> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| (-32602, format!("missing required string '{key}'")))
}

/// A `tools/call` result carrying a single text block. `is_error = true` marks a
/// tool-level failure (denied, locked, not found) — distinct from a protocol error.
fn tool_text(text: &str, is_error: bool) -> Value {
    json!({
        "content": [ { "type": "text", "text": text } ],
        "isError": is_error,
    })
}

/// A granted-secret result: the value is the whole text block (the agent reads it).
fn secret_text(value: &str) -> Value {
    json!({
        "content": [ { "type": "text", "text": value } ],
        "isError": false,
    })
}

fn ok(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(method: &str, id: Value, params: Value) -> Value {
        let mut m = json!({ "jsonrpc": "2.0", "method": method, "id": id });
        if !params.is_null() {
            m["params"] = params;
        }
        m
    }

    #[test]
    fn initialize_advertises_tools_and_capability_descriptor() {
        let resp = dispatch(&req("initialize", json!(1), Value::Null)).unwrap();
        let result = &resp["result"];
        assert_eq!(result["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(result["serverInfo"]["name"], "svault");
        assert!(result["capabilities"]["tools"].is_object());
        // The capability descriptor must tell agents how to request, and must not
        // leak the decision criteria.
        let instr = result["instructions"].as_str().unwrap();
        assert!(instr.contains("svault_get_secret"));
        assert!(instr.contains("reason"));
        assert_eq!(resp["id"], json!(1));
    }

    #[test]
    fn tools_list_returns_both_tools_with_schemas() {
        let resp = dispatch(&req("tools/list", json!(2), Value::Null)).unwrap();
        let tools = resp["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert!(names.contains(&TOOL_LIST_VAULTS));
        assert!(names.contains(&TOOL_GET_SECRET));
        // get_secret advertises its required fields.
        let get = tools.iter().find(|t| t["name"] == TOOL_GET_SECRET).unwrap();
        let required = get["inputSchema"]["required"].as_array().unwrap();
        for f in ["name", "scope", "reason"] {
            assert!(required.iter().any(|r| r == f), "missing required {f}");
        }
    }

    #[test]
    fn ping_returns_empty_result() {
        let resp = dispatch(&req("ping", json!(3), Value::Null)).unwrap();
        assert_eq!(resp["result"], json!({}));
    }

    #[test]
    fn notifications_get_no_response() {
        let note = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        assert!(dispatch(&note).is_none());
    }

    #[test]
    fn unknown_method_is_method_not_found() {
        let resp = dispatch(&req("frobnicate", json!(4), Value::Null)).unwrap();
        assert_eq!(resp["error"]["code"], json!(-32601));
    }

    #[test]
    fn get_secret_missing_required_field_is_invalid_params() {
        let resp = dispatch(&req(
            "tools/call",
            json!(5),
            json!({ "name": TOOL_GET_SECRET, "arguments": { "name": "DB", "scope": "database" } }),
        ))
        .unwrap();
        // reason is missing → -32602
        assert_eq!(resp["error"]["code"], json!(-32602));
    }

    #[test]
    fn unknown_tool_is_rejected() {
        let resp = dispatch(&req(
            "tools/call",
            json!(6),
            json!({ "name": "svault_nuke", "arguments": {} }),
        ))
        .unwrap();
        assert_eq!(resp["error"]["code"], json!(-32602));
    }

    #[test]
    fn serve_processes_a_session_and_skips_blank_lines() {
        let input = format!(
            "{}\n\n{}\n",
            serde_json::to_string(&req("initialize", json!(1), Value::Null)).unwrap(),
            serde_json::to_string(&req("ping", json!(2), Value::Null)).unwrap(),
        );
        let mut out = Vec::new();
        serve(io::Cursor::new(input), &mut out).unwrap();
        let lines: Vec<&str> = std::str::from_utf8(&out).unwrap().lines().collect();
        // Two requests → exactly two response lines (blank line produced nothing).
        assert_eq!(lines.len(), 2);
        let r1: Value = serde_json::from_str(lines[0]).unwrap();
        let r2: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(r1["id"], json!(1));
        assert_eq!(r2["id"], json!(2));
        assert_eq!(r2["result"], json!({}));
    }

    #[test]
    fn parse_error_yields_jsonrpc_parse_error() {
        let mut out = Vec::new();
        serve(io::Cursor::new("{ not json\n"), &mut out).unwrap();
        let resp: Value = serde_json::from_str(std::str::from_utf8(&out).unwrap().trim()).unwrap();
        assert_eq!(resp["error"]["code"], json!(-32700));
    }

    // ── End-to-end simulation ────────────────────────────────────────────────
    //
    // Drives a full client session through the real `serve()` transport against a
    // real vault and the real gate (no daemon → the in-process session path), so
    // it exercises the whole stack: JSON-RPC framing → tool dispatch → policy/tier
    // gate → AES-GCM decrypt. Changes the cwd (the tools resolve `./.svault`), so
    // it shares the process-wide chdir lock with the keyring/master tests.

    use crate::core::meta::{VaultMeta, VaultSettings};
    use crate::core::policy::{SecretRule, Tier, VaultPolicyData};
    use crate::core::vault::Vault;
    use crate::core::{session, testlock};
    use std::path::Path;

    const PASS: &str = "Str0ng!Pass#99";

    fn classify(scope: &str, tier: Tier) -> SecretRule {
        SecretRule {
            scope: scope.to_string(),
            tier,
            ..Default::default()
        }
    }

    /// Build `./.svault/db` with a low- and a high-tier secret, then cache its key
    /// in the session (the "human unlocked once" precondition the MCP path needs).
    fn setup_unlocked_vault() {
        std::fs::create_dir_all(".svault").unwrap();
        let dir = Path::new(".svault/db");
        let meta = VaultMeta::new("db".into(), "demo".into(), VaultSettings::default());
        let mut policy = VaultPolicyData::default();
        policy
            .secrets
            .insert("LOW_KEY".into(), classify("database", Tier::Low));
        policy
            .secrets
            .insert("HIGH_KEY".into(), classify("database", Tier::High));
        let v = Vault::init(dir, PASS, meta, policy).unwrap();
        v.add_secret("LOW_KEY", "low-value-123").unwrap();
        v.add_secret("HIGH_KEY", "top-secret-999").unwrap();
        // Human unlocks once: cache the DEK in the 0600 session.
        let opened = Vault::open(dir, PASS).unwrap();
        session::unlock_with_key(dir, opened.key().bytes()).unwrap();
    }

    /// Run a transcript of requests through `serve()` and return responses keyed
    /// by request id.
    fn run_session(requests: &[Value]) -> std::collections::HashMap<i64, Value> {
        let input: String = requests
            .iter()
            .map(|r| serde_json::to_string(r).unwrap() + "\n")
            .collect();
        let mut out = Vec::new();
        serve(io::Cursor::new(input), &mut out).unwrap();
        std::str::from_utf8(&out)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str::<Value>(l).unwrap())
            .map(|v| (v["id"].as_i64().unwrap(), v))
            .collect()
    }

    fn get_secret_req(id: i64, name: &str, reason: &str) -> Value {
        req(
            "tools/call",
            json!(id),
            json!({
                "name": TOOL_GET_SECRET,
                "arguments": { "name": name, "scope": "database", "reason": reason }
            }),
        )
    }

    fn text_of(result: &Value) -> &str {
        result["content"][0]["text"].as_str().unwrap()
    }

    #[test]
    fn simulated_client_session_enforces_the_gate_end_to_end() {
        let _cwd = testlock::CWD_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();

        setup_unlocked_vault();

        let resps = run_session(&[
            req("initialize", json!(1), Value::Null),
            req("tools/list", json!(2), Value::Null),
            req(
                "tools/call",
                json!(3),
                json!({ "name": TOOL_LIST_VAULTS, "arguments": {} }),
            ),
            // Low tier: allowed, returns the value.
            get_secret_req(4, "LOW_KEY", "run the nightly database backup"),
            // High tier, no judge configured: human-only → generic denial.
            get_secret_req(5, "HIGH_KEY", "rotate the production credentials"),
            // Unknown secret, valid reason → allowed by the low default, then not found.
            get_secret_req(6, "NOPE", "look up the staging connection string"),
            // Weak (too-short) reason → denied by the base policy.
            get_secret_req(8, "LOW_KEY", "need"),
        ]);

        // Handshake.
        assert_eq!(resps[&1]["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert!(resps[&2]["result"]["tools"].as_array().unwrap().len() >= 2);

        // list_vaults shows our unlocked vault.
        let listed: Value = serde_json::from_str(text_of(&resps[&3]["result"])).unwrap();
        assert_eq!(listed[0]["name"], "db");
        assert_eq!(listed[0]["unlocked"], json!(true));

        // Low tier allowed → the actual value comes back, not an error.
        let low = &resps[&4]["result"];
        assert_eq!(low["isError"], json!(false));
        assert_eq!(text_of(low), "low-value-123");

        // High tier human-only → denied with the generic message (no leak).
        let high = &resps[&5]["result"];
        assert_eq!(high["isError"], json!(true));
        assert_eq!(text_of(high), gate::GENERIC_DENY);
        assert!(!text_of(high).contains("top-secret"));

        // Unknown secret → not found.
        assert_eq!(resps[&6]["result"]["isError"], json!(true));
        assert!(text_of(&resps[&6]["result"]).contains("not found"));

        // Weak reason → generic denial (the base policy rejects it before any value).
        let weak = &resps[&8]["result"];
        assert_eq!(weak["isError"], json!(true));
        assert_eq!(text_of(weak), gate::GENERIC_DENY);

        // Lock the vault: now even the low-tier secret needs a human to unlock.
        session::lock(Path::new(".svault/db")).unwrap();
        let locked = run_session(&[get_secret_req(
            7,
            "LOW_KEY",
            "run the nightly database backup",
        )]);
        let r = &locked[&7]["result"];
        assert_eq!(r["isError"], json!(true));
        assert!(text_of(r).contains("locked"));

        std::env::set_current_dir(prev).unwrap();
    }

    #[test]
    fn sealed_secret_returns_generic_denial_with_no_value() {
        let _cwd = testlock::CWD_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();

        std::fs::create_dir_all(".svault").unwrap();
        let dir = Path::new(".svault/db");
        let meta = VaultMeta::new("db".into(), "demo".into(), VaultSettings::default());
        let mut policy = VaultPolicyData::default();
        policy
            .secrets
            .insert("API_KEY".into(), classify("database", Tier::Medium));
        // Pre-seal the secret (as the gate would after sustained abuse).
        policy.seals.insert(
            "API_KEY".into(),
            crate::core::policy::Seal {
                sealed_at: "2026-06-02T00:00:00Z".into(),
                trigger: "5 denials in 300s".into(),
                last_caller: "attacker".into(),
                denials: 5,
            },
        );
        let v = Vault::init(dir, PASS, meta, policy).unwrap();
        v.add_secret("API_KEY", "super-secret-value").unwrap();
        let opened = Vault::open(dir, PASS).unwrap();
        session::unlock_with_key(dir, opened.key().bytes()).unwrap();

        // Even a well-formed, on-scope request is denied while sealed — and the
        // value never leaks.
        let resps = run_session(&[get_secret_req(
            1,
            "API_KEY",
            "legitimate use of the api key for the nightly job",
        )]);
        let r = &resps[&1]["result"];
        assert_eq!(r["isError"], json!(true));
        assert_eq!(text_of(r), gate::GENERIC_DENY);
        assert!(!text_of(r).contains("super-secret-value"));

        std::env::set_current_dir(prev).unwrap();
    }
}
