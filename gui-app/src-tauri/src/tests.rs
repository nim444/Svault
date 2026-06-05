//! End-to-end test of the GUI command layer against a throwaway store. Exercises
//! the same code paths the React frontend calls, asserting parity with core: a
//! vault created here is classified, revealed, audited, and governed exactly as
//! the CLI would do it. Run with `cargo test`.

use crate::commands::secrets::SecretForm;
use crate::commands::vaults::VaultForm;
use crate::commands::{audit, judge, mcp, pending, policy, secrets, vaults};
use svault_ai::core::master;

fn vault_form(name: &str) -> VaultForm {
    VaultForm {
        name: name.into(),
        description: "test vault".into(),
        allow_agent_mode: "all".into(),
        allow_agent_list: vec![],
        rate_limit: "10/hour".into(),
        autolock: true,
        autolock_timer: "1d".into(),
        login_method: "passphrase".into(),
        default_tier: "low".into(),
        judge_enabled: false,
        assigned_judge: None,
    }
}

#[test]
fn gui_command_layer_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("SVAULT_HOME", tmp.path());
    // Mirror what `run()` does at startup.
    svault_ai::core::usage::set_source(svault_ai::core::usage::Source::Gui);

    // Set the master + cache the session (what sign-in/onboarding does).
    let m = master::Master::init("a-strong-master-passphrase-123").unwrap();
    master::unlock_session(m.key_bytes()).unwrap();

    // Create a vault (screen 04).
    let res = vaults::create_vault(vault_form("proj")).unwrap();
    assert!(!res.recovery_code.is_empty(), "recovery code shown once");

    // It shows up in the list (screen 03), unlocked, under the master.
    let listed = vaults::list_vaults().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "proj");
    assert!(listed[0].unlocked);
    // The create was recorded to the usage log → surfaced as last activity.
    assert!(listed[0].last_activity.is_some(), "human activity recorded");
    let leaf = listed[0].leaf.clone();

    // Add + classify a medium-tier secret (screen 05).
    secrets::add_secret(
        leaf.clone(),
        SecretForm {
            name: "DB_PASSWORD".into(),
            value: Some("s3cr3t-value".into()),
            scope: "database".into(),
            tier: "medium".into(),
            require_reason: false,
            description: "prod db".into(),
            windows: vec![],
            require_callers: vec![],
        },
    )
    .unwrap();

    let rows = secrets::list_secrets(leaf.clone()).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].name, "DB_PASSWORD");
    assert_eq!(rows[0].tier, "medium");
    assert_eq!(rows[0].scope, "database");

    // Human reveal path returns the real value.
    let value = secrets::reveal_secret(leaf.clone(), "DB_PASSWORD".into()).unwrap();
    assert_eq!(value, "s3cr3t-value");

    // The audit timeline (gate decisions) reads cleanly. It is empty here — no
    // agent has made a gated request yet; human actions live in the usage log
    // (surfaced as "last activity" above), not the decision audit.
    let events = audit::audit_events(audit::AuditFilter {
        limit: Some(100),
        ..Default::default()
    })
    .unwrap();
    assert!(events.is_empty(), "no gated agent requests yet");

    // Judge registry (screen 06): first judge becomes default.
    judge::judge_save(judge::JudgeFormInput {
        name: "fast".into(),
        model: "google/gemini-2.5-flash".into(),
        allow_threshold: 60,
        high_threshold: 80,
        criteria: "be strict".into(),
        api_key: None,
    })
    .unwrap();
    let judges = judge::judge_list().unwrap();
    assert_eq!(judges.len(), 1);
    assert!(judges[0].is_default);
    assert!(!judges[0].has_key);

    // MCP enable switch (screen 07) round-trips and is observable.
    mcp::mcp_toggle(false).unwrap();
    assert!(!mcp::mcp_enabled());
    mcp::mcp_toggle(true).unwrap();
    assert!(mcp::mcp_enabled());

    // Policy surface (screen 06) reflects the vault.
    let surface = policy::policy_surface(leaf.clone()).unwrap();
    assert_eq!(surface.default_tier, "low");
    assert_eq!(surface.allow_agent, "all agents");

    // Nothing sealed yet (screen 09).
    assert!(pending::pending().unwrap().is_empty());

    // Lock + delete the vault (screen 03 destructive action).
    vaults::lock_vault(leaf.clone()).unwrap();
    vaults::delete_vault(leaf.clone()).unwrap();
    assert!(vaults::list_vaults().unwrap().is_empty());
}
