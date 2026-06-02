//! CLI frontend — the `svault` command-line interface.
//!
//! Parses arguments (clap), dispatches each subcommand to its `cmd_*` handler,
//! and falls back to launching the [`crate::tui`] when invoked with no
//! subcommand. All secret-handling work is delegated to [`crate::core`] and the
//! [`crate::daemon`] client; this module is presentation and orchestration only.

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use console::style;
use dialoguer::{Confirm, Input, Password, Select};
use std::path::{Path, PathBuf};

use crate::core::{
    audit, gate, judge, keyring, master, passphrase, policy, portable, recovery, secfile, session,
    usage, yubikey,
};
use crate::daemon::{self, client};
use crate::tui;

use crate::core::crypto::VaultKey;
use crate::core::meta::{AccessConfig, AllowAgent, LoginMethod, VaultMeta, VaultSettings};
use crate::core::vault::{list_vault_dirs, svault_dir, Vault, SVAULT_DIR};
use zeroize::Zeroizing;

/// Prompt for a secret (passphrase, recovery code, or secret value) and return
/// it wrapped in `Zeroizing` so the heap copy is wiped on drop (finding #6).
fn prompt_secret(prompt: impl Into<String>) -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(
        Password::new().with_prompt(prompt).interact()?,
    ))
}

#[derive(Parser)]
#[command(
    name = "svault",
    about = "Secret access layer for cooperative AI agents — structured, policy-gated, audited",
    version
)]
struct Cli {
    /// Run with no subcommand to launch the interactive TUI.
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new encrypted vault in .svault/<name>/
    #[command(alias = "init")]
    Create {
        #[arg(long)]
        name: Option<String>,
        /// Skip the passphrase strength floor (for non-interactive / scripted use)
        #[arg(long)]
        force: bool,
    },
    /// View or change a vault's settings (description, agents, rate limit, auto-lock, login, AI judge + assigned judge)
    Settings {
        /// Vault name — positional, or via `-v/--vault`. Omit to use the only vault or pick interactively.
        vault: Option<String>,
        #[arg(
            long = "vault",
            short = 'v',
            value_name = "VAULT",
            conflicts_with = "vault"
        )]
        vault_flag: Option<String>,
    },
    /// Manage secrets: add | get | list | remove
    Secret {
        action: String,
        name: Option<String>,
        /// Vault name. Omit to use the only vault or pick interactively.
        #[arg(long, short = 'v')]
        vault: Option<String>,
        /// (add) Classify the secret's scope, e.g. `database`.
        #[arg(long)]
        scope: Option<String>,
        /// (add) Sensitivity tier: low | medium | high.
        #[arg(long)]
        tier: Option<String>,
        /// (add) Always run the AI judge for this secret, even at low tier.
        #[arg(long)]
        require_reason: bool,
        /// (add) What this secret is for — given to the AI judge as context.
        #[arg(long)]
        description: Option<String>,
        /// (add) Allowed access window, local time, e.g. `mon-fri 09:00-18:00`.
        /// Repeatable; outside every window the secret is denied.
        #[arg(long = "window")]
        windows: Vec<String>,
        /// (add) Restrict this secret to these callers. Repeatable.
        #[arg(long = "require-caller")]
        require_callers: Vec<String>,
    },
    /// List all vaults in .svault/
    Vaults,
    /// Unlock vault — caches the derived key for this session
    Unlock {
        /// Vault name — positional, or via `-v/--vault`. Omit to use the only vault or pick interactively.
        vault: Option<String>,
        #[arg(
            long = "vault",
            short = 'v',
            value_name = "VAULT",
            conflicts_with = "vault"
        )]
        vault_flag: Option<String>,
    },
    /// Lock vault — clears the cached key
    Lock {
        /// Lock all vaults
        #[arg(long)]
        all: bool,
        /// Vault name — positional, or via `-v/--vault`. Omit to use the only vault or pick interactively.
        vault: Option<String>,
        #[arg(
            long = "vault",
            short = 'v',
            value_name = "VAULT",
            conflicts_with = "vault"
        )]
        vault_flag: Option<String>,
    },
    /// Show lock status of all vaults
    Status,
    /// [not yet implemented] Wire Svault into your AI platform. For now, configure
    /// the MCP server manually — see docs/mcp.md.
    Install {
        #[arg(long, default_value = "auto")]
        platform: String,
        #[arg(long)]
        project: bool,
    },
    /// Run the local MCP server (stdio): expose gated secret access to AI agents
    Mcp,
    /// [DEPRECATED] Request a secret through the policy engine. Agents should use
    /// the MCP server (`svault mcp`) instead — this still works but will be removed.
    Get {
        name: String,
        #[arg(long)]
        scope: String,
        #[arg(long)]
        reason: String,
        /// Identify the caller. Falls back to $SVAULT_CALLER, then "default".
        #[arg(long)]
        caller: Option<String>,
        #[arg(long, short = 'v')]
        vault: Option<String>,
    },
    /// Inspect the policy engine: `policy check <caller>` or `policy init`.
    Policy {
        /// Action: check | init
        action: String,
        /// Caller name (for `check`).
        caller: Option<String>,
        /// Vault name. Omit to use the only vault or pick interactively.
        #[arg(long, short = 'v')]
        vault: Option<String>,
    },
    /// List sealed secrets awaiting human approval (one vault, or all).
    Pending {
        /// Vault name — positional, or via `-v/--vault`. Omit to scan every vault.
        vault: Option<String>,
        #[arg(
            long = "vault",
            short = 'v',
            value_name = "VAULT",
            conflicts_with = "vault"
        )]
        vault_flag: Option<String>,
    },
    /// Clear a seal so agents can request the secret again (human-only).
    Approve {
        /// The sealed secret's name.
        secret: String,
        /// Vault name. Omit to use the only vault or pick interactively.
        #[arg(long, short = 'v')]
        vault: Option<String>,
    },
    /// Recover a vault with its recovery code and set a new passphrase
    Recover {
        /// Vault name — positional, or via `-v/--vault`. Omit to use the only vault or pick interactively.
        vault: Option<String>,
        #[arg(
            long = "vault",
            short = 'v',
            value_name = "VAULT",
            conflicts_with = "vault"
        )]
        vault_flag: Option<String>,
        /// Skip the passphrase strength floor (for non-interactive / scripted use)
        #[arg(long)]
        force: bool,
    },
    /// Export a vault to a portable encrypted bundle
    Export {
        /// Vault name — positional, or via `-v/--vault`. Omit to use the only vault or pick interactively.
        vault: Option<String>,
        #[arg(
            long = "vault",
            short = 'v',
            value_name = "VAULT",
            conflicts_with = "vault"
        )]
        vault_flag: Option<String>,
        /// Output file (default: <name>.svault-export.json)
        #[arg(long)]
        out: Option<String>,
    },
    /// Import a vault from a bundle created by `svault export`
    Import {
        /// Path to the .svault-export.json bundle
        file: String,
        /// Import under this name instead of the bundle's own (auto-suffixed if it also exists)
        #[arg(long)]
        name: Option<String>,
    },
    /// Background unlock daemon (Unix): run | start | stop | status | doctor
    Daemon {
        /// Action: run | start | stop | status | doctor
        action: String,
        /// For `doctor`: clean up stale socket / pid files.
        #[arg(long)]
        fix: bool,
    },
    /// Master passphrase — the single secret that unlocks every vault.
    ///
    /// Set it once (`init`); thereafter `svault unlock` opens all vaults with it
    /// and `svault create` wraps each new vault under it (no per-vault
    /// passphrase). Actions: `init`, `rekey` (change it), `recover` (reset a
    /// forgotten one with the recovery code), `status`, and `yubikey
    /// <enroll|remove|status>` to manage a hardware-key slot.
    Master {
        /// init | rekey | recover | status | yubikey
        action: String,
        /// Sub-action for `yubikey`: enroll | remove | status
        sub: Option<String>,
        /// Skip the passphrase strength floor (for non-interactive / scripted use)
        #[arg(long)]
        force: bool,
    },
    /// Encrypted keyring: the single store for judges, API keys, and operational
    /// config (replaces the old plaintext config.yaml + openrouter.key).
    ///
    /// Actions: `init` (create it), `unlock` / `lock` (cache/clear its key for
    /// this session), `status`. The keyring is opened by your master passphrase —
    /// there is no separate keyring passphrase, so to change it use `master rekey`.
    Keyring {
        /// init | unlock | lock | status
        action: String,
    },
    /// AI judge registry: define multiple named judges (model, thresholds,
    /// criteria, key), pick a default, toggle the judge on/off, and test it.
    /// Operates on the unlocked keyring.
    ///
    /// Actions: `add` / `edit` / `remove` <name>, `list`, `set-default <name>`,
    /// `set-key <name>`, `enable` / `disable` (global), `status`, `test`.
    Judge {
        /// add | edit | remove | list | set-default | set-key | enable | disable | status | test
        action: String,
        /// (add/edit/remove/set-key/set-default) The judge name.
        name: Option<String>,
        /// (test) Which judge to test (defaults to the keyring's default judge).
        #[arg(long = "judge")]
        judge_name: Option<String>,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long, default_value = "misc")]
        scope: String,
        #[arg(long, default_value = "SAMPLE_SECRET")]
        secret: String,
        #[arg(long, default_value = "tester")]
        caller: String,
        /// Treat the sample as this tier (affects thresholds): low | medium | high.
        #[arg(long, default_value = "medium")]
        tier: String,
        /// (test) Sample secret purpose — context the judge weighs against the reason.
        #[arg(long)]
        description: Option<String>,
        /// (test) Vault name the request is against (the model sees it; avoid
        /// misleading names like "test" for production secrets).
        #[arg(long, default_value = "demo-vault")]
        vault: String,
        /// (test) Sample vault purpose — overall context for the judge.
        #[arg(long)]
        vault_description: Option<String>,
    },
}

/// Parse CLI arguments and run the requested command. The `svault` binary's
/// `main` is a thin wrapper over this.
pub fn run() -> Result<()> {
    // Default the store to the user's home (`~/.svault`) so an installed svault
    // behaves the same from any directory — in particular the `mcp` server, whose
    // working directory the MCP host chooses. An explicit `SVAULT_HOME` is honoured;
    // if there's no home dir, svault_dir() falls back to `./.svault`. Children we
    // spawn (the daemon) inherit this, so every surface agrees on the store.
    let svault_home_unset = match std::env::var_os("SVAULT_HOME") {
        Some(h) => h.is_empty(),
        None => true,
    };
    if svault_home_unset {
        if let Some(home) = crate::core::vault::user_home() {
            std::env::set_var("SVAULT_HOME", home);
        }
    }

    let cli = Cli::parse();
    let Some(command) = cli.command else {
        // No subcommand → interactive TUI.
        return tui::run();
    };
    match command {
        Commands::Create { name, force } => cmd_create(name, force),
        Commands::Settings { vault, vault_flag } => cmd_settings(vault_flag.or(vault).as_deref()),
        Commands::Secret {
            action,
            name,
            vault,
            scope,
            tier,
            require_reason,
            description,
            windows,
            require_callers,
        } => cmd_secret(
            &action,
            name.as_deref(),
            vault.as_deref(),
            scope.as_deref(),
            tier.as_deref(),
            require_reason,
            description.as_deref(),
            &windows,
            require_callers,
        ),
        Commands::Vaults => cmd_vaults(),
        Commands::Unlock { vault, vault_flag } => cmd_unlock(vault_flag.or(vault).as_deref()),
        Commands::Lock {
            all,
            vault,
            vault_flag,
        } => cmd_lock(all, vault_flag.or(vault).as_deref()),
        Commands::Status => cmd_status(),
        Commands::Install { platform, .. } => {
            println!(
                "{} `svault install` is not yet implemented (requested platform: '{}').",
                style("pending:").yellow(),
                platform
            );
            println!(
                "  For now, wire the MCP server in by hand — see docs/mcp.md (`command: svault`, `args: [mcp]`)."
            );
            Ok(())
        }
        Commands::Mcp => crate::mcp::run(),
        Commands::Get {
            name,
            scope,
            reason,
            caller,
            vault,
        } => cmd_get(&name, &scope, &reason, caller.as_deref(), vault.as_deref()),
        Commands::Policy {
            action,
            caller,
            vault,
        } => cmd_policy(&action, caller.as_deref(), vault.as_deref()),
        Commands::Pending { vault, vault_flag } => cmd_pending(vault_flag.or(vault).as_deref()),
        Commands::Approve { secret, vault } => cmd_approve(&secret, vault.as_deref()),
        Commands::Recover {
            vault,
            vault_flag,
            force,
        } => cmd_recover(vault_flag.or(vault).as_deref(), force),
        Commands::Export {
            vault,
            vault_flag,
            out,
        } => cmd_export(vault_flag.or(vault).as_deref(), out.as_deref()),
        Commands::Import { file, name } => cmd_import(&file, name.as_deref()),
        Commands::Daemon { action, fix } => cmd_daemon(&action, fix),
        Commands::Master { action, sub, force } => cmd_master(&action, sub.as_deref(), force),
        Commands::Keyring { action } => cmd_keyring(&action),
        Commands::Judge {
            action,
            name,
            judge_name,
            reason,
            scope,
            secret,
            caller,
            tier,
            description,
            vault,
            vault_description,
        } => cmd_judge(
            &action,
            name.as_deref(),
            judge_name.as_deref(),
            JudgeTestArgs {
                reason: reason.as_deref(),
                scope: &scope,
                secret: &secret,
                caller: &caller,
                tier: &tier,
                description: description.as_deref(),
                vault: &vault,
                vault_description: vault_description.as_deref(),
            },
        ),
    }
}

fn cmd_daemon(action: &str, fix: bool) -> Result<()> {
    match action {
        "run" => daemon::run(),
        "start" => daemon::start(),
        "stop" => daemon::stop(),
        "status" => daemon::status(),
        "doctor" => daemon::doctor(fix),
        _ => {
            eprintln!(
                "{} Unknown action '{}'. Use: run | start | stop | status | doctor",
                style("error:").red(),
                action
            );
            std::process::exit(1);
        }
    }
}

/// The directory leaf name (== vault name) the daemon keys vaults by.
fn vault_leaf(dir: &Path) -> String {
    dir.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

// ── Commands ─────────────────────────────────────────────────────────────────

fn cmd_create(name_arg: Option<String>, force: bool) -> Result<()> {
    println!(
        "{}",
        style("┌─ New Vault ─────────────────────────────┐").dim()
    );

    let default_name = std::env::current_dir()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_else(|| "my-vault".to_string());

    let name: String = match name_arg {
        Some(n) => n,
        None => Input::new()
            .with_prompt("  Vault name")
            .default(default_name)
            .interact_text()?,
    };

    let vault_dir = svault_dir().join(&name);
    if vault_dir.exists() {
        let existing = VaultMeta::load_unverified(&vault_dir)
            .map(|m| m.storage)
            .unwrap_or_else(|_| "local".to_string());
        eprintln!(
            "{} a vault named '{}' already exists ({}:{}) — vault names must be unique",
            style("error:").red(),
            name,
            existing,
            name,
        );
        std::process::exit(1);
    }

    let description: String = Input::new()
        .with_prompt("  Description")
        .allow_empty(true)
        .interact_text()?;

    let allow_agent = prompt_allow_agent(None)?;

    let rate_limit: String = Input::new()
        .with_prompt("  Rate limit")
        .default("10/hour".to_string())
        .interact_text()?;

    let autolock = Confirm::new()
        .with_prompt("  Auto-lock when idle?")
        .default(true)
        .interact()?;

    let autolock_timer: String = if autolock {
        Input::new()
            .with_prompt("  Auto-lock timer (e.g. 1d, 12h, 30m)")
            .default("1d".to_string())
            .interact_text()?
    } else {
        "1d".to_string()
    };

    let login_method = prompt_login_method(None)?;

    // Default sensitivity for secrets added later, and whether the AI judge
    // gates this vault's medium/high secrets (needs an OpenRouter key to act).
    let default_tier = prompt_tier(policy::Tier::Low)?;
    let judge_enabled = Confirm::new()
        .with_prompt("  Use the AI judge for medium/high secrets in this vault?")
        .default(false)
        .interact()?;
    // If a judge is wanted and the keyring already has some, let the user assign a
    // specific one now; otherwise it uses the keyring default (assignable later
    // via `svault settings`).
    let judge_name = if judge_enabled && !available_judge_names().is_empty() {
        prompt_assigned_judge(None)?
    } else {
        None
    };

    // Unlock (or, on first run, set) the master passphrase — the single secret
    // that unlocks every vault. The new vault gets a random data key wrapped
    // under the master; it has no passphrase of its own.
    let master = ensure_master_unlocked(force)?;

    println!("\n  Creating vault...");

    let mut meta = VaultMeta::new(
        name.clone(),
        description,
        VaultSettings {
            autolock,
            autolock_timer,
            login_method,
        },
    );
    meta.storage = "local".to_string();
    // The policy surface (access, default tier, judge override) is stored
    // AES-256-GCM encrypted inside vault.enc, not in the plaintext meta.yaml.
    let mut vault_policy = policy::VaultPolicyData {
        access: AccessConfig {
            allow_agent,
            rate_limit,
        },
        default_tier,
        ..policy::VaultPolicyData::default()
    };
    vault_policy.judge.enabled = Some(judge_enabled);
    vault_policy.judge.judge = judge_name;
    // Random data key (DEK) encrypts this vault; wrap it under the master so the
    // single master passphrase opens it, then cache its session.
    let dek = master::new_dek();
    let vault = Vault::init_with_key(&vault_dir, dek, meta, vault_policy)?;
    master.wrap_dek(&vault_dir, vault.key())?;
    session::unlock_with_key(&vault_dir, vault.key().bytes())?;

    // Generate a recovery code and wrap the vault key under it. Shown once.
    let recovery_code = recovery::generate_code();
    recovery::write(&vault_dir, vault.key(), &recovery_code)?;
    usage::human(&vault_dir, "vault.create", None);

    println!();
    println!(
        "  {:<14} {}",
        style("Name").dim(),
        style(format!("local:{}", &name)).bold().cyan()
    );
    println!("  {:<14} {}", style("Storage").dim(), style("local").cyan());
    println!(
        "  {:<14} {}",
        style("Location").dim(),
        style(format!("{}/", vault_dir.display())).cyan()
    );
    println!();
    println!("{} Vault '{}' created", style("ok:").green().bold(), name);
    println!(
        "{}",
        style("  vault.enc + meta.yaml are safe to commit — encrypted at rest.").dim()
    );
    // Only suggest `git add` for a project-scoped store (SVAULT_HOME pointed at a
    // project dir). The default store is `~/.svault`, which no one commits into a
    // repo, so the hint would be misleading there.
    let under_home = crate::core::vault::user_home()
        .map(|h| vault_dir.starts_with(&h))
        .unwrap_or(false);
    if !under_home {
        println!(
            "{}",
            style(format!("  git add {}/", vault_dir.display())).dim()
        );
    }

    println!();
    println!("{}", style("  RECOVERY CODE").yellow().bold());
    println!("  {}", style(&recovery_code).bold());
    println!(
        "{}",
        style("  This is the ONLY time this code is shown — it is not stored in plaintext.")
            .yellow()
    );
    println!(
        "{}",
        style("  Save it now in a password manager (or on paper, offline).").dim()
    );
    println!(
        "{}",
        style("  It is the only way back in if you lose your passphrase — run 'svault recover'.")
            .dim()
    );

    // Require an explicit acknowledgment that the code was saved — the code is
    // not recoverable once this screen is gone.
    println!();
    while !Confirm::new()
        .with_prompt("  I have saved my recovery code")
        .default(false)
        .interact()?
    {
        println!(
            "{}",
            style("  Save it first — it cannot be retrieved later.").yellow()
        );
    }

    // If the vault opted into the judge, tell the user what's still needed for it
    // to actually gate access — a keyring with an enabled judge and a key.
    if judge_enabled {
        let ready = keyring::open_from_session()
            .map(|kr| kr.data.judge_enabled && !kr.data.judges.is_empty())
            .unwrap_or(false);
        if !ready {
            println!();
            println!(
                "{} the AI judge is on for this vault, but it won't act until the",
                style("note:").cyan()
            );
            println!(
                "{}",
                style("      keyring has an enabled judge with a key:").cyan()
            );
            println!(
                "{}",
                style(
                    "    • svault keyring init   • svault judge add <name>   • svault judge enable"
                )
                .dim()
            );
        }
    }
    Ok(())
}

/// Interactive settings editor — re-prompts each field with the current value
/// as the default, then re-signs meta.yaml. Requires the passphrase.
fn cmd_settings(vault_name: Option<&str>) -> Result<()> {
    let vault_dir = resolve_vault_dir(vault_name)?;
    let preview = VaultMeta::load_unverified(&vault_dir)?;

    let vault = open_unlocked_or_prompt(&vault_dir, &preview.name)?;

    let mut meta = vault.meta.clone();
    let mut vault_policy = vault.policy.clone();

    println!(
        "{}",
        style(format!(
            "┌─ Settings · {} ──────────────────────┐",
            meta.name
        ))
        .dim()
    );
    println!(
        "  {:<16} {}",
        style("Description").dim(),
        if meta.description.is_empty() {
            "-".into()
        } else {
            meta.description.clone()
        }
    );
    println!(
        "  {:<16} {}",
        style("Allow agent").dim(),
        vault_policy.access.allow_agent
    );
    println!(
        "  {:<16} {}",
        style("Rate limit").dim(),
        vault_policy.access.rate_limit
    );
    println!(
        "  {:<16} {}",
        style("Auto-lock").dim(),
        meta.settings.autolock
    );
    println!(
        "  {:<16} {}",
        style("Auto-lock timer").dim(),
        meta.settings.autolock_timer
    );
    println!(
        "  {:<16} {}",
        style("Login method").dim(),
        meta.settings.login_method
    );
    println!(
        "  {:<16} {}",
        style("AI judge").dim(),
        if vault_policy.judge.enabled.unwrap_or(false) {
            "on"
        } else {
            "off"
        }
    );
    println!(
        "  {:<16} {}",
        style("Assigned judge").dim(),
        vault_policy.judge.judge.as_deref().unwrap_or("default")
    );
    println!();

    meta.description = Input::new()
        .with_prompt("  Description")
        .allow_empty(true)
        .with_initial_text(&meta.description)
        .interact_text()?;

    vault_policy.access.allow_agent = prompt_allow_agent(Some(&vault_policy.access.allow_agent))?;

    vault_policy.access.rate_limit = Input::new()
        .with_prompt("  Rate limit")
        .with_initial_text(&vault_policy.access.rate_limit)
        .interact_text()?;

    meta.settings.autolock = Confirm::new()
        .with_prompt("  Auto-lock when idle?")
        .default(meta.settings.autolock)
        .interact()?;

    if meta.settings.autolock {
        meta.settings.autolock_timer = Input::new()
            .with_prompt("  Auto-lock timer (e.g. 1d, 12h, 30m)")
            .with_initial_text(&meta.settings.autolock_timer)
            .interact_text()?;
    }

    meta.settings.login_method = prompt_login_method(Some(meta.settings.login_method))?;

    // AI judge: whether it gates this vault's medium/high secrets, and which
    // keyring judge it uses (default falls back to the keyring's default judge).
    let judge_enabled = Confirm::new()
        .with_prompt("  Use the AI judge for medium/high secrets in this vault?")
        .default(vault_policy.judge.enabled.unwrap_or(false))
        .interact()?;
    vault_policy.judge.enabled = Some(judge_enabled);
    vault_policy.judge.judge = prompt_assigned_judge(vault_policy.judge.judge.as_deref())?;

    vault.save_meta(&meta)?;
    vault.save_policy(&vault_policy)?;
    usage::human(&vault_dir, "settings.update", None);

    println!();
    println!(
        "{} Settings for '{}' updated",
        style("ok:").green().bold(),
        meta.name
    );
    Ok(())
}

fn cmd_unlock(vault_name: Option<&str>) -> Result<()> {
    // The unified unlock: open the master once, then unwrap every vault's data
    // key from its keyslot and cache it — daemon memory if the daemon is up
    // (no file written), else a 0600 file session. With a vault name, unlock
    // just that one — still via the master.
    // A keyring (with a master keyslot) is unlockable even with no vaults yet.
    let keyring_unlockable = vault_name.is_none()
        && keyring::exists()
        && master::keyring_has_keyslot()
        && !keyring::is_unlocked();

    let targets: Vec<PathBuf> = match vault_name {
        Some(_) => vec![resolve_vault_dir(vault_name)?],
        None => {
            let dirs = list_vault_dirs();
            if dirs.is_empty() && !keyring_unlockable {
                println!("{}", style("No vaults yet. Run 'svault create'.").dim());
                return Ok(());
            }
            dirs
        }
    };

    let master = ensure_master_unlocked(false)?;

    let mut unlocked = 0usize;
    let mut already = 0usize;
    for dir in &targets {
        let name = VaultMeta::load_unverified(dir)
            .map(|m| m.name)
            .unwrap_or_else(|_| vault_leaf(dir));
        let leaf = vault_leaf(dir);

        if client::unlocked_vaults().iter().any(|n| n == &leaf) || session::is_unlocked(dir) {
            already += 1;
            continue;
        }
        if !master::vault_has_keyslot(dir) {
            eprintln!(
                "{} '{}' is not wrapped under the master (no keyslot) — skipping",
                style("warning:").yellow(),
                name
            );
            continue;
        }
        let dek = match master.unwrap_dek(dir) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("{} '{}': {}", style("error:").red(), name, e);
                continue;
            }
        };
        // Prefer the daemon (key in memory, no file); else a 0600 file session.
        match client::unlock_with_key(&leaf, dek.bytes()) {
            Some(Ok(())) => {}
            Some(Err(e)) => {
                eprintln!("{} '{}': {}", style("error:").red(), name, e);
                continue;
            }
            None => session::unlock_with_key(dir, dek.bytes())?,
        }
        usage::human(dir, "unlock", None);
        unlocked += 1;
    }

    // A full unlock also opens the keyring (judges + their keys) under the same
    // master — so the AI judge is live without a second prompt.
    let mut keyring_unlocked = false;
    if keyring_unlockable {
        match master.unwrap_keyring_dek() {
            Ok(dek) => {
                keyring::unlock_session(dek.bytes())?;
                println!("{} keyring unlocked", style("ok:").green());
                keyring_unlocked = true;
            }
            Err(e) => eprintln!("{} keyring: {}", style("warning:").yellow(), e),
        }
    }

    if unlocked == 0 && already > 0 {
        println!(
            "{} {} vault(s) already unlocked",
            style("ok:").green(),
            already
        );
    } else if targets.is_empty() && keyring_unlocked {
        // Keyring-only unlock (no vaults yet) — the keyring line above says it all.
        println!(
            "{}",
            style("  Run 'svault lock --all' to clear it and the master session.").dim()
        );
    } else {
        let tail = if already > 0 {
            format!(" ({already} already open)")
        } else {
            String::new()
        };
        println!(
            "{} Unlocked {} vault(s){}",
            style("ok:").green().bold(),
            unlocked,
            tail
        );
        println!(
            "{}",
            style("  Run 'svault lock --all' to clear them and the master session.").dim()
        );
    }
    Ok(())
}

fn cmd_lock(lock_all: bool, vault_name: Option<&str>) -> Result<()> {
    if lock_all {
        // Lock the daemon's in-memory keys, any file sessions, and the master
        // session — so re-unlocking re-prompts the master passphrase.
        let daemon_count = client::lock_all().unwrap_or(0);
        let file_count = session::lock_all(&svault_dir())?;
        master::lock_session()?;
        keyring::lock_session()?;
        let count = daemon_count + file_count;
        if count == 0 {
            println!("{}", style("All vaults already locked.").dim());
        } else {
            println!("{} Locked {} vault(s)", style("ok:").yellow().bold(), count);
        }
        return Ok(());
    }

    let vault_dir = resolve_vault_dir(vault_name)?;
    let meta = VaultMeta::load_unverified(&vault_dir)?;
    let leaf = vault_leaf(&vault_dir);
    // Clear the key from the daemon (if up) and the file session (if present).
    client::lock(&leaf);
    session::lock(&vault_dir)?;
    usage::human(&vault_dir, "lock", None);
    println!(
        "{} Vault '{}' locked",
        style("ok:").yellow().bold(),
        meta.name
    );
    Ok(())
}

fn cmd_status() -> Result<()> {
    let dirs = list_vault_dirs();
    if dirs.is_empty() {
        println!(
            "{}",
            style("No vaults found. Run 'svault create' to make one.").dim()
        );
        return Ok(());
    }

    println!(
        "{:<26} {:<12} {}",
        style("VAULT").bold(),
        style("STATUS").bold(),
        style("DESCRIPTION").bold()
    );
    println!("{}", style("─".repeat(60)).dim());

    let daemon_unlocked = client::unlocked_vaults();
    for dir in &dirs {
        if let Ok(meta) = VaultMeta::load_unverified(dir) {
            let in_daemon = daemon_unlocked.contains(&vault_leaf(dir));
            let status = if in_daemon {
                style("unlocked (daemon)").green().to_string()
            } else if session::is_unlocked(dir) {
                style("unlocked").green().to_string()
            } else {
                style("locked").dim().to_string()
            };
            println!(
                "{:<26} {:<12} {}",
                style(format!("{}:{}", meta.storage, meta.name)).cyan(),
                status,
                if meta.description.is_empty() {
                    "-".into()
                } else {
                    meta.description.clone()
                },
            );
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_secret(
    action: &str,
    name: Option<&str>,
    vault_name: Option<&str>,
    scope_arg: Option<&str>,
    tier_arg: Option<&str>,
    require_reason: bool,
    description_arg: Option<&str>,
    window_args: &[String],
    require_callers: Vec<String>,
) -> Result<()> {
    let vault_dir = resolve_vault_dir(vault_name)?;
    let meta_preview = VaultMeta::load_unverified(&vault_dir)?;
    let leaf = vault_leaf(&vault_dir);

    // Read path: when a daemon holds the key, serve `secret get` with no prompt.
    if action == "get" {
        if let Some(secret_name) = name {
            if let Some(outcome) = client::get(&leaf, secret_name) {
                match outcome {
                    client::GetOutcome::Value(value) => {
                        usage::human(&vault_dir, "secret.get", Some(secret_name));
                        println!("{value}");
                        return Ok(());
                    }
                    client::GetOutcome::NotFound => {
                        eprintln!(
                            "{} Secret '{}' not found",
                            style("error:").red(),
                            secret_name
                        );
                        std::process::exit(1);
                    }
                    // Daemon up but vault locked — fall through to the prompt path.
                    client::GetOutcome::NotUnlocked => {}
                }
            }
        }
    }

    // Use the cached session key if unlocked, otherwise prompt for the passphrase.
    let cached = session::is_unlocked(&vault_dir) && session::get_key(&vault_dir).is_some();
    let vault = open_unlocked_or_prompt(&vault_dir, &meta_preview.name)?;
    if !cached {
        println!(
            "{}",
            style("  Tip: run 'svault unlock' to cache the key for this session").dim()
        );
    }

    match action {
        "add" => {
            let secret_name: String = match name {
                Some(n) => n.to_string(),
                None => Input::new().with_prompt("  Secret name").interact_text()?,
            };
            let value = prompt_secret(format!("  Value for '{secret_name}'"))?;
            vault.add_secret(&secret_name, &value)?;

            // Classify the secret in the signed meta so the policy gate can
            // enforce it (#5). Flags drive non-interactive use; otherwise prompt.
            let scope = match scope_arg {
                Some(s) => s.to_string(),
                None => Input::new()
                    .with_prompt("  Scope (capability, e.g. database / api)")
                    .with_initial_text("misc")
                    .interact_text()?,
            };
            let tier = match tier_arg {
                Some(t) => parse_tier(t),
                None => prompt_tier(vault.policy.default_tier)?,
            };
            // Optional purpose note the AI judge uses to assess whether a
            // request's reason fits the secret. Blank is fine.
            let description = match description_arg {
                Some(d) => d.trim().to_string(),
                None => Input::new()
                    .with_prompt("  Description (what it's for — optional, used by the AI judge)")
                    .allow_empty(true)
                    .interact_text()?,
            };
            // Conditional access (0.9.9): parse any --window specs up front so a
            // bad spec fails before we touch the policy.
            let windows = window_args
                .iter()
                .map(|s| policy::AccessWindow::parse(s))
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| anyhow!("invalid --window: {e}"))?;
            // Classification lives in the encrypted policy (not the plaintext
            // meta.yaml), so a same-UID agent can't read the tier/scope/purpose
            // to plan a bypass. Re-encrypts the vault; values are untouched.
            let mut policy = vault.policy.clone();
            policy.secrets.insert(
                secret_name.clone(),
                policy::SecretRule {
                    scope,
                    tier,
                    require_reason,
                    description,
                    windows,
                    require_callers,
                },
            );
            vault.save_policy(&policy)?;
            usage::human(&vault_dir, "secret.add", Some(&secret_name));
            println!(
                "{} Secret '{}' added (scope={}, tier={})",
                style("ok:").green().bold(),
                secret_name,
                policy.secrets[&secret_name].scope,
                tier
            );
        }
        "get" => {
            let Some(secret_name) = name else {
                eprintln!(
                    "{} Provide a secret name: svault secret get <NAME>",
                    style("error:").red()
                );
                std::process::exit(1);
            };
            match vault.get_secret(secret_name)? {
                Some(value) => {
                    usage::human(&vault_dir, "secret.get", Some(secret_name));
                    println!("{}", *value);
                }
                None => {
                    eprintln!(
                        "{} Secret '{}' not found",
                        style("error:").red(),
                        secret_name
                    );
                    std::process::exit(1);
                }
            }
        }
        "list" => {
            let names = vault.list_secret_names()?;
            if names.is_empty() {
                println!("{}", style("No secrets stored yet.").dim());
            } else {
                println!(
                    "{}",
                    style(format!("Secrets in '{}':", vault.meta.name)).bold()
                );
                for n in &names {
                    println!("  {}", style(n).cyan());
                }
            }
        }
        "remove" => {
            let secret_name: String = match name {
                Some(n) => n.to_string(),
                None => Input::new()
                    .with_prompt("  Secret name to remove")
                    .interact_text()?,
            };
            if Confirm::new()
                .with_prompt(format!("  Remove '{secret_name}'?"))
                .default(false)
                .interact()?
            {
                if vault.remove_secret(&secret_name)? {
                    usage::human(&vault_dir, "secret.remove", Some(&secret_name));
                    println!("{} Secret '{}' removed", style("ok:").yellow(), secret_name);
                } else {
                    eprintln!(
                        "{} Secret '{}' not found",
                        style("error:").red(),
                        secret_name
                    );
                }
            }
        }
        _ => {
            eprintln!(
                "{} Unknown action '{}'. Use: add | get | list | remove",
                style("error:").red(),
                action
            );
            std::process::exit(1);
        }
    }
    Ok(())
}

fn cmd_vaults() -> Result<()> {
    let dirs = list_vault_dirs();
    if dirs.is_empty() {
        println!(
            "{}",
            style("No vaults found. Run 'svault create' to make one.").dim()
        );
        return Ok(());
    }
    // Access rules + classification are encrypted inside each vault now, so the
    // pre-unlock listing shows only public metadata. Use 'svault policy check'
    // (unlocks) to see who may access what.
    println!(
        "{:<12} {:<20} {:<40} {}",
        style("STORAGE").bold(),
        style("NAME").bold(),
        style("DESCRIPTION").bold(),
        style("CREATED").bold(),
    );
    println!("{}", style("─".repeat(80)).dim());
    for dir in &dirs {
        if let Ok(meta) = VaultMeta::load_unverified(dir) {
            let created = &meta.created_at[..10];
            println!(
                "{:<12} {:<20} {:<40} {}",
                meta.storage,
                style(&meta.name).cyan(),
                if meta.description.is_empty() {
                    "-".into()
                } else {
                    meta.description.clone()
                },
                created,
            );
        }
    }
    Ok(())
}

/// The agent path: a structured, policy-gated secret request.
/// On allow, the secret value is printed to stdout (so agents can capture it)
/// and all status goes to stderr. Every request is recorded to the audit log.
fn cmd_get(
    name: &str,
    scope: &str,
    reason: &str,
    caller_arg: Option<&str>,
    vault_name: Option<&str>,
) -> Result<()> {
    // Deprecated agent door. The gated path is the same as the MCP server's, so
    // this still works, but agents should move to `svault mcp` — we'll remove the
    // CLI agent path in a later release. Warning goes to stderr so it never
    // pollutes the value an agent reads from stdout.
    eprintln!(
        "{} `svault get` is deprecated — agents should use the MCP server (`svault mcp`). It still works for now.",
        style("note:").yellow()
    );
    let vault_dir = resolve_vault_dir(vault_name)?;
    let meta_preview = VaultMeta::load_unverified(&vault_dir)?;

    let caller = caller_arg
        .map(|s| s.to_string())
        .or_else(|| std::env::var("SVAULT_CALLER").ok())
        .unwrap_or_else(|| "default".to_string());
    let leaf = vault_leaf(&vault_dir);

    // Prefer the daemon: it is the enforced choke point — it evaluates policy,
    // consults the AI judge, audits the decision (with the peer UID), and only
    // then returns a value. The CLI just relays the verdict.
    if let Some(outcome) = client::get_gated(&leaf, name, &caller, scope, reason) {
        match outcome {
            client::GatedOutcome::Granted(value, tier) => {
                usage::agent(&vault_dir, &caller, "get.allow", Some(name));
                eprintln!(
                    "{} {} (caller={caller}, scope={scope}, tier={tier})",
                    style("granted:").green().bold(),
                    name
                );
                println!("{value}");
                return Ok(());
            }
            client::GatedOutcome::Denied(why) => {
                usage::agent(&vault_dir, &caller, "get.deny", Some(name));
                deny_and_exit(&why, &caller, name, scope);
            }
            client::GatedOutcome::NotFound => {
                eprintln!("{} Secret '{}' not found", style("error:").red(), name);
                std::process::exit(1);
            }
            // Daemon up but vault locked — fall through to the local gate.
            client::GatedOutcome::NotUnlocked => {}
        }
    }

    // No daemon (or vault not unlocked there): run the SAME gate locally against
    // the decrypted, key-authenticated policy. The agent path NEVER prompts — it
    // reads only an already-unlocked session (like `svault mcp`). A locked vault is
    // a dead end: prompting here would let an agent induce a master entry that caches
    // the vault for 6h and is then readable via the ungated human path.
    // `gate::gated_get` is the shared enforcement path (also used by `svault mcp`).
    let Some(vault) = open_unlocked_only(&vault_dir) else {
        eprintln!(
            "{} vault '{}' is locked — a human must run 'svault unlock' first",
            style("denied:").red().bold(),
            meta_preview.name
        );
        std::process::exit(1);
    };
    match gate::gated_get(&vault, &vault_dir, &caller, name, scope, reason)? {
        gate::GatedGet::Granted { value, tier } => {
            eprintln!(
                "{} {} (caller={caller}, scope={scope}, tier={tier})",
                style("granted:").green().bold(),
                name
            );
            println!("{}", *value);
            Ok(())
        }
        gate::GatedGet::Denied => {
            deny_and_exit(gate::GENERIC_DENY, &caller, name, scope);
        }
        gate::GatedGet::NotFound => {
            eprintln!("{} Secret '{}' not found", style("error:").red(), name);
            std::process::exit(1);
        }
    }
}

/// Print a denial to stderr and exit non-zero (the agent reads stdout for the
/// value, so denials never pollute it).
fn deny_and_exit(why: &str, caller: &str, name: &str, scope: &str) -> ! {
    eprintln!("{} {}", style("denied:").red().bold(), why);
    eprintln!(
        "{}",
        style(format!("  caller={caller} secret={name} scope={scope}")).dim()
    );
    std::process::exit(1);
}

/// `svault policy check <caller>` and `svault policy init`. Caller rules now live
/// AES-256-GCM encrypted inside each vault (not a committable `svault.policy.yaml`),
/// so both subcommands resolve a vault and unlock it to read/write the policy.
fn cmd_policy(action: &str, caller: Option<&str>, vault_name: Option<&str>) -> Result<()> {
    match action {
        "check" => {
            let Some(caller) = caller else {
                eprintln!(
                    "{} Usage: svault policy check <caller> [-v <vault>]",
                    style("error:").red()
                );
                std::process::exit(1);
            };
            let vault_dir = resolve_vault_dir(vault_name)?;
            let preview = VaultMeta::load_unverified(&vault_dir)?;
            let vault = open_unlocked_or_prompt(&vault_dir, &preview.name)?;
            cmd_policy_check(&vault, caller)
        }
        "init" => cmd_policy_init(vault_name),
        _ => {
            eprintln!(
                "{} Unknown action '{}'. Use: check | init",
                style("error:").red(),
                action
            );
            std::process::exit(1);
        }
    }
}

fn cmd_policy_check(vault: &Vault, caller: &str) -> Result<()> {
    let pol = &vault.policy;
    println!(
        "{}",
        style(format!(
            "┌─ Policy · {} · {caller} ──────────────────────┐",
            vault.meta.name
        ))
        .dim()
    );

    if pol.callers.is_empty() {
        println!(
            "{}",
            style(
                "No caller rules defined — this vault runs in fallback mode (allow_agent / rate_limit).",
            )
            .dim()
        );
        println!(
            "{}",
            style("Run 'svault policy init' to add caller rules.").dim()
        );
        return Ok(());
    }

    let Some(rule) = pol.caller(caller) else {
        eprintln!(
            "{} Caller '{}' is not defined and there is no 'default' caller",
            style("error:").red(),
            caller
        );
        std::process::exit(1);
    };

    println!(
        "  {:<14} {}",
        style("Scopes").dim(),
        if rule.scopes.is_empty() {
            "(none)".to_string()
        } else {
            rule.scopes.join(", ")
        }
    );
    println!("  {:<14} {}", style("Rate limit").dim(), rule.rate_limit);
    println!();

    let rows = pol.accessible(caller);
    if rows.is_empty() {
        println!(
            "{}",
            style("This caller cannot retrieve any classified secret.").dim()
        );
    } else {
        println!(
            "{:<22} {:<12} {}",
            style("SECRET").bold(),
            style("SCOPE").bold(),
            style("TIER").bold()
        );
        println!("{}", style("─".repeat(48)).dim());
        for (secret, scope, tier) in &rows {
            println!("{:<22} {:<12} {}", secret, scope, tier);
        }
    }

    // Conditional access (0.9.9): show any windows / required callers.
    let conditioned: Vec<_> = pol
        .secrets
        .iter()
        .filter(|(n, r)| *n != "*" && (!r.windows.is_empty() || !r.require_callers.is_empty()))
        .collect();
    if !conditioned.is_empty() {
        println!();
        println!("{}", style("Conditional access").bold());
        for (secret, rule) in conditioned {
            if !rule.windows.is_empty() {
                let specs: Vec<String> = rule.windows.iter().map(|w| w.to_string()).collect();
                println!("  {:<20} window: {}", secret, specs.join(" | "));
            }
            if !rule.require_callers.is_empty() {
                println!(
                    "  {:<20} callers: {}",
                    secret,
                    rule.require_callers.join(", ")
                );
            }
        }
    }

    // Sealed secrets (anomaly-escalated, awaiting `svault approve`).
    if !pol.seals.is_empty() {
        println!();
        println!("{}", style("Sealed — awaiting approval").bold().yellow());
        for (secret, seal) in &pol.seals {
            println!(
                "  {:<20} {} ({})",
                secret,
                style(&seal.trigger).dim(),
                seal.last_caller
            );
        }
    }

    // Audit summary for this vault.
    let mut total = 0usize;
    let mut denied = 0usize;
    for e in audit::all(&vault.vault_dir).unwrap_or_default() {
        if e.caller == caller {
            total += 1;
            if e.decision == "deny" {
                denied += 1;
            }
        }
    }
    println!();
    println!(
        "{} {} request(s) logged, {} denied",
        style("audit:").dim(),
        total,
        denied
    );
    Ok(())
}

/// Seed default caller rules into a vault's encrypted policy.
fn cmd_policy_init(vault_name: Option<&str>) -> Result<()> {
    let vault_dir = resolve_vault_dir(vault_name)?;
    let preview = VaultMeta::load_unverified(&vault_dir)?;
    let vault = open_unlocked_or_prompt(&vault_dir, &preview.name)?;

    let mut pol = vault.policy.clone();
    if !pol.callers.is_empty() {
        eprintln!(
            "{} vault '{}' already has caller rules — edit them with 'svault settings'",
            style("error:").red(),
            vault.meta.name
        );
        std::process::exit(1);
    }

    pol.callers.insert(
        "claude-code".to_string(),
        policy::CallerRule {
            scopes: vec!["misc".to_string()],
            rate_limit: "20/hour".to_string(),
        },
    );
    pol.callers.insert(
        "default".to_string(),
        policy::CallerRule {
            scopes: vec![],
            rate_limit: "5/hour".to_string(),
        },
    );
    vault.save_policy(&pol)?;
    usage::human(&vault_dir, "policy.init", None);

    println!(
        "{} Seeded caller rules for vault '{}' (claude-code, default)",
        style("ok:").green().bold(),
        vault.meta.name
    );
    println!(
        "{}",
        style("  They are encrypted inside the vault — not a committable file.").dim()
    );
    println!(
        "{}",
        style(
            "  These callers start deny-by-default: 'default' holds no scopes and \
             'claude-code' only 'misc'."
        )
        .dim()
    );
    println!(
        "{}",
        style(
            "  Grant each caller the scopes its secrets use (e.g. database, api) via \
             'svault settings' — until then scoped gets are denied."
        )
        .dim()
    );
    Ok(())
}

// ── Seal / escalation review ────────────────────────────────────────────────

/// List sealed secrets awaiting human approval, for one vault or all. Seals live
/// in the encrypted policy, so each vault must be unlocked (a single master
/// prompt opens them all). A sealed secret denies every agent get until cleared.
fn cmd_pending(vault_name: Option<&str>) -> Result<()> {
    let dirs = match vault_name {
        Some(_) => vec![resolve_vault_dir(vault_name)?],
        None => list_vault_dirs(),
    };
    if dirs.is_empty() {
        println!(
            "{}",
            style("No vaults found. Run 'svault create' to make one.").dim()
        );
        return Ok(());
    }

    let mut any = false;
    for dir in &dirs {
        let Ok(preview) = VaultMeta::load_unverified(dir) else {
            continue;
        };
        let vault = open_unlocked_or_prompt(dir, &preview.name)?;
        for (secret, seal) in &vault.policy.seals {
            if !any {
                println!(
                    "{:<20} {:<16} {:<7} {:<16} {}",
                    style("SECRET").bold(),
                    style("VAULT").bold(),
                    style("DENIALS").bold(),
                    style("LAST CALLER").bold(),
                    style("SEALED AT").bold()
                );
                println!("{}", style("─".repeat(78)).dim());
                any = true;
            }
            println!(
                "{:<20} {:<16} {:<7} {:<16} {}",
                style(secret).yellow(),
                vault.meta.name,
                seal.denials,
                seal.last_caller,
                style(&seal.sealed_at).dim()
            );
        }
    }
    if any {
        println!();
        println!(
            "{}",
            style("Clear one with 'svault approve <secret> -v <vault>'.").dim()
        );
    } else {
        println!(
            "{}",
            style("No sealed secrets — nothing pending approval.").dim()
        );
    }
    Ok(())
}

/// Clear a seal so agents can request the secret again. Human-only: requires the
/// master to read/write the encrypted policy; an agent has no path here.
fn cmd_approve(secret: &str, vault_name: Option<&str>) -> Result<()> {
    let vault_dir = resolve_vault_dir(vault_name)?;
    let preview = VaultMeta::load_unverified(&vault_dir)?;
    // Clearing a seal is a human-only escalation: require the master credential
    // NOW, ignoring any cached session, so a same-UID process can't ride a
    // lingering unlock to approve unattended.
    let vault = open_with_fresh_master(&vault_dir, &preview.name)?;
    if !vault.policy.seals.contains_key(secret) {
        eprintln!(
            "{} '{}' is not sealed in vault '{}'",
            style("error:").red(),
            secret,
            preview.name
        );
        std::process::exit(1);
    }
    let mut policy = vault.policy.clone();
    policy.seals.remove(secret);
    vault.save_policy(&policy)?;
    usage::human(&vault_dir, "seal.cleared", Some(secret));
    println!(
        "{} cleared the seal on '{}' — agents may request it again",
        style("ok:").green().bold(),
        secret
    );
    Ok(())
}

// ── Recovery, export, import ────────────────────────────────────────────────

fn cmd_recover(vault_name: Option<&str>, force: bool) -> Result<()> {
    let vault_dir = resolve_vault_dir(vault_name)?;
    let meta = VaultMeta::load_unverified(&vault_dir)?;

    if !recovery::exists(&vault_dir) {
        eprintln!(
            "{} Vault '{}' has no recovery file — it predates recovery support.",
            style("error:").red(),
            meta.name
        );
        std::process::exit(1);
    }

    let code = prompt_secret(format!("  Recovery code for '{}'", meta.name))?;

    // The code unwraps the vault's data key directly (it never changed).
    let dek = recovery::unlock_with_code(&vault_dir, &code).unwrap_or_else(|e| {
        eprintln!("{} {}", style("error:").red(), e);
        std::process::exit(1);
    });

    println!("{} Recovery code accepted.", style("ok:").green());
    // Re-attach the vault to the master: wrap its recovered data key under the
    // current master passphrase (set one now if there isn't one). The data key
    // and vault.enc are untouched — no re-encryption, no new per-vault secret.
    let master = ensure_master_unlocked(force)?;
    master.wrap_dek(&vault_dir, &dek)?;
    session::unlock_with_key(&vault_dir, dek.bytes())?;
    usage::human(&vault_dir, "recover", None);

    println!(
        "{} Vault '{}' is back under your master passphrase. Recovery code unchanged.",
        style("ok:").green().bold(),
        meta.name
    );
    Ok(())
}

fn cmd_export(vault_name: Option<&str>, out: Option<&str>) -> Result<()> {
    let vault_dir = resolve_vault_dir(vault_name)?;
    let meta = VaultMeta::load_unverified(&vault_dir)?;

    let json = portable::build_bundle(&vault_dir, &meta.name, &meta.storage).unwrap_or_else(|e| {
        eprintln!("{} {}", style("error:").red(), e);
        std::process::exit(1);
    });

    let out_path = out
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("{}.svault-export.json", meta.name)));
    // A bundle is a full backup (carries the wrapped key) — write it owner-only (#14).
    secfile::write_owner_only(&out_path, json.as_bytes())?;

    // Keep the bundle out of git so it can't be pushed by mistake.
    let out_dir = out_path.parent().filter(|p| !p.as_os_str().is_empty());
    portable::ensure_export_gitignored(out_dir.unwrap_or_else(|| Path::new(".")));
    usage::human(&vault_dir, "export", None);

    println!(
        "{} Exported '{}' to {}",
        style("ok:").green().bold(),
        meta.name,
        out_path.display()
    );
    println!(
        "{}",
        style("  The bundle is encrypted — import it with 'svault import'.").dim()
    );
    Ok(())
}

fn cmd_import(file: &str, name: Option<&str>) -> Result<()> {
    let raw = std::fs::read_to_string(file).unwrap_or_else(|e| {
        eprintln!("{} cannot read {}: {}", style("error:").red(), file, e);
        std::process::exit(1);
    });

    let bundle = portable::parse_bundle(&raw).unwrap_or_else(|e| {
        eprintln!("{} {}", style("error:").red(), e);
        std::process::exit(1);
    });
    let base = svault_dir();
    let base = base.as_path();

    // Resolve a free name: the requested name (or the bundle's own), suffixed if
    // it's already taken — so re-importing onto the same machine never errors.
    let desired = name.unwrap_or(&bundle.name);
    let target = portable::unique_vault_name(base, desired);
    let renamed = target != bundle.name;
    if target != desired {
        println!(
            "{} '{}' already exists — importing as '{}'",
            style("note:").cyan(),
            desired,
            target
        );
    }

    portable::import_bundle_as(&raw, base, &target).unwrap_or_else(|e| {
        eprintln!("{} {}", style("error:").red(), e);
        std::process::exit(1);
    });
    let dir = base.join(&target);

    // An imported vault is keyed by a random data key (no per-vault passphrase),
    // and its machine-specific keyslot is *not* bundled — only `recovery.enc` is.
    // So the recovery code is the way in. If the name changed we need the key to
    // re-sign meta.name; either way we attach the vault to this machine's master
    // so it opens with the master passphrase afterwards.
    let attach = renamed || recovery::exists(&dir);
    if attach {
        if !recovery::exists(&dir) {
            let _ = std::fs::remove_dir_all(&dir);
            eprintln!(
                "{} bundle has no recovery file — cannot bring '{}' under your master",
                style("error:").red(),
                target
            );
            std::process::exit(1);
        }
        let code = prompt_secret(format!(
            "  Recovery code for '{}' (to attach it to your master)",
            bundle.name
        ))?;
        let dek = recovery::unlock_with_code(&dir, &code).unwrap_or_else(|e| {
            if renamed {
                let _ = std::fs::remove_dir_all(&dir);
            }
            eprintln!("{} {}", style("error:").red(), e);
            std::process::exit(1);
        });
        let vault = Vault::open_with_key(&dir, dek).unwrap_or_else(|e| {
            eprintln!("{} {}", style("error:").red(), e);
            std::process::exit(1);
        });
        if renamed {
            let mut meta = vault.meta.clone();
            meta.name = target.clone();
            if let Err(e) = vault.save_meta(&meta) {
                let _ = std::fs::remove_dir_all(&dir);
                eprintln!("{} could not finalize rename: {}", style("error:").red(), e);
                std::process::exit(1);
            }
        }
        let master = ensure_master_unlocked(false)?;
        master.wrap_dek(&dir, vault.key())?;
        session::unlock_with_key(&dir, vault.key().bytes()).ok();
    }

    usage::human(&dir, "import", None);

    println!(
        "{} Imported '{}' into {}/{}/",
        style("ok:").green().bold(),
        target,
        SVAULT_DIR,
        target
    );
    if !attach {
        println!(
            "{}",
            style("  Run 'svault recover' with its recovery code to open it under your master.")
                .dim()
        );
    }
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Resolve which vault a command targets.
/// - explicit `--vault <name>`: use it (error if it does not exist)
/// - no flag, one vault: use it
/// - no flag, many vaults: prompt the user to pick one
fn resolve_vault_dir(vault_name: Option<&str>) -> Result<PathBuf> {
    if let Some(n) = vault_name {
        let dir = svault_dir().join(n);
        if !dir.join("meta.yaml").exists() {
            eprintln!(
                "{} Vault '{}' not found in {}/",
                style("error:").red(),
                n,
                svault_dir().display()
            );
            std::process::exit(1);
        }
        return Ok(dir);
    }

    let dirs = list_vault_dirs();
    match dirs.len() {
        0 => {
            eprintln!(
                "{} No vault found. Run {} first.",
                style("error:").red(),
                style("svault create").bold()
            );
            std::process::exit(1);
        }
        1 => Ok(dirs[0].clone()),
        _ => {
            let names: Vec<String> = dirs
                .iter()
                .map(|d| {
                    VaultMeta::load_unverified(d)
                        .map(|m| m.name)
                        .unwrap_or_else(|_| d.display().to_string())
                })
                .collect();
            let idx = Select::new()
                .with_prompt("  Which vault?")
                .items(&names)
                .default(0)
                .interact()?;
            Ok(dirs[idx].clone())
        }
    }
}

/// Open a vault for a local (non-daemon) operation, preferring the cached
/// session *key* so the passphrase is neither re-entered nor stored on disk.
/// Falls back to a passphrase prompt when the vault is locked or the cached
/// session is stale/invalid.
/// Open a vault **only** from an existing unlocked session — never prompt for a
/// credential. Returns `None` when the vault is locked. The agent `get` path uses
/// this (mirroring `svault mcp`) so an agent can't induce a master prompt: if a
/// human typed it, the vault would be cached for the full 6h and then readable via
/// the *ungated* human path. A locked vault is a dead end for the agent — a human
/// must `svault unlock` first.
fn open_unlocked_only(vault_dir: &Path) -> Option<Vault> {
    if session::is_unlocked(vault_dir) {
        if let Some(key) = session::get_key(vault_dir) {
            if let Ok(v) = Vault::open_with_key(vault_dir, VaultKey::from_bytes(key)) {
                return Some(v);
            }
            let _ = session::lock(vault_dir); // stale/invalid cached key — drop it
        }
    }
    None
}

/// Open a vault by forcing a **fresh** master credential — the cached session is
/// ignored. Privileged human-only actions (clearing a seal) use this so a same-UID
/// process can't ride a lingering session to perform them. On a vault with a master
/// keyslot the fresh master both proves human presence and unwraps the data key; a
/// legacy own-passphrase vault re-prompts its passphrase. In a non-TTY context the
/// prompt fails, which correctly refuses unattended approval.
fn open_with_fresh_master(vault_dir: &Path, vault_name: &str) -> Result<Vault> {
    if master::vault_has_keyslot(vault_dir) {
        let master = ensure_master_unlocked_inner(false, true)?;
        let dek = master.unwrap_dek(vault_dir).map_err(|e| {
            eprintln!("{} {}", style("error:").red(), e);
            std::process::exit(1);
            #[allow(unreachable_code)]
            e
        })?;
        session::unlock_with_key(vault_dir, dek.bytes()).ok();
        return Vault::open_with_key(vault_dir, dek).map_err(|e| {
            eprintln!("{} {}", style("error:").red(), e);
            std::process::exit(1);
            #[allow(unreachable_code)]
            e
        });
    }
    let passphrase = prompt_secret(format!("  Passphrase for '{vault_name}'"))?;
    Vault::open(vault_dir, &passphrase).map_err(|e| {
        eprintln!("{} {}", style("error:").red(), e);
        std::process::exit(1);
        #[allow(unreachable_code)]
        e
    })
}

fn open_unlocked_or_prompt(vault_dir: &Path, vault_name: &str) -> Result<Vault> {
    if session::is_unlocked(vault_dir) {
        if let Some(key) = session::get_key(vault_dir) {
            if let Ok(v) = Vault::open_with_key(vault_dir, VaultKey::from_bytes(key)) {
                return Ok(v);
            }
            let _ = session::lock(vault_dir); // stale/invalid cached key — drop it
        }
    }
    // Unified unlock: unwrap this vault's data key via the master passphrase
    // (prompting, or setting it on first run). No per-vault passphrase exists.
    if master::vault_has_keyslot(vault_dir) {
        let master = ensure_master_unlocked(false)?;
        let dek = master.unwrap_dek(vault_dir).map_err(|e| {
            eprintln!("{} {}", style("error:").red(), e);
            std::process::exit(1);
            #[allow(unreachable_code)]
            e
        })?;
        session::unlock_with_key(vault_dir, dek.bytes()).ok();
        return Vault::open_with_key(vault_dir, dek).map_err(|e| {
            eprintln!("{} {}", style("error:").red(), e);
            std::process::exit(1);
            #[allow(unreachable_code)]
            e
        });
    }
    // Legacy fallback: a vault that still has its own passphrase (no keyslot).
    let _ = vault_name;
    let passphrase = prompt_secret(format!("  Passphrase for '{vault_name}'"))?;
    Vault::open(vault_dir, &passphrase).map_err(|e| {
        eprintln!("{} {}", style("error:").red(), e);
        std::process::exit(1);
        #[allow(unreachable_code)]
        e
    })
}

/// Prompt for agent access. `current` pre-selects the matching choice when editing.
fn prompt_allow_agent(current: Option<&AllowAgent>) -> Result<AllowAgent> {
    let choices = &[
        "yes — all agents",
        "no — block all agents",
        "list — specific agents only",
    ];
    let (default_idx, default_list) = match current {
        Some(AllowAgent::Bool(true)) => (0, String::new()),
        Some(AllowAgent::Bool(false)) => (1, String::new()),
        Some(AllowAgent::List(agents)) => (2, agents.join(", ")),
        None => (0, String::new()),
    };

    let idx = Select::new()
        .with_prompt("  Allow agent access")
        .items(choices)
        .default(default_idx)
        .interact()?;

    Ok(match idx {
        0 => AllowAgent::Bool(true),
        1 => AllowAgent::Bool(false),
        _ => {
            let raw: String = Input::new()
                .with_prompt("  Agent names (comma-separated)")
                .with_initial_text(&default_list)
                .interact_text()?;
            AllowAgent::List(
                raw.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect(),
            )
        }
    })
}

/// Prompt for login method. Only passphrase works today — yubikey and google
/// auth are shown but fall back to passphrase with a notice.
fn prompt_login_method(current: Option<LoginMethod>) -> Result<LoginMethod> {
    let choices = &[
        "passphrase",
        "yubikey (coming soon)",
        "google auth (coming soon)",
    ];
    let default_idx = match current {
        Some(LoginMethod::Passphrase) | None => 0,
        Some(LoginMethod::Yubikey) => 1,
        Some(LoginMethod::GoogleAuth) => 2,
    };

    let idx = Select::new()
        .with_prompt("  Login method")
        .items(choices)
        .default(default_idx)
        .interact()?;

    if idx != 0 {
        println!(
            "{} Only passphrase is available right now — using passphrase.",
            style("note:").cyan()
        );
    }
    Ok(LoginMethod::Passphrase)
}

/// Names of the judges in the unlocked keyring (sorted). Empty when the keyring
/// is locked or has no judges.
fn available_judge_names() -> Vec<String> {
    match keyring::open_from_session() {
        Some(kr) => {
            let mut names: Vec<String> = kr.data.judges.keys().cloned().collect();
            names.sort();
            names
        }
        None => Vec::new(),
    }
}

/// Pick which keyring judge gates a vault: `default` (the keyring's default
/// judge) or a specific named judge. Returns the chosen name, or `None` for
/// default. When the keyring is locked or empty there is nothing to choose, so
/// `current` is kept (with a note).
fn prompt_assigned_judge(current: Option<&str>) -> Result<Option<String>> {
    let names = available_judge_names();
    if names.is_empty() {
        println!(
            "{} no judges to assign (keyring locked or empty) — keeping {}.",
            style("note:").cyan(),
            current.unwrap_or("default")
        );
        return Ok(current.map(str::to_string));
    }
    // index 0 = default; then each judge. Keep the current selection reachable
    // even if it was removed/renamed in the keyring.
    let mut labels: Vec<String> = vec!["default (keyring default)".to_string()];
    let mut values: Vec<Option<String>> = vec![None];
    for n in &names {
        labels.push(n.clone());
        values.push(Some(n.clone()));
    }
    if let Some(c) = current {
        if !names.iter().any(|n| n == c) {
            labels.push(format!("{c} (not in keyring)"));
            values.push(Some(c.to_string()));
        }
    }
    let default_idx = values
        .iter()
        .position(|v| v.as_deref() == current)
        .unwrap_or(0);
    let idx = Select::new()
        .with_prompt("  Assigned judge")
        .items(&labels)
        .default(default_idx)
        .interact()?;
    Ok(values[idx].clone())
}

/// Parse a tier string leniently (unknown → low).
fn parse_tier(s: &str) -> policy::Tier {
    match s.trim().to_lowercase().as_str() {
        "medium" | "med" => policy::Tier::Medium,
        "high" => policy::Tier::High,
        _ => policy::Tier::Low,
    }
}

fn prompt_tier(default: policy::Tier) -> Result<policy::Tier> {
    let choices = &[
        "low — auto-allow",
        "medium — AI-judged (fail-open if judge down)",
        "high — AI-judged, fail-closed (human-only when judge off)",
    ];
    let default_idx = match default {
        policy::Tier::Low => 0,
        policy::Tier::Medium => 1,
        policy::Tier::High => 2,
    };
    let idx = Select::new()
        .with_prompt("  Sensitivity tier")
        .items(choices)
        .default(default_idx)
        .interact()?;
    Ok(match idx {
        1 => policy::Tier::Medium,
        2 => policy::Tier::High,
        _ => policy::Tier::Low,
    })
}

/// Sample request for `svault judge test` — everything the dry-run feeds the
/// model. Bundled so the command functions stay under the argument limit.
struct JudgeTestArgs<'a> {
    reason: Option<&'a str>,
    scope: &'a str,
    secret: &'a str,
    caller: &'a str,
    tier: &'a str,
    description: Option<&'a str>,
    vault: &'a str,
    vault_description: Option<&'a str>,
}

/// Open the keyring for a management command: reuse the cached session if it's
/// unlocked, else unlock it via the master passphrase and cache a session (so the
/// keyring is unlocked for the rest of this session, and the daemon sees it).
fn unlock_keyring_interactive() -> Result<keyring::Keyring> {
    if !keyring::exists() {
        anyhow::bail!("no keyring yet — run 'svault keyring init'");
    }
    if let Some(kr) = keyring::open_from_session() {
        return Ok(kr);
    }
    if !master::keyring_has_keyslot() {
        anyhow::bail!("the keyring has no master keyslot — wipe .svault/ and re-init");
    }
    let master = ensure_master_unlocked(false)?;
    let dek = master.unwrap_keyring_dek()?;
    keyring::unlock_session(dek.bytes())?;
    keyring::open_from_session().ok_or_else(|| anyhow::anyhow!("could not open the keyring"))
}

/// Prompt for a brand-new passphrase: enforce the entropy floor (unless
/// `--force`), warn on weak-but-allowed input, and confirm. Shared by master
/// init/rekey. Exits on a confirm mismatch.
fn prompt_new_passphrase(label: &str, force: bool) -> Result<Zeroizing<String>> {
    let passphrase = loop {
        let p = prompt_secret(label.to_string())?;
        match passphrase::meets_floor(&p) {
            Ok(()) => break p,
            Err(e) if force => {
                println!("{} {} (--force)", style("warning:").yellow(), e);
                break p;
            }
            Err(e) => eprintln!("{} {}", style("error:").red(), e),
        }
    };
    if let Some(w) = passphrase::check(&passphrase) {
        println!("{} {}", style("warning:").yellow(), w.0);
    }
    let confirm = prompt_secret(format!("{} (confirm)", label.trim()))?;
    if *passphrase != *confirm {
        eprintln!("{} passphrases do not match", style("error:").red());
        std::process::exit(1);
    }
    Ok(passphrase)
}

/// Return an unlocked master, prompting as needed: reuse the cached session,
/// else prompt the existing master passphrase, else (first run on this machine)
/// set a new one. The single place the "first time → set a passphrase" flow
/// lives, shared by `create` and `unlock`.
fn ensure_master_unlocked(force: bool) -> Result<master::Master> {
    ensure_master_unlocked_inner(force, false)
}

/// As [`ensure_master_unlocked`], but `fresh` skips the cached master session and
/// forces the human to re-enter the master credential (passphrase or YubiKey
/// touch) now. Privileged human-only actions — clearing a seal — use this so a
/// lingering session can't let a same-UID process perform them unattended.
fn ensure_master_unlocked_inner(force: bool, fresh: bool) -> Result<master::Master> {
    if !fresh {
        if let Some(m) = master::open_from_session() {
            return Ok(m);
        }
    }
    if master::exists() {
        // Offer the YubiKey when one is enrolled and plugged in. It's an
        // alternative slot, so the master passphrase is always the fallback.
        if master::yubikey_enrolled() && yubikey::is_present() {
            let use_key = Confirm::new()
                .with_prompt("  A YubiKey is enrolled — unlock with it?")
                .default(true)
                .interact()
                .unwrap_or(false);
            if use_key {
                match try_yubikey_unlock() {
                    Ok(m) => return Ok(m),
                    Err(e) => eprintln!(
                        "{} {} — falling back to the master passphrase",
                        style("yubikey:").yellow(),
                        e
                    ),
                }
            }
        }
        let passphrase = prompt_secret("  Master passphrase")?;
        let m = master::Master::open(&passphrase).map_err(|e| {
            eprintln!("{} {}", style("error:").red(), e);
            std::process::exit(1);
            #[allow(unreachable_code)]
            e
        })?;
        master::unlock_session(m.key_bytes())?;
        return Ok(m);
    }
    println!();
    println!(
        "{}",
        style("  No master passphrase yet — let's set one. It unlocks every vault.").cyan()
    );
    let passphrase = prompt_new_passphrase("  Master passphrase", force)?;
    let m = master::Master::init(&passphrase)?;
    master::unlock_session(m.key_bytes())?;
    print_master_recovery_code(&m)?;
    Ok(m)
}

/// Prompt for the YubiKey PIN, allowing a blank entry for keys with no PIN set.
fn prompt_optional_pin() -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(
        Password::new()
            .with_prompt("  YubiKey PIN (leave blank if none)")
            .allow_empty_password(true)
            .interact()?,
    ))
}

/// Derive the master key from the enrolled YubiKey (touch + optional PIN) and
/// cache the master session, mirroring the passphrase path.
fn try_yubikey_unlock() -> Result<master::Master> {
    let pin = prompt_optional_pin()?;
    println!("{}", style("  Touch your YubiKey...").dim());
    let m = master::open_with_yubikey(Some(&pin))?;
    master::unlock_session(m.key_bytes())?;
    Ok(m)
}

/// `svault master yubikey <enroll|remove|status>` — manage the YubiKey keyslot.
fn cmd_master_yubikey(sub: Option<&str>, force: bool) -> Result<()> {
    match sub {
        Some("enroll") => {
            if !yubikey::is_present() {
                eprintln!(
                    "{} no YubiKey / FIDO2 device found — plug it in and retry",
                    style("error:").red()
                );
                std::process::exit(1);
            }
            if master::yubikey_enrolled() {
                eprintln!(
                    "{} a YubiKey is already enrolled — remove it first with 'svault master yubikey remove'",
                    style("error:").red()
                );
                std::process::exit(1);
            }
            // Need the master key in hand to wrap it under the new slot.
            let m = ensure_master_unlocked(force)?;
            let pin = prompt_optional_pin()?;
            println!(
                "{}",
                style("  Touch your YubiKey twice (enroll, then verify)...").dim()
            );
            m.enroll_yubikey(Some(&pin)).map_err(|e| {
                eprintln!("{} {}", style("error:").red(), e);
                std::process::exit(1);
                #[allow(unreachable_code)]
                e
            })?;
            println!(
                "{} YubiKey enrolled. 'svault unlock' now offers it, and your master passphrase still works.",
                style("ok:").green().bold()
            );
            println!(
                "{}",
                style("  If you lose the key, the master passphrase or recovery code still opens everything.")
                    .dim()
            );
            Ok(())
        }
        Some("remove") => {
            if !master::yubikey_enrolled() {
                println!("{} no YubiKey is enrolled", style("ok:").green());
                return Ok(());
            }
            master::remove_yubikey()?;
            println!(
                "{} YubiKey keyslot removed. The master passphrase and recovery code still open everything.",
                style("ok:").green().bold()
            );
            Ok(())
        }
        Some("status") | None => {
            let enrolled = master::yubikey_enrolled();
            let present = yubikey::is_present();
            println!(
                "  {:<14} {}",
                style("Enrolled").dim(),
                if enrolled {
                    style("yes").green()
                } else {
                    style("no").dim()
                }
            );
            println!(
                "  {:<14} {}",
                style("Device").dim(),
                if present {
                    style("connected").green()
                } else {
                    style("not connected").dim()
                }
            );
            Ok(())
        }
        Some(other) => {
            eprintln!(
                "{} unknown yubikey action '{}' — use enroll | remove | status",
                style("error:").red(),
                other
            );
            std::process::exit(1);
        }
    }
}

/// Generate the master recovery code and show it once. Called the moment the
/// master passphrase is first set — it's the only way back in if the passphrase
/// is forgotten, and it opens every store (all vaults + the keyring).
fn print_master_recovery_code(master: &master::Master) -> Result<()> {
    let code = master.write_recovery()?;
    println!();
    println!(
        "  {} {}",
        style("Master recovery code").yellow().bold(),
        style("(shown once — store it safely)").dim()
    );
    println!("    {}", style(&code).cyan().bold());
    println!(
        "{}",
        style("  Recovers your master if you forget it (opens every vault + the keyring).").dim()
    );
    println!(
        "{}",
        style("  Reset later with 'svault master recover'.").dim()
    );
    Ok(())
}

/// `svault master <action>` — the single passphrase that unlocks every vault.
fn cmd_master(action: &str, sub: Option<&str>, force: bool) -> Result<()> {
    match action {
        "init" => cmd_master_init(force),
        "rekey" => cmd_master_rekey(force),
        "recover" => cmd_master_recover(force),
        "status" => cmd_master_status(),
        "yubikey" => cmd_master_yubikey(sub, force),
        other => {
            eprintln!(
                "{} unknown master action '{}' — use init | rekey | recover | status | yubikey",
                style("error:").red(),
                other
            );
            std::process::exit(1);
        }
    }
}

/// `svault master recover` — reset a forgotten master passphrase with the
/// recovery code shown when the master was first set.
fn cmd_master_recover(force: bool) -> Result<()> {
    if !master::exists() {
        eprintln!(
            "{} no master passphrase set yet — run 'svault master init'",
            style("error:").red()
        );
        std::process::exit(1);
    }
    if !master::master_recovery_exists() {
        eprintln!(
            "{} no master recovery code on this machine — recover each vault with its own code instead",
            style("error:").red()
        );
        std::process::exit(1);
    }
    let code = prompt_secret("  Master recovery code")?;
    let new = prompt_new_passphrase("  New master passphrase", force)?;
    let m = master::recover(&code, &new).map_err(|e| {
        eprintln!("{} {}", style("error:").red(), e);
        std::process::exit(1);
        #[allow(unreachable_code)]
        e
    })?;
    master::unlock_session(m.key_bytes())?;
    println!(
        "{} Master passphrase reset. Every vault and the keyring stay accessible (nothing was re-encrypted).",
        style("ok:").green().bold()
    );
    Ok(())
}

fn cmd_master_init(force: bool) -> Result<()> {
    if master::exists() {
        println!(
            "{} a master passphrase is already set — use 'svault master rekey' to change it",
            style("ok:").green()
        );
        return Ok(());
    }
    println!(
        "{}",
        style("Set your master passphrase — one secret unlocks every vault.").bold()
    );
    let passphrase = prompt_new_passphrase("  Master passphrase", force)?;
    let m = master::Master::init(&passphrase)?;
    master::unlock_session(m.key_bytes())?;
    println!(
        "{} Master passphrase set. 'svault unlock' now opens all vaults with it.",
        style("ok:").green().bold()
    );
    print_master_recovery_code(&m)?;
    Ok(())
}

fn cmd_master_rekey(force: bool) -> Result<()> {
    if !master::exists() {
        eprintln!(
            "{} no master passphrase set yet — run 'svault master init'",
            style("error:").red()
        );
        std::process::exit(1);
    }
    let m = match master::open_from_session() {
        Some(m) => m,
        None => {
            let current = prompt_secret("  Current master passphrase")?;
            master::Master::open(&current).map_err(|e| {
                eprintln!("{} {}", style("error:").red(), e);
                std::process::exit(1);
                #[allow(unreachable_code)]
                e
            })?
        }
    };
    let new = prompt_new_passphrase("  New master passphrase", force)?;
    m.rekey(&new)?;
    master::unlock_session(m.key_bytes())?;
    println!(
        "{} Master passphrase changed. Every vault stays accessible (the data keys never moved).",
        style("ok:").green().bold()
    );
    Ok(())
}

fn cmd_master_status() -> Result<()> {
    if !master::exists() {
        println!(
            "{}",
            style(
                "· no master passphrase set — run 'svault master init' (or just 'svault create')"
            )
            .dim()
        );
        return Ok(());
    }
    let dirs = list_vault_dirs();
    let wrapped = dirs.iter().filter(|d| master::vault_has_keyslot(d)).count();
    println!("  {:<14} {}", style("Master").dim(), style("set").green());
    println!(
        "  {:<14} {}",
        style("Session").dim(),
        if master::is_unlocked() {
            style("unlocked").green()
        } else {
            style("locked").yellow()
        }
    );
    println!(
        "  {:<14} {} of {} vault(s) wrapped under the master",
        style("Vaults").dim(),
        wrapped,
        dirs.len()
    );
    Ok(())
}

/// `svault keyring <action>` — lifecycle of the encrypted keyring.
fn cmd_keyring(action: &str) -> Result<()> {
    match action {
        "init" => cmd_keyring_init(),
        "unlock" => cmd_keyring_unlock(),
        "lock" => cmd_keyring_lock(),
        "rekey" => {
            println!(
                "{} the keyring is opened by your master passphrase — change it with 'svault master rekey'",
                style("note:").cyan()
            );
            Ok(())
        }
        "status" => cmd_keyring_status(),
        other => {
            eprintln!(
                "{} Unknown action '{}'. Use: init | unlock | lock | status (rekey → 'svault master rekey')",
                style("error:").red(),
                other
            );
            std::process::exit(1);
        }
    }
}

fn cmd_keyring_init() -> Result<()> {
    if keyring::exists() {
        eprintln!("{} a keyring already exists", style("error:").red());
        std::process::exit(1);
    }
    println!("  The keyring holds your AI judges, their API keys, and operational");
    println!("  config — AES-256-GCM encrypted at rest, opened by your master passphrase.");
    let master = ensure_master_unlocked(false)?;
    let dek = master::new_dek();
    let kr = keyring::Keyring::init_with_key(dek)?;
    master.wrap_keyring_dek(kr.key())?;
    keyring::unlock_session(kr.key().bytes())?;
    println!(
        "{} keyring created and unlocked under your master passphrase",
        style("ok:").green().bold()
    );
    println!("  add a judge:   svault judge add <name>");
    println!("  turn it on:    svault judge enable");
    Ok(())
}

fn cmd_keyring_unlock() -> Result<()> {
    if !keyring::exists() {
        eprintln!(
            "{} no keyring yet — run 'svault keyring init'",
            style("error:").red()
        );
        std::process::exit(1);
    }
    if !master::keyring_has_keyslot() {
        eprintln!(
            "{} the keyring predates the master and has no keyslot — wipe .svault/ and re-init",
            style("error:").red()
        );
        std::process::exit(1);
    }
    let master = ensure_master_unlocked(false)?;
    let dek = master.unwrap_keyring_dek()?;
    keyring::unlock_session(dek.bytes())?;
    println!("{} keyring unlocked", style("ok:").green().bold());
    Ok(())
}

fn cmd_keyring_lock() -> Result<()> {
    keyring::lock_session()?;
    println!("{} keyring locked", style("ok:").green().bold());
    Ok(())
}

fn cmd_keyring_status() -> Result<()> {
    if !keyring::exists() {
        println!(
            "keyring: {} — run 'svault keyring init'",
            style("not created").red()
        );
        return Ok(());
    }
    if let Some(kr) = keyring::open_from_session() {
        println!("keyring: {}", style("unlocked").green());
        println!(
            "  judge (global): {}",
            if kr.data.judge_enabled { "on" } else { "off" }
        );
        println!(
            "  default judge:  {}",
            kr.data.default_judge.as_deref().unwrap_or("(none)")
        );
        if kr.data.judges.is_empty() {
            println!("  judges:         (none) — add one with 'svault judge add <name>'");
        } else {
            println!(
                "  judges:         {}",
                kr.data
                    .judges
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    } else {
        println!("keyring: {}", style("locked").yellow());
        println!("  unlock to manage judges: svault keyring unlock");
    }
    Ok(())
}

/// Require a judge name for actions that take one.
fn require_judge_name(name: Option<&str>, action: &str) -> Result<String> {
    name.map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("'svault judge {action} <name>' needs a judge name"))
}

/// Prompt for one judge's fields (model/url/timeout/thresholds/criteria),
/// pre-filled from `existing` when editing. The API key is prompted separately.
fn prompt_judge_def(existing: Option<&keyring::JudgeDef>) -> Result<keyring::JudgeDef> {
    let base = existing.cloned().unwrap_or_default();
    let model: String = Input::new()
        .with_prompt("  Model")
        .default(base.model.clone())
        .interact_text()?;
    let base_url: String = Input::new()
        .with_prompt("  Base URL")
        .default(base.base_url.clone())
        .interact_text()?;
    let timeout_secs: u64 = Input::new()
        .with_prompt("  Timeout (s)")
        .default(base.timeout_secs)
        .interact_text()?;
    let allow_threshold: u8 = Input::new()
        .with_prompt("  Allow threshold (0-100)")
        .default(base.allow_threshold)
        .interact_text()?;
    let high_threshold: u8 = Input::new()
        .with_prompt("  High threshold (0-100)")
        .default(base.high_threshold)
        .interact_text()?;
    let criteria: String = Input::new()
        .with_prompt("  Criteria (extra rules added to this judge's prompt — optional)")
        .allow_empty(true)
        .with_initial_text(base.criteria.clone())
        .interact_text()?;
    Ok(keyring::JudgeDef {
        model,
        base_url,
        timeout_secs,
        allow_threshold,
        high_threshold,
        criteria,
        api_key: base.api_key,
    })
}

/// Prompt for an OpenRouter key (hidden). Empty = leave/clear (fall back to env).
fn prompt_optional_key(prompt: &str) -> Result<String> {
    let key = Password::new()
        .with_prompt(prompt)
        .allow_empty_password(true)
        .interact()?;
    Ok(key.trim().to_string())
}

/// `svault judge <action>` — manage the judge registry inside the keyring.
fn cmd_judge(
    action: &str,
    name: Option<&str>,
    judge_name: Option<&str>,
    t: JudgeTestArgs,
) -> Result<()> {
    match action {
        "add" => cmd_judge_add(name),
        "edit" => cmd_judge_edit(name),
        "remove" | "rm" | "delete" => cmd_judge_remove(name),
        "list" | "ls" => cmd_judge_list(),
        "set-default" | "default" => cmd_judge_set_default(name),
        "set-key" | "key" => cmd_judge_set_key(name),
        "enable" | "on" => cmd_judge_toggle(true),
        "disable" | "off" => cmd_judge_toggle(false),
        "status" => cmd_keyring_status(),
        "test" => cmd_judge_test(judge_name, t),
        other => {
            eprintln!(
                "{} Unknown action '{}'. Use: add | edit | remove | list | set-default | set-key | enable | disable | status | test",
                style("error:").red(),
                other
            );
            std::process::exit(1);
        }
    }
}

fn cmd_judge_add(name: Option<&str>) -> Result<()> {
    let name = require_judge_name(name, "add")?;
    let mut kr = unlock_keyring_interactive()?;
    if kr.data.judges.contains_key(&name) {
        eprintln!(
            "{} a judge named '{}' already exists (use 'edit')",
            style("error:").red(),
            name
        );
        std::process::exit(1);
    }
    let mut def = prompt_judge_def(None)?;
    def.api_key =
        prompt_optional_key("  OpenRouter API key (sk-or-…, blank = use $SVAULT_OPENROUTER_KEY)")?;
    let first = kr.data.judges.is_empty();
    kr.data.judges.insert(name.clone(), def);
    if first {
        kr.data.default_judge = Some(name.clone());
    }
    kr.save()?;
    println!("{} judge '{}' added", style("ok:").green().bold(), name);
    if !kr.data.judge_enabled {
        println!("  turn the judge on globally: svault judge enable");
    }
    Ok(())
}

fn cmd_judge_edit(name: Option<&str>) -> Result<()> {
    let name = require_judge_name(name, "edit")?;
    let mut kr = unlock_keyring_interactive()?;
    let existing = kr
        .data
        .judges
        .get(&name)
        .ok_or_else(|| anyhow::anyhow!("no judge named '{name}'"))?
        .clone();
    let def = prompt_judge_def(Some(&existing))?;
    kr.data.judges.insert(name.clone(), def);
    kr.save()?;
    println!("{} judge '{}' updated", style("ok:").green().bold(), name);
    println!("  (key unchanged — set it with 'svault judge set-key {name}')");
    Ok(())
}

fn cmd_judge_remove(name: Option<&str>) -> Result<()> {
    let name = require_judge_name(name, "remove")?;
    let mut kr = unlock_keyring_interactive()?;
    if kr.data.judges.remove(&name).is_none() {
        eprintln!("{} no judge named '{}'", style("error:").red(), name);
        std::process::exit(1);
    }
    if kr.data.default_judge.as_deref() == Some(name.as_str()) {
        kr.data.default_judge = kr.data.judges.keys().next().cloned();
    }
    kr.save()?;
    println!("{} judge '{}' removed", style("ok:").green().bold(), name);
    Ok(())
}

fn cmd_judge_list() -> Result<()> {
    let kr = unlock_keyring_interactive()?;
    if kr.data.judges.is_empty() {
        println!("No judges yet — add one with 'svault judge add <name>'.");
        return Ok(());
    }
    println!(
        "judge (global): {}   default: {}",
        if kr.data.judge_enabled { "on" } else { "off" },
        kr.data.default_judge.as_deref().unwrap_or("(none)")
    );
    println!(
        "{:<18} {:<26} {:>6} {:>5} KEY",
        "NAME", "MODEL", "ALLOW", "HIGH"
    );
    println!("{}", "─".repeat(72));
    for (n, d) in &kr.data.judges {
        let mark = if kr.data.default_judge.as_deref() == Some(n.as_str()) {
            "*"
        } else {
            " "
        };
        let key = if d.api_key.trim().is_empty() {
            "env/none"
        } else {
            "set"
        };
        println!(
            "{mark}{:<17} {:<26} {:>6} {:>5} {}",
            n, d.model, d.allow_threshold, d.high_threshold, key
        );
    }
    Ok(())
}

fn cmd_judge_set_default(name: Option<&str>) -> Result<()> {
    let name = require_judge_name(name, "set-default")?;
    let mut kr = unlock_keyring_interactive()?;
    if !kr.data.judges.contains_key(&name) {
        eprintln!("{} no judge named '{}'", style("error:").red(), name);
        std::process::exit(1);
    }
    kr.data.default_judge = Some(name.clone());
    kr.save()?;
    println!(
        "{} default judge is now '{}'",
        style("ok:").green().bold(),
        name
    );
    Ok(())
}

/// `svault judge enable|disable` — flip the global on/off switch in the
/// encrypted keyring. The judge only acts when this is on AND the keyring is
/// unlocked AND the resolved judge has a key; per-vault `judge.enabled = false`
/// can still opt a vault out.
fn cmd_judge_toggle(enabled: bool) -> Result<()> {
    let mut kr = unlock_keyring_interactive()?;
    kr.data.judge_enabled = enabled;
    kr.save()?;
    let word = if enabled { "enabled" } else { "disabled" };
    println!("{} AI judge {} (global)", style("ok:").green().bold(), word);
    if enabled && kr.data.judges.is_empty() {
        println!("  note: no judges yet — add one with `svault judge add <name>`.");
    }
    Ok(())
}

/// `svault judge set-key <name>` — set (or clear) one judge's OpenRouter key.
/// The key is stored encrypted in the keyring, never in a plaintext file.
fn cmd_judge_set_key(name: Option<&str>) -> Result<()> {
    use std::io::IsTerminal;
    let name = require_judge_name(name, "set-key")?;
    let mut kr = unlock_keyring_interactive()?;
    if !kr.data.judges.contains_key(&name) {
        eprintln!("{} no judge named '{}'", style("error:").red(), name);
        std::process::exit(1);
    }
    // Interactive at a TTY → hidden prompt. Piped (e.g. `echo $KEY | svault
    // judge set-key gemini`) → read from stdin so it stays out of argv/history.
    let key = if std::io::stdin().is_terminal() {
        Password::new()
            .with_prompt("  OpenRouter API key (sk-or-…)")
            .allow_empty_password(true)
            .interact()?
    } else {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)?;
        buf
    };
    let key = key.trim().to_string();
    if let Some(def) = kr.data.judges.get_mut(&name) {
        def.api_key = key.clone();
    }
    kr.save()?;
    if key.is_empty() {
        println!(
            "{} cleared key for '{}' (will fall back to ${})",
            style("ok:").green().bold(),
            name,
            keyring::KEY_ENV
        );
    } else {
        println!(
            "{} stored encrypted key for judge '{}'",
            style("ok:").green().bold(),
            name
        );
        println!("  verify it with: svault judge test --judge {name}");
    }
    Ok(())
}

/// `svault judge test [--judge <name>]` — dry-run a judge against a sample
/// request so you can verify the model + key + criteria without a real secret.
fn cmd_judge_test(judge_name: Option<&str>, t: JudgeTestArgs) -> Result<()> {
    let reason = t
        .reason
        .unwrap_or("run the nightly database migration to apply pending changes");
    let kr = unlock_keyring_interactive()?;
    let target = judge_name.or(kr.data.default_judge.as_deref());
    let Some(name) = target else {
        eprintln!(
            "{} no judge to test — pass --judge <name> or set a default.",
            style("error:").red().bold()
        );
        std::process::exit(1);
    };
    let Some(def) = kr.data.judges.get(name) else {
        eprintln!("{} no judge named '{}'", style("error:").red(), name);
        std::process::exit(1);
    };
    let Some(rt) = judge::JudgeRuntime::from_def(def) else {
        eprintln!(
            "{} judge '{}' has no API key.",
            style("error:").red().bold(),
            name
        );
        eprintln!(
            "  Set one: svault judge set-key {name}  (or export ${})",
            keyring::KEY_ENV
        );
        std::process::exit(1);
    };
    let tier_enum = parse_tier(t.tier);
    println!(
        "{} judge={name} model={} tier={tier_enum} (allow≥{}, high≥{})",
        style("judge:").bold().cyan(),
        rt.model,
        rt.allow_threshold,
        rt.high_threshold
    );
    let model = rt.model.clone();
    let ctx = judge::JudgeContext {
        caller: t.caller,
        scope: t.scope,
        reason,
        secret: t.secret,
        vault_description: t.vault_description.unwrap_or(""),
        secret_description: t.description.unwrap_or(""),
        tier: tier_enum,
        vault: t.vault,
        recent: "no prior requests in the last hour",
    };
    match judge::evaluate(&rt, &model, &ctx) {
        judge::JudgeVerdict::Allow { score, rationale } => {
            println!(
                "{} score {score} — {rationale}",
                style("ALLOW").green().bold()
            );
        }
        judge::JudgeVerdict::Deny { score, rationale } => {
            println!("{} score {score} — {rationale}", style("DENY").red().bold());
        }
        judge::JudgeVerdict::Unavailable { err } => {
            eprintln!("{} {err}", style("unavailable:").yellow().bold());
            std::process::exit(1);
        }
    }
    Ok(())
}
