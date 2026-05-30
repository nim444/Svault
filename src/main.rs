mod audit;
mod client;
mod config;
mod crypto;
mod daemon;
mod gate;
mod judge;
mod meta;
mod passphrase;
mod policy;
mod portable;
mod recovery;
mod secfile;
mod session;
mod tui;
mod usage;
mod vault;

use anyhow::Result;
use clap::{Parser, Subcommand};
use console::style;
use dialoguer::{Confirm, Input, Password, Select};
use std::path::{Path, PathBuf};

use crypto::VaultKey;
use meta::{AccessConfig, AllowAgent, LoginMethod, VaultMeta, VaultSettings};
use vault::{list_vault_dirs, Vault, SVAULT_DIR};
use zeroize::Zeroizing;

/// Prompt for a secret (passphrase, recovery code, or secret value) and return
/// it wrapped in `Zeroizing` so the heap copy is wiped on drop (finding #6).
fn prompt_secret(prompt: impl Into<String>) -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(
        Password::new().with_prompt(prompt).interact()?,
    ))
}

#[derive(Parser)]
#[command(name = "svault", about = "AI-aware secret access layer", version)]
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
    /// View or change a vault's settings (description, agents, rate limit, auto-lock, login)
    Settings {
        /// Vault name (positional). Omit to use the only vault or pick interactively.
        vault: Option<String>,
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
    },
    /// List all vaults in .svault/
    Vaults,
    /// Unlock vault — caches the derived key for this session
    Unlock {
        /// Vault name (positional). Omit to use the only vault or pick interactively.
        vault: Option<String>,
    },
    /// Lock vault — clears the cached key
    Lock {
        /// Lock all vaults
        #[arg(long)]
        all: bool,
        /// Vault name (positional). Omit to use the only vault or pick interactively.
        vault: Option<String>,
    },
    /// Show lock status of all vaults
    Status,
    /// Wire Svault into your AI platform (Step 4)
    Install {
        #[arg(long, default_value = "auto")]
        platform: String,
        #[arg(long)]
        project: bool,
    },
    /// Request a secret through the policy engine — the agent path.
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
    },
    /// Recover a vault with its recovery code and set a new passphrase
    Recover {
        /// Vault name (positional). Omit to use the only vault or pick interactively.
        vault: Option<String>,
        /// Skip the passphrase strength floor (for non-interactive / scripted use)
        #[arg(long)]
        force: bool,
    },
    /// Export a vault to a portable encrypted bundle
    Export {
        /// Vault name (positional). Omit to use the only vault or pick interactively.
        vault: Option<String>,
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
    /// AI judge: manage the OpenRouter key and test it.
    ///
    /// Actions: `set-key` (store the key as a 0600 file), `status` (show where
    /// the key resolves from + model config), `remove-key` (delete the file),
    /// `test` (dry-run a sample request against the model).
    Judge {
        /// set-key | status | remove-key | test
        action: String,
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

fn main() -> Result<()> {
    let cli = Cli::parse();
    let Some(command) = cli.command else {
        // No subcommand → interactive TUI.
        return tui::run();
    };
    match command {
        Commands::Create { name, force } => cmd_create(name, force),
        Commands::Settings { vault } => cmd_settings(vault.as_deref()),
        Commands::Secret {
            action,
            name,
            vault,
            scope,
            tier,
            require_reason,
            description,
        } => cmd_secret(
            &action,
            name.as_deref(),
            vault.as_deref(),
            scope.as_deref(),
            tier.as_deref(),
            require_reason,
            description.as_deref(),
        ),
        Commands::Vaults => cmd_vaults(),
        Commands::Unlock { vault } => cmd_unlock(vault.as_deref()),
        Commands::Lock { all, vault } => cmd_lock(all, vault.as_deref()),
        Commands::Status => cmd_status(),
        Commands::Install { platform, .. } => {
            println!(
                "{} Install for '{}' coming in Step 4",
                style("pending:").yellow(),
                platform
            );
            Ok(())
        }
        Commands::Get {
            name,
            scope,
            reason,
            caller,
            vault,
        } => cmd_get(&name, &scope, &reason, caller.as_deref(), vault.as_deref()),
        Commands::Policy { action, caller } => cmd_policy(&action, caller.as_deref()),
        Commands::Recover { vault, force } => cmd_recover(vault.as_deref(), force),
        Commands::Export { vault, out } => cmd_export(vault.as_deref(), out.as_deref()),
        Commands::Import { file, name } => cmd_import(&file, name.as_deref()),
        Commands::Daemon { action, fix } => cmd_daemon(&action, fix),
        Commands::Judge {
            action,
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

    let storage = prompt_storage_backend()?;

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

    let vault_dir = PathBuf::from(SVAULT_DIR).join(&name);
    if vault_dir.exists() {
        let existing = VaultMeta::load_unverified(&vault_dir)
            .map(|m| m.storage)
            .unwrap_or_else(|_| "local".to_string());
        eprintln!(
            "{} a vault named '{}' already exists ({}:{}) — names must be unique across storage backends",
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

    println!();
    // Hard entropy floor (finding #12): re-prompt until it clears, unless --force.
    let passphrase = loop {
        let p = prompt_secret("  Passphrase")?;
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
        if !Confirm::new()
            .with_prompt("  Continue anyway?")
            .default(false)
            .interact()?
        {
            return Ok(());
        }
    }

    let confirm = prompt_secret("  Confirm passphrase")?;
    if *passphrase != *confirm {
        eprintln!("{} Passphrases do not match", style("error:").red());
        std::process::exit(1);
    }

    println!("\n  Creating vault...");

    let mut meta = VaultMeta::new(
        name.clone(),
        description,
        AccessConfig {
            allow_agent,
            rate_limit,
        },
        VaultSettings {
            autolock,
            autolock_timer,
            login_method,
        },
    );
    meta.storage = storage.to_string();
    meta.default_tier = default_tier;
    meta.judge.enabled = Some(judge_enabled);
    let vault = Vault::init(&vault_dir, &passphrase, meta)?;

    // Generate a recovery code and wrap the vault key under it. Shown once.
    let recovery_code = recovery::generate_code();
    recovery::write(&vault_dir, vault.key(), &recovery_code)?;
    usage::human(&vault_dir, "vault.create", None);

    println!();
    println!(
        "  {:<14} {}",
        style("Name").dim(),
        style(format!("{}:{}", storage, &name)).bold().cyan()
    );
    println!("  {:<14} {}", style("Storage").dim(), style(storage).cyan());
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
    println!(
        "{}",
        style(format!("  git add {}/", vault_dir.display())).dim()
    );

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
    Ok(())
}

/// Interactive settings editor — re-prompts each field with the current value
/// as the default, then re-signs meta.yaml. Requires the passphrase.
fn cmd_settings(vault_name: Option<&str>) -> Result<()> {
    let vault_dir = resolve_vault_dir(vault_name)?;
    let preview = VaultMeta::load_unverified(&vault_dir)?;

    let vault = open_unlocked_or_prompt(&vault_dir, &preview.name)?;

    let mut meta = vault.meta.clone();

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
        meta.access.allow_agent
    );
    println!(
        "  {:<16} {}",
        style("Rate limit").dim(),
        meta.access.rate_limit
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
    println!();

    meta.description = Input::new()
        .with_prompt("  Description")
        .allow_empty(true)
        .with_initial_text(&meta.description)
        .interact_text()?;

    meta.access.allow_agent = prompt_allow_agent(Some(&meta.access.allow_agent))?;

    meta.access.rate_limit = Input::new()
        .with_prompt("  Rate limit")
        .with_initial_text(&meta.access.rate_limit)
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

    vault.save_meta(&meta)?;
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
    let vault_dir = resolve_vault_dir(vault_name)?;
    let meta = VaultMeta::load_unverified(&vault_dir)?;
    let leaf = vault_leaf(&vault_dir);

    let daemon_has = client::unlocked_vaults().iter().any(|n| n == &leaf);
    if daemon_has || session::is_unlocked(&vault_dir) {
        println!(
            "{} Vault '{}' is already unlocked",
            style("ok:").green(),
            meta.name
        );
        return Ok(());
    }

    let passphrase = prompt_secret(format!("  Passphrase for '{}'", meta.name))?;

    // Prefer the daemon: it validates the passphrase and holds the derived key
    // in memory — no .session file is written.
    if let Some(res) = client::unlock(&leaf, &passphrase) {
        res.map_err(|e| {
            eprintln!("{} {}", style("error:").red(), e);
            std::process::exit(1);
            #[allow(unreachable_code)]
            e
        })?;
        usage::human(&vault_dir, "unlock", None);
        println!(
            "{} Vault '{}' unlocked",
            style("ok:").green().bold(),
            meta.name
        );
        println!(
            "{}",
            style("  Key held by the daemon (in memory, no file written). Run 'svault lock' to clear it.").dim()
        );
        return Ok(());
    }

    // No daemon — fall back to the file session, caching the derived key
    // (never the passphrase) at mode 0600.
    let vault = Vault::open(&vault_dir, &passphrase).map_err(|e| {
        eprintln!("{} {}", style("error:").red(), e);
        std::process::exit(1);
        #[allow(unreachable_code)]
        e
    })?;

    session::unlock_with_key(&vault_dir, vault.key().bytes())?;
    usage::human(&vault_dir, "unlock", None);

    println!(
        "{} Vault '{}' unlocked",
        style("ok:").green().bold(),
        meta.name
    );
    println!(
        "{}",
        style("  Session active — derived key cached in .svault/<name>/.session (mode 0600, not the passphrase)").dim()
    );
    println!("{}", style("  Run 'svault lock' to clear it.").dim());
    Ok(())
}

fn cmd_lock(lock_all: bool, vault_name: Option<&str>) -> Result<()> {
    if lock_all {
        // Lock both the daemon's in-memory keys and any file sessions.
        let daemon_count = client::lock_all().unwrap_or(0);
        let file_count = session::lock_all(std::path::Path::new(SVAULT_DIR))?;
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

fn cmd_secret(
    action: &str,
    name: Option<&str>,
    vault_name: Option<&str>,
    scope_arg: Option<&str>,
    tier_arg: Option<&str>,
    require_reason: bool,
    description_arg: Option<&str>,
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
                None => prompt_tier(vault.meta.default_tier)?,
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
            let mut meta = vault.meta.clone();
            meta.secrets.insert(
                secret_name.clone(),
                policy::SecretRule {
                    scope,
                    tier,
                    require_reason,
                    description,
                },
            );
            vault.save_meta(&meta)?;
            usage::human(&vault_dir, "secret.add", Some(&secret_name));
            println!(
                "{} Secret '{}' added (scope={}, tier={})",
                style("ok:").green().bold(),
                secret_name,
                meta.secrets[&secret_name].scope,
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
    println!(
        "{:<12} {:<20} {:<28} {:<18} {:<12} {}",
        style("STORAGE").bold(),
        style("NAME").bold(),
        style("DESCRIPTION").bold(),
        style("ALLOW AGENT").bold(),
        style("RATE LIMIT").bold(),
        style("CREATED").bold(),
    );
    println!("{}", style("─".repeat(98)).dim());
    for dir in &dirs {
        if let Ok(meta) = VaultMeta::load_unverified(dir) {
            let created = &meta.created_at[..10];
            println!(
                "{:<12} {:<20} {:<28} {:<18} {:<12} {}",
                meta.storage,
                style(&meta.name).cyan(),
                if meta.description.is_empty() {
                    "-".into()
                } else {
                    meta.description.clone()
                },
                meta.access.allow_agent.to_string(),
                meta.access.rate_limit,
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
    // the verified meta, then fetch from the session/prompt.
    let vault = open_unlocked_or_prompt(&vault_dir, &meta_preview.name)?;
    let meta = &vault.meta; // verified by open — #22
    let policy_box;
    let policy_opt = match policy::load() {
        policy::PolicyLoad::Absent => None,
        policy::PolicyLoad::Loaded(p) => {
            policy_box = p;
            Some(policy_box.as_ref())
        }
        policy::PolicyLoad::Error(msg) => {
            let why = format!("policy file error (failing closed): {msg}");
            audit::record(
                &vault_dir,
                &audit::Entry::now(&caller, name, scope, "low", "deny", &why, reason),
            )?;
            usage::agent(&vault_dir, &caller, "get.deny", Some(name));
            deny_and_exit(&why, &caller, name, scope);
        }
    };

    let judge = judge::JudgeRuntime::from_config(&config::SvaultConfig::load().judge);
    let req = policy::Request {
        vault: &meta.name,
        vault_dir: &vault_dir,
        secret: name,
        scope,
        reason,
        caller: &caller,
    };
    let verdict = gate::authorize(policy_opt, meta, &req, judge.as_ref());
    let decision_str = if verdict.allowed() { "allow" } else { "deny" };
    audit::record(
        &vault_dir,
        &audit::Entry::now(
            &caller,
            name,
            scope,
            &verdict.tier().to_string(),
            decision_str,
            &verdict.note,
            reason,
        ),
    )?;
    usage::agent(
        &vault_dir,
        &caller,
        &format!("get.{decision_str}"),
        Some(name),
    );

    if !verdict.allowed() {
        let why = match verdict.decision {
            policy::Decision::Deny(_, why) => why,
            _ => verdict.note,
        };
        deny_and_exit(&why, &caller, name, scope);
    }
    let tier = verdict.tier();
    match vault.get_secret(name)? {
        Some(value) => {
            eprintln!(
                "{} {} (caller={caller}, scope={scope}, tier={tier})",
                style("granted:").green().bold(),
                name
            );
            println!("{}", *value);
            Ok(())
        }
        None => {
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

/// `svault policy check <caller>` and `svault policy init`.
fn cmd_policy(action: &str, caller: Option<&str>) -> Result<()> {
    match action {
        "check" => {
            let Some(caller) = caller else {
                eprintln!(
                    "{} Usage: svault policy check <caller>",
                    style("error:").red()
                );
                std::process::exit(1);
            };
            match policy::load() {
                policy::PolicyLoad::Loaded(policy) => cmd_policy_check(&policy, caller),
                policy::PolicyLoad::Absent => {
                    println!(
                        "{}",
                        style("No svault.policy.yaml found — running in fallback mode (meta.yaml allow_agent / rate_limit).").dim()
                    );
                    println!("{}", style("Run 'svault policy init' to create one.").dim());
                    Ok(())
                }
                policy::PolicyLoad::Error(msg) => {
                    eprintln!("{} {}", style("error:").red(), msg);
                    std::process::exit(1);
                }
            }
        }
        "init" => cmd_policy_init(),
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

fn cmd_policy_check(policy: &policy::Policy, caller: &str) -> Result<()> {
    let Some(rule) = policy.caller(caller) else {
        eprintln!(
            "{} Caller '{}' is not defined and there is no 'default' caller",
            style("error:").red(),
            caller
        );
        std::process::exit(1);
    };

    println!(
        "{}",
        style(format!("┌─ Policy · {caller} ──────────────────────────┐")).dim()
    );
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

    // Classification now lives in each vault's signed meta.yaml, so enumerate
    // across vaults using their metadata.
    let mut rows: Vec<(String, String, String, policy::Tier)> = Vec::new();
    for dir in list_vault_dirs() {
        if let Ok(meta) = VaultMeta::load_unverified(&dir) {
            for (secret, scope, tier) in policy.accessible(caller, &meta) {
                rows.push((meta.name.clone(), secret, scope, tier));
            }
        }
    }
    if rows.is_empty() {
        println!(
            "{}",
            style("This caller cannot retrieve any classified secret.").dim()
        );
    } else {
        println!(
            "{:<18} {:<22} {:<12} {}",
            style("VAULT").bold(),
            style("SECRET").bold(),
            style("SCOPE").bold(),
            style("TIER").bold()
        );
        println!("{}", style("─".repeat(60)).dim());
        for (vault, secret, scope, tier) in &rows {
            println!(
                "{:<18} {:<22} {:<12} {}",
                style(vault).cyan(),
                secret,
                scope,
                tier
            );
        }
    }

    // Audit summary across all vaults.
    let mut total = 0usize;
    let mut denied = 0usize;
    for dir in list_vault_dirs() {
        for e in audit::all(&dir).unwrap_or_default() {
            if e.caller == caller {
                total += 1;
                if e.decision == "deny" {
                    denied += 1;
                }
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

/// Scaffold a `svault.policy.yaml` from the vaults that exist today.
fn cmd_policy_init() -> Result<()> {
    let path = Path::new(policy::POLICY_FILE);
    if path.exists() {
        eprintln!(
            "{} {} already exists",
            style("error:").red(),
            policy::POLICY_FILE
        );
        std::process::exit(1);
    }

    // Per-secret classification (scope/tier/require_reason) now lives in each
    // vault's signed meta.yaml — set it with `svault secret add` or `svault
    // settings`. The policy file holds only the caller definitions (who may
    // request which scopes), which are non-secret and committable.
    let out = String::from(
        "version: 1\n\n# Callers that may request secrets via 'svault get'.\n\
         # Secret classification (scope/tier) lives in each vault's signed\n\
         # meta.yaml — set it per-secret with 'svault secret add' / 'svault settings'.\n\
         callers:\n  claude-code:\n    scopes: [misc]\n    rate_limit: 20/hour\n\
         \x20\x20default:\n    scopes: []\n    rate_limit: 5/hour\n",
    );

    std::fs::write(path, out)?;
    println!(
        "{} Wrote {}",
        style("ok:").green().bold(),
        policy::POLICY_FILE
    );
    println!(
        "{}",
        style("  Edit the caller scopes, then commit it — it holds no secrets.").dim()
    );
    println!(
        "{}",
        style("  Classify secrets with 'svault secret add' (you'll be asked for scope/tier).")
            .dim()
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

    // Confirm the code opens this vault before asking for a new passphrase.
    recovery::unlock_with_code(&vault_dir, &code).unwrap_or_else(|e| {
        eprintln!("{} {}", style("error:").red(), e);
        std::process::exit(1);
    });

    println!(
        "{} Recovery code accepted — set a new passphrase.",
        style("ok:").green()
    );
    let new_pass = loop {
        let p = prompt_secret("  New passphrase")?;
        match passphrase::meets_floor(&p) {
            Ok(()) => break p,
            Err(e) if force => {
                println!("{} {} (--force)", style("warning:").yellow(), e);
                break p;
            }
            Err(e) => eprintln!("{} {}", style("error:").red(), e),
        }
    };
    if let Some(w) = passphrase::check(&new_pass) {
        println!("{} {}", style("warning:").yellow(), w.0);
    }
    let confirm = prompt_secret("  Confirm passphrase")?;
    if *new_pass != *confirm {
        eprintln!("{} Passphrases do not match", style("error:").red());
        std::process::exit(1);
    }

    recovery::recover_and_rekey(&vault_dir, &code, &new_pass)?;
    usage::human(&vault_dir, "recover", None);
    // Drop any stale cached session (it holds the old, now-invalid key).
    session::lock(&vault_dir).ok();

    println!(
        "{} Passphrase reset for '{}'. Recovery code unchanged.",
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
    let base = Path::new(SVAULT_DIR);

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

    // If the name changed, meta.name still says the bundle's original name and
    // is HMAC-signed — re-sign it with the vault key so the directory and
    // metadata agree. That needs the passphrase.
    if renamed {
        let passphrase = Zeroizing::new(
            Password::new()
                .with_prompt(format!(
                    "  Passphrase for '{}' (to finish importing as '{}')",
                    bundle.name, target
                ))
                .interact()
                .unwrap_or_else(|e| {
                    let _ = std::fs::remove_dir_all(&dir);
                    eprintln!("{} {}", style("error:").red(), e);
                    std::process::exit(1);
                }),
        );
        match Vault::open(&dir, &passphrase) {
            Ok(vault) => {
                let mut meta = vault.meta.clone();
                meta.name = target.clone();
                if let Err(e) = vault.save_meta(&meta) {
                    let _ = std::fs::remove_dir_all(&dir);
                    eprintln!("{} could not finalize rename: {}", style("error:").red(), e);
                    std::process::exit(1);
                }
            }
            Err(_) => {
                // Don't leave a half-imported vault whose name doesn't match.
                let _ = std::fs::remove_dir_all(&dir);
                eprintln!(
                    "{} wrong passphrase — import cancelled. Re-run to try again.",
                    style("error:").red()
                );
                std::process::exit(1);
            }
        }
    }

    usage::human(&dir, "import", None);

    println!(
        "{} Imported '{}' into {}/{}/",
        style("ok:").green().bold(),
        target,
        SVAULT_DIR,
        target
    );
    if !renamed {
        println!(
            "{}",
            style("  Unlock it with its original passphrase (or 'svault recover').").dim()
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
        let dir = PathBuf::from(SVAULT_DIR).join(n);
        if !dir.join("meta.yaml").exists() {
            eprintln!(
                "{} Vault '{}' not found in {}/",
                style("error:").red(),
                n,
                SVAULT_DIR
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
fn open_unlocked_or_prompt(vault_dir: &Path, vault_name: &str) -> Result<Vault> {
    if session::is_unlocked(vault_dir) {
        if let Some(key) = session::get_key(vault_dir) {
            if let Ok(v) = Vault::open_with_key(vault_dir, VaultKey::from_bytes(key)) {
                return Ok(v);
            }
            let _ = session::lock(vault_dir); // stale/invalid cached key — drop it
        }
    }
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
/// Where the encrypted vault lives. Only local storage is implemented today;
/// remote (Soluzy cloud / self-hosted) is a reserved placeholder for a later step.
/// Storage backend ids, indexed to match the picker order. Only "local" is
/// wired today; the rest are reserved placeholders (remote sync is coming soon).
const STORAGE_IDS: [&str; 4] = ["local", "cloud", "self-hosted", "s3"];

fn prompt_storage_backend() -> Result<&'static str> {
    let choices = &[
        "local — encrypted vault on this machine (default)",
        "Soluzy cloud (coming soon)",
        "self-hosted (coming soon)",
        "S3 / MinIO (coming soon)",
    ];

    let idx = Select::new()
        .with_prompt("  Storage")
        .items(choices)
        .default(0)
        .interact()?;

    if idx != 0 {
        println!(
            "{} Remote storage isn't wired yet — the vault is created with the \
             '{}' target but data stays local until remote sync ships.",
            style("note:").cyan(),
            STORAGE_IDS[idx],
        );
    }
    Ok(STORAGE_IDS[idx])
}

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

/// `svault judge <action>` — manage the OpenRouter key (`set-key` / `status` /
/// `remove-key`) and dry-run the configured model with `test`.
fn cmd_judge(action: &str, t: JudgeTestArgs) -> Result<()> {
    match action {
        "test" => cmd_judge_test(t),
        "set-key" | "set" => cmd_judge_set_key(),
        "status" | "key" | "key-status" => cmd_judge_status(),
        "remove-key" | "remove" | "unset" => cmd_judge_remove_key(),
        other => {
            eprintln!(
                "{} Unknown action '{}'. Use: set-key | status | remove-key | test",
                style("error:").red(),
                other
            );
            std::process::exit(1);
        }
    }
}

/// `svault judge set-key` — prompt for the OpenRouter key (hidden) and store it
/// as a `0600` file at `~/.config/svault/openrouter.key`. The key is never
/// echoed and never written to config.
fn cmd_judge_set_key() -> Result<()> {
    use std::io::IsTerminal;
    let cfg = config::SvaultConfig::load();
    // Interactive at a TTY → hidden prompt. Piped (e.g. `echo $KEY | svault
    // judge set-key`) → read the key from stdin so it stays out of the shell
    // history / argv.
    let key = if std::io::stdin().is_terminal() {
        Password::new()
            .with_prompt("  OpenRouter API key (sk-or-...)")
            .interact()?
    } else {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)?;
        buf
    };
    let key = key.trim().to_string();
    if key.is_empty() {
        eprintln!("{} empty key — nothing written", style("error:").red());
        std::process::exit(1);
    }
    let path = config::set_openrouter_key(&cfg.judge, &key)?;
    println!(
        "{} stored OpenRouter key at {} (0600)",
        style("ok:").green().bold(),
        path.display()
    );
    if std::env::var(config::KEY_ENV).is_ok() {
        println!(
            "  note: ${} is also set and takes precedence over the file",
            config::KEY_ENV
        );
    }
    println!("  verify it with: svault judge test");
    Ok(())
}

/// `svault judge status` — show where the key resolves from (without revealing
/// it) plus the active model/threshold config.
fn cmd_judge_status() -> Result<()> {
    let cfg = config::SvaultConfig::load();
    let j = &cfg.judge;
    println!(
        "{} enabled={} model={} (allow≥{}, high≥{}) timeout={}s",
        style("judge:").bold().cyan(),
        j.enabled,
        j.model,
        j.allow_threshold,
        j.high_threshold,
        j.timeout_secs
    );
    match config::key_source(j) {
        config::KeySource::Env => println!(
            "  key: from ${} (environment)",
            style(config::KEY_ENV).green()
        ),
        config::KeySource::File(p) => {
            println!("  key: {} ({})", style("present").green(), p.display())
        }
        config::KeySource::None => {
            let path = config::key_file_path(j)
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "~/.config/svault/openrouter.key".to_string());
            println!(
                "  key: {} — run `svault judge set-key`",
                style("none").red()
            );
            println!("       (would be stored at {path})");
        }
    }
    Ok(())
}

/// `svault judge remove-key` — delete the stored key file.
fn cmd_judge_remove_key() -> Result<()> {
    let cfg = config::SvaultConfig::load();
    match config::remove_openrouter_key(&cfg.judge)? {
        Some(path) => println!(
            "{} removed key file {}",
            style("ok:").green().bold(),
            path.display()
        ),
        None => println!("{} no key file to remove", style("note:").dim()),
    }
    if std::env::var(config::KEY_ENV).is_ok() {
        println!(
            "  note: ${} is still set in your environment",
            config::KEY_ENV
        );
    }
    Ok(())
}

/// `svault judge test` — dry-run the configured model/key against a sample
/// request so you can verify OpenRouter setup without touching a real secret.
fn cmd_judge_test(t: JudgeTestArgs) -> Result<()> {
    let reason = t
        .reason
        .unwrap_or("run the nightly database migration to apply pending changes");
    let cfg = config::SvaultConfig::load();
    // Attempt regardless of the global on/off toggle — the point is to verify the
    // model + key plumbing works.
    let mut jcfg = cfg.judge.clone();
    jcfg.enabled = true;
    let Some(rt) = judge::JudgeRuntime::from_config(&jcfg) else {
        eprintln!(
            "{} No OpenRouter API key found.",
            style("error:").red().bold()
        );
        eprintln!(
            "  Run `svault judge set-key`, or set ${} in the environment.",
            config::KEY_ENV
        );
        std::process::exit(1);
    };
    let tier_enum = parse_tier(t.tier);
    println!(
        "{} model={} tier={tier_enum} (allow≥{}, high≥{})",
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
