mod audit;
mod config;
mod crypto;
mod meta;
mod passphrase;
mod policy;
mod session;
mod tui;
mod vault;

use anyhow::Result;
use clap::{Parser, Subcommand};
use console::style;
use dialoguer::{Confirm, Input, Password, Select};
use std::path::{Path, PathBuf};

use meta::{AccessConfig, AllowAgent, LoginMethod, VaultMeta, VaultSettings};
use vault::{list_vault_dirs, Vault, SVAULT_DIR};

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
    },
    /// List all vaults in .svault/
    Vaults,
    /// Unlock vault — caches passphrase for this session
    Unlock {
        /// Vault name (positional). Omit to use the only vault or pick interactively.
        vault: Option<String>,
    },
    /// Lock vault — clears cached passphrase
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
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let Some(command) = cli.command else {
        // No subcommand → interactive TUI.
        return tui::run();
    };
    match command {
        Commands::Create { name } => cmd_create(name),
        Commands::Settings { vault } => cmd_settings(vault.as_deref()),
        Commands::Secret {
            action,
            name,
            vault,
        } => cmd_secret(&action, name.as_deref(), vault.as_deref()),
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
    }
}

// ── Commands ─────────────────────────────────────────────────────────────────

fn cmd_create(name_arg: Option<String>) -> Result<()> {
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

    println!();
    let passphrase = Password::new().with_prompt("  Passphrase").interact()?;

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

    let confirm = Password::new()
        .with_prompt("  Confirm passphrase")
        .interact()?;
    if passphrase != confirm {
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
    Vault::init(&vault_dir, &passphrase, meta)?;

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
    Ok(())
}

/// Interactive settings editor — re-prompts each field with the current value
/// as the default, then re-signs meta.yaml. Requires the passphrase.
fn cmd_settings(vault_name: Option<&str>) -> Result<()> {
    let vault_dir = resolve_vault_dir(vault_name)?;
    let preview = VaultMeta::load_unverified(&vault_dir)?;

    let passphrase = obtain_passphrase(&vault_dir, &preview.name)?;
    let vault = Vault::open(&vault_dir, &passphrase).map_err(|e| {
        eprintln!("{} {}", style("error:").red(), e);
        std::process::exit(1);
        #[allow(unreachable_code)]
        e
    })?;

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

    if session::is_unlocked(&vault_dir) {
        println!(
            "{} Vault '{}' is already unlocked",
            style("ok:").green(),
            meta.name
        );
        return Ok(());
    }

    let passphrase = Password::new()
        .with_prompt(format!("  Passphrase for '{}'", meta.name))
        .interact()?;

    // Validate passphrase before caching
    Vault::open(&vault_dir, &passphrase).map_err(|e| {
        eprintln!("{} {}", style("error:").red(), e);
        std::process::exit(1);
        #[allow(unreachable_code)]
        e
    })?;

    session::unlock(&vault_dir, &passphrase)?;

    println!(
        "{} Vault '{}' unlocked",
        style("ok:").green().bold(),
        meta.name
    );
    println!(
        "{}",
        style("  Session active — passphrase cached in .svault/<name>/.session (mode 0600)").dim()
    );
    println!("{}", style("  Run 'svault lock' to clear it.").dim());
    Ok(())
}

fn cmd_lock(lock_all: bool, vault_name: Option<&str>) -> Result<()> {
    if lock_all {
        let count = session::lock_all(std::path::Path::new(SVAULT_DIR))?;
        if count == 0 {
            println!("{}", style("All vaults already locked.").dim());
        } else {
            println!("{} Locked {} vault(s)", style("ok:").yellow().bold(), count);
        }
        return Ok(());
    }

    let vault_dir = resolve_vault_dir(vault_name)?;
    let meta = VaultMeta::load_unverified(&vault_dir)?;
    session::lock(&vault_dir)?;
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

    for dir in &dirs {
        if let Ok(meta) = VaultMeta::load_unverified(dir) {
            let status = if session::is_unlocked(dir) {
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

fn cmd_secret(action: &str, name: Option<&str>, vault_name: Option<&str>) -> Result<()> {
    let vault_dir = resolve_vault_dir(vault_name)?;
    let meta_preview = VaultMeta::load_unverified(&vault_dir)?;

    // Use cached passphrase if unlocked, otherwise prompt
    let passphrase = if session::is_unlocked(&vault_dir) {
        session::get_passphrase(&vault_dir).unwrap_or_else(|| {
            Password::new()
                .with_prompt(format!("  Passphrase for '{}'", meta_preview.name))
                .interact()
                .unwrap()
        })
    } else {
        let p = Password::new()
            .with_prompt(format!("  Passphrase for '{}'", meta_preview.name))
            .interact()?;
        println!(
            "{}",
            style("  Tip: run 'svault unlock' to cache passphrase for this session").dim()
        );
        p
    };

    let vault = Vault::open(&vault_dir, &passphrase).map_err(|e| {
        eprintln!("{} {}", style("error:").red(), e);
        std::process::exit(1);
        #[allow(unreachable_code)]
        e
    })?;

    match action {
        "add" => {
            let secret_name: String = match name {
                Some(n) => n.to_string(),
                None => Input::new().with_prompt("  Secret name").interact_text()?,
            };
            let value = Password::new()
                .with_prompt(format!("  Value for '{secret_name}'"))
                .interact()?;
            vault.add_secret(&secret_name, &value)?;
            println!(
                "{} Secret '{}' added",
                style("ok:").green().bold(),
                secret_name
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
                Some(value) => println!("{value}"),
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
    let meta = VaultMeta::load_unverified(&vault_dir)?;

    let caller = caller_arg
        .map(|s| s.to_string())
        .or_else(|| std::env::var("SVAULT_CALLER").ok())
        .unwrap_or_else(|| "default".to_string());

    let loaded = policy::load();
    let req = policy::Request {
        vault: &meta.name,
        vault_dir: &vault_dir,
        secret: name,
        scope,
        reason,
        caller: &caller,
    };
    let decision = policy::evaluate(loaded.as_ref(), &meta, &req);

    // Audit the decision either way — never log the secret value.
    let (decision_str, rule) = match &decision {
        policy::Decision::Allow(_) => ("allow", "ok".to_string()),
        policy::Decision::Deny(_, why) => ("deny", why.clone()),
    };
    audit::record(
        &vault_dir,
        &audit::Entry::now(
            &caller,
            name,
            scope,
            &decision.tier().to_string(),
            decision_str,
            &rule,
            reason,
        ),
    )?;

    match decision {
        policy::Decision::Deny(_, why) => {
            eprintln!("{} {}", style("denied:").red().bold(), why);
            eprintln!(
                "{}",
                style(format!("  caller={caller} secret={name} scope={scope}")).dim()
            );
            std::process::exit(1);
        }
        policy::Decision::Allow(tier) => {
            let passphrase = obtain_passphrase(&vault_dir, &meta.name)?;
            let vault = Vault::open(&vault_dir, &passphrase).map_err(|e| {
                eprintln!("{} {}", style("error:").red(), e);
                std::process::exit(1);
                #[allow(unreachable_code)]
                e
            })?;
            match vault.get_secret(name)? {
                Some(value) => {
                    eprintln!(
                        "{} {} (caller={caller}, scope={scope}, tier={tier})",
                        style("granted:").green().bold(),
                        name
                    );
                    println!("{value}");
                    Ok(())
                }
                None => {
                    eprintln!("{} Secret '{}' not found", style("error:").red(), name);
                    std::process::exit(1);
                }
            }
        }
    }
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
            let Some(policy) = policy::load() else {
                println!(
                    "{}",
                    style("No svault.policy.yaml found — running in fallback mode (meta.yaml allow_agent / rate_limit).").dim()
                );
                println!("{}", style("Run 'svault policy init' to create one.").dim());
                return Ok(());
            };
            cmd_policy_check(&policy, caller)
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

    let accessible = policy.accessible(caller);
    if accessible.is_empty() {
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
        for (vault, secret, scope, tier) in &accessible {
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

    let mut out = String::from(
        "version: 1\n\n# Callers that may request secrets via 'svault get'.\n\
         callers:\n  claude-code:\n    scopes: [misc]\n    rate_limit: 20/hour\n\
         \x20\x20default:\n    scopes: []\n    rate_limit: 5/hour\n\n\
         # Per-vault secret classification. tier: low | medium | high.\nvaults:\n",
    );

    let dirs = list_vault_dirs();
    if dirs.is_empty() {
        out.push_str("  # No vaults yet — add entries after 'svault create'.\n");
    }
    for dir in &dirs {
        let Ok(meta) = VaultMeta::load_unverified(dir) else {
            continue;
        };
        out.push_str(&format!("  {}:\n    secrets:\n", meta.name));
        for n in unlocked_secret_names(dir) {
            out.push_str(&format!("      {n}: {{ scope: misc, tier: low }}\n"));
        }
        out.push_str("      \"*\": { scope: misc, tier: low }\n");
    }

    std::fs::write(path, out)?;
    println!(
        "{} Wrote {}",
        style("ok:").green().bold(),
        policy::POLICY_FILE
    );
    println!(
        "{}",
        style("  Edit scopes and tiers, then commit it — it holds no secrets.").dim()
    );
    Ok(())
}

/// Best-effort secret-name listing for `policy init`: only when the vault is
/// already unlocked (cached session), otherwise empty so we just emit "*".
fn unlocked_secret_names(vault_dir: &Path) -> Vec<String> {
    if !session::is_unlocked(vault_dir) {
        return vec![];
    }
    let Some(pass) = session::get_passphrase(vault_dir) else {
        return vec![];
    };
    Vault::open(vault_dir, &pass)
        .and_then(|v| v.list_secret_names())
        .unwrap_or_default()
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

/// Return the cached passphrase if the vault is unlocked, otherwise prompt.
fn obtain_passphrase(vault_dir: &Path, vault_name: &str) -> Result<String> {
    if session::is_unlocked(vault_dir) {
        if let Some(p) = session::get_passphrase(vault_dir) {
            return Ok(p);
        }
    }
    Ok(Password::new()
        .with_prompt(format!("  Passphrase for '{vault_name}'"))
        .interact()?)
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
