mod audit;
mod client;
mod config;
mod crypto;
mod daemon;
mod gate;
mod judge;
mod keyring;
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
    /// Encrypted keyring: the single store for judges, API keys, and operational
    /// config (replaces the old plaintext config.yaml + openrouter.key).
    ///
    /// Actions: `init` (create it), `unlock` / `lock` (cache/clear its key for
    /// this session), `rekey` (change its passphrase), `status`.
    Keyring {
        /// init | unlock | lock | rekey | status
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
        VaultSettings {
            autolock,
            autolock_timer,
            login_method,
        },
    );
    meta.storage = storage.to_string();
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
    let vault = Vault::init(&vault_dir, &passphrase, meta, vault_policy)?;

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
    // the decrypted, key-authenticated policy, then fetch from the session/prompt.
    let vault = open_unlocked_or_prompt(&vault_dir, &meta_preview.name)?;
    // Resolve the judge from the unlocked keyring (the vault's assigned judge or
    // the keyring default); None when the keyring is locked / judge off / no key.
    let judge = keyring::open_from_session().and_then(|kr| {
        kr.data
            .resolve_judge(vault.policy.judge.judge.as_deref())
            .and_then(|(_n, def)| judge::JudgeRuntime::from_def(def))
    });
    let req = policy::Request {
        vault: &vault.meta.name,
        vault_description: &vault.meta.description,
        vault_dir: &vault_dir,
        secret: name,
        scope,
        reason,
        caller: &caller,
    };
    let verdict = gate::authorize(&vault.policy, &req, judge.as_ref());
    let decision_str = if verdict.allowed() { "allow" } else { "deny" };
    // Audit keeps the full reason; the caller only ever sees a generic denial.
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
        deny_and_exit(gate::GENERIC_DENY, &caller, name, scope);
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

/// `svault policy check <caller>` and `svault policy init`. Caller rules now live
/// AES-256-GCM encrypted inside each vault (not a committable `svault.policy.yaml`),
/// so both subcommands resolve a vault and unlock it to read/write the policy.
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
            let vault_dir = resolve_vault_dir(None)?;
            let preview = VaultMeta::load_unverified(&vault_dir)?;
            let vault = open_unlocked_or_prompt(&vault_dir, &preview.name)?;
            cmd_policy_check(&vault, caller)
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
fn cmd_policy_init() -> Result<()> {
    let vault_dir = resolve_vault_dir(None)?;
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

/// Open the keyring for a management command: reuse the cached session if it's
/// unlocked, else prompt for the keyring passphrase and cache a session (so the
/// keyring is unlocked for the rest of this session, and the daemon sees it).
fn unlock_keyring_interactive() -> Result<keyring::Keyring> {
    if !keyring::exists() {
        anyhow::bail!("no keyring yet — run 'svault keyring init'");
    }
    if let Some(kr) = keyring::open_from_session() {
        return Ok(kr);
    }
    let pass = prompt_secret("  Keyring passphrase")?;
    let kr = keyring::Keyring::open(&pass)?;
    keyring::unlock_session(kr.key().bytes())?;
    Ok(kr)
}

/// `svault keyring <action>` — lifecycle of the encrypted keyring.
fn cmd_keyring(action: &str) -> Result<()> {
    match action {
        "init" => cmd_keyring_init(),
        "unlock" => cmd_keyring_unlock(),
        "lock" => cmd_keyring_lock(),
        "rekey" => cmd_keyring_rekey(),
        "status" => cmd_keyring_status(),
        other => {
            eprintln!(
                "{} Unknown action '{}'. Use: init | unlock | lock | rekey | status",
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
    println!("  config — AES-256-GCM encrypted under this passphrase, never plaintext.");
    let passphrase = loop {
        let p = prompt_secret("  Keyring passphrase")?;
        match passphrase::meets_floor(&p) {
            Ok(()) => break p,
            Err(e) => eprintln!("{} {}", style("error:").red(), e),
        }
    };
    let confirm = prompt_secret("  Confirm passphrase")?;
    if *passphrase != *confirm {
        eprintln!("{} passphrases do not match", style("error:").red());
        std::process::exit(1);
    }
    let kr = keyring::Keyring::init(&passphrase)?;
    keyring::unlock_session(kr.key().bytes())?;
    println!(
        "{} keyring created and unlocked",
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
    let pass = prompt_secret("  Keyring passphrase")?;
    let kr = keyring::Keyring::open(&pass)?;
    keyring::unlock_session(kr.key().bytes())?;
    println!("{} keyring unlocked", style("ok:").green().bold());
    Ok(())
}

fn cmd_keyring_lock() -> Result<()> {
    keyring::lock_session()?;
    println!("{} keyring locked", style("ok:").green().bold());
    Ok(())
}

fn cmd_keyring_rekey() -> Result<()> {
    if !keyring::exists() {
        eprintln!("{} no keyring to rekey", style("error:").red());
        std::process::exit(1);
    }
    let old = prompt_secret("  Current keyring passphrase")?;
    let mut kr = keyring::Keyring::open(&old)?;
    let new = loop {
        let p = prompt_secret("  New keyring passphrase")?;
        match passphrase::meets_floor(&p) {
            Ok(()) => break p,
            Err(e) => eprintln!("{} {}", style("error:").red(), e),
        }
    };
    let confirm = prompt_secret("  Confirm new passphrase")?;
    if *new != *confirm {
        eprintln!("{} passphrases do not match", style("error:").red());
        std::process::exit(1);
    }
    kr.rekey(&new)?;
    keyring::unlock_session(kr.key().bytes())?;
    println!("{} keyring passphrase changed", style("ok:").green().bold());
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
