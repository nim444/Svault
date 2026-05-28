mod config;
mod crypto;
mod meta;
mod passphrase;
mod session;
mod vault;

use anyhow::Result;
use clap::{Parser, Subcommand};
use console::style;
use dialoguer::{Confirm, Input, Password, Select};
use std::path::PathBuf;

use meta::{AccessConfig, AllowAgent, VaultMeta};
use vault::{list_vault_dirs, Vault, SVAULT_DIR};

#[derive(Parser)]
#[command(name = "svault", about = "AI-aware secret access layer", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new encrypted vault in .svault/<name>/
    Init {
        #[arg(long)]
        name: Option<String>,
    },
    /// Manage secrets: add | get | list | remove
    Secret {
        action: String,
        name: Option<String>,
        #[arg(long)]
        vault: Option<String>,
    },
    /// List all vaults in .svault/
    Vaults,
    /// Unlock vault — caches passphrase for this session
    Unlock {
        #[arg(long)]
        vault: Option<String>,
    },
    /// Lock vault — clears cached passphrase
    Lock {
        /// Lock all vaults
        #[arg(long)]
        all: bool,
        #[arg(long)]
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
    /// Request a secret through the policy engine (Step 2)
    Get {
        name: String,
        #[arg(long)]
        scope: String,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        vault: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Init { name }                        => cmd_init(name),
        Commands::Secret { action, name, vault }       => cmd_secret(&action, name.as_deref(), vault.as_deref()),
        Commands::Vaults                               => cmd_vaults(),
        Commands::Unlock { vault }                     => cmd_unlock(vault.as_deref()),
        Commands::Lock { all, vault }                  => cmd_lock(all, vault.as_deref()),
        Commands::Status                               => cmd_status(),
        Commands::Install { platform, .. } => {
            println!("{} Install for '{}' coming in Step 4", style("⏳").yellow(), platform);
            Ok(())
        }
        Commands::Get { name, scope, reason, .. } => {
            println!("{} Requesting: {}", style("→").cyan(), style(&name).bold());
            println!("  scope:  {scope}");
            println!("  reason: {reason}");
            println!("{} Policy engine coming in Step 2", style("⏳").yellow());
            Ok(())
        }
    }
}

// ── Commands ─────────────────────────────────────────────────────────────────

fn cmd_init(name_arg: Option<String>) -> Result<()> {
    println!("{}", style("┌─ New Vault ─────────────────────────────┐").dim());

    let default_name = std::env::current_dir()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_else(|| "my-vault".to_string());

    let name: String = match name_arg {
        Some(n) => n,
        None => Input::new().with_prompt("  Vault name").default(default_name).interact_text()?,
    };

    let vault_dir = PathBuf::from(SVAULT_DIR).join(&name);
    if vault_dir.exists() {
        eprintln!("{} Vault '{}' already exists", style("✗").red(), name);
        std::process::exit(1);
    }

    let description: String = Input::new()
        .with_prompt("  Description")
        .allow_empty(true)
        .interact_text()?;

    let agent_choices = &["yes — all agents", "no — block all agents", "list — specific agents only"];
    let agent_idx = Select::new()
        .with_prompt("  Allow agent access")
        .items(agent_choices)
        .default(0)
        .interact()?;

    let allow_agent = match agent_idx {
        0 => AllowAgent::Bool(true),
        1 => AllowAgent::Bool(false),
        _ => {
            let raw: String = Input::new()
                .with_prompt("  Agent names (comma-separated)")
                .interact_text()?;
            AllowAgent::List(
                raw.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
            )
        }
    };

    let rate_limit: String = Input::new()
        .with_prompt("  Rate limit")
        .default("10/hour".to_string())
        .interact_text()?;

    println!();
    let passphrase = Password::new().with_prompt("  Passphrase").interact()?;

    if let Some(w) = passphrase::check(&passphrase) {
        println!("{} {}", style("⚠").yellow(), w.0);
        if !Confirm::new().with_prompt("  Continue anyway?").default(false).interact()? {
            return Ok(());
        }
    }

    let confirm = Password::new().with_prompt("  Confirm passphrase").interact()?;
    if passphrase != confirm {
        eprintln!("{} Passphrases do not match", style("✗").red());
        std::process::exit(1);
    }

    println!("\n  Creating vault...");

    let meta = VaultMeta::new(name.clone(), description, AccessConfig { allow_agent, rate_limit });
    Vault::init(&vault_dir, &passphrase, meta)?;

    println!();
    println!("  {:<14} {}", style("Name").dim(),     style(&name).bold().cyan());
    println!("  {:<14} {}", style("Location").dim(), style(format!("{}/", vault_dir.display())).cyan());
    println!();
    println!("{} Vault '{}' created", style("✓").green().bold(), name);
    println!("{}", style("  vault.enc + meta.yaml are safe to commit — encrypted at rest.").dim());
    println!("{}", style(format!("  git add {}/", vault_dir.display())).dim());
    Ok(())
}

fn cmd_unlock(vault_name: Option<&str>) -> Result<()> {
    let vault_dir = resolve_vault_dir(vault_name)?;
    let meta = VaultMeta::load_unverified(&vault_dir)?;

    if session::is_unlocked(&vault_dir) {
        println!("{} Vault '{}' is already unlocked", style("✓").green(), meta.name);
        return Ok(());
    }

    let passphrase = Password::new()
        .with_prompt(format!("  Passphrase for '{}'", meta.name))
        .interact()?;

    // Validate passphrase before caching
    Vault::open(&vault_dir, &passphrase)
        .map_err(|e| { eprintln!("{} {}", style("✗").red(), e); std::process::exit(1); #[allow(unreachable_code)] e })?;

    session::unlock(&vault_dir, &passphrase)?;

    println!("{} Vault '{}' unlocked", style("✓").green().bold(), meta.name);
    println!("{}", style("  Session active — passphrase cached in .svault/<name>/.session (mode 0600)").dim());
    println!("{}", style("  Run 'svault lock' to clear it.").dim());
    Ok(())
}

fn cmd_lock(lock_all: bool, vault_name: Option<&str>) -> Result<()> {
    if lock_all {
        let count = session::lock_all(std::path::Path::new(SVAULT_DIR))?;
        if count == 0 {
            println!("{}", style("All vaults already locked.").dim());
        } else {
            println!("{} Locked {} vault(s)", style("✓").yellow().bold(), count);
        }
        return Ok(());
    }

    let vault_dir = resolve_vault_dir(vault_name)?;
    let meta = VaultMeta::load_unverified(&vault_dir)?;
    session::lock(&vault_dir)?;
    println!("{} Vault '{}' locked", style("✓").yellow().bold(), meta.name);
    Ok(())
}

fn cmd_status() -> Result<()> {
    let dirs = list_vault_dirs();
    if dirs.is_empty() {
        println!("{}", style("No vaults found. Run 'svault init' to create one.").dim());
        return Ok(());
    }

    println!("{:<20} {:<12} {}", style("VAULT").bold(), style("STATUS").bold(), style("DESCRIPTION").bold());
    println!("{}", style("─".repeat(55)).dim());

    for dir in &dirs {
        if let Ok(meta) = VaultMeta::load_unverified(dir) {
            let (lock_icon, status) = if session::is_unlocked(dir) {
                (style("🔓").to_string(), style("unlocked").green().to_string())
            } else {
                (style("🔒").to_string(), style("locked").dim().to_string())
            };
            println!("{} {:<18} {:<12} {}",
                lock_icon,
                style(&meta.name).cyan(),
                status,
                if meta.description.is_empty() { "—".into() } else { meta.description.clone() },
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
        println!("{}", style("  Tip: run 'svault unlock' to cache passphrase for this session").dim());
        p
    };

    let vault = Vault::open(&vault_dir, &passphrase)
        .map_err(|e| { eprintln!("{} {}", style("✗").red(), e); std::process::exit(1); #[allow(unreachable_code)] e })?;

    match action {
        "add" => {
            let secret_name: String = match name {
                Some(n) => n.to_string(),
                None => Input::new().with_prompt("  Secret name").interact_text()?,
            };
            let value = Password::new().with_prompt(format!("  Value for '{secret_name}'")).interact()?;
            vault.add_secret(&secret_name, &value)?;
            println!("{} Secret '{}' added", style("✓").green().bold(), secret_name);
        }
        "get" => {
            let Some(secret_name) = name else {
                eprintln!("{} Provide a secret name: svault secret get <NAME>", style("✗").red());
                std::process::exit(1);
            };
            match vault.get_secret(secret_name)? {
                Some(value) => println!("{value}"),
                None => { eprintln!("{} Secret '{}' not found", style("✗").red(), secret_name); std::process::exit(1); }
            }
        }
        "list" => {
            let names = vault.list_secret_names()?;
            if names.is_empty() {
                println!("{}", style("No secrets stored yet.").dim());
            } else {
                println!("{}", style(format!("Secrets in '{}':", vault.meta.name)).bold());
                for n in &names { println!("  {}", style(n).cyan()); }
            }
        }
        "remove" => {
            let secret_name: String = match name {
                Some(n) => n.to_string(),
                None => Input::new().with_prompt("  Secret name to remove").interact_text()?,
            };
            if Confirm::new().with_prompt(format!("  Remove '{secret_name}'?")).default(false).interact()? {
                if vault.remove_secret(&secret_name)? {
                    println!("{} Secret '{}' removed", style("✓").yellow(), secret_name);
                } else {
                    eprintln!("{} Secret '{}' not found", style("✗").red(), secret_name);
                }
            }
        }
        _ => {
            eprintln!("{} Unknown action '{}'. Use: add | get | list | remove", style("✗").red(), action);
            std::process::exit(1);
        }
    }
    Ok(())
}

fn cmd_vaults() -> Result<()> {
    let dirs = list_vault_dirs();
    if dirs.is_empty() {
        println!("{}", style("No vaults found. Run 'svault init' to create one.").dim());
        return Ok(());
    }
    println!("{:<20} {:<30} {:<20} {:<12} {}",
        style("NAME").bold(), style("DESCRIPTION").bold(),
        style("ALLOW AGENT").bold(), style("RATE LIMIT").bold(), style("CREATED").bold(),
    );
    println!("{}", style("─".repeat(90)).dim());
    for dir in &dirs {
        if let Ok(meta) = VaultMeta::load_unverified(dir) {
            let created = &meta.created_at[..10];
            println!("{:<20} {:<30} {:<20} {:<12} {}",
                style(&meta.name).cyan(),
                if meta.description.is_empty() { "—".into() } else { meta.description.clone() },
                meta.access.allow_agent.to_string(),
                meta.access.rate_limit,
                created,
            );
        }
    }
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn resolve_vault_dir(vault_name: Option<&str>) -> Result<PathBuf> {
    match vault_name {
        Some(n) => Ok(PathBuf::from(SVAULT_DIR).join(n)),
        None => {
            let dirs = list_vault_dirs();
            if dirs.is_empty() {
                eprintln!("{} No vault found. Run {} first.", style("✗").red(), style("svault init").bold());
                std::process::exit(1);
            }
            Ok(dirs[0].clone())
        }
    }
}
