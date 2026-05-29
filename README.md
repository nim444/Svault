# Svault

[![lint](https://github.com/Soluzy/Svault/actions/workflows/lint.yml/badge.svg)](https://github.com/Soluzy/Svault/actions/workflows/lint.yml)
[![ubuntu](https://github.com/Soluzy/Svault/actions/workflows/ubuntu.yml/badge.svg)](https://github.com/Soluzy/Svault/actions/workflows/ubuntu.yml)
[![fedora](https://github.com/Soluzy/Svault/actions/workflows/fedora.yml/badge.svg)](https://github.com/Soluzy/Svault/actions/workflows/fedora.yml)
[![macos](https://github.com/Soluzy/Svault/actions/workflows/macos.yml/badge.svg)](https://github.com/Soluzy/Svault/actions/workflows/macos.yml)
[![windows](https://github.com/Soluzy/Svault/actions/workflows/windows.yml/badge.svg)](https://github.com/Soluzy/Svault/actions/workflows/windows.yml)

[![crates.io](https://img.shields.io/crates/v/svault-ai.svg)](https://crates.io/crates/svault-ai)
[![downloads](https://img.shields.io/crates/d/svault-ai.svg)](https://crates.io/crates/svault-ai)
[![docs.rs](https://img.shields.io/docsrs/svault-ai)](https://docs.rs/svault-ai)
[![license](https://img.shields.io/crates/l/svault-ai.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org)

> The secret manager that knows an AI is asking.

Svault is an AI-aware secret access layer written in Rust. It sits between AI agents and your credentials — enforcing structured requests, detecting suspicious patterns, and making sure an agent has a real reason before it touches anything sensitive.

**Why Svault?** Every existing secret manager (1Password, Infisical, HashiCorp Vault) treats an AI agent the same as a human or a script. Svault doesn't. It knows the difference.

![Svault Banner](https://raw.githubusercontent.com/Soluzy/Svault/main/_docs/banner.jpg)

---

## Install

### From crates.io (recommended)

```bash
cargo install svault-ai
svault --version
```

### From source

```bash
git clone https://github.com/Soluzy/Svault.git
cd Svault
cargo build --release
./target/release/svault --version
```

### Binary install (coming soon)

```bash
curl -fsSL https://svault.soluzy.net/install.sh | bash
```

---

## Interactive mode (TUI)

Run `svault` with no subcommand to open the full-screen terminal UI:

```bash
svault
```

From the keyboard you can browse all vaults (with live lock state), `c` create,
`u` unlock / `l` lock, `s` edit settings, and — once a vault is unlocked —
`a` add, view, and `d` delete secrets. The TUI reuses the cached session
passphrase, so an unlocked vault is never re-prompted. Every subcommand below
still works for scripting and automation.

---

## Quick Start

```bash
# 1. Create an encrypted vault (prompts for storage, name, description, agents,
#    rate limit, auto-lock, auto-lock timer, login method, passphrase)
#    Storage: local (default). Soluzy cloud / self-hosted / S3 — coming soon.
svault create

# 2. Add secrets (use --vault NAME when you have more than one vault)
svault secret add DB_URL
svault secret add API_KEY

# 3. Unlock for your session (passphrase cached, not prompted again)
svault unlock

# 4. Use secrets without re-entering passphrase
svault secret get DB_URL
svault secret list

# 5. View or change a vault's settings
svault settings

# 6. Check lock status
svault status

# 7. Lock when done
svault lock
```

---

## How it works

```
AI Agent / User
   │
   │  svault_get_secret(name, scope, reason)   ← reason required (Step 2+)
   ▼
┌──────────────────────────────────┐
│          Svault daemon            │
│                                  │
│  Multi-factor auth               │
│  (Passphrase, YubiKey,          │
│   TOTP, Touch ID/Face ID)        │
│                                  │
│  Policy checks:                  │
│  reason → capability → rate limit│
│  burst detection, audit log      │
│  Claude anomaly score (cloud)    │  ← optional
│  sensitivity tier enforcement    │
└──────────────┬───────────────────┘
               │
               ▼
     .svault/<vault>/vault.enc     ← AES-256-GCM encrypted, safe to commit
```

**Authentication options (Step 3+, choose any combination):**
- **Passphrase** — Always available, works everywhere
- **YubiKey** — Hardware HMAC-SHA1 challenge-response
- **Google Authenticator** — Time-based OTP (TOTP) 
- **Touch ID / Face ID** — macOS biometric unlock

The `reason` field is required by the policy engine (below). An AI that cannot explain why it needs a secret is refused immediately.

---

## Policy engine (Step 2)

`svault secret get` is the **human path** — passphrase, no questions asked. `svault get` is the **agent path**: a structured request that an AI must justify, run through a pipeline before any secret is handed over.

```
svault get DB_URL --scope database --reason "run nightly migration" --caller claude-code
        │
        ├─ identify caller   (--caller, else $SVAULT_CALLER, else "default")
        ├─ reason required    (rejects empty / too-short / placeholder reasons)
        ├─ capability check   (caller holds the scope AND it matches the secret)
        ├─ sensitivity tier   (low=allow, medium=allow+log, high=deny)
        ├─ rate limit + burst (per-caller, from the audit log)
        └─ audit log          (every allow/deny appended, never the value)
```

On **allow**, the secret value is printed to stdout (status goes to stderr, so agents capture only the value). On **deny**, it exits non-zero and logs why. `high`-tier secrets are never handed to an agent — a human retrieves those with `secret get`.

Policy lives in a committable **`svault.policy.yaml`** at the project root (it holds no secrets):

```yaml
version: 1
callers:
  claude-code:
    scopes: [database, api]
    rate_limit: 20/hour
  default:                 # applies to any unlisted caller
    scopes: []
    rate_limit: 5/hour
vaults:
  my-project:
    secrets:
      DB_URL:      { scope: database, tier: low }
      DB_PASSWORD: { scope: database, tier: high }
      API_KEY:     { scope: api,      tier: medium }
      "*":         { scope: misc,     tier: medium }   # default for unlisted secrets
```

Run `svault policy init` to scaffold one, and `svault policy check <caller>` to see what a caller can access plus its recent activity. Each request is recorded to `.svault/<vault>/audit.log` (gitignored).

**No policy file?** `svault get` falls back to the vault's `meta.yaml` `allow_agent` / `rate_limit` settings (a reason is still required), so the policy file is optional but recommended.

---

## Vault structure

```
.svault/
  my-project/
    vault.enc     ← AES-256-GCM encrypted secrets  (safe to commit)
    meta.yaml     ← name, storage backend, description, access rules (safe to commit, HMAC-signed)
    .gitignore    ← auto-written at create, blocks .session + audit.log from being committed
    .session      ← passphrase cache while unlocked (gitignored, mode 0600)
    audit.log     ← policy decisions for 'svault get' (gitignored, mode 0600)
```

**vault.enc** and **meta.yaml** are safe to commit. They are useless without the passphrase.  
**.session** is always gitignored and created with mode `0600` (owner read/write only).

---

## Storage backends

At create time you pick where a vault lives. **`local`** is the default and the only backend wired today; **`cloud`** (Soluzy SaaS), **`self-hosted`**, and **`s3`** are reserved placeholders — remote sync ships in a later step.

The chosen backend is recorded in `meta.yaml` (`storage:`) and shown as a `storage:name` prefix everywhere a vault is listed (`svault vaults`, `svault status`, the TUI):

```
local:my-project        unlocked   primary app secrets
cloud:shared-secrets    locked     team-wide credentials
```

The prefix keeps vault identity unambiguous per backend, and **vault names must be unique** — creating a second vault with an existing name is rejected, so the same name can't be duplicated across storage.

---

## Commands

```bash
svault                             # launch the interactive TUI (no subcommand)
svault create                      # create encrypted vault (storage backend, name, description, agents, rate limit, auto-lock, login)
svault settings [VAULT]            # view or change a vault's settings
svault unlock   [VAULT]            # unlock vault, cache passphrase for session
svault lock     [VAULT]            # clear cached passphrase
svault lock     --all              # lock all vaults
svault status                      # show lock state of all vaults

svault secret add    <NAME> [-v VAULT]   # add or update a secret
svault secret get    <NAME> [-v VAULT]   # retrieve a secret value
svault secret list          [-v VAULT]   # list secret names (never values)
svault secret remove <NAME> [-v VAULT]   # delete a secret

svault vaults                      # list all vaults with metadata (storage:name prefix)

# Policy engine — the agent path (Step 2)
svault get <NAME> --scope <S> --reason "<R>" [--caller C] [-v VAULT]   # policy-gated request
svault policy check <caller>       # what a caller can access + recent activity
svault policy init                 # scaffold svault.policy.yaml from existing vaults

svault install [--platform claude|cursor|...]             # wire into AI platform (Step 4)

# VAULT is positional for create/settings/unlock/lock; secret & get use -v/--vault.
# Omit it to use the only vault, or get prompted to pick when several exist.
```

---

## Security

| Property | Implementation |
|---|---|
| Encryption | AES-256-GCM |
| Key derivation | Argon2id (64MB memory, 3 iterations) — GPU-resistant |
| Metadata integrity | HMAC-SHA256 — tampering with `meta.yaml` is detected |
| Memory safety | `VaultKey` and secrets derive `ZeroizeOnDrop` — wiped on drop |
| Session file | Created atomically with mode `0600`, never at permissive permissions |
| Vault file | Safe to commit to git — encrypted at rest |

**The passphrase is the only key.** Strong passphrase + Argon2id = brute force is not practical with current hardware.

---

## Roadmap

| Phase | Status | What |
|---|---|---|
| **Step 1** | DONE | Local encrypted vault with AES-256-GCM + Argon2id |
| **Step 1+** | DONE | Interactive Ratatui TUI (run `svault` with no args) — forms, browsers, lock-aware secret management |
| **Step 2** | DONE | Policy engine — `svault get` with caller identity, `reason`, scope capability checks, sensitivity tiers, rate limiting + burst detection, audit log |
| **Step 3** | TODO | Daemon + multi-select auth (Passphrase, YubiKey, TOTP, Touch ID/Face ID) |
| **Step 4** | TODO | Desktop GUI (Tauri) for vault management + system tray |
| **Step 5** | TODO | MCP integration — Claude Code, Cursor, Copilot, VS Code, Aider |
| **Cloud** | TODO | Anomaly scoring via Claude Haiku — free tier + premium plans |

---

## Tests

```bash
cargo test
```

34 tests covering: roundtrip encryption, wrong key rejection, bit-flip authentication failure, different salts produce different keys, vault create/open, wrong passphrase, add/get/list/remove, persistence across reopen, tampered vault.enc rejected, tampered meta.yaml rejected, session unlock/lock/lock-all, passphrase strength checks, audit log record/read, rate-limit parsing, the policy engine (capability, tiers, rate limit, burst, unknown caller, fallback mode), and storage-backend metadata roundtrip.

CI runs the suite on Ubuntu, Fedora, macOS, and Windows on every push and pull request.

---

## License

Apache 2.0 — see [LICENSE](LICENSE)

Built by [Soluzy](https://soluzy.ro)
