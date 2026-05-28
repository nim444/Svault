# Svault

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

## Quick Start

```bash
# 1. Create an encrypted vault (prompts for name, description, agents,
#    rate limit, auto-lock, auto-lock timer, login method, passphrase)
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

The `reason` field becomes required in Step 2. An AI that cannot explain why it needs a secret is refused immediately.

---

## Vault structure

```
.svault/
  my-project/
    vault.enc     ← AES-256-GCM encrypted secrets  (safe to commit)
    meta.yaml     ← name, description, access rules (safe to commit, HMAC-signed)
    .gitignore    ← auto-written at init, blocks .session from being committed
    .session      ← passphrase cache while unlocked (gitignored, mode 0600)
```

**vault.enc** and **meta.yaml** are safe to commit. They are useless without the passphrase.  
**.session** is always gitignored and created with mode `0600` (owner read/write only).

---

## Commands

```bash
svault create                      # create encrypted vault (name, description, agents, rate limit, auto-lock, login)
svault settings [--vault NAME]     # view or change a vault's settings
svault unlock [--vault NAME]       # unlock vault, cache passphrase for session
svault lock   [--vault NAME]       # clear cached passphrase
svault lock   --all                # lock all vaults
svault status                      # show lock state of all vaults

svault secret add    <NAME> [--vault NAME]   # add or update a secret
svault secret get    <NAME> [--vault NAME]   # retrieve a secret value
svault secret list          [--vault NAME]   # list secret names (never values)
svault secret remove <NAME> [--vault NAME]   # delete a secret

svault vaults                      # list all vaults with metadata

svault get <NAME> --scope <S> --reason "<R>"   # structured request (Step 2)
svault install [--platform claude|cursor|...]  # wire into AI platform (Step 4)
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
| **Step 1+** | NEXT | Interactive CLI with Ratatui TUI (forms, browsers, dashboards) |
| **Step 2** | TODO | Policy engine — `reason` field, capability checks, rate limiting |
| **Step 3** | TODO | Daemon + multi-select auth (Passphrase, YubiKey, TOTP, Touch ID/Face ID) |
| **Step 4** | TODO | Desktop GUI (Tauri) for vault management + system tray |
| **Step 5** | TODO | MCP integration — Claude Code, Cursor, Copilot, VS Code, Aider |
| **Cloud** | TODO | Anomaly scoring via Claude Haiku — free tier + premium plans |

---

## Tests

```bash
cargo test
```

12 tests covering: roundtrip encryption, wrong key rejection, bit-flip authentication failure, different salts produce different keys, vault create/open, wrong passphrase, add/get/list/remove, persistence across reopen, tampered vault.enc rejected, tampered meta.yaml rejected.

---

## License

Apache 2.0 — see [LICENSE](LICENSE)

Built by [Soluzy](https://soluzy.ro)
