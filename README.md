# Svault

> The secret manager that knows an AI is asking.

Svault is an AI-aware secret access layer written in Rust. It sits between AI agents and your credentials — enforcing structured requests, detecting suspicious patterns, and making sure an agent has a real reason before it touches anything sensitive.

**Why Svault?** Every existing secret manager (1Password, Infisical, HashiCorp Vault) treats an AI agent the same as a human or a script. Svault doesn't. It knows the difference.

---

## Install

```bash
curl -fsSL https://svault.soluzy.net/install.sh | bash
```

> Binary install coming at v0.1 release. Until then, build from source (see below).

---

## Build from source

```bash
git clone https://github.com/Soluzy/Svault.git
cd Svault
cargo build --release
./target/release/svault --version
```

---

## Quick Start

```bash
# 1. Create an encrypted vault
svault init

# 2. Add secrets
svault secret add DB_URL
svault secret add API_KEY

# 3. Unlock for your session (passphrase cached, not prompted again)
svault unlock

# 4. Use secrets without re-entering passphrase
svault secret get DB_URL
svault secret list

# 5. Check lock status
svault status

# 6. Lock when done
svault lock
```

---

## How it works

```
AI Agent
   │
   │  svault_get_secret(name, scope, reason)   ← reason is required
   ▼
┌──────────────────────────────────┐
│          Svault daemon            │
│                                  │
│  reason check → capability check │
│  rate limit → burst detection    │
│  Claude anomaly score (cloud)    │  ← optional
│  sensitivity tier → audit log    │
└──────────────┬───────────────────┘
               │
               ▼
     .svault/<vault>/vault.enc     ← AES-256-GCM encrypted, safe to commit
```

The `reason` field is not optional. An AI that cannot explain why it needs a secret is refused immediately.

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
svault init                        # create encrypted vault (prompts for name, passphrase, access rules)
svault unlock [--vault NAME]       # unlock vault, cache passphrase for session
svault lock   [--vault NAME]       # clear cached passphrase
svault lock   --all                # lock all vaults
svault status                      # show lock state of all vaults

svault secret add    <NAME>        # add or update a secret
svault secret get    <NAME>        # retrieve a secret value
svault secret list                 # list secret names (never values)
svault secret remove <NAME>        # delete a secret

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

| Step | Status | What |
|---|---|---|
| **Step 1** | ✅ Done | Local encrypted vault — init, add, get, list, remove, lock/unlock |
| **Step 2** | 🔲 Next | Policy engine — `reason` field, capability check, rate limit, sensitivity tiers |
| **Step 3** | 🔲 | Daemon — unlock once, serve requests over local socket, auto-lock timer |
| **Step 4** | 🔲 | Platform install — `svault install` for Claude Code, Cursor, Codex, Copilot |
| **Cloud** | 🔲 | Claude-powered anomaly scoring — $1–2/month optional service |

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
