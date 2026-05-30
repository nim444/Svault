<div align="center">

# Svault

**The secret manager that knows an AI is asking.**

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

</div>

![Svault Banner](https://raw.githubusercontent.com/Soluzy/Svault/main/docs/banner.jpg)

Svault is an **AI-aware secret access layer** written in Rust. It sits between AI agents and your credentials — enforcing structured requests, detecting suspicious patterns, and making sure an agent has a real reason before it touches anything sensitive.

> **Why Svault?** Every existing secret manager (1Password, Infisical, HashiCorp Vault) treats an AI agent the same as a human or a script. Svault doesn't. It knows the difference.

```mermaid
flowchart LR
    H["Human"] -->|"svault secret get<br/>(passphrase)"| V["Svault"]
    A["AI Agent"] -->|"svault get<br/>scope + reason"| P["Policy engine"]
    P -->|"allow / deny + audit"| V
    V --> E["vault.enc<br/>AES-256-GCM"]
```

---

## Documentation

| Guide | What's inside |
|---|---|
| [Installation](docs/installation.md) | crates.io, from source, supported platforms |
| [Interactive mode (TUI)](docs/tui.md) | The full-screen dashboard and keybindings |
| [Command reference](docs/commands.md) | Every subcommand and flag |
| [End-to-end walkthrough](docs/walkthrough.md) | Full flow: create → classify → judge → gated `get`, with real model output |
| [Policy engine](docs/policy-engine.md) | The agent path — `svault get`, scopes, tiers, audit |
| [Recovery & portability](docs/recovery.md) | Recovery code for a lost passphrase, export/import bundles |
| [Daemon](docs/daemon.md) | Optional Unix daemon — keys in memory, auto-lock, `daemon start/stop/status/doctor` |
| [Storage backends](docs/storage-backends.md) | Local today; cloud / self-hosted / S3 placeholders |
| [Security model](docs/security.md) | Crypto, memory safety, what's safe to commit |
| [Security review & audit](docs/security-review/) | Independent review per release + the bulletproofing process |
| [Architecture](docs/architecture.md) | How it works, on-disk layout, auth methods |
| [Roadmap](docs/roadmap.md) | Where Svault is headed |
| [Changelog](CHANGELOG.md) | What's shipped, version by version |

---

## Quick start

```bash
# Install
cargo install svault-ai

# 1. Create an encrypted vault (interactive: storage, name, agents, auto-lock,
#    default tier, AI judge, passphrase…). Prints a one-time recovery code — save it.
svault create

# 2. Add secrets — also classifies each one (scope + sensitivity tier) for the gate
svault secret add DB_URL --scope database --tier medium
svault secret add API_KEY --scope api --tier low

# 3. Unlock for your session (derived key cached, not prompted again)
svault unlock

# 4. Use secrets without re-entering the passphrase
svault secret get DB_URL
svault secret list

# 5. Lock when done
svault lock
```

Or just run `svault` with no arguments for the [interactive TUI](docs/tui.md).

<div align="center">

⭐ **Star us if you like the project!**

</div>

---

<details>
<summary><b>Interactive mode (TUI)</b></summary>

<br>

Run `svault` with no subcommand to open the full-screen terminal UI:

```bash
svault
```

Browse all vaults (with live lock state), `c` create, `u` unlock / `l` lock, `s` edit settings, and — once a vault is unlocked — `a` add, view, and `d` delete secrets. The TUI reuses the cached session key, so an unlocked vault is never re-prompted. Every subcommand still works for scripting.

**Full keybindings → [docs/tui.md](docs/tui.md)**

</details>

<details>
<summary><b>Policy engine — the agent path</b></summary>

<br>

`svault secret get` is the **human path** — passphrase, no questions asked. `svault get` is the **agent path**: a structured request that an AI must justify. As of 0.9.0 it is **enforced inside the daemon** (the component that holds the key), not advisory — there is no unguarded read path, and every decision is audited with the connecting process's peer UID.

```bash
svault get DB_URL --scope database --reason "run nightly migration" --caller claude-code
```

```mermaid
flowchart TD
    REQ["svault get"] --> ID["Identify caller"]
    ID --> RSN{"Reason valid?"}
    RSN -->|no| DENY["Deny + audit"]
    RSN -->|yes| CAP{"Caller holds scope<br/>& matches secret?"}
    CAP -->|no| DENY
    CAP -->|yes| RATE{"Within rate limit<br/>& no burst?"}
    RATE -->|no| DENY
    RATE -->|yes| TIER{"Tier?"}
    TIER -->|low| ALLOW["Return value + audit"]
    TIER -->|medium / high| JUDGE{"AI judge"}
    JUDGE -->|allow| ALLOW
    JUDGE -->|deny| DENY
```

**AI judge (0.9.0):** for medium/high-tier secrets, Svault asks a cheap, fast LLM via your OpenRouter account whether the stated *reason* plausibly justifies the request — the behavioural gate that makes Svault AI-aware. Per-secret classification (scope/tier + an optional **description** the judge weighs against the request's reason) lives in the **signed `meta.yaml`** (set with `svault secret add --scope --tier --description`); the committable `svault.policy.yaml` holds only caller definitions. The judge is **off until you configure a key** — store it with `svault judge set-key` (or `$SVAULT_OPENROUTER_KEY`), then try `svault judge test`.

**Full pipeline, tiers, judge setup → [docs/policy-engine.md](docs/policy-engine.md)**

</details>

<details>
<summary><b>Recovery & portability</b></summary>

<br>

`svault create` prints a one-time **recovery code** — a 160-bit second key that resets a lost passphrase. It's shown once and never stored in plaintext; keep it in a password manager.

```bash
svault recover                       # enter the code, set a new passphrase
svault export myvault --out vault.json   # portable, checksummed encrypted bundle
svault import vault.json                 # restore on another machine
```

The bundle carries no machine-specific state and every byte is encrypted or signed — safe to move between machines (same major Svault version).

**Recovery code + export/import → [docs/recovery.md](docs/recovery.md)**

</details>

<details>
<summary><b>Storage backends</b></summary>

<br>

| Backend | Status |
|---|---|
| `local` | Available (default) |
| `cloud` | Coming soon — Soluzy SaaS |
| `self-hosted` | Coming soon — your own server |
| `s3` | Coming soon — S3 / MinIO |

The chosen backend is recorded in `meta.yaml` and shown as a `storage:name` prefix everywhere a vault is listed. Vault names must be unique.

**Details → [docs/storage-backends.md](docs/storage-backends.md)**

</details>

<details>
<summary><b>Security model</b></summary>

<br>

| Property | Implementation |
|---|---|
| Encryption | AES-256-GCM |
| Key derivation | Argon2id (64 MB, 3 iterations) — GPU-resistant |
| Metadata integrity | HMAC-SHA256 — tampering with `meta.yaml` is detected |
| Memory safety | `VaultKey` + secrets derive `ZeroizeOnDrop` — wiped on drop |
| Session file | Atomic write, mode `0600` |
| Vault file | Safe to commit — encrypted at rest |

**The passphrase is the only key.**

**Threat model + on-disk layout → [docs/security.md](docs/security.md)**

Every `0.x.0` release goes through an **independent security review + bulletproofing pass** — see [docs/security-review/](docs/security-review/).

</details>

<details>
<summary><b>Architecture</b></summary>

<br>

```mermaid
flowchart TD
    U["AI Agent"] -->|"svault get (scope + reason)"| D["Svault daemon<br/>(enforced gate)"]
    D --> POL["Policy checks<br/>reason → capability → rate limit · burst"]
    POL --> TIER{"Sensitivity tier"}
    TIER -->|low| OUT["audit (peer UID) → value"]
    TIER -->|medium / high| JUDGE["AI judge (OpenRouter)"]
    JUDGE --> OUT
    OUT --> ENC["(.svault/&lt;vault&gt;/vault.enc<br/>AES-256-GCM encrypted)"]
```

**Enforced-engine details, full layout → [docs/architecture.md](docs/architecture.md)**

</details>

---

## Roadmap

| Phase | Status | What |
|---|---|---|
| **Step 1** | Done | Local encrypted vault — AES-256-GCM + Argon2id |
| **Step 1+** | Done | Interactive Ratatui TUI — forms, browsers, lock-aware secrets |
| **Step 2** | Done | Policy engine — caller identity, `reason`, scopes, tiers, rate limit, audit log |
| **Step 3** | Done | Recovery (code + export/import) and the Unix daemon (keys in memory, auto-lock). Extra auth methods (YubiKey, TOTP, Touch ID/Face ID) deferred |
| **0.9.0** | Done | **Enforced** policy engine (in the daemon, peer-UID-audited) + signed per-secret classification + **AI judge** (OpenRouter) |
| **1.0.0** | Planned | Final independent review + install channels, then the first stable release |
| **2.0.0** | Planned | Desktop GUI (Tauri) + system tray |
| **3.0.0** | Planned | MCP integration — Claude Code, Cursor, Copilot, VS Code, Aider |
| **Cloud** | Planned | Anomaly scoring via Claude Haiku — free tier + premium plans |

**Full roadmap → [docs/roadmap.md](docs/roadmap.md)**

---

## Tests

```bash
cargo test
```

99 tests (plus one `#[ignore]`d stress benchmark) covering: roundtrip encryption, wrong-key rejection, bit-flip authentication failure, distinct salts → distinct keys, key-from-bytes roundtrip, vault create/open, open-with-key, re-key, wrong passphrase, add/get/list/remove, persistence across reopen, tampered `vault.enc` rejected, **truncated `vault.enc` errors instead of panicking**, tampered `meta.yaml` rejected, session unlock/lock/lock-all, **the session caching a derived key (never a passphrase)**, passphrase strength checks + **entropy floor**, **owner-only file (0600) / dir (0700) permissions**, audit record/read, rate-limit parsing, the policy engine (capability, tiers, rate limit, burst, unknown caller, fallback mode), recovery code write/unlock + wrong-code rejection, full recover-and-rekey roundtrip (old passphrase rejected, secret preserved, code still valid), export-bundle checksum integrity, build→import recreating an openable vault, **import name-collision suffixing + rename re-signing meta**, storage-backend metadata roundtrip, the daemon (protocol JSON roundtrip, **client-derived-key unlock + bogus-key rejection**, auto-lock idle/hard-max/active decisions, a unix unlock→get→lock→shutdown integration test, a concurrent-reads stress test, **poisoned-mutex recovery**, and **connection-slot accounting**), usage-log source stamping (event tagged with the current surface; old logs parse as unknown), TUI key dispatch (field navigation, the rate-limit space-toggle regression, paste handling, and **help opening with `h` or `?`**), and the **0.9.0 enforced engine** — the AI judge's JSON parsing + tier-dependent fail modes (with a fake transport, no network), **the vault/secret descriptions reaching the judge prompt only when set**, and the daemon's gated read path (policy allow/deny, **high-tier fail-closed when the judge is unavailable**, medium fail-open, peer-UID-stamped audit), and the **OpenRouter key store** (`set-key`/`status`/`remove-key` round-trip writes a `0600` file, trims the key, and resolves the source).

A heavier concurrency / pressure simulation runs on demand (`cargo test --release daemon_stress_simulation -- --ignored --nocapture`); methodology and a recorded run are in [docs/security-review/stress/0.6.0.md](docs/security-review/stress/0.6.0.md).

CI runs the suite on **Ubuntu, Fedora, macOS, and Windows** on every push and pull request.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

Built by [Soluzy](https://soluzy.ro).
