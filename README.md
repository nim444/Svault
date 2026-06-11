<div align="center">

# Svault

**The principled way to give cooperative AI agents secret access.**

[![lint](https://github.com/nim444/Svault/actions/workflows/lint.yml/badge.svg)](https://github.com/nim444/Svault/actions/workflows/lint.yml)
[![ubuntu](https://github.com/nim444/Svault/actions/workflows/ubuntu.yml/badge.svg)](https://github.com/nim444/Svault/actions/workflows/ubuntu.yml)
[![fedora](https://github.com/nim444/Svault/actions/workflows/fedora.yml/badge.svg)](https://github.com/nim444/Svault/actions/workflows/fedora.yml)
[![macos](https://github.com/nim444/Svault/actions/workflows/macos.yml/badge.svg)](https://github.com/nim444/Svault/actions/workflows/macos.yml)
[![windows](https://github.com/nim444/Svault/actions/workflows/windows.yml/badge.svg)](https://github.com/nim444/Svault/actions/workflows/windows.yml)

[![crates.io](https://img.shields.io/crates/v/svault-cli.svg)](https://crates.io/crates/svault-cli)
[![downloads](https://img.shields.io/crates/d/svault-cli.svg)](https://crates.io/crates/svault-cli)
[![docs.rs](https://img.shields.io/docsrs/svault-cli)](https://docs.rs/svault-cli)
[![license](https://img.shields.io/github/license/nim444/Svault)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org)

</div>

> [!WARNING]
> **This project is deprecated.** Svault is no longer actively developed. Its successor is **[Kelid](https://github.com/nim444/kelid)** — a native Swift macOS rebuild of the same idea (structured agent requests, policy engine, AI judge, audit trail). Svault 1.x remains usable as-is and `svault-cli` stays on crates.io, but no new features or fixes are planned here.

![Svault Banner](https://raw.githubusercontent.com/nim444/Svault/main/docs/banner.jpg)

Svault is a **secret access layer for AI agents**, written in Rust. It sits between an agent and your credentials and makes every request structured, policy-gated, and audited: the agent must say *which* secret, in *what* scope, and *why* — and a sensitive request is scored by an AI judge before any value is returned.

> **The boundary, stated up front.** Svault is built for **cooperative and semi-trusted agents**. It encrypts secrets at rest and gives you an enforced, tamper-resistant gate over agent access plus an audit trail. It is **not** a sandbox against a hostile process running as your own user — that process can read an unlocked session directly. Svault raises the bar for agents that mostly play by the rules and gives you the audit trail when one doesn't; it does not pretend to contain a determined local attacker. If that distinction matters to you, you're exactly who it's for. See the [threat model](docs/security.md#threat-model).

> **Why not just 1Password / Infisical / HashiCorp Vault?** Those treat an AI agent like any other client. Svault makes the agent path first-class — structured requests, per-secret policy and tiers, an AI judge for sensitive reads, and an audit record stamped with the caller's real (un-forgeable) UID.

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
| [Desktop GUI (Tauri)](docs/gui.md) | The 2.0.0 desktop app — all 12 screens, daemon auto-start, one install for GUI + CLI + TUI + MCP (in development) |
| [Command reference](docs/commands.md) | Every subcommand and flag |
| [End-to-end walkthrough](docs/walkthrough.md) | Full flow: create → classify → judge → gated `get`, with real model output |
| [Policy engine](docs/policy-engine.md) | The agent path (via the MCP server), scopes, tiers, audit |
| [MCP server](docs/mcp.md) | `svault mcp` — gated secret access for AI agents (Claude Code, Cursor) |
| [Recovery & portability](docs/recovery.md) | Recovery code for a lost passphrase, export/import bundles |
| [Daemon](docs/daemon.md) | Optional Unix daemon — keys in memory, auto-lock, `daemon start/stop/status/doctor` |
| [Architecture](docs/architecture.md) | How it works, on-disk layout, storage and vault naming, auth methods |
| [Security model](docs/security.md) | Crypto, memory safety, what's safe to commit |
| [Security review & audit](docs/security-review/) | Independent review per release + the bulletproofing process |
| [QA checklist](docs/qa-checklist.md) | Scenario-driven manual test pass (CLI / TUI / MCP) before a release |
| [Roadmap](docs/roadmap.md) | Where Svault is headed |
| [Changelog](CHANGELOG.md) | What's shipped, version by version |

---

## Quick start

```bash
# Install (`svault-cli` from 2.0.0; up to 1.0.0 the crate was `svault-ai`)
cargo install svault-cli

# 1. Create an encrypted vault (interactive: name, agents, auto-lock,
#    default tier, AI judge). On first run you set one master passphrase — it
#    unlocks every vault. Prints a one-time recovery code — save it.
svault create

# 2. Add secrets — also classifies each one (scope + sensitivity tier) for the gate
svault secret add DB_URL --scope database --tier medium
svault secret add API_KEY --scope api --tier low

# 3. Unlock for your session — one master passphrase opens every vault
svault unlock

# 4. Use secrets without re-entering the passphrase
svault secret get DB_URL
svault secret list

# 5. Lock when done
svault lock
```

Or just run `svault` with no arguments for the [interactive TUI](docs/tui.md).

---

<details>
<summary><b>Interactive mode (TUI)</b></summary>

<br>

Run `svault` with no subcommand to open the full-screen terminal UI:

```bash
svault
```

Browse all vaults (with live lock state), `c` create, `u` unlock / `l` lock, `s` edit settings, `shift-J` manage the AI judges (create or unlock the keyring, toggle the global on/off switch, add/edit/view judges with their model/thresholds/criteria, set the default judge, set/clear a judge's API key, live test, remove a judge), and — once a vault is unlocked — `a` add, `c` classify (tier/scope/reason/description), view, and `d` delete secrets, with each secret's classification shown inline. The TUI reuses the cached session key, so an unlocked vault is never re-prompted. Every subcommand still works for scripting.

**Full keybindings → [docs/tui.md](docs/tui.md)**

</details>

<details>
<summary><b>Policy engine — the agent path</b></summary>

<br>

`svault secret get` is the **human path** — passphrase, no questions asked. The **agent path** is a structured request that an AI must justify, **enforced inside the daemon** that holds the key — not advisory. Agents reach it through the **MCP server** (`svault mcp`, see [mcp.md](docs/mcp.md)); the `svault get` CLI below is the same gate but is **deprecated** (kept for illustration). There is no unguarded read path, and every decision is audited with the connecting process's peer UID.

```bash
# deprecated CLI form of the agent gate (new integrations use the MCP server)
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

**The AI judge.** For medium/high-tier secrets, Svault asks a fast LLM — via your OpenRouter account — whether the stated *reason* plausibly justifies the request. This is the behavioural gate that makes Svault AI-aware. You can define **multiple named judges**, each with its own model, thresholds, and free-text **criteria**, pick a default, and assign one per vault. A judge carries its own API key or draws one from a named **AI provider** (an API account stored encrypted in the keyring — how the desktop GUI wires judges up; OpenRouter today).

Everything that gates access is **AES-256-GCM encrypted at rest** — per-secret classification (scope/tier + an optional description the judge weighs against the reason) and caller rules live inside `vault.enc`; the judge registry and its API keys live in a separate encrypted **keyring** (`.svault/keyring.enc`). There are no plaintext config or key files. Because the policy is unreadable at rest, an agent can't study it to craft a passing request — and a denied `svault get` returns only a **generic** message, with the real reason recorded in the audit log for you.

```bash
svault keyring init          # create the encrypted keyring (one-time)
svault judge add reviewer    # name a judge: model, thresholds, criteria, key
svault judge enable          # turn the judge on globally
```

**Full pipeline, tiers, judge setup → [docs/policy-engine.md](docs/policy-engine.md)**

</details>

<details>
<summary><b>Recovery & portability</b></summary>

<br>

`svault create` prints a one-time **recovery code** — a 160-bit second keyslot into the vault, used if you lose the master passphrase. It's shown once and never stored in plaintext; keep it in a password manager.

```bash
svault recover                       # enter the code, re-attach the vault to your master
svault export myvault --out vault.json   # portable, checksummed encrypted bundle
svault import vault.json                 # restore on another machine
```

The bundle carries no machine-specific state and every byte is encrypted or signed — safe to move between machines (same major Svault version).

**Recovery code + export/import → [docs/recovery.md](docs/recovery.md)**

</details>

<details>
<summary><b>Storage</b></summary>

<br>

Every vault is stored **locally** — an encrypted vault on this machine. The backend is recorded in `meta.yaml` as `storage: local` and shown as a `local:` prefix everywhere a vault is listed. Vault names must be unique.

**Details → [docs/architecture.md](docs/architecture.md#storage-and-vault-naming)**

</details>

<details>
<summary><b>Security model</b></summary>

<br>

| Property | Implementation |
|---|---|
| Encryption | AES-256-GCM (authenticated) |
| Key derivation | Argon2id (64 MB, 3 iterations) — GPU-resistant |
| Unlock | One **master passphrase** wraps a random per-vault data key (keyslot model) — unlock once, every vault opens. Alternative keyslots: YubiKey (FIDO2), Touch ID on macOS, recovery code |
| Policy & judge config | Encrypted at rest — the policy in `vault.enc`, the judge registry + API keys in `keyring.enc`. No plaintext config or key files |
| Metadata integrity | HMAC-SHA256 — tampering with the public `meta.yaml` is detected |
| Memory safety | `VaultKey` + secrets derive `ZeroizeOnDrop` — wiped on drop |
| Session / on-disk files | Owner-only (`0600`), written atomically |
| Vault file | Safe to commit — encrypted at rest, useless without the master passphrase |

**One master passphrase is the only key you type** — it wraps each vault's random
data key, so unlocking once opens everything. The recovery code is a second
keyslot into a vault if you lose the master.

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

## Screenshots

<p align="center">
  <img src="docs/screenshots/tui-activity.png" width="760" alt="Svault TUI activity timeline"><br>
  <sub>The Svault TUI — daemon status, vaults, and a live activity timeline.</sub>
</p>

<p align="center">
  <img src="docs/screenshots/tui-dashboard-first.png" width="760" alt="Svault TUI dashboard"><br>
  <sub>The vault dashboard with live lock state.</sub>
</p>

<details open>
<summary><b>Onboarding &amp; setup</b></summary>

<table>
<tr>
<td align="center" width="33%"><img src="docs/screenshots/onboarding-disclaimer.png" width="280"><br><sub>Honest first-run disclaimer (same-UID boundary)</sub></td>
<td align="center" width="33%"><img src="docs/screenshots/set-your-master-passphrase.png" width="280"><br><sub>Set the one master passphrase</sub></td>
<td align="center" width="33%"><img src="docs/screenshots/save-recovery-code.png" width="280"><br><sub>One-time master recovery code</sub></td>
</tr>
<tr>
<td align="center" width="33%"><img src="docs/screenshots/create-vault.png" width="280"><br><sub>Create an encrypted vault</sub></td>
<td align="center" width="33%"><img src="docs/screenshots/create-vault-recovery-key.png" width="280"><br><sub>Per-vault recovery code</sub></td>
<td align="center" width="33%"><img src="docs/screenshots/enrol-yubikey.png" width="280"><br><sub>Optional YubiKey enrollment</sub></td>
</tr>
</table>
</details>

<details open>
<summary><b>The TUI</b></summary>

<table>
<tr>
<td align="center" width="33%"><img src="docs/screenshots/deamon-active.png" width="280"><br><sub>Daemon running (keys in memory)</sub></td>
<td align="center" width="33%"><img src="docs/screenshots/vault-list.png" width="280"><br><sub>Vault list</sub></td>
<td align="center" width="33%"><img src="docs/screenshots/vault-no-secret-yet.png" width="280"><br><sub>A new, empty vault</sub></td>
</tr>
<tr>
<td align="center" width="33%"><img src="docs/screenshots/vault-add-secret-low.png" width="280"><br><sub>Add a secret</sub></td>
<td align="center" width="33%"><img src="docs/screenshots/vault-secret-list.png" width="280"><br><sub>Secrets with their classification</sub></td>
<td align="center" width="33%"><img src="docs/screenshots/vault-secret-classify.png" width="280"><br><sub>Classify: scope / tier / windows / callers</sub></td>
</tr>
<tr>
<td align="center" width="33%"><img src="docs/screenshots/tui-activity.png" width="280"><br><sub>Activity timeline</sub></td>
<td align="center" width="33%"><img src="docs/screenshots/vault-activity-tui.png" width="280"><br><sub>Per-vault activity</sub></td>
<td align="center" width="33%"><img src="docs/screenshots/help-popup.png" width="280"><br><sub>Help overlay</sub></td>
</tr>
</table>
</details>

<details open>
<summary><b>The AI judge</b></summary>

<table>
<tr>
<td align="center" width="33%"><img src="docs/screenshots/ai-judge-first.png" width="280"><br><sub>Judge manager</sub></td>
<td align="center" width="33%"><img src="docs/screenshots/ai-add-judge.png" width="280"><br><sub>Add a named judge</sub></td>
<td align="center" width="33%"><img src="docs/screenshots/ai-judge-add-key.png" width="280"><br><sub>Set the judge's API key</sub></td>
</tr>
<tr>
<td align="center" width="33%"><img src="docs/screenshots/ai-judge-test.png" width="280"><br><sub>Test the judge</sub></td>
<td align="center" width="33%"><img src="docs/screenshots/ai-judge-yes.png" width="280"><br><sub>Judge allows</sub></td>
<td align="center" width="33%"><img src="docs/screenshots/ai-judge-no.png" width="280"><br><sub>Judge denies</sub></td>
</tr>
</table>
</details>

<details open>
<summary><b>Agent access over MCP (Claude Code)</b></summary>

<table>
<tr>
<td align="center" width="33%"><img src="docs/screenshots/claude-code-mcp.png" width="280"><br><sub>Svault MCP server connected</sub></td>
<td align="center" width="33%"><img src="docs/screenshots/claude-code-mcp-tools.png" width="280"><br><sub>Exposed MCP tools</sub></td>
<td align="center" width="33%"><img src="docs/screenshots/claude-code-mcpsvault_list_vaults.png" width="280"><br><sub><code>svault_list_vaults</code></sub></td>
</tr>
<tr>
<td align="center" width="33%"><img src="docs/screenshots/claude-code-get-list-of-vault.png" width="280"><br><sub>Agent lists vaults</sub></td>
<td align="center" width="33%"><img src="docs/screenshots/claude-code-mcp-svault_get_secret.png" width="280"><br><sub><code>svault_get_secret</code></sub></td>
<td align="center" width="33%"><img src="docs/screenshots/claude-code-get-low-secret.png" width="280"><br><sub>Agent reads a low-tier secret</sub></td>
</tr>
<tr>
<td align="center" width="33%"><img src="docs/screenshots/claude-code-get-secret-medium-deny.png" width="280"><br><sub>Higher-tier read denied to the agent</sub></td>
<td align="center" width="33%"><img src="docs/screenshots/claude-code-refuse.png" width="280"><br><sub>Generic denial — no reason leaked</sub></td>
<td align="center" width="33%"></td>
</tr>
</table>
</details>

> Full set with capture notes in [`docs/screenshots/`](docs/screenshots/).

---

## Roadmap

| Milestone | Status | What |
|---|---|---|
| **Foundation** | Shipped | Local AES-256-GCM vaults (Argon2id), the interactive Ratatui TUI, recovery code + encrypted export/import, and the Unix daemon (keys in memory, auto-lock) |
| **Enforced policy + AI judge** | Shipped | Daemon-enforced policy engine (peer-UID-audited) — reason, scopes, tiers, rate limit, burst — plus the AI judge (OpenRouter) gating medium/high-tier secrets |
| **Everything encrypted at rest** | Shipped | The whole policy surface in `vault.enc` and all global config + the judge registry (multiple named judges, with API keys) in `keyring.enc` — nothing abusable in plaintext; per-vault judge assignment; generic caller-facing denials |
| **Unified unlock** | Shipped | One master passphrase wraps a random data key per store (keyslot model); per-vault passphrases removed and the keyring brought under the master too; `svault master init / rekey / status` |
| **Layered source** | Shipped | Source split into a frontend-agnostic `core` plus `cli` / `tui` / `daemon` frontends (a library crate), with `mcp` / `gui` placeholders — structural only, so future frontends reuse `core` |
| **Local MCP** | Shipped | `svault mcp` — a local stdio MCP server exposing gated `svault_get_secret` / `svault_list_vaults` to AI agents; serves only unlocked state, never the passphrase, with a capability descriptor that advertises the request interface, not the decision criteria |
| **Hardware-key unlock + hardening** | Shipped | YubiKey (FIDO2 hmac-secret) unlock — an alternative keyslot over the master key (passphrase or touch, not 2FA); a re-auth cap on every unlock path (default 6h, configurable 15min–7d); first-run onboarding + an app-level TUI sign-in / logout; storage local-only |
| **Conditional access + escalation** | Shipped | Time-window / required-caller conditions in the encrypted policy; repeated denials seal a secret and escalate to a human (`svault pending` / `approve`, TUI `A`) — agents never self-clear |
| **Independent security review** | Shipped | Three independent external-model reviews of the full 0.9.9 surface (no Critical/High); the actionable findings fixed before 1.0 (`docs/security-review/`) |
| **1.0.0 — stable** | Shipped | First stable release: the agent-ready layer consolidated and reviewed, agents on the MCP door, the store at `~/.svault`. Published on [crates.io](https://crates.io/crates/svault-ai) (as `svault-ai`; the crate is `svault-cli` from 2.0.0). Install channels (script, Homebrew, Docker) follow post-1.0 |
| **Desktop GUI (2.0.0)** | In progress | Cross-platform Tauri vault manager + system tray — all 12 handoff screens built over the same core/daemon, daemon auto-start, one install delivering GUI + CLI + TUI + MCP (`gui/`, [docs/gui.md](docs/gui.md)). Adds Touch ID unlock (macOS) and local AI judges (Ollama / LM Studio). Develops on the 1.1.x line; ships publicly as 2.0.0 |

Detail for each milestone lives in the [changelog](CHANGELOG.md) and the [full roadmap](docs/roadmap.md).

**Full roadmap → [docs/roadmap.md](docs/roadmap.md)**

---

## Tests

```bash
cargo test
```

**144 tests** (plus an `#[ignore]`d concurrency stress benchmark) cover the crypto core and tamper detection, vault operations, the master keyslot model (wrap/unwrap a data key under the master for both vaults and the keyring, rekey, master recovery-code reset, wrong-master rejection), the policy engine and the enforced daemon gate (including peer-UID-stamped audit and high-tier fail-closed behaviour), the AI judge — run against a fake transport, so the suite never touches the network — and the encrypted-at-rest guarantees for both the policy (`vault.enc`) and the keyring (`keyring.enc`).

CI runs the full suite on **Ubuntu, Fedora, macOS, and Windows** on every push and pull request. A heavier concurrency simulation runs on demand:

```bash
cargo test --release daemon_stress_simulation -- --ignored --nocapture
```

Methodology and a recorded run are in [docs/security-review/stress/0.6.0.md](docs/security-review/stress/0.6.0.md).

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

Built by [nim444](https://github.com/nim444).
