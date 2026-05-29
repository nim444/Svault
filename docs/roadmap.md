# Roadmap

For the detailed build plan (stack, per-step checklists, design notes), see [PLAN.md](../PLAN.md).

Svault is built CLI-first. The major versions are deliberately sequenced so the
command-line tool is fully hardened and stable **before** any GUI or AI-platform
surface is added:

| Milestone | Status | What |
|---|---|---|
| **0.1 – 0.6** | Shipped | CLI core — encrypted vault (AES-256-GCM + Argon2id), Ratatui TUI, policy engine (`svault get`), Unix daemon, recovery + export/import, and the 0.6.0 security-hardening pass |
| **0.7.0 → 1.0.0** | In progress | **Security hardening** (acting on the review findings), a supply-chain/CI gate, and the install channels — the road to a stable CLI |
| **1.0.0** | Planned | First **stable release**: a hardened, audited command-line tool |
| **2.0.0** | Planned | Desktop **GUI** (Tauri) for vault management + system tray |
| **3.0.0** | Planned | **Claude / AI-platform access** — MCP server + Pre/PostToolUse hooks (Claude Code, Cursor, Copilot, VS Code, Aider) |
| **Cloud** (opt-in) | Planned | Anomaly scoring via Claude Haiku — free tier + premium plans |

> Why this order: a secret manager has to be trustworthy as a CLI first. A GUI
> and AI-platform integrations widen the attack surface, so they come only after
> the core is hardened and the security-review process has had a full release
> cycle behind it.

## 0.7.0 → 1.0.0 — Hardening & stable CLI

The focus until 1.0.0 is the security-review backlog, not new surfaces. Working
order (from the [0.6.0 findings carry-forward](security-review/findings/0.6.0.md)):

- **Supply chain** — add a `cargo audit` / `cargo-deny` CI gate (#9) and bump `ratatui` to clear the two transitive advisories (#10).
- **Policy as an enforced control** — evaluate policy + audit inside the daemon so the socket is the choke point (#2); sign / pin `svault.policy.yaml` (#5).
- **Socket secrecy** — derive the key client-side so the passphrase never crosses the daemon socket (#3).
- **Finish #4** — Windows DPAPI/ACL (or refuse-to-cache) and route the TUI through the daemon so `.session` can be deprecated on Unix.
- **Smaller** — zeroize secret/passphrase strings (#6), release-artifact checksums/signing (#11), a passphrase entropy floor (#12); then the peer-UID bond (#1), #14, #16, #17, #22.
- **Distribution** — `install.sh`, Homebrew tap, cargo-binstall, Docker (see below).

## Step 3 — Daemon + recovery

**Done — recovery:**
- Recovery code generated at create; `svault recover` resets a lost passphrase (see [Recovery](recovery.md)).
- `svault export` / `svault import` — portable, checksummed encrypted bundles to move a vault between machines.

**Done — daemon (Unix):**
- Real daemon — unlock once, keys held in memory, served over a local `0600` Unix socket (no `.session` file while up); Windows keeps the file-session fallback. See [Daemon](daemon.md).
- `svault daemon start | stop | status | doctor | run`; `doctor` reports liveness, socket permissions, and stale-file cleanup.
- Idle timeout (default 15 min) + hard max lock (default 8h), configurable in `.svault/config.yaml`; keys zeroized on lock, auto-lock, and shutdown.

**Deferred** to a later step: extra auth methods — YubiKey (HMAC-SHA1), Google Authenticator (TOTP), Touch ID / Face ID (macOS Keychain), and the multi-method `svault unlock --yubikey/--otp/--biometric` selection.

## 2.0.0 — GUI client (Tauri)

- Vault dashboard, lock/unlock panel, auto-lock controls, session monitor.
- Secret management (names only, never values), policy viewer, audit log viewer.
- System tray icon + notifications; lightweight single binary, works offline.

## 3.0.0 — Claude / AI-platform access (MCP)

- `svault mcp` — MCP server exposing `svault_get_secret(name, scope, reason)`.
- `svault install` — auto-detect platform, write MCP config.
- Claude Code: MCP server + PreToolUse hook (blocks direct `.env` reads) + PostToolUse hook (scans output for leaked credentials).
- Cursor, Codex, Copilot, Aider, VS Code: MCP server.

## Distribution

All channels reuse the prebuilt binaries the release workflow already builds for four targets (macOS arm64/x64, Linux x64, Windows x64), so most are low-effort once wired.

**Done:**
- **crates.io** — `cargo install svault-ai` (builds from source).

**Next (one pass — Mac/Linux/Rust users + agents):**
- **Install script** — `curl -fsSL https://svault.soluzy.app/install.sh | sh`: detect OS/arch, download the matching release binary, drop it on PATH. The link the README and website lead with.
- **Homebrew tap** — `brew install soluzy/tap/svault` from a `Soluzy/homebrew-tap` repo (own tap, not homebrew-core); CI bumps the formula on each `v*` tag.
- **cargo-binstall** — `[package.metadata.binstall]` in `Cargo.toml` so `cargo binstall svault-ai` pulls a prebuilt binary instead of compiling.
- **Docker image** — `ghcr.io/soluzy/svault`, pushed on each tag; matters for the AI-agent / CI use case (agents run in containers).

**Later (niche audiences, more upkeep):**
- **Scoop** (Windows, own bucket) and **WinGet** (PR per release).
- **AUR** (`PKGBUILD`) for Arch.
- **Nix** — flake / nixpkgs.

**Skip for now:**
- **homebrew-core** and other official repos — the notability/age bar rejects young projects; use the own tap until there's traction.
- **npm wrapper** — only if JS-ecosystem agents (`npx`) show real demand.

The website (`svault.soluzy.app`) becomes the hub: hosts `install.sh` and a tabbed Install block (brew / curl / cargo / docker).

## Cloud tier (optional)

- The per-vault **usage log** (human + agent activity, no secret values) is the local data foundation this builds on.
- `svault.soluzy.net/api/score` — Claude Haiku scores justification for anomaly detection.
- Personal plan — scored requests/month; Team plan — shared audit dashboard + Slack alerts.

## Not planned (yet)

- External backends (Vaultwarden, Infisical, AWS SM).
- Secret rotation.
- Linux biometric support (needs libpam + libfprint).
