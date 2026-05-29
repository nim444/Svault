# Roadmap

For the detailed build plan (stack, per-step checklists, design notes), see [PLAN.md](../PLAN.md).

| Phase | Status | What |
|---|---|---|
| **Step 1** | Done | Local encrypted vault — AES-256-GCM + Argon2id |
| **Step 1+** | Done | Interactive Ratatui TUI (run `svault` with no args) — vault table, forms, secret browser, help overlay, and an activity timeline (`v`) over the per-vault usage log |
| **Step 2** | Done | Policy engine — `svault get` with caller identity, `reason`, scope capability checks, sensitivity tiers, rate limiting + burst detection, audit log |
| **Step 3** | Done | Recovery (code + export/import) and the Unix daemon (keys in memory, auto-lock, `daemon doctor`). Extra auth methods (YubiKey, TOTP, Touch ID/Face ID) deferred |
| **Step 4** | Planned | Desktop GUI (Tauri) for vault management + system tray |
| **Step 5** | Planned | MCP integration — Claude Code, Cursor, Copilot, VS Code, Aider |
| **Distribution** | In progress | Install channels — crates.io **done**; install script, Homebrew tap, cargo-binstall, Docker next; Scoop/WinGet/AUR/Nix later |
| **Cloud** | Planned | Anomaly scoring via Claude Haiku — free tier + premium plans |

## Step 3 — Daemon + recovery

**Done — recovery:**
- Recovery code generated at create; `svault recover` resets a lost passphrase (see [Recovery](recovery.md)).
- `svault export` / `svault import` — portable, checksummed encrypted bundles to move a vault between machines.

**Done — daemon (Unix):**
- Real daemon — unlock once, keys held in memory, served over a local `0600` Unix socket (no `.session` file while up); Windows keeps the file-session fallback. See [Daemon](daemon.md).
- `svault daemon start | stop | status | doctor | run`; `doctor` reports liveness, socket permissions, and stale-file cleanup.
- Idle timeout (default 15 min) + hard max lock (default 8h), configurable in `.svault/config.yaml`; keys zeroized on lock, auto-lock, and shutdown.

**Deferred** to a later step: extra auth methods — YubiKey (HMAC-SHA1), Google Authenticator (TOTP), Touch ID / Face ID (macOS Keychain), and the multi-method `svault unlock --yubikey/--otp/--biometric` selection.

## Step 4 — GUI client (Tauri)

- Vault dashboard, lock/unlock panel, auto-lock controls, session monitor.
- Secret management (names only, never values), policy viewer, audit log viewer.
- System tray icon + notifications; lightweight single binary, works offline.

## Step 5 — Platform install + MCP

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
