# Svault — Build Plan

## Stack

- **Rust** — single native binary, no runtime deps
- `clap` — CLI argument parsing
- `ratatui` — Terminal UI framework (TUI) for interactive CLI (Step 1+)
- `crossterm` — Cross-platform terminal backend for Ratatui
- `console` + `dialoguer` — rich terminal output and prompts (fallback for non-TUI mode)
- `aes-gcm` — AES-256-GCM encryption
- `argon2` — Argon2id key derivation (GPU-resistant)
- `hmac` + `sha2` — HMAC-SHA256 meta.yaml integrity + TOTP (Google Authenticator)
- `zeroize` — secrets zeroed from memory on drop
- `totp-rs` — Time-based OTP (TOTP) generation + validation for Google Authenticator (Step 3)
- `qrcode` — QR code generation for TOTP enrollment (Step 3)
- `yubico` — YubiKey HMAC-SHA1 challenge-response (Step 3)
- `security-framework` — macOS Touch ID / Face ID via Keychain (Step 3, macOS only)
- `tauri` — Cross-platform GUI client (Rust + WebView, Step 4)
- `serde_json` — JSON serialization for GUI ↔ daemon communication (Step 4)

## Progress

### [DONE] Step 1 — Local encrypted vault
- [x] `svault create` — interactive setup: name / description / allow_agent / rate_limit / auto-lock / auto-lock timer (default 1d) / login method / passphrase (`init` kept as alias)
- [x] `svault settings [--vault NAME]` — view and edit a vault's settings, re-signs meta.yaml
- [x] `svault secret add | get | list | remove` — all accept `--vault NAME`; prompts which vault when several exist
- [x] Login method field — passphrase today; yubikey + google auth reserved for later steps
- [x] AES-256-GCM encryption, Argon2id key derivation
- [x] HMAC-SHA256 signed `meta.yaml` — tampering is detectable
- [x] `ZeroizeOnDrop` on `VaultKey` and secret store — memory wiped on drop
- [x] `vault.enc` + `meta.yaml` safe to commit (encrypted / signed, no secret values)
- [x] Session-based lock/unlock simulation (file-based, mode 0600, atomic write)
- [x] `svault status` — lock state of all vaults
- [x] Per-vault `.gitignore` written at init — `.session` can never be accidentally committed
- [x] 18 unit tests — all passing (crypto, vault, session, passphrase)

#### [DONE] Enhancement: Interactive TUI (Ratatui)
- [x] **Ratatui-powered TUI** — run `svault` with no subcommand to launch it (all subcommands still work for scripting)
  - [x] Vault list (home) — arrow keys / j/k to navigate, lock state shown inline (locked / unlocked)
  - [x] `c` create — form-based setup (name, description, allow agent select, agent list, rate limit, auto-lock toggle, auto-lock timer, login method select, passphrase + confirm)
  - [x] `u` unlock / `l` lock — lock-aware: locked vaults route through a passphrase prompt and resume the pending action on success
  - [x] `s` settings — edit form (description, allow agent, rate limit, auto-lock, timer, login method), re-signs `meta.yaml`
  - [x] enter → secret browser — `a` add (set), enter/`g` view (get, masked toggle), `d` delete with confirm; requires an unlocked vault
  - [x] Cached session passphrase reused everywhere — no re-prompt while unlocked; `l` from any screen locks and wipes the session
  - [x] Plain-ASCII status line (ok / warning / error / note), context key hints in the footer

### [TODO] Step 2 — Policy engine
- [ ] `svault.policy.yaml` — define callers, scopes, tiers per vault
- [ ] `svault get <NAME> --scope <S> --reason "<R>"` — structured request
- [ ] Policy checks: reason present → capability check → rate limit → burst detection
- [ ] Sensitivity tiers: `low` (auto-approve) / `medium` (log) / `high` (human confirm)
- [ ] `svault policy check <caller>` — show what a caller can access

### [TODO] Step 3 — Daemon + multi-select auth unlock
- [ ] **Multi-select auth at init** — `svault init` prompts user to choose/combine auth methods:
  - [ ] Passphrase (always available, works everywhere)
  - [ ] YubiKey (HMAC-SHA1 challenge-response, hardware-backed)
  - [ ] Google Authenticator (Time-based OTP, TOTP, phone-based)
  - [ ] Touch ID / Face ID (macOS Keychain, biometric unlock)
  - [ ] Users can enable any combination (e.g., Passphrase + YubiKey, Passphrase + OTP, Touch ID + Passphrase, all four)
  - [ ] Store auth config in `meta.yaml` (which methods are enabled for this vault)
- [ ] Real daemon — unlock once, serve requests over local Unix socket, no file-based session
- [ ] `svault unlock` — interactive prompt shows enabled methods, user selects which to use
  - [ ] Passphrase-only vault: `svault unlock` prompts for passphrase
  - [ ] YubiKey-enabled vault: `svault unlock --yubikey` — HMAC-SHA1 challenge-response
    - Challenge stored in `meta.yaml` at init (not secret)
    - YubiKey slot 2 configured for HMAC-SHA1
    - Response → Argon2id → vault key. Hardware never exposes the HMAC secret.
  - [ ] OTP-enabled vault: `svault unlock --otp <code>` — 6-digit TOTP from Google Authenticator
    - Secret seed stored encrypted in `meta.yaml` (useless without vault key)
    - On init: QR code displayed, user scans with Google Authenticator / Authy / Microsoft Authenticator
  - [ ] Touch ID / Face ID (macOS): `svault unlock --biometric` — fingerprint or face recognition
    - Uses macOS Keychain to store vault key securely
    - Prompts for biometric unlock, Keychain handles auth
    - Falls back to passphrase if biometric fails
    - macOS only; ignored on Linux/Windows
  - [ ] Multi-method unlock: `svault unlock --yubikey --otp <code> --phrase --biometric` — user selects combination
- [ ] Recovery fallback at init — passphrase OR recovery key if hardware methods are lost
- [ ] Auto-lock: idle timeout (default 15 min) — reset on every secret request
- [ ] Hard max lock (default 8h) — re-locks unconditionally regardless of activity
- [ ] On lock: secrets wiped from memory immediately (`zeroize`)
- [ ] Both timers configurable in `.svault/config.yaml`

### [TODO] Step 4 — GUI client (Tauri)
- [ ] `svault-gui` — cross-platform desktop app (macOS, Linux, Windows)
  - [ ] **Vault dashboard** — list all vaults, show lock/unlock status, last accessed
  - [ ] **Lock/unlock panel** — quick unlock with selected auth methods (passphrase, biometric, etc.)
  - [ ] **Auto-lock settings** — visual controls for idle timeout (default 15 min) and hard max lock (default 8h)
  - [ ] **Session monitor** — show active sessions, locked/unlocked state, auto-lock countdown timer
  - [ ] **Secret management** — view secret names (never values), add/remove secrets with GUI
  - [ ] **Policy viewer** — inspect what a caller can access (from `svault.policy.yaml`)
  - [ ] **Status notifications** — system tray icon, notifications for lock/unlock, timeouts
  - [ ] **Settings UI** — configure Svault defaults, daemon socket path, log level
  - [ ] **Audit log viewer** — see who accessed what (from policy logs)
  - [ ] Built with Tauri: lightweight, single binary, works offline, no runtime deps

### [TODO] Step 5 — Platform install + MCP
- [ ] `svault mcp` — start MCP server exposing `svault_get_secret(name, scope, reason)`
- [ ] `svault install` — auto-detect platform, write MCP config
- [ ] Claude Code: MCP server + PreToolUse hook (blocks direct `.env` reads) + PostToolUse hook (scans output for leaked credentials)
- [ ] Cursor, Codex, Copilot, Aider, VS Code: MCP server
- [ ] `--project` flag — project-scoped install, files are git-committable
- [ ] GUI client integration — optional: Svault GUI can show active MCP sessions

### [TODO] Cloud tier (optional)
- [ ] `svault.soluzy.net/api/score` — Claude Haiku scores justification for anomaly detection
- [ ] Personal plan $1–2/month — 10k scored requests/month
- [ ] Team plan $8–15/month — shared audit dashboard, Slack alerts

## Auth method comparison

| Method | UX | Security | Notes |
|---|---|---|---|
| Passphrase | Type passphrase | Strong if long | Always available, works anywhere |
| YubiKey | Touch key | Strong, hardware-backed | Fast daily use, requires YubiKey |
| Google Authenticator (TOTP) | Scan QR + enter 6-digit code | Medium-strong, time-based | Works on phone, no hardware needed |
| Touch ID / Face ID (macOS) | Fingerprint or face scan | Strong, biometric | Fastest unlock, macOS only |
| Passphrase + YubiKey | Touch + type | Strongest (2FA) | Hardware + knowledge, high-security vaults |
| Passphrase + TOTP | Type + enter 6-digit code | Very strong (2FA) | No hardware needed, something-you-know + something-you-have |
| Passphrase + Touch ID | Type + biometric (macOS) | Very strong (2FA) | Knowledge + biometric, fastest on Mac |
| YubiKey + Touch ID (macOS) | Touch key + fingerprint | Strongest (2FA hardware) | Hardware + biometric, maximum portability |
| All four (Passphrase + YubiKey + TOTP + Touch ID) | Type + key + code + biometric | Maximum security | All factors; requires YubiKey + macOS |
| Multi-select custom | User chooses enabled methods at init | Configurable | Flexible per-vault security posture |

## Next Steps: Build Sequence

1. **Step 1 Enhancement** — Interactive TUI with Ratatui (form-based init, interactive browsers, live dashboard)
2. **Step 2** — Policy engine (structured requests with `reason` + capability checks)
3. **Step 3** — Daemon + multi-select auth (passphrase, YubiKey, TOTP, Touch ID)
4. **Step 4** — GUI client (Tauri desktop app for vault management)
5. **Step 5** — MCP integration + platform installs (Claude Code, Cursor, etc.)
6. **Cloud tier** (optional) — Justification scoring + premium plans

## What's NOT planned (yet)

- External backends (Vaultwarden, Infisical, AWS SM — v0.2)
- Secret rotation
- Windows support (session file uses Unix permissions; daemon design is Unix-first)
- Linux biometric support (fingerprint readers — possible future, needs libpam + libfprint)

## Run locally

```bash
cargo build --release
./target/release/svault --help
cargo test
```
