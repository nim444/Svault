# Roadmap

For the detailed build plan (stack, per-step checklists, design notes), see [PLAN.md](../PLAN.md).

| Phase | Status | What |
|---|---|---|
| **Step 1** | Done | Local encrypted vault — AES-256-GCM + Argon2id |
| **Step 1+** | Done | Interactive Ratatui TUI (run `svault` with no args) — vault table, forms, secret browser, help overlay, and an activity timeline (`v`) over the per-vault usage log |
| **Step 2** | Done | Policy engine — `svault get` with caller identity, `reason`, scope capability checks, sensitivity tiers, rate limiting + burst detection, audit log |
| **Step 3** | In progress | Recovery (code + export/import) **done**; daemon next. Extra auth methods (YubiKey, TOTP, Touch ID/Face ID) deferred |
| **Step 4** | Planned | Desktop GUI (Tauri) for vault management + system tray |
| **Step 5** | Planned | MCP integration — Claude Code, Cursor, Copilot, VS Code, Aider |
| **Cloud** | Planned | Anomaly scoring via Claude Haiku — free tier + premium plans |

## Step 3 — Daemon + recovery

**Done — recovery:**
- Recovery code generated at create; `svault recover` resets a lost passphrase (see [Recovery](recovery.md)).
- `svault export` / `svault import` — portable, checksummed encrypted bundles to move a vault between machines.

**Next — daemon (Unix):**
- Real daemon — unlock once, serve requests over a local Unix socket (no file-based session); Windows keeps the file-session fallback.
- Idle timeout (default 15 min) + hard max lock (default 8h); secrets wiped from memory on lock.

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

## Cloud tier (optional)

- The per-vault **usage log** (human + agent activity, no secret values) is the local data foundation this builds on.
- `svault.soluzy.net/api/score` — Claude Haiku scores justification for anomaly detection.
- Personal plan — scored requests/month; Team plan — shared audit dashboard + Slack alerts.

## Not planned (yet)

- External backends (Vaultwarden, Infisical, AWS SM).
- Secret rotation.
- Linux biometric support (needs libpam + libfprint).
