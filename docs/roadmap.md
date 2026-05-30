# Roadmap

For the detailed build plan (stack, per-step checklists, design notes), see [PLAN.md](../PLAN.md).

Svault is built CLI-first. The major versions are deliberately sequenced so the
command-line tool is fully hardened and stable **before** any GUI or AI-platform
surface is added:

| Milestone | Status | What |
|---|---|---|
| **0.1 – 0.6** | Shipped | CLI core — encrypted vault (AES-256-GCM + Argon2id), Ratatui TUI, policy engine (`svault get`), Unix daemon, recovery + export/import, and the 0.6.0 security-hardening pass |
| **0.7.0** | Shipped | Security-hardening pass — `cargo audit` CI gate, client-side key derivation, daemon peer-UID bond, owner-only files/dirs, entropy floor, zeroized secrets, SLSA provenance |
| **0.8.0** | Shipped | Security-review-response release — owner-only TUI export, daemon transport zeroization, `sigaction`, etc. |
| **0.9.0** | In review (PR #15) | **Enforced policy engine + AI judge** — daemon-side policy + audit (peer-UID stamped), signed per-secret classification, OpenRouter judge for medium/high secrets, and `svault judge set-key/status/remove-key` to manage the key |
| **1.0.0** | Planned | First **stable release**: install channels + a final independent review of the enforced engine, then a hardened, audited CLI |
| **2.0.0** | Planned | Desktop **GUI** (Tauri) for vault management + system tray |
| **3.0.0** | Planned | **Claude / AI-platform access** — MCP server + Pre/PostToolUse hooks (Claude Code, Cursor, Copilot, VS Code, Aider) |
| **Cloud** (opt-in) | Planned | Anomaly scoring via Claude Haiku — free tier + premium plans |

> Why this order: a secret manager has to be trustworthy as a CLI first. A GUI
> and AI-platform integrations widen the attack surface, so they come only after
> the core is hardened and the security-review process has had a full release
> cycle behind it.

## 0.7.0 → 1.0.0 — Hardening & stable CLI

The focus until 1.0.0 is the security-review backlog, not new surfaces.

**Done in 0.7.0** (see [0.7.0 findings](security-review/findings/0.7.0.md)): the
`cargo audit` CI gate + `ratatui` 0.30 (#9/#10), client-side key derivation so the
passphrase never crosses the socket (#3), the daemon peer-UID bond (#1), owner-only
files/dirs + atomic socket (#14/#16), graceful shutdown (#17), zeroized secrets
(#6), release checksums + SLSA provenance (#11), and the passphrase entropy floor
(#12).

**Done in 0.8.0** (review-response): owner-only TUI export (N-3) and import dir
(N-4), `0600` rotated `daemon.log` (N-10), daemon transport zeroization (N-6), and
`sigaction` shutdown signals (N-9).

**Done in 0.9.0** (the enforced-policy release): policy + audit moved **inside the daemon** so the socket is the choke point (#2, N-5), the audit trail is stamped with the unforgeable peer UID (N-1), secret classification moved to the **signed `meta.yaml`** with anchored policy discovery (#5) and verified-meta gating (#22), unparseable policy **fails closed** (N-2), and the **AI judge** (OpenRouter) gates medium/high secrets — with `svault judge set-key`/`status`/`remove-key` to manage the key as a `0600` file.

**Remaining before 1.0.0** (see the [0.9.0 findings register](security-review/findings/0.9.0.md)):
- A final **independent security review of the 0.9.0 enforced engine** — the explicit gate.
- **Decide N-1** — caller *authorization* is still self-asserted (audit is now peer-UID-stamped, so attribution is honest); accept that as the boundary, or add a per-agent token / OS-bound caller identity.
- **Adversarially test the AI judge** — prompt injection via the `reason` field (J-1) in particular.
- **Accepted/backlog, not blockers** — Windows atomic owner-only DACL (N-7), tamper-evident audit sink (#15/N-8), tunable Argon2id (N-12).
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
