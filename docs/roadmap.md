# Roadmap

Svault is an AI-aware secret manager built CLI-first. The path to a stable
release is deliberately sequenced: the command-line tool is fully hardened and
independently reviewed **before** any GUI or AI-platform surface is added. A
secret manager has to be trustworthy as a CLI first; a GUI and platform
integrations only widen the attack surface, so they come after the core is
proven.

For per-release detail, see [CHANGELOG.md](../CHANGELOG.md). For the build plan
(stack, step checklists, design notes), see [PLAN.md](../PLAN.md).

| Milestone | Status | Theme |
|---|---|---|
| Foundation (0.1 – 0.8) | Shipped | Encrypted local vaults, interactive TUI, Unix daemon, and a multi-release security-hardening track |
| Enforced policy + AI judge (0.9.0 – 0.9.1) | Shipped | The behavioural gate: daemon-enforced policy, peer-UID-stamped audit, and an AI judge for medium/high secrets — driven from both CLI and TUI |
| Everything-encrypted-at-rest (0.9.2 – 0.9.3) | Shipped | The entire policy surface and all global config moved into encrypted stores; no plaintext config or key files remain |
| Stable release (1.0.0) | Next | Final independent security review + distribution channels, then the first stable release |
| Desktop GUI (2.0.0) | Planned | Tauri vault manager + system tray |
| AI-platform access (3.0.0) | Planned | MCP integration across Claude Code, Cursor, Copilot, VS Code, and Aider |
| Cloud (optional) | Planned | Anomaly scoring via Claude Haiku — free tier + premium plans |

The project is intentionally staying on the 0.9.x line. **1.0.0 is reserved for
when everything is finished and independently reviewed** — it is the target, not
a date.

## Shipped

### Foundation

A complete, self-contained secret manager that works fully offline:

- **Encrypted local vaults** — AES-256-GCM with Argon2id key derivation
  (GPU-resistant); secrets are zeroized in memory on drop.
- **Signed public metadata** — non-sensitive vault metadata is HMAC-SHA256
  signed, so tampering is detectable.
- **Interactive TUI** — a full-screen Ratatui dashboard for vault, secret, and
  policy management, with a live lock-state indicator and an activity timeline.
- **Recovery and portability** — a one-time recovery code resets a lost
  passphrase (`svault recover`), and checksummed encrypted bundles move a vault
  between machines (`svault export` / `svault import`).
- **Unix daemon** — unlock once and hold keys **in memory** behind a `0600`
  Unix socket, with idle and hard-max auto-lock (keys zeroized on lock,
  auto-lock, and shutdown) and a per-connection peer-UID check so only the
  owner's own processes are served.
- **Hardening track** — a release-gated security-review process drove a
  multi-version hardening pass: a `cargo audit` CI gate, client-side key
  derivation (the passphrase never crosses the socket), owner-only files and
  directories, a passphrase entropy floor, transport zeroization, and signed
  SLSA build provenance on every release artifact.

### Enforced policy engine + AI judge

The behavioural gate that makes Svault AI-aware. Policy is **enforced inside the
daemon**, so the socket is the single choke point and there is no unguarded read
path:

- **Policy pipeline** — each `svault get` is evaluated through reason → scope →
  rate limit / burst detection → sensitivity tier before a value is returned.
- **AI judge** — for medium and high-tier secrets, the daemon asks an LLM (via
  OpenRouter) whether the caller's stated reason plausibly justifies the
  request, given the secret's purpose and the caller's recent activity. Medium
  fails open with an audit flag if the judge is unavailable; high fails closed.
- **Honest audit** — every read is recorded stamped with the connecting
  process's **peer UID**, which is unforgeable, unlike a self-asserted caller
  string.
- **Generic denials** — a denied caller gets a single opaque message; the real
  reason (score, rationale, scope or rate-limit mismatch) is recorded only in
  the audit log, so a caller cannot hill-climb toward a request that passes.
- **Full CLI and TUI parity** — the judge, per-secret classification, and the
  global switch are all drivable from the keyboard, and every policy or judge
  change is reflected in the audit timeline.

### Everything that gates access is encrypted at rest

Signing prevents tampering but not reading. These releases closed the
read-the-files reconnaissance path entirely:

- **Encrypted policy surface** — per-secret classification, caller rules, access
  fallback, and the per-vault judge assignment all live AES-256-GCM encrypted
  inside `vault.enc`. A same-UID agent can no longer read the tiers, scopes,
  descriptions, caller scopes, or rate limits at rest to craft a passing
  request.
- **Encrypted keyring** — all global config and the judge registry live in a
  single encrypted store, `.svault/keyring.enc`, under its own passphrase
  (`svault keyring init | unlock | lock | rekey | status`). The former plaintext
  `config.yaml` and `openrouter.key` file are gone — **no plaintext config or
  key files remain.**
- **Multiple named judges** — the judge is a registry, not a single global
  setting (`svault judge add | edit | remove | list | set-default | set-key`).
  Each judge has its own model, thresholds, free-text criteria, and encrypted
  API key. A vault is assigned a judge by name (stored in its encrypted policy)
  and falls back to the keyring default.

**Honest boundary:** the at-rest encryption closes the read-the-files
reconnaissance path. It is **not** a sandbox against a hostile same-UID process
that reads the unlocked daemon's memory directly — that remains inherent to the
documented same-UID trust model.

## Next — 1.0.0 (stable release)

1.0.0 is gated on two things, in this order:

1. **A final independent security review of the enforced engine** — the explicit
   gate. This includes adversarially testing the AI judge (prompt injection via
   the `reason` field) and a decision on caller authorization, which is still
   self-asserted (audit is peer-UID-stamped, so attribution is already honest):
   accept that as the documented boundary, or add an OS-bound caller identity.
2. **Distribution channels** — an install script, a Homebrew tap, and a Docker
   image (see below).

A small backlog of accepted, non-blocking items remains: a Windows owner-only
DACL, a tamper-evident audit sink, and tunable Argon2id parameters.

## Planned

### 2.0.0 — Desktop GUI (Tauri)

- Vault dashboard with lock/unlock, auto-lock controls, and a session monitor.
- Secret management (names only, never values), a policy viewer, and an audit
  log viewer.
- System tray icon and notifications; a lightweight single binary that works
  offline.

### 3.0.0 — AI-platform access (MCP)

- `svault mcp` — an MCP server exposing `svault_get_secret(name, scope, reason)`.
- `svault install` — auto-detect the platform and write its MCP config.
- **Claude Code** — MCP server plus a PreToolUse hook (blocks direct `.env`
  reads) and a PostToolUse hook (scans output for leaked credentials).
- **Cursor, Copilot, VS Code, Aider** — MCP server.

### Cloud tier (optional)

The per-vault usage log (human and agent activity, no secret values) is the
local foundation this builds on:

- `api/score` — Claude Haiku scores request justifications for anomaly detection.
- A personal plan with scored requests per month, and a team plan with a shared
  audit dashboard and Slack alerts.

## Distribution

All channels reuse the prebuilt binaries the release workflow already builds for
four targets (macOS arm64/x64, Linux x64, Windows x64), so most are low-effort
once wired.

**Shipped:**

- **crates.io** — `cargo install svault-ai` (builds from source).

**Next (one pass — covers Mac/Linux/Rust users and agents):**

- **Install script** — `curl -fsSL https://svault.soluzy.app/install.sh | sh`:
  detect OS and arch, download the matching release binary, drop it on PATH. The
  link the README and website lead with.
- **Homebrew tap** — `brew install soluzy/tap/svault` from a `Soluzy/homebrew-tap`
  repo (own tap, not homebrew-core); CI bumps the formula on each `v*` tag.
- **cargo-binstall** — `[package.metadata.binstall]` in `Cargo.toml` so
  `cargo binstall svault-ai` pulls a prebuilt binary instead of compiling.
- **Docker image** — `ghcr.io/soluzy/svault`, pushed on each tag; this matters
  for the AI-agent and CI use case, where agents run in containers.

**Later (niche audiences, more upkeep):**

- **Scoop** (Windows, own bucket) and **WinGet** (PR per release).
- **AUR** (`PKGBUILD`) for Arch.
- **Nix** — flake / nixpkgs.

**Not planned yet:**

- **homebrew-core** and other official repos — the notability bar rejects young
  projects; use the own tap until there's traction.
- **npm wrapper** — only if JS-ecosystem agents (`npx`) show real demand.

The website (`svault.soluzy.app`) becomes the hub: it hosts `install.sh` and a
tabbed Install block (brew / curl / cargo / docker).

## Not planned (yet)

- Additional unlock methods — YubiKey (HMAC-SHA1), TOTP, and Touch ID / Face ID.
- External backends (Vaultwarden, Infisical, AWS Secrets Manager).
- Secret rotation.
- Linux biometric support (needs libpam + libfprint).
