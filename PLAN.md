# Svault — Build Plan

Svault is an AI-aware secret manager written in Rust: a single native binary
(`svault`, crate `svault-ai`) with no runtime dependencies. It encrypts secrets
at rest, holds unlocked keys in a memory-only daemon, and gates agent access
through an enforced policy engine and an optional AI judge.

This document is the engineering plan: the current state at **0.9.3** and the
work remaining to reach a stable **1.0.0**. Shipped versions are detailed in
[CHANGELOG.md](CHANGELOG.md); the public roadmap lives in
[docs/roadmap.md](docs/roadmap.md).

> **Version policy.** The project stays on **0.9.x** until everything is built
> and independently reviewed. **1.0.0 is reserved for the first stable, audited
> release** — it has not shipped and is the target the current work builds
> toward, not a date.

## Current state (0.9.3)

The CLI is feature-complete for its 1.0.0 scope. Every layer below is implemented,
tested, and shipping.

**Encrypted local vaults.** AES-256-GCM secret storage with Argon2id key
derivation. Secret values are zeroized from memory on drop (`ZeroizeOnDrop` on
the vault key and secret store). The committable `vault.enc` and the public,
HMAC-SHA256-signed `meta.yaml` carry no secret values, so tampering is
detectable and the files are safe to commit.

**Interactive TUI.** Running `svault` with no subcommand launches a full Ratatui
dashboard — vault list with live lock state, form-based create, lock-aware
unlock/lock, a settings editor, and a secret browser (add / view / delete) once
a vault is unlocked. Every operation is also a scriptable subcommand.

**Recovery and portability.** A 160-bit recovery code is generated at create
time, with the vault key wrapped under it in `recovery.enc`; `svault recover`
resets a lost passphrase without invalidating the code. `svault export` /
`import` move a vault between machines as a checksummed (`sha256`), encrypted
bundle; import refuses to overwrite an existing name.

**Memory-only daemon (Unix).** `svault daemon run|start|stop|status|doctor`
holds unlocked keys in memory and serves reads over a `0600` Unix socket — no
`.session` file while it runs. Auto-lock enforces an idle timeout and a hard-max
cap, zeroizing evicted keys. Each connection is bonded to its peer UID
(`getpeereid`); a non-owner peer is refused. The passphrase never crosses the
socket: the client derives and validates the key locally. Windows has no daemon
and uses the file-session fallback (the CLI is otherwise fully supported and
tested on Windows in CI).

**Enforced policy engine.** Policy is evaluated *inside* the daemon, which is the
single choke point — the CLI runs the identical gate locally when no daemon is
up, so there is no unguarded read path. The agent path (`svault get`) is a
structured `GetGated` request evaluated through a fixed pipeline:

    reason present → scope/capability check → sensitivity tier → rate limit / burst → AI judge

Each access is audited and stamped with the unforgeable **peer UID**, not the
self-asserted caller string. Per-secret classification (`scope`, `tier`,
`require_reason`, `description`) drives the decision; tiers are `low`
(auto-allow), `medium` (judge-gated, fail-open with an audit flag), and `high`
(judge-gated, fail-closed). With the judge off, `high` is human-only.

**AI judge (OpenRouter).** For medium/high-tier secrets, the daemon asks a cheap,
fast LLM whether the caller's stated reason plausibly justifies the request,
given the secret's scope, tier, and description and the caller's recent activity.
Synchronous (`ureq`, bundled rustls — no async runtime). Off until a key is
configured, so upgrading never silently calls an external API.

**Policy and config encrypted at rest (0.9.2 → 0.9.3).** Two releases closed the
reconnaissance path that signing alone left open — a same-UID agent could *read*
the tiers, scopes, descriptions, caller rules, and judge thresholds, then craft
a request designed to pass.

- *0.9.2* moved the entire policy surface — per-secret classification,
  `allow_agent`/`rate_limit`, the per-vault judge override, the default tier, and
  caller rules — into an AES-256-GCM-encrypted payload inside `vault.enc`
  (`VaultPayload v2`). The public `meta.yaml` retains only non-sensitive
  metadata. Denials to the caller are now generic (`request not authorized for
  this secret`); the real reason — judge score and rationale, scope/caller
  mismatch, rate limit — is recorded only in the audit log, so a caller cannot
  hill-climb toward a passing request.
- *0.9.3* removed the last two plaintext artifacts: the judge config in
  `.svault/config.yaml` and the OpenRouter key file. All global config and the
  judge registry now live in a single AES-256-GCM-encrypted **keyring**
  (`.svault/keyring.enc`) under its own passphrase, unlocked once per session.
  The judge is no longer single and global: you can define **multiple named
  judges**, each with its own model, base URL, timeout, allow/high thresholds,
  free-text **criteria** injected into its prompt, and **API key**; pick a
  default and assign one per vault. There are no plaintext `config.yaml` or
  `openrouter.key` files anymore.

**Quality.** 108 tests pass (plus one ignored concurrency stress benchmark). CI
runs on Ubuntu, Fedora, macOS, and Windows, with `cargo fmt --check`, `cargo
clippy -D warnings`, and a `cargo audit` advisory gate.

### Security boundary (stated, not over-claimed)

Svault's encrypted-at-rest design closes the read-the-files reconnaissance path:
secrets, policy, classification, caller rules, judge thresholds, criteria, and
API keys are all unreadable at rest. It is **not** a sandbox against a hostile
same-UID process that reads the unlocked daemon's memory (or the `0600` session)
directly — that remains inherent to the documented same-UID trust model. This
boundary must stay stated plainly in the docs and never be over-claimed.

### Security-review history

Releases 0.5.0 through 0.9.0 were driven by a release-gated security process:
each `0.x.0` got one or more independent, model-agnostic reviews, with all
findings de-duplicated into a decision register. The full carry-forward lives in
`docs/security-review/`. Highlights of what those reviews closed:

- **0.6.0** — daemon connection ceiling + per-connection read timeout (#8),
  poison-recovery on the key-store lock (#13), truncated-`vault.enc` guard (#20),
  session caches the derived key rather than the passphrase (#4); logged
  concurrency stress run.
- **0.7.0** — `cargo audit` CI gate (#9/#10), client-side key derivation so the
  passphrase never crosses the socket (#3), daemon peer-UID bond (#1), owner-only
  files/dirs + atomic socket (#14/#16), graceful shutdown (#17), zeroized secrets
  (#6), release checksums + SLSA provenance (#11), passphrase entropy floor (#12).
- **0.8.0** — owner-only TUI export and import dir (N-3/N-4), `0600` rotated
  `daemon.log` (N-10), daemon transport zeroization (N-6), `sigaction` shutdown
  (N-9).
- **0.9.0** — the headline release: policy moved from advisory to **enforced**
  inside the daemon, and the AI judge landed, closing the gap (#2/#5/#22,
  N-1/N-2/N-5) all prior reviews named as the 1.0.0 blocker.

## Path to 1.0.0

Three pieces remain before the first stable, audited release.

### 1. Final independent security review — Next

A final review pass over the enforced, encrypted-policy engine and the keyring,
following the established release-gated review process. This is the gate on the
1.0.0 label.

### 2. Distribution / install channels — In progress

All channels reuse the four prebuilt binaries that the release workflow
(`release.yml`, on `v*` tags) already produces — macOS arm64/x64, Linux x64,
Windows x64. Standing constraint: publishing to external registries is done
manually by the maintainer (Claude does not run `cargo publish` or push to
registries).

**Done**

- **crates.io** — published as `svault-ai`, binary `svault` (`cargo install
  svault-ai`, builds from source).
- **GitHub Releases** — `release.yml` builds and uploads four target archives on
  each `v*` tag (the artifact source every channel below points at), with a
  matching `.sha256` and SLSA provenance per archive.

**Planned — first pass (Mac / Linux / Rust users and agents)**

- **Install script** — `install.sh`: detect OS and arch, resolve the latest (or
  pinned) release, download and verify the matching archive, extract `svault`
  onto PATH. Served from `svault.soluzy.app/install.sh`
  (`curl -fsSL https://svault.soluzy.app/install.sh | sh`); the primary install
  link in the README and on the website.
- **cargo-binstall** — add `[package.metadata.binstall]` mapping `pkg-url` /
  `pkg-fmt` to the release asset names so `cargo binstall svault-ai` fetches a
  prebuilt binary instead of compiling.
- **Homebrew tap** — own `Soluzy/homebrew-tap` with `Formula/svault.rb`
  (per-arch `url` + `sha256`), auto-bumped on each `v*` tag. Install:
  `brew install soluzy/tap/svault`. An own tap, not homebrew-core.
- **Docker image** — `Dockerfile` (Debian-slim or distroless/scratch for static)
  pushed to `ghcr.io/soluzy/svault` on each tag, targeting the AI-agent and CI
  use case where agents and pipelines run in containers.

**Planned — later (niche audiences, more upkeep)**

- **Scoop** (Windows) — manifest in an own bucket (`Soluzy/scoop-bucket`).
- **WinGet** — manifest PR to `microsoft/winget-pkgs` per release.
- **AUR** (Arch) — `PKGBUILD` `-bin` package pointing at the release binary.
- **Nix** — flake output and/or a nixpkgs derivation.

**Deliberately skipped (for now)**

- **homebrew-core** and other curated repos — their notability/age bar rejects
  young projects; revisit with traction. The own tap covers the need.
- **npm wrapper** — a `bin`-shim so JS-ecosystem agents can `npx svault`; only if
  real demand appears.

> Website hub: `svault.soluzy.app` hosts `install.sh` and a tabbed install block
> (brew / curl / cargo / docker).

### 3. Remaining polish — Planned

Final documentation, UX, and consistency passes surfaced during the review and
distribution work.

## Beyond 1.0.0

These are deliberately sequenced after a stable, audited CLI.

### 2.0.0 — Desktop GUI (Tauri)

`svault-gui`, a cross-platform desktop app (macOS, Linux, Windows) built with
Tauri — lightweight, single binary, offline, no runtime deps. Planned surface:

- Vault dashboard (list, lock/unlock state, last accessed).
- Lock/unlock panel and visual auto-lock settings (idle timeout, hard-max cap).
- Session monitor with an auto-lock countdown.
- Secret management (names only, never values; add/remove).
- Policy viewer (what a caller can access, from the unlocked vault's encrypted
  policy) and an audit-log viewer.
- System-tray status, notifications, and a settings UI (daemon socket path, log
  level).

### 3.0.0 — AI-platform access (MCP)

- `svault mcp` — an MCP server exposing `svault_get_secret(name, scope, reason)`,
  routed through the same enforced gate.
- `svault install` — auto-detect the platform and write MCP config.
- **Claude Code** — MCP server plus a PreToolUse hook (blocks direct `.env`
  reads) and a PostToolUse hook (scans output for leaked credentials).
- **Cursor, Copilot, VS Code, Aider** — MCP server.
- `--project` flag — project-scoped, git-committable install.

### Cloud anomaly-scoring tier (optional)

A hosted endpoint (e.g. `svault.soluzy.net/api/score`) that scores request
justifications for anomaly detection, with optional paid plans for higher
volumes and a shared audit dashboard. Optional and post-1.0.

## Deferred / not planned

- **Extra unlock methods** (YubiKey HMAC-SHA1, TOTP, macOS Touch ID / Face ID) —
  designed but deferred; passphrase is the supported method today. The intended
  UX is multi-select at create time (any combination) with method config in
  `meta.yaml`.
- **External backends** (cloud / self-hosted / S3) — `local` is the only wired
  backend; the others are recorded placeholders in `meta.yaml` for future remote
  sync.
- **Secret rotation.**
- **Windows daemon** — the daemon is Unix-only (Unix socket + `setsid`); Windows
  uses the file-session fallback.
- **Linux biometrics** — would need libpam + libfprint.

## Stack

- **Rust** — single native binary, no runtime dependencies.
- `clap` — CLI argument parsing.
- `ratatui` + `crossterm` — interactive terminal UI; `console` + `dialoguer` for
  non-TUI prompts.
- `aes-gcm` — AES-256-GCM encryption.
- `argon2` — Argon2id key derivation (GPU-resistant).
- `hmac` + `sha2` — HMAC-SHA256 `meta.yaml` integrity and checksums.
- `zeroize` — secrets wiped from memory on drop.
- `ureq` (bundled rustls) — synchronous OpenRouter calls for the AI judge.
- `libc` (Unix) — `setsid` to detach the daemon, `getpeereid` for the peer-UID
  bond, `sigaction` for shutdown signals.

Planned for later milestones: `tauri` + `serde_json` (2.0.0 GUI), and the
deferred auth crates (`totp-rs`, `qrcode`, `yubico`, `security-framework`).

## Run locally

```bash
cargo build --release
./target/release/svault --help
cargo test
```
