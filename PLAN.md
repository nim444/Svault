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

> Shipped versions are tracked in [CHANGELOG.md](CHANGELOG.md); the public-facing
> roadmap lives in [docs/roadmap.md](docs/roadmap.md). This file is the detailed
> internal build plan.

### [DONE] Step 1 — Local encrypted vault
- [x] `svault create` — interactive setup: storage backend (local default; Soluzy cloud / self-hosted / S3 — placeholders, coming soon) / name / description / allow_agent / rate_limit / auto-lock / auto-lock timer (default 1d) / login method / passphrase (`init` kept as alias)
- [x] Storage backend recorded in `meta.yaml` (`storage:`) and shown as a `storage:name` prefix in `svault vaults` / `svault status` / TUI; vault names must be unique (duplicate create rejected)
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

#### [DONE] Docs reorganization
- [x] README rebuilt as a lean landing page — badges, doc index table, collapsible `<details>` sections, Mermaid diagrams (overview, policy pipeline, architecture)
- [x] Long-form docs split into `docs/` — `installation`, `tui`, `commands`, `policy-engine`, `storage-backends`, `security`, `architecture`, `roadmap`
- [x] `CHANGELOG.md` added (Keep a Changelog + SemVer)

### [DONE] Step 2 — Policy engine
- [x] `svault.policy.yaml` — committable root file defining callers (scopes + rate limit) and per-vault secret scope/tier; `svault policy init` scaffolds it
- [x] `svault get <NAME> --scope <S> --reason "<R>" [--caller C]` — structured request; caller from `--caller`, else `$SVAULT_CALLER`, else `default`
- [x] Policy checks: reason present → capability (scope) check → tier → rate limit → burst detection
- [x] Sensitivity tiers: `low` (auto-approve) / `medium` (allow + flagged in audit) / `high` (denied for agents — humans use `secret get`)
- [x] `svault policy check <caller>` — show scopes, accessible secrets, rate limit, recent activity
- [x] Append-only audit log at `.svault/<vault>/audit.log` (gitignored); fallback to `meta.yaml` `allow_agent`/`rate_limit` when no policy file
- [x] 15 new unit tests (audit + policy) — suite now 33, all passing

### [DONE] Step 3 — Daemon + recovery

> Rescoped: the extra auth methods (YubiKey, TOTP, Touch ID/Face ID) are **deferred** to a later step. Step 3 delivered recovery and the daemon; both are shipped.

#### [DONE] Recovery — code + export/import
- [x] Recovery code generated at `svault create` (160-bit), vault key wrapped under it in `recovery.enc` (committable/portable, like `vault.enc`)
- [x] `svault recover [VAULT]` — unlock with the code and reset a lost passphrase (re-keys `vault.enc`, re-signs `meta.yaml`, re-wraps `recovery.enc`; code stays stable)
- [x] `svault export [VAULT] [--out FILE]` / `svault import <FILE>` — portable, checksummed (`sha256`) encrypted bundle; import refuses to overwrite an existing name
- [x] `VaultKey::from_bytes` + `Vault::open_with_key` (Argon2-free open path, reused by recovery and the upcoming daemon)
- [x] 10 new tests (key-from-bytes, open-with-key, re-key, recovery write/unlock + wrong code, export checksum) — suite now 44

#### [DONE/DEFERRED] original Step 3 checklist
- [ ] **Multi-select auth at init** — *(deferred)* `svault init` prompts user to choose/combine auth methods:
  - [ ] Passphrase (always available, works everywhere)
  - [ ] YubiKey (HMAC-SHA1 challenge-response, hardware-backed)
  - [ ] Google Authenticator (Time-based OTP, TOTP, phone-based)
  - [ ] Touch ID / Face ID (macOS Keychain, biometric unlock)
  - [ ] Users can enable any combination (e.g., Passphrase + YubiKey, Passphrase + OTP, Touch ID + Passphrase, all four)
  - [ ] Store auth config in `meta.yaml` (which methods are enabled for this vault)
- [x] **Real daemon (Unix)** — `svault daemon run|start|stop|status|doctor`; unlock once, keys held in memory, served over a `0600` Unix socket, no `.session` file while up. `daemon doctor` health-checks liveness / socket perms / stale files. Windows falls back to the file session. See [docs/daemon.md](docs/daemon.md).
- [x] **Auto-lock** — idle timeout (default 15 min, reset on read) + hard-max cap (default 8h), configurable in `.svault/config.yaml`; ticker evicts + zeroizes expired keys.
- [x] **Source/surface tracking** — `usage.log` + `audit.log` record a `source` (`cli`/`tui`/`gui`/`mcp`) alongside the actor; TUI activity view shows a VIA column.
- [x] 9 new tests (daemon protocol/auto-lock/integration/concurrency + usage source stamping) — suite now 74.
- [ ] `svault unlock` — interactive prompt shows enabled methods, user selects which to use *(deferred — tied to the extra auth methods above)*
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
- [x] Auto-lock: idle timeout (default 15 min) — reset on every secret request *(daemon)*
- [x] Hard max lock (default 8h) — re-locks unconditionally regardless of activity *(daemon)*
- [x] On lock: secrets wiped from memory immediately (`zeroize`) *(daemon keys are `Zeroizing`)*
- [x] Both timers configurable in `.svault/config.yaml`

### [DONE] Security hardening (0.6.0)

> Acts on the 0.5.0 security-review register. Full carry-forward status for all
> 22 findings is in [docs/security-review/findings/0.6.0.md](docs/security-review/findings/0.6.0.md);
> the logged stress run is in [docs/security-review/stress/0.6.0.md](docs/security-review/stress/0.6.0.md).

- [x] **#4 — session caches the derived key, not the passphrase** — `.session` now stores the 32-byte derived key (hex, mode 0600) on every platform incl. the TUI; a stolen session no longer leaks the reusable passphrase. *(Remaining: Windows ACL/DPAPI + route TUI through the daemon — deferred.)*
- [x] **#8 — daemon connection ceiling** — configurable `daemon.max_connections` (default 512) + 30s per-connection read timeout + slot accounting that survives panics. Validated by a logged concurrency stress simulation (128k concurrent reads, 0 wrong values).
- [x] **#13 — daemon survives a poisoned mutex** — key-store lock taken with poison recovery so a panicking handler can't down the daemon.
- [x] **#20 — truncated `vault.enc` errors instead of panicking** — checked length guard on the salt slice.
- [x] **Connect resilience** — `daemon::send` retries the socket connect with short backoff (absorbs OS listener-backlog drops under burst).
- [x] Suite now 82 (+1 ignored stress benchmark); clippy clean.

### [DONE] Security-review hardening (0.7.0)

> Acts on the 0.7.0 review register ([findings/0.7.0.md](docs/security-review/findings/0.7.0.md)).

- [x] `cargo audit` CI gate + `ratatui` 0.30 (#9/#10); client-side key derivation so the passphrase never crosses the socket (#3); daemon peer-UID bond (#1); owner-only files/dirs + atomic socket (#14/#16); graceful shutdown (#17); zeroized secrets (#6); release checksums + SLSA provenance (#11); passphrase entropy floor (#12).

### [DONE] Review-response (0.8.0)

- [x] Owner-only TUI export (N-3) + import dir (N-4); `0600` rotated `daemon.log` (N-10); daemon transport zeroization (N-6); `sigaction` shutdown signals (N-9). Idempotent `release.yml` publish step.

### [DONE] Enforced policy engine + AI judge (0.9.0)

> The headline release: the policy engine moves from advisory to **enforced**, and the AI judge lands. Closes #2/#5/#22 + N-1/N-2/N-5.

- [x] **Policy + audit inside the daemon** — the agent path is a `GetGated` request; the daemon evaluates policy, consults the judge, audits (stamped with the unforgeable **peer UID**), then returns a value. The socket is the single choke point; the CLI runs the identical gate locally when no daemon is up. No unguarded read path (#2, N-1, N-5).
- [x] **Signed per-secret classification** — `scope`/`tier`/`require_reason` live in the HMAC-signed `meta.yaml` (`svault secret add --scope --tier --require-reason`), so a same-UID attacker can't downgrade a tier without the key (#5/#22). Vault create sets a `default_tier` + per-vault judge toggle.
- [x] **Anchored, fail-closed policy discovery** — `svault.policy.yaml` holds callers only; discovery stops at the project root (#5); an unparseable policy denies rather than allow-all (N-2).
- [x] **AI judge (OpenRouter)** — blocking `ureq` (bundled rustls, no async), default `google/gemini-2.5-flash`; tier-dependent fail modes (medium fail-open + audit flag, high fail-closed). Off until a key is configured. Manage the key with `svault judge set-key` / `status` / `remove-key` (0600 file or `$SVAULT_OPENROUTER_KEY`); `svault judge test` dry-runs setup. New modules `gate.rs` + `judge.rs`.
- [x] Suite now 98 (+1 ignored stress benchmark); clippy + `cargo fmt --check` clean.

### [DONE] Policy + judge in the TUI (0.9.1)

> Surfaces the 0.9.0 engine in the interactive UI — no new security surface, it manages the same signed meta + `0600` key file the CLI does.

- [x] **`J` judge-management screen** — toggle the judge globally, edit model / allow- & high-thresholds / timeout (persisted via new `SvaultConfig::save()` → owner-only `.svault/config.yaml`), set the OpenRouter key (masked entry → `0600`), remove it (`Del`), and run a live `test`.
- [x] **Per-secret classification in the browser** — secrets render as a table (`TIER · SCOPE · REASON? · DESCRIPTION`); `c` reclassifies a secret (re-signs `meta.yaml`, value untouched).
- [x] **`svault judge enable` / `disable`** — CLI parity for the global switch; `svault create` nudges what's still needed when a vault opts into the judge.
- [x] **Audit** — `secret.classify` + global `judge.config`/`judge.key.set`/`judge.key.remove` events; the activity timeline folds the global events in. Suite now 101; clippy + `cargo fmt --check` clean.

### [DONE] Policy encrypted at rest (0.9.2)

> Closes the policy-reconnaissance path. Through 0.9.1 only secret *values* were
> encrypted; the whole policy surface sat in the plaintext (HMAC-signed)
> `meta.yaml` plus the committable `svault.policy.yaml`, so a same-UID agent could
> *read* every tier/scope/description/caller and craft a request designed to pass.
> Honest boundary: this defeats reading the files to plan a bypass; it is **not** a
> sandbox against a hostile same-UID process reading the unlocked daemon's memory.

- [x] **Policy moved into the encrypted payload** — per-secret classification (scope/tier/`require_reason`/description), `allow_agent` + `rate_limit`, the per-vault judge override, `default_tier`, and **caller rules** all live in `policy::VaultPolicyData`, stored AES-256-GCM-encrypted inside `vault.enc` (`VaultPayload { version: 2, secrets, policy }`). The public `meta.yaml` now carries only non-sensitive metadata (name, description, storage, created-at, version, settings) and stays HMAC-signed.
- [x] **Caller rules are per-vault and encrypted** — the committable `svault.policy.yaml` is gone; `svault policy init` seeds callers into a vault's encrypted policy and `svault policy check <caller>` unlocks the vault to read them.
- [x] **Generic denials to the caller** — every denied `svault get` returns the single opaque `gate::GENERIC_DENY` string (`denied: request not authorized for this secret`); the real reason (judge score + rationale, scope/caller mismatch, rate limit) is recorded only in the audit log.
- [x] **Policy view/edit requires an unlocked vault** — `svault settings`, `svault secret add`, the TUI classification table, and `svault policy check`/`init` all open the vault first; the vault list no longer shows allow-agent / rate-limit columns.
- [x] TUI judge-management shortcut labelled **`shift-J`** (`j` is list-down).
- [x] On-disk payload bumped to **v2**; no migration (no released users) — vaults are created fresh. Suite now 103 (+1 ignored stress benchmark); clippy + `cargo fmt --check` clean.

### [TODO] 2.0.0 — GUI client (Tauri)
> Version plan: the CLI is hardened to a stable **1.0.0** first; the GUI is a
> deliberate **2.0.0**, and Claude / AI-platform access is **3.0.0**. 0.7.0+ is
> security hardening (see the [findings register](docs/security-review/findings/0.6.0.md)).
- [ ] `svault-gui` — cross-platform desktop app (macOS, Linux, Windows)
  - [ ] **Vault dashboard** — list all vaults, show lock/unlock status, last accessed
  - [ ] **Lock/unlock panel** — quick unlock with selected auth methods (passphrase, biometric, etc.)
  - [ ] **Auto-lock settings** — visual controls for idle timeout (default 15 min) and hard max lock (default 8h)
  - [ ] **Session monitor** — show active sessions, locked/unlocked state, auto-lock countdown timer
  - [ ] **Secret management** — view secret names (never values), add/remove secrets with GUI
  - [ ] **Policy viewer** — inspect what a caller can access (from the unlocked vault's encrypted policy)
  - [ ] **Status notifications** — system tray icon, notifications for lock/unlock, timeouts
  - [ ] **Settings UI** — configure Svault defaults, daemon socket path, log level
  - [ ] **Audit log viewer** — see who accessed what (from policy logs)
  - [ ] Built with Tauri: lightweight, single binary, works offline, no runtime deps

### [TODO] 3.0.0 — Claude / AI-platform access (MCP)
- [ ] `svault mcp` — start MCP server exposing `svault_get_secret(name, scope, reason)`
- [ ] `svault install` — auto-detect platform, write MCP config
- [ ] Claude Code: MCP server + PreToolUse hook (blocks direct `.env` reads) + PostToolUse hook (scans output for leaked credentials)
- [ ] Cursor, Codex, Copilot, Aider, VS Code: MCP server
- [ ] `--project` flag — project-scoped install, files are git-committable
- [ ] GUI client integration — optional: Svault GUI can show active MCP sessions

### [IN PROGRESS] Distribution — install channels

> All channels reuse the four prebuilt binaries the release workflow (`release.yml`, on `v*` tags) already produces — macOS arm64/x64, Linux x64, Windows x64 — so most are low-effort. **crates.io is shipped** (`cargo install svault-ai`). Standing constraint: Claude does **not** run `cargo publish` or push to external registries — the user publishes manually.

#### [DONE]
- [x] **crates.io** — published as `svault-ai`, binary `svault` (`cargo install svault-ai`, builds from source)
- [x] **GitHub Releases** — `release.yml` builds + uploads 4 target archives on each `v*` tag (the artifact source every channel below points at)

#### [TODO] First pass (Mac / Linux / Rust users + agents)
- [ ] **Install script** — `install.sh`: detect OS + arch, resolve latest (or pinned) release, download the matching archive, verify, extract `svault` onto PATH. Served from `svault.soluzy.app/install.sh`; usage `curl -fsSL https://svault.soluzy.app/install.sh | sh`. The primary install link in README + website.
- [ ] **cargo-binstall** — add `[package.metadata.binstall]` to `Cargo.toml` mapping the `pkg-url`/`pkg-fmt` to the release asset naming, so `cargo binstall svault-ai` fetches a prebuilt binary instead of compiling. Near-zero effort; verify against an actual tag's asset names.
- [ ] **Homebrew tap** — create `Soluzy/homebrew-tap` repo with `Formula/svault.rb` (downloads the release tarball, per-arch `url`+`sha256`). Add a CI job (in `release.yml` or the tap repo) to auto-bump the formula version + checksums on each `v*` tag. Install: `brew install soluzy/tap/svault`. Use an **own tap**, not homebrew-core.
- [ ] **Docker image** — `Dockerfile` (`FROM debian:slim` + copied Linux binary, or `scratch`/`distroless` for static); push to `ghcr.io/soluzy/svault` on each tag via a release-workflow job. Targets the AI-agent / CI use case (agents and pipelines run in containers).

#### [TODO] Later (niche audiences, more upkeep)
- [ ] **Scoop** (Windows) — manifest in an own bucket repo (`Soluzy/scoop-bucket`); easier than WinGet.
- [ ] **WinGet** — manifest PR to `microsoft/winget-pkgs` per release; broader Windows reach.
- [ ] **AUR** (Arch) — `PKGBUILD` (`-bin` package pointing at the release binary).
- [ ] **Nix** — flake output and/or a nixpkgs derivation.

#### Deliberately skipped (for now)
- [ ] **homebrew-core** and other official/curated repos — notability + age bar rejects young projects; revisit once there's traction. Own tap covers the need meanwhile.
- [ ] **npm wrapper** — a `bin`-shim package so JS-ecosystem agents can `npx svault`; only if real demand appears.

> Website hub: `svault.soluzy.app` hosts `install.sh` and a tabbed Install block (brew / curl / cargo / docker), the standard CLI landing-page pattern.

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

## Build sequence (by version)

Done: Step 1 (vault) · Step 1+ (TUI) · Step 2 (policy engine) · Step 3
(daemon + recovery) · 0.6.0–0.8.0 (security hardening) · 0.9.0 (enforced policy
engine + AI judge) · 0.9.1 (policy + judge in the TUI) · 0.9.2 (policy encrypted
at rest, generic denials).

1. **→ 1.0.0** — a final independent review of the enforced, encrypted-policy
   engine plus the install channels below → the first stable, audited CLI.
   **(current focus)**
2. **2.0.0** — GUI client (Tauri desktop app for vault management)
3. **3.0.0** — Claude / AI-platform access: MCP server + platform hooks
   (Claude Code, Cursor, Copilot, VS Code, Aider)
4. **Cloud tier** (optional) — justification scoring + premium plans

## What's NOT planned (yet)

- External backends (Vaultwarden, Infisical, AWS SM — v0.2)
- Secret rotation
- Windows daemon — the daemon is Unix-only (Unix socket + `setsid`); Windows uses the file session fallback (CLI is otherwise fully supported and tested on Windows in CI)
- Linux biometric support (fingerprint readers — possible future, needs libpam + libfprint)

## Run locally

```bash
cargo build --release
./target/release/svault --help
cargo test
```
