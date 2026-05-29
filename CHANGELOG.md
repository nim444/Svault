# Changelog

All notable changes to Svault are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2026-05-29

### Added
- **Background daemon (Unix)** — `svault daemon start | stop | status | doctor | run`. An opt-in local process that holds unlocked vault keys **in memory** and serves secret reads over a `0600` Unix socket (`.svault/daemon.sock`), replacing the on-disk `.session` while it's running. Keys are zeroized on lock, on auto-lock, and on shutdown. See [docs/daemon.md](docs/daemon.md).
  - **Auto-lock** — idle timeout (default 15 min, reset on each read) and a hard-max cap (default 8 h), both configurable in `.svault/config.yaml`. A background ticker evicts and zeroizes expired keys.
  - **`daemon doctor`** — health check: daemon liveness + pid, socket presence and `0600` permissions, effective timeouts, and detection of stale socket / pid files left by a crash. `--fix` cleans them up; exits non-zero when unhealthy.
  - **Daemon-aware commands** — when a daemon is running, `unlock` caches the key in it (no `.session` file written), and `get` / `secret get` are served from memory with no prompt; `status` shows `unlocked (daemon)`; `lock` / `lock --all` drop keys from both the daemon and any file session.
  - **TUI integration** — the interactive UI shows a `daemon running` / `daemon off` indicator in the header, and `d` on the vault list starts / stops the daemon.
  - **Concurrency** — one thread per connection; a `Get` holds the shared lock only long enough to copy the key and bump the last-used timestamp, decrypting outside the lock so parallel reads don't serialize.
- **Source/surface tracking in the logs** — `usage.log` and `audit.log` now record a `source` field (`cli` / `tui` / `gui` / `mcp`) alongside the actor (human/agent). Together they distinguish a human at the CLI, a human in the TUI, an agent via the CLI, and (later) a GUI or MCP caller. The TUI activity view (`v`) gains a **VIA** column; events from before this change show `-`.

### Changed
- The daemon is **Unix-only**. On Windows, `svault daemon <...>` reports that it's Unix-only and all other commands fall back to the file session unchanged.
- `secret add` / `secret list` / `secret remove` still prompt for the passphrase even when the daemon is up — the daemon deliberately holds only the key (not the passphrase) and exposes no write operations over the socket.

### Internal
- New `daemon` and `client` modules; `libc` added as a Unix-only dependency (`setsid` to detach, `kill` for liveness / stop).
- 7 new tests (protocol JSON roundtrips, idle / hard-max / active auto-lock decisions, a unix unlock→get→lock→shutdown integration test, and a 16-thread concurrent-reads stress test) — suite now 72.

## [0.4.0] - 2026-05-29

### Added
- **Usage log + activity view** — every vault now keeps a per-vault `usage.log` (JSON lines, owner-only, gitignored) recording human and agent activity (unlock, lock, secret add/get/reveal/remove, create, export, import, recover, settings, and agent `get.allow`/`get.deny`). It never stores secret values. Press `v` on a vault in the TUI for a read-only timeline (WHEN / ACTOR / ACTION / TARGET, agents highlighted). This is groundwork for later usage analysis.
- **CREATED column** in the TUI vault table, from each vault's `created_at`.
- **TUI help overlay** — press `?` on the vault list or in the secret browser for an on-screen keybinding cheat sheet.
- **Quit confirmation** — `q` / `Esc` on the vault list (or `q` in the secret browser) now asks before exiting: `enter` quits, any other key stays.
- **Paste support** — bracketed paste works in every TUI text field (passphrases, recovery codes, bundle paths); newlines are stripped so a multi-line paste can't break the layout.
- **Block cursor** — the focused text field shows a solid cursor block (even when empty) so it's obvious where typed/pasted text lands.

### Changed
- **Vault list is now a real table** with STORAGE / VAULT / STATUS / DESCRIPTION columns and a clean selection highlight, replacing the single packed line whose per-cell reverse-video highlight looked garbled.
- **TUI status line** — transient `ok` / `warning` / `error` / `note` messages moved out of the title bar into a dedicated line below the body.
- **Readable empty states** — the "No vaults yet" / "No secrets yet" placeholders are now a high-contrast heading plus a readable hint instead of hard-to-read dark gray.
- **Clearer field label** — the create/recover forms label the second passphrase field "Confirm passphrase" (was just "Confirm").
- **Honest pickers** — the create and settings forms no longer offer non-functional Storage (cloud / self-hosted / S3) and Login (yubikey / google) choices that were silently coerced to `local` / `passphrase`. Storage and login are shown as a static note instead; the roadmap items live in the docs.
- **Recovery code is shown as typed** (not masked) on the TUI recover form, so a mistype while copying it from paper or a password manager is visible.
- Centralized TUI colors into a single theme module for a consistent look.

### Fixed
- Pressing `space` while editing the **Rate limit** field in the TUI create form no longer secretly toggles auto-lock (an off-by-one in the focus handling). Form focus now uses named field enums so the draw order and key logic can't drift apart.
- **TUI export** now reports the full absolute path of the written bundle instead of a bare filename, so the file is easy to find.

### Internal
- Added unit tests for TUI key dispatch and field logic (no terminal required), covering the bug fix and navigation/paste/help behavior.

## [0.3.0] - 2026-05-29

### Added
- **Recovery code** — `svault create` now generates a one-time 160-bit recovery code and stores the vault key wrapped under it in `recovery.enc`. `svault recover` uses the code to reset a lost passphrase (re-keys the vault; the code stays valid). Part of Step 3.
- **Export / import** — `svault export` writes a portable, checksummed JSON bundle of an encrypted vault (`meta.yaml` + `vault.enc` + `recovery.enc`); `svault import` verifies the checksum and restores it on another machine, refusing to overwrite an existing vault name.
- **TUI support** — the recovery code is shown once on its own screen after create and requires an explicit `y` confirmation that it was saved; the vault list gains `e` export, `i` import, and `r` recover, mirroring the CLI.

### Security
- The recovery code is displayed once and never stored in plaintext; both the CLI and TUI now require an explicit acknowledgment that it was saved before continuing.

## [0.2.1] - 2026-05-29

### Added
- **Storage backends** — pick where a vault lives at create time: `local` (default, the only one wired today) plus `cloud`, `self-hosted`, and `s3` placeholders for upcoming remote sync. Selectable in both `svault create` and the TUI create form.
- `storage:name` prefix shown everywhere a vault is listed (`svault vaults`, `svault status`, the TUI) so vault identity is unambiguous per backend.
- `CHANGELOG.md` (this file).

### Changed
- **Documentation revamp** — the README is now a lean landing page (badges, doc index, collapsible sections, Mermaid diagrams) and the long-form content moved into a dedicated `docs/` folder (`installation`, `tui`, `commands`, `policy-engine`, `storage-backends`, `security`, `architecture`, `roadmap`).
- `storage` is now a required field on `meta.yaml` — vault names must be unique, and creating a duplicate name is rejected.

### Removed
- Backward compatibility for vaults created before the `storage` field existed (Svault is in beta — re-create affected vaults).

## [0.2.0] - 2026-05-29

### Added
- **Policy engine (Step 2)** — `svault get` is the agent path: a structured request an AI must justify, run through a pipeline (caller identity → required reason → scope capability check → sensitivity tier → rate limit + burst detection → audit log).
- Committable `svault.policy.yaml` at the project root defining callers (scopes + rate limit) and per-vault secret scope/tier; `svault policy init` scaffolds it.
- Sensitivity tiers — `low` (auto-allow), `medium` (allow + flagged in audit), `high` (denied for agents).
- `svault policy check <caller>` — show a caller's scopes, accessible secrets, rate limit, and recent activity.
- Append-only, gitignored audit log at `.svault/<vault>/audit.log`; falls back to `meta.yaml` `allow_agent` / `rate_limit` when no policy file is present.

## [0.1.1] - 2026-05-29

### Added
- **Interactive TUI (Ratatui)** — run `svault` with no subcommand for a full-screen dashboard: vault list with live lock state, form-based create, lock-aware unlock/lock, settings editor, and a secret browser (add / view / delete) once a vault is unlocked.
- `svault create` (with `init` kept as an alias) and `svault settings` commands; per-vault targeting via positional name or `-v/--vault`.
- CI across Ubuntu, Fedora, macOS, and Windows, plus a release workflow; status and crates.io badges in the README.

## [0.1.0] - 2026-05-28

### Added
- **Local encrypted vault (Step 1)** — AES-256-GCM encryption with Argon2id key derivation (GPU-resistant).
- HMAC-SHA256 signed `meta.yaml` — tampering is detectable.
- `ZeroizeOnDrop` on the vault key and secret store — secrets wiped from memory on drop.
- `svault secret add | get | list | remove`, session-based lock/unlock, and `svault status`.
- Per-vault `.gitignore` written at init so `.session` is never committed; `vault.enc` + `meta.yaml` are safe to commit.
- Published to crates.io as [`svault-ai`](https://crates.io/crates/svault-ai).
