# Changelog

All notable changes to Svault are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.0] - Unreleased

The **enforced policy engine** release — closes the advisory-policy gap that all
three 0.7.0 reviews named as the 1.0.0 blocker (#2/#5/#22, review N-1/N-2/N-5) —
plus the **AI judge**, Svault's behavioural gate.

### Added
- **AI judge (OpenRouter)** — for medium/high-tier secrets (and any secret flagged `require_reason`), the daemon asks a cheap, fast LLM whether the caller's stated *reason* plausibly justifies the request, given the secret's scope/tier and the caller's recent activity. Configurable model (default `google/gemini-2.5-flash`), thresholds, and timeout in `.svault/config.yaml` `[judge]`. The key comes from `$SVAULT_OPENROUTER_KEY` or a `0600` key file — never committable config. **Off until a key is configured**, so upgrading never silently calls an external API. Synchronous (`ureq`, bundled rustls — no async runtime). Manage the key with `svault judge set-key` (hidden prompt or stdin → `0600` file), `svault judge status` (resolves the source without printing the key), and `svault judge remove-key`; `svault judge test [--vault --vault-description --description ...]` dry-runs a sample request against the live model without touching a secret.
- **Per-secret classification in the signed `meta.yaml`** — each secret carries a `scope`, `tier` (low/medium/high), `require_reason`, and an optional `description`, set via `svault secret add [--scope --tier --require-reason --description]` or interactively (and in the TUI add form). The **description** records what the secret is for and is given to the AI judge as context, so a request whose reason doesn't fit the secret's purpose is denied; the vault's own description is included too. Because it's HMAC-signed, a same-UID attacker can't downgrade a tier without the vault key (#5/#22). Vault creation now also sets a `default_tier` and a per-vault judge toggle.

### Changed
- **Policy is now enforced inside the daemon.** The agent path (`svault get`) sends a structured `GetGated` request; the daemon evaluates policy, consults the judge per tier, audits the decision, and only then returns a value — the socket is the single choke point (#2). The CLI runs the identical gate locally when no daemon is up. There is no longer an unguarded read path.
- **Tiers, with the judge on:** low = auto-allow; medium = judge-gated, **fail-open** + audit-flag if the judge is unavailable; high = judge-gated, **fail-closed**. With the judge **off**, behaviour is the pre-0.9.0 rule (high = human-only), so nothing regresses.
- **Audit trail** now records every daemon read (human and agent) stamped with the connecting process's **peer UID** — unforgeable, unlike the self-asserted caller string (N-1) — closing the unaudited-daemon-read gap (N-5).
- The policy file (`svault.policy.yaml`) now holds **caller definitions only**; secret classification moved to the signed meta. Discovery is **anchored to the project root** (no unbounded upward walk, #5) and a present-but-unparseable policy now **fails closed** (N-2).

## [0.8.0] - 2026-05-30

A security-review-response + hardening release. Acts on the three independent
0.7.0 model reviews (`docs/security-review/reviews/0.7.0-*.md`), consolidated with
maintainer dispositions in `docs/security-review/findings/0.7.0.md`. All three
re-confirmed the advisory-policy gap (#2/#5/#22) as the 1.0.0 blocker; that policy
work is **deferred to 0.9.0** (not dropped) so this stays a clean hardening
release. Everything else the review surfaced is addressed here.

### Fixed
- **Owner-only TUI export** (review N-3) — the TUI export wrote the bundle (which wraps the vault key) with the default umask, leaving it potentially world-readable; it now uses `secfile::write_owner_only` like the CLI path.
- **Owner-only import directory** (review N-4) — importing a bundle created the vault directory with the default `0755`; it is now `0700` (`secfile::create_dir_owner_only`), matching `Vault::init`. Regression test added.
- **`daemon.log` rotated file is `0600`** (review N-10) — the log is opened with mode `0600` so a rotated/recreated file is never group/other-readable (it already sat inside the `0700` `.svault/`).
- **Daemon transport zeroization** (review N-6) — the serialized reply buffer and the in-memory `Response::Secret` value are now wiped (`zeroize`) after the secret is written to the socket, instead of lingering in freed heap.
- **`sigaction` for shutdown signals** (review N-9) — SIGTERM/SIGINT handlers are installed via `libc::sigaction` (zeroed mask, `SA_RESTART`) rather than the legacy `signal()`, for well-defined semantics across Unix variants.

### Deferred (gates 1.0.0)
- Policy engine as an enforced control: evaluate policy + write the audit record inside the daemon `Get` path (#2/#5, review N-1/N-2/N-5/#22), authenticate the caller, sign/pin `svault.policy.yaml`, and fail closed on an unparseable policy. This is the last substantive gap before a 1.0.0 "stable CLI" label and is scheduled for 0.9.0.

## [0.7.0] - 2026-05-29

Continued security hardening on the road to a stable 1.0.0 CLI (GUI is planned
for 2.0.0, Claude/AI-platform access for 3.0.0). Acts on the 0.6.0 review
carry-forward (`docs/security-review/findings/0.6.0.md`).

### Added
- **Supply-chain CI gate** (#9) — a `cargo audit` job in `lint.yml` fails CI on any RustSec advisory (vulnerability, unsound, or unmaintained) across the dependency tree.
- **Passphrase entropy floor** (#12) — `create` and `recover` now require a passphrase to clear a ~50-bit entropy estimate (`passphrase::entropy_bits`), re-prompting until it does; a `--force` flag overrides for non-interactive use. The TUI create/recover forms enforce the same floor.
- **Release-artifact integrity + provenance** (#11) — each release archive ships a matching `<archive>.sha256`, plus a signed SLSA build-provenance attestation (`actions/attest-build-provenance`, verifiable with `gh attestation verify`).
- **Daemon peer-UID bond** (#1) — the daemon checks `getpeereid` on each connection and refuses any peer whose UID isn't our own, on top of the `0600` socket.

### Changed
- **`ratatui` 0.29 → 0.30** (#10, crossterm 0.28 → 0.29) — pulls a fixed `lru` and drops the unmaintained `paste` crate, so `cargo audit` is now clean. No source changes were needed.
- **Daemon key handling — passphrase never crosses the socket** (#3) — `Unlock` now carries the hex-encoded 32-byte derived key. The client derives + validates the key locally (a wrong passphrase fails before any socket traffic); the daemon re-validates it with `open_with_key` before caching.
- **Owner-only at-rest files** (#14, #16) — `recovery.enc`, export bundles, and the `.session` key are written owner-only (mode `0600` on Unix, an `icacls` owner-only ACL on Windows — the latter also closes the Windows half of #4). `.svault/` and vault dirs are created `0700`, and the daemon socket is bound under a `0077` umask so it's born `0600` (no TOCTOU window).

### Security
- **Zeroized secrets in memory** (#6) — passphrase / recovery-code / secret-value prompts and `get_secret`'s return are `Zeroizing<String>`, and the TUI reveal modal holds the secret in `Zeroizing`, so these heap copies are wiped on drop (the bulk decrypted store was already zeroized via `SecretStore`).
- **Graceful daemon shutdown** (#17) — `SIGTERM`/`SIGINT` now trigger an orderly shutdown that zeroizes keys and cleans up the socket/pid files (instead of an abrupt terminate); `daemon.log` rotates past ~5 MB.

### Internal
- New `secfile` module (owner-only file/dir writes). Suite now 84 (+ 1 ignored benchmark); `cargo audit`, `cargo fmt`, and `cargo clippy -D warnings` all clean across Linux/macOS/Windows/Fedora CI.

> **Not in this release:** policy enforcement in the daemon + a signed/pinned policy file (#2/#5) — the policy layer remains advisory/audit-only for now and is the next iteration's focus.

## [0.6.0] - 2026-05-29

Security-hardening release. Acts on the consolidated 0.5.0 review register
(`docs/security-review/findings/0.5.0.md`) and adds a logged concurrency stress
simulation. Carry-forward status for every 0.5.0 finding is recorded in
`docs/security-review/findings/0.6.0.md`.

### Added
- **Security review process** — `docs/security-review/` documents a release-gated security workflow: every `0.x.0` release gets one or more independent, model-agnostic security reviews (prompt in `docs/security-review/PROMPT.md`) plus a tooling/bulletproofing pass. For 0.5.0, five independent reviews (Grok 4.3, GLM-5-1, Gemini 3.5 Flash, DeepSeek-V4-Pro, Claude Opus 4.8) are recorded under `docs/security-review/reviews/`, with all findings de-duplicated into a consolidated decision register at `docs/security-review/findings/0.5.0.md`. Maintainer dispositions for all 22 findings are recorded and signed off in that register.
- **Configurable daemon connection ceiling** (finding #8) — `daemon.max_connections` in `.svault/config.yaml` (default 512) caps simultaneously-served connections so the thread-per-connection model can't be driven to spawn unbounded handler threads. Each connection also gets a 30 s read timeout so a stalled client can't pin a handler. A connection refused at the ceiling gets a `too many connections` error and the client falls back.
- **Concurrency stress simulation** — an `#[ignore]`d benchmark (`daemon_stress_simulation`) drives the real daemon under sustained parallel reads plus a connection flood, classifying every outcome (correct / busy-refused / connect-error / wrong) and logging latency percentiles + throughput. Methodology and a recorded run live in `docs/security-review/stress/0.6.0.md`. Run: `cargo test --release daemon_stress_simulation -- --ignored --nocapture`.

### Changed
- **TUI footer survives narrow windows.** The key-hint footer used to clip from the right on small terminals, hiding the "help" and "quit" hints entirely. It now falls back to a compact hint that always keeps `h/? help` visible, and the help overlay opens with **`h`** as well as `?`.
- **Import no longer errors when the name already exists.** Re-importing a bundle onto a machine that already has that vault now picks a free name by appending a suffix (`TUI-Vault` → `TUI-Vault-2`), or you can choose one with `svault import <file> --name <NEW>`. Since the vault name is part of the HMAC-signed `meta.yaml`, importing under a different name re-signs it and asks for the passphrase once to finish (a clean import under the original name still needs no passphrase). The TUI import flow does the same.
- **Session caches the derived key, not the passphrase** (finding #4) — the no-daemon `.session` fallback now stores the vault's 32-byte derived key (hex, mode 0600 on Unix) instead of the raw passphrase, on every platform including the TUI. A stolen `.session` still opens that one vault, but no longer leaks the reusable passphrase that may protect other vaults or services. The daemon (keys in memory, nothing on disk) remains the preferred path. Pre-0.6 sessions that cached a passphrase are treated as locked and require a re-unlock.

### Fixed
- **Daemon survives a poisoned mutex** (finding #13) — the key-store lock is now taken with poison recovery, so a panicking connection handler can no longer take down the whole daemon (and every key it holds) on the next lock.
- **Truncated `vault.enc` returns an error instead of panicking** (finding #20) — `save_secrets` length-checks the salt slice rather than `unwrap()`-ing it.
- **Daemon connect resilience** — `daemon::send` retries the socket connect a few times with short backoff, so a momentary OS listener-backlog drop under connect-churn surfaces as a served request rather than a hard error.

### Internal
- New `DaemonConfig` in `config.rs`; the connection ceiling is threaded through `serve`. Stress-classification and poison-recovery covered by new tests. Suite now 82 (+ 1 ignored benchmark).

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
