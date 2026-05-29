# Changelog

All notable changes to Svault are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
