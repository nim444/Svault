# Roadmap

Svault is a secret access layer for cooperative AI agents, built CLI-first. The
core is hardened and proven as a command-line tool before any wider surface is
added — a secret manager has to be trustworthy at its base first. The 0.9.x line
made that proven core **agent-ready**: a single way to unlock, conditional access,
anomaly defence that escalates to a human, and a local MCP surface. Each reuses
the existing daemon choke point rather than introducing a new trust model. A
desktop GUI comes only after 1.0.

For per-release detail, see [CHANGELOG.md](../CHANGELOG.md). For the build plan
(stack, step checklists, design notes), see [PLAN.md](../PLAN.md).

| Milestone | Status | Theme |
|---|---|---|
| Foundation (0.1 – 0.8) | Shipped | Encrypted local vaults, interactive TUI, Unix daemon, and a multi-release security-hardening track |
| Enforced policy + AI judge (0.9.0 – 0.9.1) | Shipped | The behavioural gate: daemon-enforced policy, peer-UID-stamped audit, and an AI judge for medium/high secrets — driven from both CLI and TUI |
| Everything-encrypted-at-rest (0.9.2 – 0.9.3) | Shipped | The entire policy surface and all global config moved into encrypted stores; no plaintext config or key files remain |
| Unified unlock (0.9.4 – 0.9.5) | Shipped | One master passphrase opens every vault (0.9.4) **and the keyring** (0.9.5) — per-vault and keyring passphrases removed; all keyslots over a random data key |
| Layered source (0.9.6) | Shipped | Source split into a frontend-agnostic `core` plus `cli` / `tui` / `daemon` frontends (a library crate), with `mcp` / `gui` placeholders — structural only, no behavior change |
| Agent surface — MCP (0.9.7) | Shipped | `svault mcp` — a local stdio MCP server exposing the gated `svault_get_secret` / `svault_list_vaults` tools to AI agents, with a capability descriptor that advertises the request interface, not the decision criteria |
| Hardware-key unlock + hardening (0.9.8) | Shipped | YubiKey (FIDO2 hmac-secret) unlock as an alternative keyslot (passphrase or touch, not 2FA); a 6-hour re-auth cap on every unlock path; a first-run onboarding flow with an app-level TUI sign-in / logout; storage is local-only and the docs are repositioned honestly |
| Conditional access + escalation (0.9.9) | Shipped | Time-window / caller conditions in the encrypted policy; repeated denials seal a secret and escalate to a human (`svault pending` / `approve`, TUI `A`); agents never self-clear |
| Independent security review | Shipped | Three independent external-model reviews of the full 0.9.9 surface (no Critical/High); the actionable findings fixed before 1.0 (`docs/security-review/`) |
| Stable release (1.0.0) | In review | The agent-ready layer consolidated, independently reviewed, and stabilized — the first stable release. Distribution channels (install script, Homebrew, Docker) follow post-1.0 |
| Desktop GUI (2.0.0) | In progress | Tauri vault manager + system tray — all 12 handoff screens built over the existing core/daemon (`gui-app/`, `docs/gui.md`) |

The agent-ready surface is complete and independently reviewed. **1.0.0 is the
consolidation of that work into the first stable release** — it is in a final
manual QA pass before tagging, not new scope.

## Shipped

### Foundation

A complete, self-contained secret manager that works fully offline:

- **Encrypted local vaults** — AES-256-GCM with Argon2id key derivation
  (GPU-resistant); secrets are zeroized in memory on drop.
- **Signed public metadata** — non-sensitive vault metadata is HMAC-SHA256
  signed, so tampering is detectable.
- **Interactive TUI** — a full-screen Ratatui dashboard for vault, secret, and
  policy management, with a live lock-state indicator and an activity timeline.
- **Recovery and portability** — a one-time master recovery code resets a
  forgotten master passphrase and reopens every store (`svault master recover`),
  per-vault codes recover a single vault (`svault recover`), and checksummed
  encrypted bundles move a vault between machines (`svault export` / `import`).
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
  single encrypted store, `.svault/keyring.enc`, opened by the master passphrase
  (`svault keyring init | unlock | lock | status`; as of 0.9.5 it has no separate
  passphrase). The former plaintext `config.yaml` and `openrouter.key` file are
  gone — **no plaintext config or key files remain.**
- **Multiple named judges** — the judge is a registry, not a single global
  setting (`svault judge add | edit | remove | list | set-default | set-key`).
  Each judge has its own model, thresholds, free-text criteria, and encrypted
  API key, and is fully managed from the TUI judge screen as well. A vault is
  assigned a judge by name (stored in its encrypted policy) and falls back to the
  keyring default.

**Honest boundary:** the at-rest encryption closes the read-the-files
reconnaissance path. It is **not** a sandbox against a hostile same-UID process
that reads the unlocked daemon's memory directly — that remains inherent to the
documented same-UID trust model.

## The agent-ready path (0.9.4 – 0.9.9, shipped)

These releases turned the proven core into something that sits safely in front of
day-to-day AI agents. They all extend existing primitives — the keyslot pattern
already in `recovery.rs`, the encrypted policy in `vault.enc`, and the
peer-UID-bonded daemon socket — rather than adding a new trust model.

### Unified unlock — one master passphrase (0.9.4 – 0.9.5, shipped)

Each vault used to have its own passphrase and the keyring another — too many
secrets to type. The fix is the **keyslot model** (the same idea as LUKS or
1Password):

- Each store gets a **random data key** that encrypts its contents. That data key
  is wrapped in one or more **keyslots** — a master passphrase, the existing
  recovery code, and (since the hardening pass) a YubiKey. Per-vault and keyring
  passphrases go away.
- **Any one slot opens the store.** `svault unlock` opens every vault **and the
  keyring** at once; `svault lock --all` clears them and the master session.

**Shipped in 0.9.4 (vaults):** `svault master init | rekey | status`; a random
data key per vault wrapped under a master key in `<vault>/keyslot.enc`, and the
master key wrapped under the passphrase in `.svault/master.enc`. `create` no longer
asks for a per-vault passphrase; `unlock` opens every vault at once; `recover` and
cross-machine `import` re-attach a vault to the local master via its recovery code.
Generalises the wrap/unwrap already in `recovery.rs`.

**Shipped in 0.9.5 (keyring):** the keyring is now a keyslot-backed store exactly
like a vault — a random data key wrapped under the master in
`.svault/keyring.keyslot.enc`. The keyring's own passphrase is gone; `svault keyring
init | unlock` and the TUI judge screen go through the master, and `svault unlock`
opens the keyring along with the vaults. There is truly one secret to type.

### Layered source (0.9.6, shipped)

A structural refactor only — no behavior, CLI surface, or on-disk format change.
`src/` became a **library crate** (`lib.rs`) with the `svault` binary reduced to a
thin wrapper over `cli::run()`, split into a frontend-agnostic **`core`** (crypto,
vault storage, the policy engine, the AI judge, keyring/master, recovery, audit,
…) and the **frontends** that drive it: `daemon/`, `tui/`, `cli/`, plus `mcp/` and
`gui/` placeholders. This lets the planned MCP and GUI surfaces reuse `core`
without touching the CLI or TUI.

### Agent surface — MCP (0.9.7, shipped)

- `svault mcp` runs a local MCP server (stdio JSON-RPC) that is a thin frontend
  over the existing gate. **It never sees the master passphrase** — it serves only
  from already-unlocked state (the daemon's keys, or the `0600` session key). The
  human unlocks once; every `svault_get_secret(name, scope, reason, caller)` call
  then runs through the same policy + judge gate, audited with `source = mcp`. A
  locked vault returns "a human must run `svault unlock`" — the agent cannot open
  it, and high-tier secrets stay human-only.
- **Tools:** `svault_get_secret` (the gated agent path) and `svault_list_vaults`
  (names + lock state). See [mcp.md](mcp.md) for the security model, wiring into
  Claude Code / Cursor, and a transcript.
- **Capability descriptor** (inspired by WorkOS `auth.md`) — the `initialize`
  response tells an agent *how to request* a secret (which fields to send, that
  high-tier may be human-only) **without** revealing the decision criteria (tiers,
  thresholds, judge prompts stay encrypted and server-side). Advertise the
  interface, never the policy an agent could game.
- **Follow-ups:** `svault install` to auto-write each platform's MCP config (plus
  Claude Code `.env`-read / credential-scan hooks), and a `svault_list_secrets`
  tool — both still planned.

### Hardware-key unlock + hardening (0.9.8, shipped)

- **YubiKey keyslot** — a hardware slot over the master key via the **FIDO2
  hmac-secret** extension (touch, plus the YubiKey PIN if one is set), additive
  over the same master key with no data re-encrypted. Enroll with `svault master
  yubikey enroll`; thereafter `svault unlock` and the TUI (`Ctrl+Y`) offer the key,
  and the master passphrase or recovery code still open everything if the key is
  lost. Type the passphrase **or** touch the key — either is sufficient, never a
  two-step 2FA. Manage with `svault master yubikey enroll | remove | status`.
- **6-hour re-auth cap** — every unlock path now re-prompts the master at least
  every 6 hours. File sessions (CLI/TUI) carry an unlock timestamp and expire at
  the cap (they previously never expired); the daemon's in-memory hard cap, which
  backs the MCP path, dropped from 8h to the same 6h. This bounds the window in
  which an already-unlocked vault — including one an agent was prompted into at the
  CLI — can be read before a human must re-authenticate.
- **First-run onboarding + app-level sign-in (TUI)** — opening the TUI with no
  master set walks through a disclaimer you accept, setting the master passphrase,
  the one-time recovery code, and an optional YubiKey enrollment. Thereafter the
  TUI has a sign-in gate (master passphrase or `Ctrl+Y`) shown on launch when the
  login session isn't active or has expired past the 6h cap, and `o` logs out
  (clears the login session, leaving the vaults and all data unchanged).
- **Honest repositioning** — the framing leads with "the principled way to give
  cooperative agents secret access" and states the same-UID boundary up front,
  rather than implying isolation. The never-wired cloud/self-hosted/s3 storage
  placeholders and the cloud roadmap were removed; storage is local-only.

### Conditional access + anomaly escalation (0.9.9, shipped)

- **Conditional access** — a secret carries conditions in its encrypted policy:
  allowed time windows (local time, e.g. `mon-fri 09:00-18:00`) and required
  caller(s). Outside the window, or for a non-required caller, the agent gets the
  same generic denial; it cannot read the window to wait for it. Set with
  `svault secret add --window … --require-caller …` or the TUI classify screen.
- **Seal and escalate** — repeated denials against a medium/high secret (5 within
  5 minutes, counted across any caller) **seal** it in the encrypted policy. While
  sealed, every agent `get` is denied until a human clears it with `svault approve`
  (or `A` in the TUI secret browser); `svault pending` lists what's awaiting
  approval. An agent can never unlock a vault or clear a seal — those are human-only
  by design, so a brute-force pattern is stopped and handed to a person rather than
  ground down into a leak. (A notify channel for escalations is a later add.)

## 1.0.0 — the first stable release (in review)

The agent-ready surface is built and the independent review is done, so 1.0.0 is
the consolidation, not new scope:

- **The independent security review is complete.** Three external-model reviews of
  the full 0.9.9 surface — the enforced engine (including adversarial judge testing
  for prompt injection via the `reason` field, and the caller-authorization
  decision: self-asserted today with peer-UID-stamped audit, accepted as a
  documented boundary), the keyslot unlock model, the seal/escalate path, and the
  MCP surface — found no Critical/High issues; the actionable findings were fixed
  before 1.0 (`docs/security-review/`).
- **What remains before tagging is a manual QA pass** across the CLI, TUI, and MCP
  surfaces (`docs/qa-checklist.md`) — verifying the shipped behavior end-to-end, not
  adding scope.

**Distribution channels** (an install script, a Homebrew tap, cargo-binstall, and a
Docker image — see below) follow *after* 1.0.0; `cargo install svault-ai` is the
shipped channel today.

A small backlog of accepted, non-blocking items remains for later: a Windows
owner-only DACL, a tamper-evident audit sink, and tunable Argon2id parameters.

## In progress (post-1.0)

### 2.0.0 — Desktop GUI (Tauri)

A cross-platform Tauri app in `gui-app/` that drives the **same** `core`/`daemon`
as the CLI/TUI/MCP (no reimplemented crypto or policy). All 12 screens from the
design handoff are built: sign-in/onboarding, vault list, vault config, secrets +
classification, judges & policy (with a live judge test), MCP wiring, audit
timeline, pending approvals, backup/recovery, settings, and a menu-bar/tray
popover. See [gui.md](gui.md) for architecture and how to run.

- Vault dashboard with lock/unlock, a live auto-lock countdown, and a daemon
  session monitor.
- Secret management with inline classification, a policy/judge surface, and an
  audit log viewer that shows the real peer UID and real denial reason.
- System-tray icon + popover; the bundled `svault` sidecar (and an "Install CLI
  to PATH" action) means one install delivers GUI + CLI + TUI + MCP.

Remaining before tagging 2.0.0: release bundling across the four targets
(`tauri-action`), the sidecar wiring (`scripts/bundle-sidecar.sh`), icon-state
assets for the tray, design/UX polish, and a manual QA pass over every screen.

**Versioning plan.** The crate version is now **1.1.0** (bumped in `Cargo.toml`,
the GUI crate, `tauri.conf.json`, and `package.json`). This is the development
line carrying the GUI plus the small enabling core additions (the keyring
`mcp_enabled` switch enforced by the MCP server, `daemon::client::vault_status`
for the auto-lock countdown). **1.1.0 is not published or git-tagged on its own**
— do not run `cargo publish` or cut a tag for it. The next public release is
**2.0.0**, which ships the desktop GUI together with these additions once the
"remaining" items above are done. So `1.0.0` (released) → `2.0.0` (the GUI
release), with `1.1.0` being the in-progress development line in between.

## Distribution

All channels reuse the prebuilt binaries the release workflow already builds for
four targets (macOS arm64/x64, Linux x64, Windows x64), so most are low-effort
once wired.

**Shipped:**

- **crates.io** — `cargo install svault-ai` (builds from source).

**Next (one pass — covers Mac/Linux/Rust users and agents):**

- **Install script** — `curl -fsSL https://<install-host>/install.sh | sh`
  (hosting URL not finalized yet): detect OS and arch, download the matching
  release binary, drop it on PATH. The link the README leads with.
- **Homebrew tap** — `brew install nim444/tap/svault` from a `nim444/homebrew-tap`
  repo (own tap, not homebrew-core); CI bumps the formula on each `v*` tag.
- **cargo-binstall** — `[package.metadata.binstall]` in `Cargo.toml` so
  `cargo binstall svault-ai` pulls a prebuilt binary instead of compiling.
- **Docker image** — `ghcr.io/nim444/svault`, pushed on each tag; this matters
  for the AI-agent and CI use case, where agents run in containers.

**Later (niche audiences, more upkeep):**

- **Scoop** (Windows, own bucket) and **WinGet** (PR per release).
- **AUR** (`PKGBUILD`) for Arch.
- **Nix** — flake / nixpkgs.

**Not planned yet:**

- **homebrew-core** and other official repos — the notability bar rejects young
  projects; use the own tap until there's traction.
- **npm wrapper** — only if JS-ecosystem agents (`npx`) show real demand.

A project website (host TBD) becomes the hub: it hosts `install.sh` and a
tabbed Install block (brew / curl / cargo / docker).

## Not planned (yet)

- TOTP and Touch ID / Face ID unlock (the keyslot model could host them later,
  but they are not on the path to 1.0).
- External backends (Vaultwarden, Infisical, AWS Secrets Manager).
- Secret rotation.
- Linux biometric support (needs libpam + libfprint).
