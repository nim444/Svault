# Roadmap

Svault is an AI-aware secret manager built CLI-first. The core is hardened and
proven as a command-line tool before any wider surface is added — a secret
manager has to be trustworthy at its base first. The remaining pre-1.0 work makes
that proven core **agent-ready**: a single way to unlock, conditional access,
anomaly defence that escalates to a human, and a local MCP surface. Each reuses
the existing daemon choke point rather than introducing a new trust model. A
desktop GUI and remote/cloud surfaces come only after 1.0.

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
| Conditional access + escalation (0.9.8) | Next | Time-window / caller conditions in the encrypted policy; brute-force and anomaly patterns seal a secret and escalate to a human |
| Stable release (1.0.0) | Target | Final independent security review of the full agent-ready surface + distribution channels, then the first stable release |
| YubiKey keyslot (post-1.0) | Planned | A YubiKey HMAC-SHA1 touch as an alternative unlock slot over the same master key (passphrase or touch, not 2FA) — postponed past 1.0 |
| Desktop GUI (2.0.0) | Planned | Tauri vault manager + system tray |
| Remote / cloud (3.0.0+) | Planned | Remote MCP with OAuth, more platforms, and optional anomaly scoring via Claude Haiku |

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

## Next — the agent-ready path (remaining 0.9.x)

These releases turn the proven core into something that sits safely in front of
day-to-day AI agents. They all extend existing primitives — the keyslot pattern
already in `recovery.rs`, the encrypted policy in `vault.enc`, and the
peer-UID-bonded daemon socket — rather than adding a new trust model.

### Unified unlock — one master passphrase (0.9.4 – 0.9.5, shipped)

Each vault used to have its own passphrase and the keyring another — too many
secrets to type. The fix is the **keyslot model** (the same idea as LUKS or
1Password):

- Each store gets a **random data key** that encrypts its contents. That data key
  is wrapped in one or more **keyslots** — a master passphrase and the existing
  recovery code (a YubiKey slot is planned post-1.0). Per-vault and keyring
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
without touching the CLI or TUI. (The YubiKey keyslot that previously held the
0.9.6 slot is **postponed to post-1.0** — see [Planned (post-1.0)](#planned-post-10).)

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

### Conditional access + anomaly escalation (0.9.8)

- **Conditional access** — a secret can carry conditions in its encrypted policy:
  allowed time windows (e.g. only Fri 10:00–12:00 while CI runs) and required
  caller(s). Outside the window the agent gets the same generic denial; it cannot
  read the window to wait for it.
- **Seal and escalate** — repeated denials, bursts, or out-of-window probing
  against a medium/high secret **seal** it and raise an escalation that only a
  human can clear (`svault approve`, a TUI pending-approvals view, and later a
  notify channel). An agent can never unlock a vault or clear an escalation —
  those are human-only by design, so a brute-force pattern is stopped and handed
  to a person rather than ground down into a leak.

## Target — 1.0.0 (stable release)

1.0.0 is gated on two things, in this order:

1. **A final independent security review** of the full agent-ready surface — the
   enforced engine (including adversarial judge testing for prompt injection via
   the `reason` field, and the caller-authorization decision: self-asserted today
   with peer-UID-stamped audit — accept as a documented boundary or add an
   OS-bound caller identity), plus the new keyslot unlock model, the seal/escalate
   path, and the MCP surface.
2. **Distribution channels** — an install script, a Homebrew tap, and a Docker
   image (see below).

A small backlog of accepted, non-blocking items remains: a Windows owner-only
DACL, a tamper-evident audit sink, and tunable Argon2id parameters.

## Planned (post-1.0)

### YubiKey keyslot

A **YubiKey keyslot** via `svault master enroll-yubikey` (HMAC-SHA1
challenge-response, KeePassXC-style) — additive over the same master key, no data
re-encrypted: type the master passphrase **or** touch the YubiKey, either is
sufficient (not a two-step 2FA). Built behind a `ChallengeResponse` trait with a
fake responder for CI and verified on real hardware before it ships. Originally
slated for 0.9.6; **postponed to after 1.0** so the 1.0 review focuses on the
agent-ready surface rather than hardware-token unlock.

### 2.0.0 — Desktop GUI (Tauri)

- Vault dashboard with lock/unlock, auto-lock controls, and a session monitor.
- Secret management (names only, never values), a policy viewer, and an audit
  log viewer.
- System tray icon and notifications; a lightweight single binary that works
  offline.

### 3.0.0+ — Remote / cloud

- **Remote MCP with OAuth** — the fuller `auth.md` / MCP-OAuth story, so an agent
  on another machine can be authenticated and authorized, not just a same-UID
  local process.
- **Cloud anomaly scoring (optional)** — the per-vault usage log (human and agent
  activity, no secret values) is the local foundation; `api/score` has Claude
  Haiku score request justifications, with a personal plan and a team plan
  (shared audit dashboard, Slack alerts).

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

- TOTP and Touch ID / Face ID unlock (the keyslot model could host them later,
  but they are not on the path to 1.0).
- External backends (Vaultwarden, Infisical, AWS Secrets Manager).
- Secret rotation.
- Linux biometric support (needs libpam + libfprint).
