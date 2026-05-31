# Security model

| Property | Implementation |
|---|---|
| Encryption | AES-256-GCM |
| Key derivation | Argon2id (64 MB memory, 3 iterations) — GPU-resistant |
| Unlock (keyslot model) | A random 32-byte data key encrypts each store — every vault **and the keyring**; it is wrapped under a random master key (MK) in a keyslot (`<vault>/keyslot.enc` or `.svault/keyring.keyslot.enc`), and MK is wrapped under your **master passphrase** (Argon2id) in `.svault/master.enc`. One passphrase unlocks everything; changing it rewraps only MK, never any ciphertext |
| Metadata integrity | HMAC-SHA256 — tampering with the public `meta.yaml` is detected |
| Policy at rest | The full policy surface (classification, caller rules, access, the vault's judge assignment) is AES-256-GCM **encrypted inside `vault.enc`** — unreadable at rest, so an agent can't read it to plan a bypass |
| Global config at rest | The judge registry, every judge's **API key**, their criteria/thresholds, and operational knobs are AES-256-GCM **encrypted inside `keyring.enc`**, opened by the master passphrase (data key wrapped in `keyring.keyslot.enc`) — no plaintext config file, no plaintext key file |
| Memory safety | `VaultKey`, returned secret values, prompts, and the daemon's reply buffer are `Zeroizing`/`ZeroizeOnDrop` — wiped after use. (The transient decrypted secret map built while reading a vault is freed but not individually wiped — best-effort residue, consistent with the cooperative same-UID model.) |
| Session file | Created atomically with mode `0600`, never at permissive permissions |
| Vault file | Safe to commit to git — encrypted at rest |

**The master passphrase is the root of trust** — or a vault's recovery code, which is an equal-strength second keyslot into that vault. A strong master passphrase combined with Argon2id makes brute force impractical on current hardware; the recovery code is 160 bits of randomness. The vault data keys themselves are random and never derived from the passphrase, so the passphrase only ever unwraps the master key.

## What's safe to commit

`vault.enc`, `meta.yaml`, `recovery.enc`, `keyslot.enc`, `master.enc`, `master.recovery.enc`, `keyring.enc`, and `keyring.keyslot.enc` are safe to commit to git — they are useless without the master passphrase or a recovery code. (`keyslot.enc` holds the vault's data key wrapped under the master key; `keyring.keyslot.enc` holds the keyring's data key wrapped under the master key; `master.enc` holds the master key wrapped under your passphrase; `master.recovery.enc` holds the master key wrapped under the master recovery code; `recovery.enc` holds the vault data key wrapped under that vault's recovery code — see [Recovery](recovery.md). `keyring.enc` is the encrypted global config — judge registry, API keys, knobs.) The `.session`, the master session `.master.session`, the keyring's `.keyring.session`, `audit.log`, `usage.log`, the daemon's `daemon.sock` / `daemon.pid` / `daemon.log`, and any local lock state are always gitignored (`.svault/` itself is gitignored, and a per-vault `.gitignore` is written at create time and self-heals to add the log lines on first use) and created with mode `0600` (owner read/write only).

## Session state: file vs daemon

Two ways to stay unlocked, both owner-only:

- **File session** (default, all platforms) — `svault unlock` caches the vault's **derived key** (32 bytes, hex) in `.svault/<vault>/.session` — never the passphrase. A stolen `.session` opens that one vault, but doesn't reveal the passphrase (which may protect other vaults or services). The file is owner-only (mode `0600` on Unix; an `icacls` owner-only ACL on Windows). On `lock` it's overwritten with zeros and deleted.
- **Daemon** (Unix, opt-in) — when `svault daemon start` is running, the client derives the key locally and hands **only the key** (never the passphrase) to the daemon, which keeps it **in memory only**; no `.session` file is written. Keys are zeroized on lock, on idle / hard-max auto-lock, on `SIGTERM`/`SIGINT`, and on shutdown. The socket is `0600` (bound under a tight umask so there's no world-readable window) and the daemon refuses any connecting peer whose UID isn't your own (`getpeereid`). It exposes no write operations — only scoped reads. See [Daemon](daemon.md).

`.svault/` and each vault directory are created `0700`, so other local users can't traverse in. `recovery.enc` and export bundles are written owner-only too (they wrap a key-equivalent).

## Policy enforcement and encryption at rest

The agent path (`svault get`) is **enforced inside the daemon** — the component
that holds the key. The daemon evaluates policy, consults the AI judge for
sensitive secrets, writes the audit record (stamped with the connecting process's
**peer UID**, which — unlike the self-asserted `--caller` — can't be forged), and
only then returns a value. The CLI runs the identical gate locally when no daemon
is up, so there is no unguarded read path.

The entire policy surface — per-secret classification
(scope/tier/`require_reason`/`description`), caller rules, access fallback, and the
per-vault judge assignment (which named judge gates the vault) — is **AES-256-GCM
encrypted inside `vault.enc`**, not the plaintext `meta.yaml`. A same-UID process
can therefore neither *read* the policy at rest to learn what reason or scope
would pass (no reconnaissance) nor *tamper* with a tier or caller without the
passphrase. The public `meta.yaml` keeps only non-sensitive metadata (name,
description, storage, created-at, version, settings).

**Denials are opaque to the caller.** A denied `svault get` returns only a generic
message; the detailed reason (judge score and rationale, scope/caller mismatch,
rate limit) is recorded in the audit log for the human, never returned to the
caller — so an agent can't hill-climb a denied request into a passing one.

This raises the bar for cooperative and semi-trusted agents and produces a
tamper-resistant audit trail. It is **not** a sandbox against a hostile same-UID
process (see [Threat model](#threat-model) below).

## The encrypted keyring

There is **no plaintext config file and no plaintext key file.** All global config
lives in a single **AES-256-GCM-encrypted keyring** at `.svault/keyring.enc`, opened
by the **master passphrase** — the keyring has a random data key wrapped under the
master in `.svault/keyring.keyslot.enc`, exactly like a vault (no separate keyring
passphrase). It holds the judge registry, each judge's **API key**, each judge's
**criteria and thresholds**, and the operational knobs (lock timers, daemon
`max_connections`, backend). **Nothing abusable is readable at rest:** a same-UID
agent can no longer read thresholds or criteria to tune a passing request, nor lift
the API key from a plaintext file.

Unlock the keyring once per session with `svault keyring unlock` — or just
`svault unlock`, which opens it along with your vaults (a `0600` session caches its
data key, exactly like a vault); `svault keyring lock` clears it and the judge goes
back to off; `svault master rekey` changes the master that opens it (there is no
keyring rekey). Until the keyring is unlocked the judge is off and the static tier
rules apply. The
daemon reads the operational knobs from the keyring at start (built-in defaults
until unlocked; lock, connection, and backend changes apply at the next daemon
start) and resolves the judge per request, so the judge activates the moment the
keyring unlocks.

**Honest boundary:** the keyring is exactly as protected as a vault — it closes
the read-at-rest path, but it is **not** a sandbox against a hostile same-UID
process that reads the unlocked daemon's memory or the `0600` session.

## AI judge

For medium- and high-tier secrets (and any `require_reason` secret) the daemon
asks an LLM, via your OpenRouter account, whether the stated reason plausibly
justifies the request. The judge is a registry of **multiple named judges** in the
keyring — each with its own `model`, `base_url`, `timeout_secs`, `allow_threshold`
(minimum score for medium), `high_threshold` (minimum score for high), free-text
**criteria** (added to that judge's prompt), and its own API key. A vault is
**assigned** a judge by name (stored encrypted in the vault policy); if unassigned,
it uses the keyring's default judge. Manage all of it with
`svault judge add|edit|remove|list|set-default|set-key|enable|disable|test` on the
unlocked keyring.

Each judge's **API key is encrypted in the keyring**, never written to a file. An
empty stored key falls back to the opt-in `$SVAULT_OPENROUTER_KEY` environment
variable — env only, never a key file. On a server, export that variable where the
daemon starts. The judge is **off until the keyring is unlocked, the global switch
is on, and the resolved judge has a key**, so upgrading never silently calls out.
Verify with `svault judge test [--judge <name>]`. Failure modes are
tier-dependent: medium **fails open** (allow, with a `judge-unavailable` audit
flag); high **fails closed** (deny).

## Threat model

- Svault protects secrets **at rest** and gates **agent access**. It does not defend against a compromised machine that already holds your unlocked session (file or daemon), nor against a **hostile same-UID process**, which can read the daemon's memory directly. The policy and judge gate is for cooperative and semi-trusted agents, plus audit and anomaly detection — not a same-UID sandbox.
- The judge sends the secret **name, scope, tier, caller, reason, and any vault or secret descriptions you set** (never the value) to your configured OpenRouter model. Keep descriptions free of sensitive data, and factor that third-party call into your data-handling posture.
- HMAC signing detects tampering with `meta.yaml`, but anyone with the passphrase can decrypt the vault — treat the passphrase as the root of trust.
- The audit log records policy *decisions and reasons*; the usage log records *actions* (by human or agent, and the surface they came through — CLI, TUI, GUI, MCP). Neither ever stores secret values.

See [Architecture](architecture.md) for how these pieces fit together on disk.
