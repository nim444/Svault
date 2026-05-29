# Security model

| Property | Implementation |
|---|---|
| Encryption | AES-256-GCM |
| Key derivation | Argon2id (64 MB memory, 3 iterations) — GPU-resistant |
| Metadata integrity | HMAC-SHA256 — tampering with `meta.yaml` is detected |
| Memory safety | `VaultKey`, returned secret values, prompts, and the daemon's reply buffer are `Zeroizing`/`ZeroizeOnDrop` — wiped after use. (The transient decrypted secret map built while reading a vault is freed but not individually wiped — a best-effort residue in the cooperative/at-rest model.) |
| Session file | Created atomically with mode `0600`, never at permissive permissions |
| Vault file | Safe to commit to git — encrypted at rest |

**The passphrase is the root of trust** — or the recovery code, which is an equal-strength second key. A strong passphrase combined with Argon2id makes brute force impractical on current hardware; the recovery code is 160 bits of randomness.

## What's safe to commit

`vault.enc`, `meta.yaml`, and `recovery.enc` are safe to commit to git — they are useless without the passphrase or recovery code. (`recovery.enc` holds the vault key wrapped under the recovery code; see [Recovery](recovery.md).) The `.session`, `audit.log`, `usage.log`, the daemon's `daemon.sock` / `daemon.pid` / `daemon.log`, and any local lock state are always gitignored (`.svault/` itself is gitignored, and a per-vault `.gitignore` is written at create time and self-heals to add the log lines on first use) and created with mode `0600` (owner read/write only).

## Session state: file vs daemon

Two ways to stay unlocked, both owner-only:

- **File session** (default, all platforms) — `svault unlock` caches the vault's **derived key** (32 bytes, hex) in `.svault/<vault>/.session` — never the passphrase. A stolen `.session` opens that one vault, but doesn't reveal the passphrase (which may protect other vaults or services). The file is owner-only (mode `0600` on Unix; an `icacls` owner-only ACL on Windows). On `lock` it's overwritten with zeros and deleted.
- **Daemon** (Unix, opt-in) — when `svault daemon start` is running, the client derives the key locally and hands **only the key** (never the passphrase) to the daemon, which keeps it **in memory only**; no `.session` file is written. Keys are zeroized on lock, on idle / hard-max auto-lock, on `SIGTERM`/`SIGINT`, and on shutdown. The socket is `0600` (bound under a tight umask so there's no world-readable window) and the daemon refuses any connecting peer whose UID isn't your own (`getpeereid`). It exposes no write operations — only scoped reads. See [Daemon](daemon.md).

`.svault/` and each vault directory are created `0700`, so other local users can't traverse in. `recovery.enc` and export bundles are written owner-only too (they wrap a key-equivalent).

## Policy enforcement (0.9.0)

The agent path (`svault get`) is **enforced inside the daemon** — the component
that holds the key. It evaluates policy, consults the AI judge for sensitive
secrets, writes the audit record (stamped with the connecting process's
**peer UID**, which — unlike the self-asserted `--caller` — can't be forged), and
only then returns a value. The CLI runs the identical gate locally when no daemon
is up. Secret classification (scope/tier/`require_reason`) lives in the
**HMAC-signed `meta.yaml`**, so a same-UID process can't downgrade a tier without
the passphrase (#5/#22). See [Policy engine](policy-engine.md).

This raises the bar for cooperative/semi-trusted agents and produces a
tamper-resistant audit trail; it is **not** a sandbox against a hostile same-UID
process (see the threat-model note below).

## AI judge

For medium/high-tier secrets (and any `require_reason` secret) the daemon asks an
LLM, via your OpenRouter account, whether the stated reason plausibly justifies
the request. Configure it in `.svault/config.yaml`:

```yaml
judge:
  enabled: true
  model: google/gemini-2.5-flash   # cheap + fast; any OpenRouter model works
  timeout_secs: 6
  allow_threshold: 60              # min score for medium
  high_threshold: 80               # min score for high
```

The **API key never lives in config**. It comes from `$SVAULT_OPENROUTER_KEY`,
falling back to a `0600` key file (`~/.config/svault/openrouter.key`, or
`key_file:`). On a server, export the env var where the daemon starts. The judge
is **off until a key is available**, so upgrading never silently calls out. Verify
with `svault judge test`. Failure modes are tier-dependent: medium **fails open**
(allow + `judge-unavailable` audit flag), high **fails closed** (deny).

## Threat model notes

- Svault protects secrets **at rest** and gates **agent access**. It does not defend against a compromised machine that already has your unlocked session (file or daemon), nor against a **hostile same-UID process** (which can read the daemon's memory directly). The policy/judge gate is for cooperative and semi-trusted agents plus audit + anomaly detection — not a same-UID sandbox.
- The judge sends the secret **name, scope, tier, caller, and reason** (never the value) to your configured OpenRouter model — factor that third-party call into your data-handling posture.
- HMAC signing detects tampering with `meta.yaml`, but anyone with the passphrase can decrypt the vault — treat the passphrase as the root of trust.
- The audit log records policy *decisions and reasons*, and the usage log records *actions* (by human or agent, and the surface they came through — CLI, TUI, GUI, MCP) — neither ever stores secret values.

See [Architecture](architecture.md) for how these pieces fit together on disk.
