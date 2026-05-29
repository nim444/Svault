# Security model

| Property | Implementation |
|---|---|
| Encryption | AES-256-GCM |
| Key derivation | Argon2id (64 MB memory, 3 iterations) — GPU-resistant |
| Metadata integrity | HMAC-SHA256 — tampering with `meta.yaml` is detected |
| Memory safety | `VaultKey` and secrets derive `ZeroizeOnDrop` — wiped on drop |
| Session file | Created atomically with mode `0600`, never at permissive permissions |
| Vault file | Safe to commit to git — encrypted at rest |

**The passphrase is the root of trust** — or the recovery code, which is an equal-strength second key. A strong passphrase combined with Argon2id makes brute force impractical on current hardware; the recovery code is 160 bits of randomness.

## What's safe to commit

`vault.enc`, `meta.yaml`, and `recovery.enc` are safe to commit to git — they are useless without the passphrase or recovery code. (`recovery.enc` holds the vault key wrapped under the recovery code; see [Recovery](recovery.md).) The `.session`, `audit.log`, and any local lock state are always gitignored (a per-vault `.gitignore` is written at create time) and created with mode `0600` (owner read/write only).

## Threat model notes

- Svault protects secrets **at rest** and gates **agent access**. It does not defend against a compromised machine that already has your unlocked session.
- HMAC signing detects tampering with `meta.yaml`, but anyone with the passphrase can decrypt the vault — treat the passphrase as the root of trust.
- The audit log records *decisions and reasons*, never secret values.

See [Architecture](architecture.md) for how these pieces fit together on disk.
