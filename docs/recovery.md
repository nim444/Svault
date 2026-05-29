# Recovery & portability

Two ways to make a vault survivable: a **recovery code** for a lost passphrase, and an **export bundle** to move a vault between machines.

## Recovery code

When you create a vault, Svault prints a one-time recovery code:

```
RECOVERY CODE — store it now:
A38A-1E39-B17B-9661-415F-54C9-5B60-C6F2-BDAB-E65F
```

This is 160 bits of randomness. Svault wraps the vault key under a key derived from this code (Argon2id) and stores the result in `recovery.enc` next to `vault.enc`.

Because `recovery.enc` is only useful with the code, it is as safe to commit (and to ship in an export) as `vault.enc`.

### Storing the code — read this

The code is a **second key to your vault**, equal in power to the passphrase. Treat it that way:

- It is **printed once at create time and never again** — Svault does not keep a plaintext copy anywhere. If you lose both the passphrase and the code, the vault is unrecoverable by design.
- **Do** save it in a password manager, or write it on paper kept offline (a safe, a sealed envelope).
- **Don't** paste it into a chat, ticket, email, shell history, or a plaintext file in the repo. Anyone with the code can re-key the vault.
- It is **not** the same as your passphrase — store it separately, so one leak doesn't expose both.

### Resetting a lost passphrase

```bash
svault recover [VAULT]
```

You'll be prompted for the recovery code, then for a new passphrase. Svault:

1. Unwraps the vault key with the code.
2. Re-encrypts the vault under the new passphrase (re-keys `vault.enc`, re-signs `meta.yaml`).
3. Re-wraps `recovery.enc` — the **recovery code stays the same**, so you don't have to record a new one.

Your secrets are preserved; the old passphrase stops working.

> Vaults created before recovery support have no `recovery.enc` and cannot be recovered — re-create them to get a code.

## Export / import

Move an encrypted vault to another machine without exposing any secret value.

```bash
svault export [VAULT] [--out FILE]   # default: <name>.svault-export.json
svault import <FILE>
```

`export` bundles `meta.yaml`, `vault.enc`, and (if present) `recovery.enc` into a single JSON file with a `sha256` integrity checksum. Every byte in the bundle is already encrypted or signed, so the file is safe at rest.

A bundle is still a **full backup** (it carries the wrapped recovery key), so it shouldn't be committed to a repo. On export, Svault automatically adds `*.svault-export.json` to a `.gitignore` in the output directory (appending to an existing one, never overwriting) so you can't push a bundle by mistake.

`import` verifies the checksum, then recreates `.svault/<name>/`. It **refuses** to overwrite an existing vault of the same name (names are unique). The restored vault opens with its original passphrase — or with `svault recover` if the bundle carried a `recovery.enc`.

A corrupted bundle (any altered file) fails the checksum check and is rejected before anything is written.

### Portability

The bundle is **fully self-contained** — it carries no machine-specific state (no absolute paths, hostnames, or user IDs), so a vault exported on one machine imports cleanly on another. The only requirement is the **same major Svault version** on both ends, since the key derivation parameters (Argon2id cost) are fixed per release.
