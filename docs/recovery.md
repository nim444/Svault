# Recovery & portability

Two ways to make a vault survivable: a **recovery code** for a lost passphrase, and an **export bundle** to move a vault between machines.

## Recovery code

When you create a vault, Svault prints a one-time recovery code:

```
  RECOVERY CODE
  A38A-1E39-B17B-9661-415F-54C9-5B60-C6F2-BDAB-E65F
  This is the ONLY time this code is shown — it is not stored in plaintext.
  Save it now in a password manager (or on paper, offline).
  It is the only way back in if you lose your passphrase — run 'svault recover'.
```

This is 160 bits of randomness. Svault wraps the vault key under a key derived from this code (Argon2id) and stores the result in `recovery.enc` next to `vault.enc`.

Because `recovery.enc` is only useful with the code, it is as safe to commit (and to ship in an export) as `vault.enc`.

### Storing the code — read this

The code is a **second key to your vault**, equal in power to the passphrase. Treat it that way:

- It is **printed once at create time and never again** — Svault does not keep a plaintext copy anywhere. If you lose both the passphrase and the code, the vault is unrecoverable by design.
- **Do** save it in a password manager, or write it on paper kept offline (a safe, a sealed envelope).
- **Don't** paste it into a chat, ticket, email, shell history, or a plaintext file in the repo. Anyone with the code can re-key the vault.
- It is **not** the same as your passphrase — store it separately, so one leak doesn't expose both.

### Recovering access when you've lost the master passphrase

```bash
svault recover [VAULT]
```

You'll be prompted for the recovery code, then for your master passphrase (on a
fresh machine with no master set, you set one). Svault:

1. Unwraps the vault's data key with the code (the data key never changed).
2. Wraps that data key under the current master — re-attaching the vault to your
   master passphrase. **No re-encryption** of `vault.enc`, and the **recovery code
   stays the same**, so you don't have to record a new one.

Your secrets are preserved. Because the data key is what the code recovers, the
same code keeps working and the vault is immediately usable under the master.

> Vaults created before recovery support have no `recovery.enc` and cannot be recovered — re-create them to get a code.

## Master recovery code

The per-vault code above gets you back into **one** vault. There is also a
**master recovery code** for the master passphrase itself — the way back in if you
forget it, without recovering each vault one by one.

When you first set the master passphrase (`svault master init`, the first `svault
create`, or the TUI set-master step), Svault prints a one-time master recovery
code and wraps the master key under it in `.svault/master.recovery.enc` (160 bits,
Argon2id — same construction and same "safe to commit" property as a vault's
`recovery.enc`). Store it offline, separately from the passphrase.

```bash
svault master recover
```

You'll be prompted for the master recovery code, then for a new master passphrase.
Svault unwraps the master key with the code and re-wraps it under the new
passphrase — the recovery code itself is unchanged. Because the code wraps the
**master key** directly, this one code reopens **every** store (all vaults and the
keyring) at once, and **nothing is re-encrypted**.

> Per-vault codes are still useful for cross-machine `import` (a bundle carries the
> vault's `recovery.enc`, not the machine-specific keyslot). The master recovery
> code only works on the machine that holds `.svault/master.recovery.enc`.

## Export / import

Move an encrypted vault to another machine without exposing any secret value.

```bash
svault export [VAULT] [--out FILE]    # default: <name>.svault-export.json
svault import <FILE> [--name NEW]     # restore; --name to import under a chosen name
```

`export` bundles `meta.yaml`, `vault.enc`, and (if present) `recovery.enc` into a single JSON file with a `sha256` integrity checksum. Every byte in the bundle is already encrypted or signed, so the file is safe at rest.

A bundle is still a **full backup** (it carries the wrapped recovery key), so it shouldn't be committed to a repo. On export, Svault automatically adds `*.svault-export.json` to a `.gitignore` in the output directory (appending to an existing one, never overwriting) so you can't push a bundle by mistake.

`import` verifies the checksum, then recreates `.svault/<name>/`. Because a vault's keyslot is specific to the machine that made it, the bundle carries `recovery.enc` (not `keyslot.enc`), so `import` asks for the **recovery code** to bring the vault under *this* machine's master passphrase. After that it opens like any other vault with your master.

If a vault of that name already exists (e.g. you're re-importing your own backup onto the same machine), import **doesn't error** — it picks a free name by appending a suffix (`TUI-Vault` → `TUI-Vault-2`), or you can pass `--name <NEW>` to choose one. Because the vault name is part of the HMAC-signed `meta.yaml`, importing under a different name re-signs it, so Svault asks for the passphrase once to finish. (A clean import under the original name needs no passphrase.)

A corrupted bundle (any altered file) fails the checksum check and is rejected before anything is written.

### Portability

The bundle is **fully self-contained** — it carries no machine-specific state (no absolute paths, hostnames, or user IDs), so a vault exported on one machine imports cleanly on another. The bundle records its own format version, and `import` rejects anything it doesn't understand. Both ends must therefore run Svault releases that share the export format and the fixed Argon2id derivation parameters; this holds across the 1.0 release line.
