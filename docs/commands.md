# Command reference

```bash
svault                             # launch the interactive TUI (no subcommand)
svault create                      # create encrypted vault (name, description, agents, rate limit, auto-lock)
svault settings [VAULT]            # view or change a vault's settings
svault unlock   [VAULT]            # unlock vault, cache passphrase for the session
svault lock     [VAULT]            # clear the cached passphrase
svault lock     --all              # lock every vault
svault status                      # show lock state of all vaults
svault vaults                      # list all vaults with metadata (storage:name prefix)
```

## Secrets

```bash
svault secret add    <NAME> [-v VAULT]   # add or update a secret
svault secret get    <NAME> [-v VAULT]   # retrieve a secret value (human path)
svault secret list          [-v VAULT]   # list secret names (never values)
svault secret remove <NAME> [-v VAULT]   # delete a secret
```

## Policy engine — the agent path

See [Policy engine](policy-engine.md) for the full pipeline.

```bash
svault get <NAME> --scope <S> --reason "<R>" [--caller C] [-v VAULT]   # policy-gated request
svault policy init                 # scaffold svault.policy.yaml from existing vaults
svault policy check <caller>       # what a caller can access + recent activity
```

## Recovery & portability

See [Recovery](recovery.md) for how the recovery key and bundle work.

```bash
svault recover [VAULT]                   # use the recovery code to reset a lost passphrase
svault export  [VAULT] [--out FILE]      # write a portable encrypted bundle (default: <name>.svault-export.json)
svault import  <FILE>                    # restore a vault from a bundle
```

## Platform integration (planned)

```bash
svault install [--platform claude|cursor|...]   # wire into an AI platform (Step 5)
```

## Vault selection

- `VAULT` is **positional** for `create`, `settings`, `unlock`, `lock`, `recover`, and `export`.
- `secret` and `get` take it via `-v` / `--vault`.
- Omit it to use the only vault, or you'll be prompted to pick when several exist.

---

# Real-world examples

## 1. First vault for a side project

You're in `~/code/billing-api` and want a vault for its API keys.

```bash
$ cd ~/code/billing-api
$ svault create
  # name defaults to the directory (billing-api); pick a strong passphrase.
  # On success svault prints a one-time RECOVERY CODE — save it now.

$ svault secret add STRIPE_SECRET_KEY
  # prompts for the value (hidden input)

$ svault secret add DATABASE_URL
$ svault secret list
  STRIPE_SECRET_KEY
  DATABASE_URL

$ svault secret get DATABASE_URL          # human path: prints the value
postgres://app:s3cr3t@db.internal:5432/billing
```

## 2. Unlock once, use all session

`unlock` caches the passphrase so you aren't re-prompted on every read.

```bash
$ svault unlock billing-api
ok: vault 'billing-api' unlocked

$ export DATABASE_URL="$(svault secret get DATABASE_URL -v billing-api)"
$ export STRIPE_SECRET_KEY="$(svault secret get STRIPE_SECRET_KEY -v billing-api)"
$ npm run dev

$ svault lock --all                        # done for the day
ok: all vaults locked
```

## 3. Give an AI agent scoped, audited access

The agent never sees your passphrase. It calls `svault get`, which the policy
engine checks against the vault's allow-list and rate limit, then logs.

```bash
# One-time: scaffold a policy file from your existing vaults
$ svault policy init

# What can the "claude" caller reach right now?
$ svault policy check claude
  vault billing-api: STRIPE_SECRET_KEY (read), DATABASE_URL (read)
  rate limit: 10/hour   used: 2

# The agent's request (this is the line an agent runs):
$ svault get STRIPE_SECRET_KEY \
    --scope deploy \
    --reason "push price update to Stripe" \
    --caller claude \
    -v billing-api
```

A request is denied (and logged) if the caller isn't allowed, the rate limit is
exceeded, or the reason/scope is missing.

## 4. Move a vault to another machine

`export` writes a single encrypted bundle; `import` restores it. The payload is
already AES-256-GCM encrypted, so the file is safe to copy over scp/USB — but it
is still a backup, so don't commit it (svault adds it to `.gitignore` for you).

```bash
# On the old laptop:
$ svault export billing-api --out ~/billing-api.svault-export.json

# Copy it across, then on the new laptop:
$ svault import ~/billing-api.svault-export.json
ok: imported 'billing-api'

$ svault secret get DATABASE_URL -v billing-api   # same passphrase still works
```

## 5. Recover a vault after losing the passphrase

Use the recovery code you saved at create time. It resets the passphrase; the
recovery code itself stays the same.

```bash
$ svault recover billing-api
  Recovery code: ____  (paste the code you saved)
  New passphrase: ____
  Confirm:        ____
ok: passphrase reset for 'billing-api'. Recovery code unchanged.
```

## 6. Tighten access on an existing vault

```bash
$ svault settings billing-api
  # set Allow-agent to "list" and enter: claude, cursor
  # set Rate limit to 5/hour
  # saving re-signs meta.yaml
```
