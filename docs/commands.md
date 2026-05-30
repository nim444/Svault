# Command reference

```bash
svault                             # launch the interactive TUI (no subcommand)
svault create                      # create encrypted vault (name, description, agents, rate limit, auto-lock)
svault settings [VAULT]            # view or change a vault's settings
svault unlock   [VAULT]            # unlock vault, cache derived key for the session
svault lock     [VAULT]            # clear the cached key
svault lock     --all              # lock every vault
svault status                      # show lock state of all vaults
svault vaults                      # list all vaults with metadata (storage:name prefix)
```

## Secrets

```bash
svault secret add    <NAME> [-v VAULT] [--scope S] [--tier low|medium|high] [--require-reason] [--description "..."]
svault secret get    <NAME> [-v VAULT]   # retrieve a secret value (human path)
svault secret list          [-v VAULT]   # list secret names (never values)
svault secret remove <NAME> [-v VAULT]   # delete a secret
```

`secret add` also **classifies** the secret (scope + sensitivity tier +
`--description`) into the signed `meta.yaml`; the flags drive non-interactive use,
otherwise you're prompted (defaulting to the vault's `default_tier`).
`--require-reason` makes the AI judge run for that secret even at low tier, and
`--description` records what the secret is for so the judge can check the stated
reason against it. (Every secret/get/settings command takes `-v <vault>` since you
can have several — local today, remote planned.)

## Policy engine — the agent path

See [Policy engine](policy-engine.md) for the full pipeline. Since 0.9.0 the agent
path is **enforced inside the daemon** (and re-run locally when no daemon is up).

```bash
svault get <NAME> --scope <S> --reason "<R>" [--caller C] [-v VAULT]   # enforced, gated request
svault policy init                 # scaffold svault.policy.yaml (caller definitions)
svault policy check <caller>       # what a caller can access + recent activity
```

## AI judge (OpenRouter)

For medium/high-tier secrets the daemon scores the caller's reason with an LLM.
Configure `[judge]` in `.svault/config.yaml`; the key comes from
`$SVAULT_OPENROUTER_KEY` or a `0600` key file (never committable config).

```bash
svault judge set-key      # prompt for the key, store it 0600 (or: echo $KEY | svault judge set-key)
svault judge status       # show where the key resolves from + model config (never prints the key)
svault judge test --reason "run the nightly migration" --scope database --tier high \
  --vault billing-api --vault-description "production billing service" \
  --description "production Postgres connection string"   # --vault/--description optional
svault judge remove-key   # delete the stored key file
```

`judge test` builds a sample request and asks the live model — nothing is read or
written. Pass a realistic `--vault` name: the model sees it, so a default like
`test` can make it (correctly) distrust a "production" reason. `--description`
(secret purpose) and `--vault-description` let you preview how those sway the verdict.

`set-key` writes `~/.config/svault/openrouter.key` (mode `0600`). If
`$SVAULT_OPENROUTER_KEY` is set it takes precedence over the file.

## Recovery & portability

See [Recovery](recovery.md) for how the recovery key and bundle work.

```bash
svault recover [VAULT]                   # use the recovery code to reset a lost passphrase
svault export  [VAULT] [--out FILE]      # write a portable encrypted bundle (default: <name>.svault-export.json)
svault import  <FILE> [--name NEW]       # restore a vault (auto-suffixes / --name on collision)
```

## Daemon (Unix)

See [Daemon](daemon.md) for the full design. Optional background process that holds keys in memory instead of in a `.session` file.

```bash
svault daemon start                # spawn detached; unlock/get/lock now route through it
svault daemon status               # unlocked vaults + idle / hard-max countdowns
svault daemon doctor [--fix]       # health check; --fix cleans stale socket / pid files
svault daemon stop                 # lock everything and stop
svault daemon run                  # foreground server (debugging)
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

$ svault secret add STRIPE_SECRET_KEY --scope payments --tier high \
    --description "production Stripe charge key"
  # prompts for the value (hidden input); classifies it as high-sensitivity
  # the description is context the AI judge weighs against each request's reason

$ svault secret add DATABASE_URL --scope database --tier medium \
    --description "production Postgres connection string"
$ svault secret list
  STRIPE_SECRET_KEY
  DATABASE_URL

$ svault secret get DATABASE_URL          # human path: prints the value
postgres://app:s3cr3t@db.internal:5432/billing
```

## 2. Unlock once, use all session

`unlock` caches the vault's derived key (not the passphrase) so you aren't re-prompted on every read.

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

The agent never sees your passphrase. It calls `svault get`; the daemon evaluates
the policy, scores the reason with the AI judge for medium/high secrets, audits
the decision (with the peer UID), and only then returns a value — there's no
unguarded path.

```bash
# One-time: scaffold the caller block, then grant scopes by editing it.
$ svault policy init
  # secret classification is set per-secret on `svault secret add` (signed meta)

# What can the "claude" caller reach right now?
$ svault policy check claude

# (optional) turn the AI judge on for this machine:
$ svault judge set-key                     # store the OpenRouter key; enable [judge] in .svault/config.yaml

# The agent's request (this is the line an agent runs):
$ svault get DATABASE_URL \
    --scope database \
    --reason "run the nightly billing migration" \
    --caller claude \
    -v billing-api
```

A request is denied (and logged) if the caller lacks the scope, the scope doesn't
match the secret, the rate limit is exceeded, the reason is missing/implausible,
or the judge scores it below the tier threshold. High-tier secrets are
judge-gated (fail-closed) — or human-only when the judge is off.

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

## 7. Keep keys in memory with the daemon (Unix)

```bash
$ svault daemon start
svault daemon started (pid 44714)

$ svault unlock billing-api
  Passphrase for 'billing-api': ****
ok: Vault 'billing-api' unlocked
  Key held by the daemon (in memory, no file written). Run 'svault lock' to clear it.

# Reads are now served from memory — no prompt, no .session file:
$ svault secret get STRIPE_KEY -v billing-api
sk_live_...

$ svault daemon status
VAULT                    IDLE LEFT      HARD LEFT
billing-api              14m52s         7h59m

$ svault daemon doctor          # confirm health; --fix cleans stale files
$ svault daemon stop            # zeroizes keys and removes the socket
```
