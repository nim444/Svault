# Command reference

Every command operates on the vaults under `.svault/`. Where a command takes a
vault, see [Vault selection](#vault-selection) for how it's resolved.

## Vault lifecycle

```bash
svault                             # launch the interactive TUI (no subcommand)
svault create [--force]            # create an encrypted vault (name, description, agents, rate limit, auto-lock)
svault settings [VAULT]            # view or change a vault's settings
svault unlock   [VAULT]            # unlock a vault and cache its derived key for the session
svault lock     [VAULT]            # clear a vault's cached key
svault lock     --all              # lock every vault
svault status                      # show the lock state of all vaults
svault vaults                      # list all vaults with metadata (storage:name prefix)
```

`create` walks you through naming the vault, choosing a [storage backend](storage-backends.md),
and setting a passphrase; `--force` skips the passphrase strength floor for
scripted use. On success it prints a one-time recovery code (see [Recovery](recovery.md)).

## Secrets

```bash
svault secret add    <NAME> [-v VAULT] [--scope S] [--tier low|medium|high] [--require-reason] [--description "..."]
svault secret get    <NAME> [-v VAULT]   # retrieve a secret value (human path)
svault secret list          [-v VAULT]   # list secret names (never values)
svault secret remove <NAME> [-v VAULT]   # delete a secret
```

`secret add` **classifies** the secret as it stores it: the scope, sensitivity
tier, and `--description` are written into the vault's AES-256-GCM **encrypted**
policy (never the plaintext `meta.yaml`). The flags drive non-interactive use;
omit them and you're prompted, defaulting to the vault's `default_tier`.
`--require-reason` makes the AI judge run for that secret even at low tier, and
`--description` records what the secret is for, so the judge can weigh each
request's stated reason against it.

## Policy engine — the agent path

See [Policy engine](policy-engine.md) for the full pipeline. Since 0.9.0 the agent
path is **enforced inside the daemon** (and re-run locally when no daemon is up).

Since 0.9.2 the policy (classification + caller rules) is **encrypted inside the
vault**, so a denied request returns only a generic message — the real reason is
in the audit log — and both `policy` subcommands unlock the vault.

```bash
svault get <NAME> --scope <S> --reason "<R>" [--caller C] [-v VAULT]   # enforced, gated request
svault policy init                 # seed caller rules into the vault's encrypted policy
svault policy check <caller>       # what a caller can access + recent activity (unlocks the vault)
```

## The keyring

All global config — the judge registry, each judge's API key, and operational
knobs (lock timers, daemon `max_connections`, backend) — lives in a single
**AES-256-GCM-encrypted keyring** at `.svault/keyring.enc`, under its own
passphrase (Argon2id). There is **no plaintext `.svault/config.yaml`** and **no
`~/.config/svault/openrouter.key`** — both are gone. Unlock the keyring once per
session (a `0600` session caches its derived key, like a vault); until it's
unlocked the judge is off and the static tier rules apply.

```bash
svault keyring init       # create the encrypted keyring (prompts for a passphrase) and unlock it
svault keyring unlock     # cache the keyring's derived key for this session
svault keyring lock       # clear the session — the judge goes back to off
svault keyring rekey      # change the keyring passphrase
svault keyring status     # show locked/unlocked, global on/off, default judge, and the judge names
```

The daemon reads the operational knobs (lock/connection/backend) from the keyring
at start — built-in defaults until unlocked — and changes to those apply at the
next daemon start. The judge itself activates as soon as the keyring is unlocked.

## AI judge (OpenRouter)

The judge is a registry of **multiple named judges** inside the keyring. Each has
its own model, base URL, timeout, `allow_threshold`/`high_threshold`, free-text
**criteria** (injected into that judge's prompt), and API key (encrypted in the
keyring; an empty key falls back to the opt-in `$SVAULT_OPENROUTER_KEY` env var,
never a file). A vault is **assigned** a judge by name (stored encrypted in the
vault policy); if unassigned it uses the keyring's default judge.

```bash
svault judge add <name>          # create a judge (prompts for model, thresholds, criteria, key)
svault judge edit <name>         # change a judge's model/url/timeout/thresholds/criteria
svault judge remove <name>       # delete a judge
svault judge list                # show all judges, the default (*), and per-judge key status
svault judge set-default <name>  # pick the judge used by vaults with no explicit assignment
svault judge set-key <name>      # set/clear one judge's key (or: echo $KEY | svault judge set-key <name>)
svault judge enable              # turn the judge on globally; `disable` to turn it off
svault judge status              # same as `svault keyring status`
svault judge test [--judge <name>] --reason "run the nightly migration" --scope database --tier high \
  --vault billing-api --vault-description "production billing service" \
  --description "production Postgres connection string"   # --judge/--vault/--description optional
```

The judge acts only when the keyring is **unlocked**, it's **enabled globally**
(`svault judge enable`, or the TUI `shift-J` screen), **and** the resolved judge
has a key; a per-vault `judge.enabled = false` can still opt one vault out. From
the TUI (`shift-J` on the vault list) you can create or unlock the keyring, toggle
the global switch, add/edit/view judges, set the default, set/clear a judge's key,
test, and remove a judge — the full lifecycle, equivalent to these commands.

`judge test` builds a sample request and asks the live model (the default judge,
or `--judge <name>`) — nothing is read or written. Pass a realistic `--vault`
name: the model sees it, so a default like `test` can make it (correctly)
distrust a "production" reason. `--description` (secret purpose) and
`--vault-description` let you preview how those sway the verdict.

`set-key <name>` stores the key **encrypted in the keyring**, never in a plaintext
file. An empty value clears the judge's key so it falls back to
`$SVAULT_OPENROUTER_KEY`, which takes effect only when a judge has no stored key.

## Recovery & portability

See [Recovery](recovery.md) for how the recovery key and bundle work.

```bash
svault recover [VAULT] [--force]         # use the recovery code to reset a lost passphrase
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
svault install [--platform claude|cursor|...]   # wire into an AI platform (not yet implemented)
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
# One-time: seed caller rules into the vault's encrypted policy, then edit
# scopes in `svault settings`.
$ svault policy init
  # secret classification is set per-secret on `svault secret add` (encrypted in the vault)

# What can the "claude" caller reach right now? (unlocks the vault)
$ svault policy check claude

# (optional) turn the AI judge on for this machine:
$ svault keyring init                      # create + unlock the encrypted keyring
$ svault judge add billing                 # define a judge (model, thresholds, criteria, key)
$ svault judge enable                      # turn the judge on globally

# The agent's request (this is the line an agent runs):
$ svault get DATABASE_URL \
    --scope database \
    --reason "run the nightly billing migration" \
    --caller claude \
    -v billing-api
```

A request is denied (and logged) if the caller lacks the scope, the scope doesn't
match the secret, the rate limit is exceeded, the reason is missing or
implausible, or the judge scores it below the tier threshold. High-tier secrets
are judge-gated (fail-closed) — or human-only when the judge is off. The caller
sees only a generic message; the real reason lives in the audit log:

```
denied: request not authorized for this secret
```

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
$ svault secret get STRIPE_SECRET_KEY -v billing-api
sk_live_...

$ svault daemon status
VAULT                    IDLE LEFT      HARD LEFT
billing-api              14m52s         7h59m

$ svault daemon doctor          # confirm health; --fix cleans stale files
$ svault daemon stop            # zeroizes keys and removes the socket
```
