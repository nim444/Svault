# Command reference

```bash
svault                             # launch the interactive TUI (no subcommand)
svault create                      # create encrypted vault (storage, name, description, agents, rate limit, auto-lock, login)
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
