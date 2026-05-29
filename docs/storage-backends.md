# Storage backends

At create time you pick where a vault lives. **`local`** is the default and the only backend wired today; the rest are reserved placeholders — remote sync ships in a later step.

| Backend | Status | What it is |
|---|---|---|
| `local` | Available | Encrypted vault on this machine (default) |
| `cloud` | Coming soon | Soluzy SaaS sync |
| `self-hosted` | Coming soon | Your own Svault server |
| `s3` | Coming soon | S3 / MinIO bucket |

## The `storage:name` prefix

The chosen backend is recorded in `meta.yaml` (`storage:`) and shown as a `storage:name` prefix everywhere a vault is listed (`svault vaults`, `svault status`, the TUI):

```
local:my-project        unlocked   primary app secrets
cloud:shared-secrets    locked     team-wide credentials
```

The prefix keeps vault identity unambiguous per backend.

## Unique names

**Vault names must be unique.** Creating a second vault with an existing name is rejected, so the same name can't be duplicated across storage backends.

> Svault is in beta — `storage` is a required field on `meta.yaml`. Vaults created before this field existed must be re-created.
