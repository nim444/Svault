# Interactive mode (TUI)

Run `svault` with no subcommand to open the full-screen terminal UI:

```bash
svault
```

The TUI is a Ratatui-powered dashboard over the same vaults the CLI uses — anything you can do interactively, you can also script with a subcommand.

## Home — vault list

The landing screen lists every vault with its `storage:name` prefix and live lock state (`locked` / `unlocked`).

| Key | Action |
|---|---|
| `↑` / `↓` or `j` / `k` | Move between vaults |
| `Enter` | Open the secret browser for the selected vault |
| `c` | Create a new vault |
| `u` | Unlock the selected vault |
| `l` | Lock the selected vault (wipes the cached session) |
| `s` | Edit the selected vault's settings |
| `q` | Quit |

## Create form

`c` opens a form-based setup. Fields, in order:

1. **Storage** — `local` (default) · Soluzy cloud · self-hosted · S3 *(remotes are placeholders — see [Storage backends](storage-backends.md))*
2. Name
3. Description
4. Allow-agent mode (all / none / list)
5. Agent allow-list
6. Rate limit
7. Auto-lock toggle
8. Auto-lock timer
9. Login method
10. Passphrase + confirm

`←` / `→` cycle select fields; typing edits text fields; `Tab` / arrows move between fields.

## Secret browser

`Enter` on an unlocked vault opens its secrets:

| Key | Action |
|---|---|
| `a` | Add or update a secret |
| `Enter` / `g` | View a secret value (toggle masked / revealed) |
| `d` | Delete a secret (with confirm) |

A locked vault routes through a passphrase prompt first, then resumes the action you asked for.

## Settings

`s` opens an edit form for description, allow-agent, rate limit, auto-lock, timer, and login method. Saving re-signs `meta.yaml`.

## Sessions

The TUI reuses the cached session passphrase everywhere — an unlocked vault is never re-prompted. Pressing `l` from any screen locks the vault and wipes the session immediately.

The footer shows context-aware key hints, and a plain-ASCII status line reports `ok` / `warning` / `error` / `note`.
