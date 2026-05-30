# Interactive mode (TUI)

Run `svault` with no subcommand to open the full-screen terminal UI:

```bash
svault
```

The TUI is a Ratatui-powered dashboard over the same vaults the CLI uses — anything you can do interactively, you can also script with a subcommand.

Press `?` on the vault list or in the secret browser for an on-screen keybinding cheat sheet. Paste works in every text field (passphrases, recovery codes, bundle paths) — newlines are stripped automatically.

## Home — vault list

The landing screen is a table with **STORAGE**, **VAULT**, **STATUS** (`locked` / `unlocked`), and **DESCRIPTION** columns. The selected row is highlighted with a `>` marker and a subtle background. The header's right side shows the **daemon indicator** — `daemon running` (green) or `daemon off` (dim) — see [Daemon](daemon.md).

| Key | Action |
|---|---|
| `↑` / `↓` or `j` / `k` | Move between vaults |
| `Enter` | Open the secret browser for the selected vault |
| `c` | Create a new vault |
| `u` | Unlock the selected vault |
| `l` | Lock the selected vault (wipes the cached session) |
| `s` | Edit the selected vault's settings |
| `v` | View the vault's activity timeline (human + agent usage) |
| `e` | Export the selected vault to a timestamped `<name>-<YYYYMMDD-HHMMSS>.svault-export.json` in the current directory (repeated exports never overwrite); the status line shows the full path to the file |
| `i` | Import a vault from a bundle file (prompts for the path) |
| `r` | Recover the selected vault — enter the code, set a new passphrase |
| `d` | Start the daemon if it's off, stop it if it's running (Unix); the outcome shows in the status line (no-op note on Windows) |
| `?` | Show the help overlay |
| `q` / `Esc` | Quit (asks for confirmation: `enter` quits, any other key stays) |

`e` / `i` / `r` mirror the `svault export` / `import` / `recover` commands — see [Recovery](recovery.md). `d` mirrors `svault daemon start` / `stop` — see [Daemon](daemon.md).

## Create form

`c` opens a form-based setup. Editable fields, in order:

1. Name
2. Description
3. Allow-agent mode (all / none / list)
4. Agent allow-list
5. Rate limit
6. Auto-lock toggle
7. Auto-lock timer
8. Default tier (low / medium / high) — applied to secrets you add later
9. AI judge (on / off) — gate medium/high secrets for this vault
10. Passphrase
11. Confirm passphrase

`←` / `→` cycle the pickers (allow-agent mode, default tier) and toggle auto-lock / the AI judge; `space` also cycles/toggles the focused picker; typing or pasting edits text fields; `Tab` / arrows move between fields. A caret marks the field you're editing. Settings (`s`) edits the same access/auto-lock fields plus the default tier and judge toggle. Storage is `local` and login is `passphrase` today — both are shown as a static note rather than a selectable field, so the form never offers a choice that does nothing (remotes and extra login methods are on the [roadmap](roadmap.md)).

After the vault is created, the **recovery code** is shown once on its own screen. It is not stored in plaintext and is never shown again — save it (password manager or offline paper), then press `y` to confirm and return to the vault list. See [Recovery](recovery.md).

## Activity timeline

`v` opens a read-only timeline of recent activity for the selected vault — no unlock needed, because the log holds no secret values. Each row shows **WHEN**, **ACTOR** (`human <user>` or `agent <caller>`, with agents in yellow), **VIA** (the surface the action came through — `cli`, `tui`, and later `gui` / `mcp`; `-` for events recorded before sources were tracked), **ACTION** (e.g. `unlock`, `secret.reveal`, `get.allow`), and **TARGET** (the secret name, when relevant). Actor + VIA together tell apart, say, a human at the CLI from an agent via MCP. `↑` / `↓` scroll; `esc` / `b` go back.

This is backed by a per-vault `usage.log` (`.svault/<name>/usage.log`, JSON lines, owner-only, gitignored) that both the CLI and TUI append to. It records human actions and agent `svault get` requests so usage can be reviewed — or fed to later analysis. Secret **values** are never logged.

## Recover form

`r` enters the recovery code (shown as typed, not masked, so you can spot a mistype while copying it) and a new passphrase. Submitting resets the passphrase; the recovery code stays the same.

## Secret browser

`Enter` on an unlocked vault opens its secrets:

| Key | Action |
|---|---|
| `↑` / `↓` or `j` / `k` | Move between secrets |
| `a` | Add or update a secret |
| `Enter` / `g` | View a secret value (`space` toggles masked / revealed) |
| `d` | Delete a secret (with `y` / `n` confirm) |
| `l` | Lock the vault and return to the list |
| `Esc` / `b` | Back to the vault list |
| `?` | Show the help overlay |

The **add-secret** form also classifies the secret: name, value, **scope**, **description** (optional — what it's for, used by the AI judge), **tier** (low/medium/high, defaulting to the vault's default tier), and a **require-reason** toggle. `space` / `←` `→` cycle the tier and toggle require-reason; the text fields (name/value/scope/description) accept typing and paste. This is the same classification you can set non-interactively with `svault secret add --scope --tier --require-reason --description`, and it's what the policy gate enforces.

A locked vault routes through a passphrase prompt first, then resumes the action you asked for.

## Settings

`s` opens an edit form for description, allow-agent mode, allow-list, rate limit, auto-lock, and timer. Saving re-signs `meta.yaml`. The login method is carried forward unchanged.

## Sessions

The TUI reuses the cached session passphrase everywhere — an unlocked vault is never re-prompted. Pressing `l` from the list or the secret browser locks the vault and wipes the session immediately.

The footer shows context-aware key hints, and a dedicated status line below the body reports `ok` / `warning` / `error` / `note`.
