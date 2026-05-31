# Interactive mode (TUI)

Run `svault` with no subcommand to open the full-screen terminal UI:

```bash
svault
```

The TUI is a Ratatui-powered dashboard over the same vaults the CLI uses; anything you can do interactively, you can also script with a subcommand.

Press `?` on the vault list or in the secret browser for an on-screen keybinding cheat sheet. Paste works in every text field (passphrases, recovery codes, bundle paths), and newlines are stripped automatically.

## Home — vault list

The landing screen is a table with **STORAGE**, **VAULT**, **STATUS** (`locked` / `unlocked`), and **DESCRIPTION** columns. The selected row carries a `>` marker and a subtle background. The header's right side shows the **daemon indicator**: `daemon running` (green) or `daemon off` (dim). See [Daemon](daemon.md).

| Key | Action |
|---|---|
| `↑` / `↓` or `j` / `k` | Move between vaults |
| `Enter` | Open the secret browser for the selected vault |
| `c` | Create a new vault |
| `u` | Unlock the selected vault |
| `l` | Lock the selected vault (wipes the cached session) |
| `s` | Edit the selected vault's settings |
| `shift-J` | Manage the AI judges — create/unlock the keyring, global on/off, add/edit/view judges, set default, set/clear a judge's key, test, remove (see below) |
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

`←` / `→` cycle the pickers (allow-agent mode, default tier) and toggle auto-lock or the AI judge; `space` also cycles or toggles the focused picker; typing or pasting edits text fields; `Tab` and the arrows move between fields. A caret marks the field you're editing. Settings (`s`) edits the same access and auto-lock fields plus the default tier and the judge toggle. Storage is `local` and login is `passphrase` today; both appear as a static note rather than a selectable field, so the form never offers a choice that does nothing (remotes and extra login methods are on the [roadmap](roadmap.md)).

After the vault is created, the **recovery code** is shown once on its own screen. It is not stored in plaintext and is never shown again — save it (password manager or offline paper), then press `y` to confirm and return to the vault list. See [Recovery](recovery.md).

## AI judge management

`shift-J` (on the vault list) opens the judge manager, backed by the encrypted [keyring](architecture.md) (`.svault/keyring.enc`). It manages the **registry of named judges** that gate medium/high secrets — the same store the `svault keyring` and `svault judge` commands use.

If no keyring exists yet, press `Enter` to **create** it: a masked prompt takes a passphrase and confirmation (the same strength floor as a vault), then creates and unlocks it in place — no need to drop to `svault keyring init`. If the keyring already exists but is **locked**, `Enter` opens a masked passphrase prompt to unlock it (a `0600` session caches the key, so the daemon and the rest of the session see it too). Until it is unlocked the judge stays off and the static tier rules apply.

Once unlocked, the screen shows the global on/off switch, the default judge, and a table of every judge (**NAME · MODEL · ALLOW · HIGH · KEY**, with `*` marking the default and `KEY` reading `set` or `env/none`). The selectable rows are the global **Enabled** row plus one per judge:

- `space` / `←` `→` on the **Enabled** row toggles the global judge on/off. It only acts when this is on **and** the keyring is unlocked **and** the resolved judge has a key; a per-vault judge toggle (in Create / Settings) can still opt an individual vault out.
- `a` — **add** a judge: opens a multi-field form (name, model, base URL, timeout, allow/high thresholds, and free-text **criteria**). Saving validates the fields and stores the judge; set its key afterwards with `k`. The first judge added becomes the default.
- `e` — **edit** the selected judge in the same form (renaming is safe and carries the default pointer and the stored key over).
- `v` / `Enter` — **view** the selected judge's full detail, including its criteria.
- `d` — make the selected judge the **default** (used by vaults with no explicit assignment).
- `k` — open a masked entry to **set or clear** the selected judge's OpenRouter key (encrypted in the keyring; blank clears it, falling back to `$SVAULT_OPENROUTER_KEY`).
- `t` — **test** the selected judge: dry-runs a sample request against the live model and shows the verdict + score inline, without touching a real secret.
- `x` — **remove** the selected judge.

`↑` / `↓` move between rows; `Esc` goes back. The whole judge lifecycle is now available here, equivalent to the `svault keyring` / `svault judge` commands (which remain for scripting; the global switch is also `svault judge enable` / `disable`). Toggling the switch, adding or editing a judge, setting or clearing a key, setting the default, and removing a judge are all recorded to the activity timeline (see below).

## Activity timeline

`v` opens a read-only timeline of recent activity for the selected vault — no unlock needed, because the log holds no secret values. Each row shows **WHEN**, **ACTOR** (`human <user>` or `agent <caller>`, with agents in yellow), **VIA** (the surface the action came through — `cli`, `tui`, and later `gui` / `mcp`; `-` for events recorded before sources were tracked), **ACTION** (e.g. `unlock`, `secret.reveal`, `secret.classify`, `get.allow`), and **TARGET** (the secret name, when relevant). Actor + VIA together tell apart, say, a human at the CLI from an agent via MCP. `↑` / `↓` scroll; `esc` / `b` go back.

This is backed by a per-vault `usage.log` (`.svault/<name>/usage.log`, JSON lines, owner-only, gitignored) that both the CLI and TUI append to. It records human actions and agent `svault get` requests, so usage can be reviewed or fed to later analysis. Global, vault-independent judge changes (`judge.config` for the global on/off toggle, `judge.key.set` for setting or clearing a judge's key) are recorded to `.svault/usage.log` and folded into every vault's timeline, sorted newest-first, so a change made from the `shift-J` screen shows up in the audit trail. Secret **values** are never logged.

## Recover form

`r` enters the recovery code (shown as typed, not masked, so you can spot a mistype while copying it) and a new passphrase. Submitting resets the passphrase; the recovery code stays the same.

## Secret browser

`Enter` on an unlocked vault opens its secrets, shown as a table with the policy classification that gates each one — **SECRET · TIER · SCOPE · REASON? · DESCRIPTION** (an unclassified secret reads `unset`, tier colour-coded low/medium/high):

| Key | Action |
|---|---|
| `↑` / `↓` or `j` / `k` | Move between secrets |
| `a` | Add or update a secret |
| `c` | Reclassify the selected secret (scope / tier / require-reason / description) |
| `Enter` / `g` | View a secret value (`space` toggles masked / revealed) |
| `d` | Delete a secret (with `y` / `n` confirm) |
| `l` | Lock the vault and return to the list |
| `Esc` / `b` | Back to the vault list |
| `?` | Show the help overlay |

The **add-secret** form also classifies the secret: name, value, **scope**, **description** (optional — what it is for, read by the AI judge), **tier** (low/medium/high, defaulting to the vault's default tier), and a **require-reason** toggle. `c` opens the same fields for an existing secret to **reclassify** it, re-encrypting the vault's policy without touching the value. `space` / `←` `→` cycle the tier and toggle require-reason; the text fields accept typing and paste. The classification (and the vault's caller and access rules) lives AES-256-GCM encrypted inside `vault.enc`, so it is unreadable at rest. This is the same classification you can set non-interactively with `svault secret add --scope --tier --require-reason --description`, and it is what the policy gate enforces.

A locked vault routes through a passphrase prompt first, then resumes the action you asked for.

## Settings

`s` opens an edit form for description, allow-agent mode, allow-list, rate limit, auto-lock, and timer. Saving re-signs the public `meta.yaml` (description, auto-lock settings) and re-encrypts the policy (allow-agent, rate limit, default tier, judge override). The login method is carried forward unchanged.

## Sessions

The TUI reuses the cached session passphrase everywhere — an unlocked vault is never re-prompted. Pressing `l` from the list or the secret browser locks the vault and wipes the session immediately.

The footer shows context-aware key hints, and a dedicated status line below the body reports `ok` / `warning` / `error` / `note`.
