# Interactive mode (TUI)

Run `svault` with no subcommand to open the full-screen terminal UI:

```bash
svault
```

The TUI is a Ratatui-powered dashboard over the same vaults the CLI uses; anything you can do interactively, you can also script with a subcommand.

Press `?` on the vault list or in the secret browser for an on-screen keybinding cheat sheet. Paste works in every text field (passphrases, recovery codes, bundle paths), and newlines are stripped automatically.

## First run — onboarding

The very first time you open the TUI (no master passphrase set yet), it walks through a short onboarding instead of dropping you straight into vault creation:

1. **Disclaimer** — a one-screen, honest summary of what Svault does and its boundary (it gates and audits cooperative agents and encrypts at rest; it is **not** a sandbox against a hostile same-UID process). Press `Enter` to acknowledge and continue (`Esc` quits).
2. **Master passphrase** — set the one passphrase that unlocks everything (with confirmation, subject to the strength floor).
3. **Recovery code** — the one-time master recovery code is shown once; save it offline and press `y` to continue.
4. **YubiKey (optional)** — if you want, enroll a YubiKey now as an alternative unlock; type its PIN (if it has one) and press `Enter` to enroll (a "Touch your YubiKey" modal appears — tap twice), or `Esc` to skip. You can always enroll later with `svault master yubikey enroll`.

After onboarding you land on the vault list, signed in.

## Sign in & logout

The TUI has an app-level **sign-in** gated by the master passphrase. When you open the TUI and a master is set but you are not signed in this run — a fresh launch, or the login session expired past the **6-hour** cap — it shows a **Sign in** screen first: type the master passphrase and press `Enter`, or press `Ctrl+Y` to sign in with an enrolled YubiKey (type the PIN first if your key has one). `Esc` quits.

Pressing `o` on the vault list **logs out**: it clears the login session and returns to the Sign in screen. Logout signs you out only — it does **not** lock or change the vaults' own state, the keyring, the daemon, the judge, or any data; signing back in returns you to the list as it was.

## Home — vault list

The landing screen is a table with **STORAGE**, **VAULT**, **STATUS** (`locked` / `unlocked`), and **DESCRIPTION** columns. The selected row carries a `>` marker and a subtle background. The header's right side shows the **daemon indicator**: `daemon running` (green) or `daemon off` (dim). See [Daemon](daemon.md).

| Key | Action |
|---|---|
| `↑` / `↓` or `j` / `k` | Move between vaults |
| `Enter` | Open the secret browser for the selected vault |
| `c` | Create a new vault |
| `u` | Unlock the selected vault (type the master passphrase; if a YubiKey is enrolled, the unlock screen also accepts `Ctrl+Y` to unlock by touch — a "Touch your YubiKey" modal appears while the key blinks) |
| `l` | Lock the selected vault (wipes the cached session) |
| `o` | Log out — clear the login session and return to the Sign in screen (does not lock or change the vaults) |
| `s` | Edit the selected vault's settings |
| `shift-J` | Manage the AI judges — create/unlock the keyring, global on/off, add/edit/view judges, set default, set/clear a judge's key, test, remove (see below) |
| `m` | MCP server — readiness, the `svault mcp` config snippet, and a one-key writer for `.mcp.json` (see below) |
| `v` | View the vault's activity timeline (human + agent usage) |
| `e` | Export the selected vault to a timestamped `<name>-<YYYYMMDD-HHMMSS>.svault-export.json` in the current directory (repeated exports never overwrite); the status line shows the full path to the file |
| `i` | Import a vault from a bundle file (prompts for the path) |
| `r` | Recover the selected vault — enter the code, re-attach it to your master |
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
10. Assigned judge — which named keyring judge gates this vault; `default` uses the keyring's default judge. Cycles through the judges in your keyring (only populated when the keyring is unlocked; otherwise just `default`)
11. Master passphrase tail — depends on machine state:
    - **first run** (no master yet): *Master passphrase* + *Confirm master passphrase* — you set the one secret that unlocks every vault
    - **master set but locked**: a single *Master passphrase* field to open it
    - **master already unlocked**: no passphrase field at all

`←` / `→` cycle the pickers (allow-agent mode, default tier, assigned judge) and toggle auto-lock or the AI judge; `space` also cycles or toggles the focused picker; typing or pasting edits text fields; `Tab` and the arrows move between fields. A caret marks the field you're editing. Settings (`s`) edits the same access and auto-lock fields plus the default tier, the judge toggle, and the assigned judge. There is **no per-vault passphrase** — every vault is unlocked by the one master passphrase (keyslot model). Storage is `local` and appears as a static note rather than a selectable field, so the form never offers a choice that does nothing.

After the vault is created, the **recovery code** is shown once on its own screen. It is not stored in plaintext and is never shown again — save it (password manager or offline paper), then press `y` to confirm and return to the vault list. If this create also set the master passphrase for the first time, the same screen shows a second, labelled **master recovery code** (resets a forgotten master, reopens every store) — save both. See [Recovery](recovery.md).

## AI judge management

`shift-J` (on the vault list) opens the judge manager, backed by the encrypted [keyring](architecture.md) (`.svault/keyring.enc`). It manages the **registry of named judges** that gate medium/high secrets — the same store the `svault keyring` and `svault judge` commands use.

The keyring is opened by your **master passphrase** — there is no separate keyring passphrase. If no keyring exists yet, press `Enter` to **create** it: if the master is already unlocked it's created in place with no prompt; otherwise you enter the master passphrase (or, on first ever use, set one with passphrase + confirmation — which then shows the one-time **master recovery code** to save), then it's created and unlocked — no need to drop to `svault keyring init`. If the keyring already exists but is **locked**, `Enter` unlocks it via the master (immediately if the master session is live, else a masked master-passphrase prompt). A `0600` session caches the key, so the daemon and the rest of the session see it too. Until it is unlocked the judge stays off and the static tier rules apply.

Once unlocked, the screen shows the global on/off switch, the default judge, and a table of every judge (**NAME · MODEL · ALLOW · HIGH · KEY**, with `*` marking the default). The **KEY** column is colour-coded: `key set` (its own stored key), `env key` (no stored key, but `$SVAULT_OPENROUTER_KEY` is exported), or `no key` (neither — press `k` to add one). If the judge is **on** but the active judge has no usable key, a warning line is shown, since medium/high requests would otherwise fail silently. The selectable rows are the global **Enabled** row plus one per judge:

- `space` / `←` `→` on the **Enabled** row toggles the global judge on/off. It only acts when this is on **and** the keyring is unlocked **and** the resolved judge has a key; the per-vault **AI judge** toggle (in Create / Settings) can still opt an individual vault out, and the **Assigned judge** picker beside it chooses which named judge gates that vault (`default` = the keyring default).
- `a` — **add** a judge: opens a multi-field form (name, model, base URL, timeout, allow/high thresholds, and free-text **criteria**). Saving validates the fields and stores the judge; set its key afterwards with `k`. The first judge added becomes the default.
- `e` — **edit** the selected judge in the same form (renaming is safe and carries the default pointer and the stored key over).
- `v` / `Enter` — **view** the selected judge's full detail, including its criteria.
- `d` — make the selected judge the **default** (used by vaults with no explicit assignment).
- `k` — open a masked entry to **set or clear** the selected judge's OpenRouter key (encrypted in the keyring; blank clears it, falling back to `$SVAULT_OPENROUTER_KEY`).
- `t` — **test** the selected judge: dry-runs a sample request against the live model and shows the verdict + score inline, without touching a real secret.
- `x` — **remove** the selected judge.

`↑` / `↓` move between rows; `Esc` goes back. The whole judge lifecycle is now available here, equivalent to the `svault keyring` / `svault judge` commands (which remain for scripting; the global switch is also `svault judge enable` / `disable`). Toggling the switch, adding or editing a judge, setting or clearing a key, setting the default, and removing a judge are all recorded to the activity timeline (see below).

## MCP server

`m` (on the vault list) opens the **MCP** screen — the place to wire and arm
`svault mcp`, the [local MCP server](mcp.md) that exposes gated secret access to AI
agents (Claude Code, Cursor, …).

The server itself is **launched by the agent platform** (it owns a stdio pipe), so
there's nothing to "start" here — a full-screen TUI and a stdio JSON-RPC server
can't share the same terminal. What this screen does is the part that matters from
the keyboard:

- **Readiness** — shows whether the daemon is running and which vaults are
  unlocked. An agent can only fetch from an unlocked vault; if none are unlocked
  the screen says so (press `Esc`, then `u`).
- **Config snippet** — the exact `.mcp.json` entry to add to Claude Code / Cursor.
- `w` — **write** that entry into `./.mcp.json` in the current folder, merging it
  in (any other MCP servers already configured are preserved). The status line
  shows the path written.
- `d` — start/stop the daemon without leaving the screen, so keys stay in memory.
- `Esc` / `b` — back to the vault list.

See [mcp.md](mcp.md) for the server's security model, tools, and a transcript.

## Activity timeline

`v` opens a read-only timeline of recent activity for the selected vault — no unlock needed, because the log holds no secret values. Each row shows **WHEN**, **ACTOR** (`human <user>` or `agent <caller>`, with agents in yellow), **VIA** (the surface the action came through — `cli`, `tui`, and later `gui` / `mcp`; `-` for events recorded before sources were tracked), **ACTION** (e.g. `unlock`, `secret.reveal`, `secret.classify`, `get.allow`), and **TARGET** (the secret name, when relevant). Actor + VIA together tell apart, say, a human at the CLI from an agent via MCP. `↑` / `↓` scroll; `esc` / `b` go back.

This is backed by a per-vault `usage.log` (`.svault/<name>/usage.log`, JSON lines, owner-only, gitignored) that both the CLI and TUI append to. It records human actions and agent `svault get` requests, so usage can be reviewed or fed to later analysis. Global, vault-independent judge changes (`judge.config` for the global on/off toggle, `judge.key.set` for setting or clearing a judge's key) are recorded to `.svault/usage.log` and folded into every vault's timeline, sorted newest-first, so a change made from the `shift-J` screen shows up in the audit trail. Secret **values** are never logged.

## Recover form

`r` enters the recovery code (shown as typed, not masked, so you can spot a mistype while copying it) and your master passphrase (on a fresh machine with no master yet, you set one with a confirmation). Submitting re-attaches the vault to the master — the recovered data key is wrapped under it; the recovery code stays the same.

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
