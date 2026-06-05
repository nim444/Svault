# Handoff: Svault — Desktop GUI

## Overview
This package documents the wireframes for the **Svault desktop GUI** — a cross-platform (Tauri) frontend over the existing Rust `svault` core/daemon. Svault is a secret-access layer for cooperative AI agents: every agent request is structured, policy-gated, AI-judge-scored, and audited. The GUI is a new frontend (the roadmap's "Desktop GUI (Tauri) + system tray" milestone) that sits beside the existing CLI, TUI, and MCP frontends and reuses the same `core` library.

The design covers the full surface: first-run onboarding, returning-user sign-in, vault list, vault create/settings, secrets management, the AI judge + policy engine, MCP server, audit timeline, pending approvals, backup/recovery, app settings, and the menu-bar/tray popover.

## About the Design Files
The files in this bundle (`Svault GUI Wireframes.html` + `wf.css`) are **design references created in HTML** — a clickable wireframe prototype showing intended structure, information architecture, and behavior. **They are not production code to copy directly.**

The task is to **recreate these designs in the Svault desktop app's environment**: a **Tauri** shell (Rust backend already exists as `crate::core` + `crate::daemon`; there is a `gui` placeholder crate) with a web frontend. Choose the frontend framework that best fits the team (React, Svelte, Vue, SolidJS — all work with Tauri) and implement the screens using that framework's idioms and a real component library/design system. The Tauri commands should call into the existing `core`/`daemon` Rust APIs rather than reimplementing crypto or policy logic.

## Fidelity
**Low-fidelity (lofi) wireframes.** The prototype deliberately uses a boxy, monospace, paper-toned "blueprint" aesthetic with hand-drawn annotation notes. **This is a wireframe style, not the intended product skin.** Use these files as the authority for:
- **Layout & information architecture** — what's on each screen, where, and the navigation model
- **Flow & behavior** — what each control does and how screens connect
- **Content & terminology** — labels, copy, and the exact vocabulary (which mirrors the CLI)

Apply your own/the project's real visual design system for final colors, typography, spacing, elevation, and motion. Do **not** ship the monospace/boxy look or the yellow annotation notes.

## Navigation Model (App Shell)
Every post-sign-in screen shares one shell:
- **Left sidebar** (fixed, ~232px): brand mark + nav items — **Vaults · Judges & Policy · MCP · Audit · Pending**, a divider, then **Backup & recovery · Settings**. The active item is highlighted. Nav items may show a count badge (e.g. Pending shows a number when approvals are waiting).
- **Daemon status block** (bottom of sidebar): always-visible state — daemon up/down, "keys in memory", how many vaults unlocked, auto-lock countdown, and quick **Lock all** / **Sign out** actions.
- **Main panel** (fills the rest): the screen's content. Dense screens use an in-panel **sub-tab strip** (see below) so no screen is a long scroll of stacked cards.
- **OS window chrome** (the prototype draws macOS traffic lights) — in Tauri this is the native window; on macOS also a **menu-bar item**, on Windows/Linux a **system-tray icon**, both opening the same popover (see Tray).

The prototype itself is a tabbed gallery (top tab bar = the 12 screens); that tab bar is a **presentation device for reviewing the wireframes**, not part of the product. In the real app, screens are reached via the sidebar nav and in-app actions.

### Sub-tab pattern
Content-heavy screens split their panel into sub-tabs (a tab strip under the panel header) instead of one long page:
- **Judge & Policy**: *Judges & test* · *Policy surface* · *Caller access*
- **MCP**: *Connection & tools* · *Wiring* · *Live log*
- **Vault config**: *Create vault* · *Edit settings*
- **Backup**: *Export & import* · *Recovery code*
- **Settings**: *Appearance & startup* · *Security & daemon* · *Diagnostics*

## Screens / Views
There are 12 screens. Each maps to one or more `svault` CLI commands (the source of truth for behavior — see `src/cli/mod.rs`).

### 01 — Sign in / Sign out  (`svault unlock`, app-level session)
- **Purpose**: Returning-user gate. The app launches **locked**: no vault is readable in the GUI until the master passphrase (or an enrolled YubiKey) unlocks the session.
- **Sign in (locked launch)**: centered card — brand mark, "Welcome back", master-passphrase field + **Unlock** button, an "or" divider, a **Touch your YubiKey** button (FIDO2 hmac-secret, shown only if enrolled), and a "Lost your passphrase? → Use recovery code" link to Backup & recovery.
- **Sign out**: a confirm card. **Critical behavior**: sign-out is a **GUI-session action only** — it returns to the sign-in screen and requires re-entering the master passphrase to use the GUI again. It must **NOT** lock vaults, stop the daemon (keys stay in memory), or stop the MCP server (agents keep working). Locking vaults and stopping services are separate, explicit dashboard actions. Note the distinction from **Lock all** (which clears keys but keeps you signed in).
- A **6-hour re-auth cap** applies to every unlock path (enforced by core).

### 02 — Onboarding (first run)  (`svault master init`, `svault create`, `svault master yubikey enroll`)
- **Purpose**: Linear, can't-skip-the-important-bits first run. Shown as 4 stepper frames.
- **Step 1 — Terms / honest boundary**: scrollable disclaimer (Svault gates cooperative agents; it is NOT a sandbox against a hostile same-UID process). Requires an "I understand" checkbox to continue.
- **Step 2 — Set master passphrase**: passphrase + confirm, strength meter, note "Argon2id, 64 MB; one passphrase unlocks every vault."
- **Step 3 — Recovery code**: shows a one-time 160-bit master recovery code, Copy / Download buttons, and a **gating checkbox** ("I've stored this somewhere safe") — cannot continue until checked. Shown once, never stored in plaintext.
- **Step 4 — YubiKey (optional)**: enroll a FIDO2 hmac-secret key (touch), or **Skip**. Skipping lands the user in the empty vault list.

### 03 — Vault list (home)  (`svault vaults`, `unlock`, `lock`, `status`)
- **Purpose**: Where the user lands after unlock. Two layout directions are shown (the team picks one):
  - **Direction A — dense table**: columns Vault (name + `local:` prefix) · State (unlocked/locked with colored dot) · Secrets (count) · Default tier (badge) · Judge (assigned name) · Last activity · **Actions**.
  - **Direction B — cards**: same data as a 2-col card grid.
- **Per-row/-card actions**: **Open** (go to that vault's secrets), **⚙** (open Vault config → Edit settings), **Lock**/**Unlock** (toggle the cached key), **✕** (delete the vault — must confirm).
- **Panel header**: title, "local only" badge, search field, **+ Create vault** (→ Vault config → Create).
- Locked rows swap **Lock** for **Unlock**.

### 04 — Vault config  (`svault create`, `svault settings <vault>`)
Two sub-tabs sharing the same field set (these fields are written into the vault's **encrypted policy**, not plaintext):
- **Create vault**: Vault name (defaults to cwd name; must be unique) · Description · **Allow agent** (segmented: none / list / all; "list" reveals a caller-names field) · Rate limit (default `10/hour`) · Auto-lock toggle + timer (`1d`/`12h`/`30m`) · **Login method** (passphrase / yubikey) · Default tier (low/medium/high) · **AI judge** toggle + assigned-judge picker. A callout explains the post-create flow: first run sets the master passphrase; a one-time recovery code is shown and must be confirmed; the vault's data key is wrapped under the master (no per-vault passphrase). Buttons: **Create vault** / Cancel.
- **Edit settings**: same fields pre-filled for an existing vault, with a vault-name header + "switch vault" control. Buttons: **Save changes** / Discard. Saving re-signs `meta.yaml` and re-encrypts the policy. (Per-secret tier/scope is edited on the secret, screen 05, not here.)

### 05 — Secrets + add/classify  (`svault secret add|get|list|remove`)
- **Purpose**: A vault's secrets with inline classification, plus an add/classify slide-over.
- **Layout**: two columns — secrets list (left, with a vertical divider) + add/classify panel (right, ~320px).
- **Secrets table**: columns Secret · Scope (badge) · Tier (badge: low/medium/high) · Callers · Window · Read (last-read time) · **Actions**. A **sealed** secret shows a "sealed" state in the Callers cell.
- **Per-row actions**: **◉ reveal** value (human path, no judge) · **✎ edit** (opens the classify panel pre-filled) · **✕ delete** (confirm).
- **Add & classify panel**: Name · Value (encrypted into `vault.enc`, never logged) · Scope · **Sensitivity tier** (segmented; note that medium/high invoke the judge) · Description (the judge weighs this against each request's reason) · Allowed callers · Time window. Add can't store an unclassified secret.

### 06 — Judge & Policy  (`svault keyring …`, `svault judge …`, `svault policy …`)
A **global AI-judge on/off** master switch at top (always visible), then three sub-tabs:
- **Judges & test**: an encrypted-**keyring** judge **registry** (named judges, default marked ★, each shows model) + a **judge editor** (Name · Model · Allow threshold · Deny threshold · free-text **Criteria** injected into the prompt · API key stored encrypted, falls back to `$SVAULT_OPENROUTER_KEY` · Assign-to-vaults) + a **Live test** bench (sample secret + reason → runs the real model → shows allow/deny + score + short rationale).
- **Policy surface** (encrypted in `vault.enc`, per-vault): Rate & burst · Conditions (time-window, required caller) · Tiers→gate mapping (low: audit only / medium: judge / high: judge + window) · Escalation (3 repeated denials → seal secret → human approval; agents never self-clear).
- **Caller access** (`policy check <caller>`): pick a caller → a table of every secret and whether it's **reachable now** (yes / yes·judged / blocked·sealed / no·scope-not-held) with the governing condition, plus that caller's active **seals** and **recent activity**.

### 07 — MCP (the agent door)  (`svault mcp`)
A **server on/off** master switch at top, then three sub-tabs:
- **Connection & tools**: a **Connected agents** table (caller · client · last call · calls today) + the two **exposed tools** as cards: `svault_get_secret` (req: name, scope, reason ≥10 chars; opt: vault, caller) and `svault_list_vaults` (no args, safe). Note: the capability descriptor advertises the *interface*, never the policy.
- **Wiring**: a per-client config block (Claude Code / Cursor / VS Code segmented) showing the `.mcp.json` snippet (`command: "svault", args: ["mcp"], env: { SVAULT_CALLER }`) with **Copy** and **Write to ./.mcp.json** (merges, doesn't clobber); Store path (`~/.svault`, `SVAULT_HOME` override) + Transport (stdio JSON-RPC 2.0); a "How the door behaves" note (no passphrase reaches the server; locked vault → agent told to ask a human; denials generic; sealed stays sealed).
- **Live log**: a streaming terminal-style tail of JSON-RPC exchanges (handshakes, tool calls, judge scores, allow/deny) with All/Allow/Deny filter + Pause/Clear. Values are never logged — only metadata + verdict.

### 08 — Audit (activity timeline)  (core `audit`/`usage`)
- **Purpose**: Every daemon decision, stamped with the connecting process's **real peer UID** (the trust anchor — not caller-claimed).
- **Layout**: filter bar (All/Allowed/Denied/Judge + vault picker + caller picker), then a vertical timeline. Each event: result badge (ALLOW/DENY/JUDGE/UNLOCK), secret name, scope·tier badges, timestamp, and a detail line (caller + uid, reason, judge score, denial reason). Denials show the **real** reason here even though the agent only got a generic message.
- Sidebar daemon box offers **Export log**.

### 09 — Pending approvals (escalation)  (`svault pending`, `svault approve`)
- **Purpose**: Sealed secrets awaiting a human; agents can never self-clear.
- **Layout**: a list of sealed-secret cards. Each: SEALED badge + secret name + vault·scope·tier · seal age · caller + uid · denied-attempt count · last reason · why (judge score / outside window). Actions: **Approve once** (single read, stays sealed) · **Approve & unseal** (clears the seal) · **Keep denied** · **View in audit**.

### 10 — Backup & recovery  (`svault export`, `import`, `recover`)
Two sub-tabs:
- **Export & import**: **Export** card (vault picker + output file `<name>.svault-export.json` + Export button; bundle is encrypted/checksummed, no machine-specific state, safe to move). **Import** card (drag-drop a `.json` bundle, checksum-verify line, Import & attach; `--name` on collision).
- **Recovery code**: **Recover with code** card (recovery-code field + new-master + confirm → Re-attach vault) and a **Recovery code status** table per vault (code saved / never viewed, with Rotate / Reveal-once). Codes shown once, never stored plaintext; rotating invalidates the old.

### 11 — Settings (app-wide)  (`svault master rekey`/`yubikey`, `svault daemon …`, app prefs)
Three sub-tabs:
- **Appearance & startup**: Theme (System/Light/Dark/Hi-contrast) · Accent · Reduce motion · **Show in menu bar** (macOS) · **Show in system tray** (Windows/Linux) · Launch at login · Close to tray · Tray-icon badge mode.
- **Security & daemon**: Auto-lock idle timeout · Re-auth cap (fixed 6h, read-only) · **Change master passphrase** (rekey — no vault re-encrypted) · **YubiKey** manage (enrolled status, enroll/remove) · Lock all. Daemon group: Run-daemon toggle · live status (pid/idle/hard countdowns) · Max connections · **Run doctor** / Restart · note that Windows has no daemon (0600 session fallback).
- **Diagnostics**: Log level · Audit source labels (cli/tui/mcp/gui) · Run daemon in foreground console · Store path (`SVAULT_HOME`) · Open log folder · **Copy diagnostics** (versions/platform/daemon state, no secrets). Plus an **About** block (version, core, store, update/docs links).

### 12 — Menu-bar / system-tray popover
- **Purpose**: Quick-access companion (~340px). The 80% case: check state, lock everything, jump to a pending approval — without opening the full window.
- **Contents**: header (brand + daemon-up state) · "Keys in memory / auto-lock countdown" + **Lock all** · list of unlocked vaults (each with a per-vault lock/unlock) · a highlighted "N pending approvals → Review" row when applicable · latest activity line · **Open Svault** (⌘↩).
- **Tray icon state**: solid = unlocked/keys-in-memory, hollow = all locked, dot badge = pending approvals. macOS → menu-bar item (top-right); Windows/Linux → tray icon (bottom). Same popover both places.

## Interactions & Behavior
- **Sign out ≠ Lock all ≠ stopping services.** Sign out ends only the GUI session (re-sign-in required); it must leave daemon, MCP, and vault-unlock state untouched. Lock all clears cached keys but keeps you signed in. Stopping the daemon/MCP are explicit toggles in Settings/MCP.
- **Unlocking is human-only.** No screen and no agent path can unlock a vault; the MCP server and agents can only read already-unlocked state.
- **Denials are generic to agents.** The real reason (judge score, scope mismatch, rate limit, condition, seal) appears only in Audit / the live log — never to the caller.
- **Gating checkboxes**: onboarding recovery-code step and any "delete vault / delete secret" must require explicit confirmation.
- **Hover help**: form-field labels carry a small `?` info affordance with an explanatory tooltip — reproduce as your component library's tooltip/help pattern.
- **Sub-tabs**: switching a sub-tab swaps the panel's inner pane only; the screen, sidebar, and any master switch (judge global on/off, MCP server on/off) stay put.
- **Live log / activity**: should stream (append newest on top) when the daemon/MCP is active; provide Pause/Clear.
- **Auto-lock countdown**: the daemon box countdown should tick and reflect real idle/hard timers.

## State Management
Frontend state the GUI needs (most is read from / written through the Rust core + daemon over Tauri commands):
- **Session**: GUI signed-in or not; master unlocked or not; re-auth deadline.
- **Daemon**: up/down, pid, per-vault idle/hard countdowns, unlocked-vault set, max connections.
- **Vaults**: list with name, storage, lock state, secret count, default tier, assigned judge, last activity.
- **Secrets** (per open vault): name, scope, tier, callers, windows, last-read, sealed flag. (Values fetched on demand via the human-path "reveal".)
- **Keyring/judges**: keyring locked/unlocked, global judge on/off, judge registry (model, thresholds, criteria, key-set status), default judge, per-vault assignment.
- **Policy/pending**: per-vault policy surface; sealed-secret queue with denial counts.
- **Audit/log**: event stream with peer UID, source (cli/tui/mcp/gui).
- **MCP**: server running/stopped, connected agents, recent JSON-RPC events.
- **Settings**: theme, tray/menu-bar visibility, launch-at-login, close-to-tray, log level, etc.
- All secret-handling, crypto, policy evaluation, and the judge call stay in Rust (`crate::core`, `crate::daemon`); the GUI never reimplements them and never holds the master passphrase longer than needed to pass it to core.

## Design Tokens (wireframe values — REPLACE with your design system)
The wireframe palette is intentionally a neutral blueprint, not the product skin. The only tokens worth carrying over are the **semantic state colors**, mapped to your own palette:
- **unlocked / allow / ok** → a green
- **locked / deny** → a red
- **pending / medium tier** → an amber
- **AI judge / info accent** → a blue
- **low tier** → neutral/hollow; **high tier** → the deny red; **medium** → amber
- Tier badges, lock-state dots, and judge allow/deny all reuse these four semantics. Everything else (paper background, mono type, square borders, hard offset shadows, hand-drawn annotation notes) is **wireframe styling to discard**.

## Assets
None. The prototype uses no external images — only Unicode glyphs for icons (⚙ ◉ ✎ ✕ ⛶ ▷ etc.), the macOS traffic-light dots, and Google Fonts (JetBrains Mono + Kalam) purely for the wireframe look. Replace glyphs with your real icon set and use the project's brand/typography.

## Files
- `Svault GUI Wireframes.html` — the full clickable wireframe (all 12 screens; top tab bar switches screens; sub-tab strips inside dense screens; an "annotations" toggle hides the design-intent notes).
- `wf.css` — the wireframe stylesheet (referenced by the HTML).

To review: open the HTML in a browser, click through the top tabs, and use the in-panel sub-tabs on Judge/MCP/Vault config/Backup/Settings. The yellow hand-written notes explain design intent and can be toggled off (bottom-right "annotations").

Source of truth for behavior/terminology: the Svault repo, especially `src/cli/mod.rs` (command tree), `docs/mcp.md`, `docs/policy-engine.md`, `docs/commands.md`, `docs/daemon.md`, `docs/recovery.md`.
