# GUI logic inventory — complete extraction for the rebrand rebuild

> **Purpose.** The current desktop GUI (Tauri 2 + React 19, `gui/`) is slated for
> deprecation in favor of a new app. This document pulls out **every piece of
> logic the GUI implements** — the full IPC command surface, app-lifecycle
> behaviors, frontend-only logic, and the conventions that hold it together — so
> it can be reviewed decision-by-decision and serve as the functional spec for
> the new app. Written 2026-06-10 against `svault-cli` 1.1.1.
> Companions: [gui-redesign-plan.md](gui-redesign-plan.md),
> [native-ui-options.md](native-ui-options.md),
> [security-review/findings/gui-1.1.0.md](security-review/findings/gui-1.1.0.md).

## 1. Architecture in one paragraph

The GUI links `svault-cli` as a Rust library and drives the same core + daemon
code paths as the CLI — no crypto, policy, or judge logic lives in the GUI; the
command layer (`gui/src-tauri/src/commands/`, ~2,800 lines, 71 commands) only
marshals data between the React frontend and core. Secret values cross the IPC
exactly once (reveal). Everything below is what the new app must re-provide (or
deliberately drop).

## 2. Process lifecycle (lib.rs)

| Behavior | Logic |
|---|---|
| Store resolution | On launch, default `SVAULT_HOME` to the user's home (one global store at `~/.svault`); an explicit env value is honored |
| Audit identity | Stamp the process audit source as `gui` (`usage::set_source(Gui)`) |
| Daemon autostart | Unix only; skip if already running; locate a *separate* `svault` binary (bundled sidecar or PATH) and start it quietly. **Fork-bomb guard:** sidecar matched by exact case-sensitive filename, and the GUI's own canonicalized exe is always rejected (a case-insensitive FS would otherwise stat-match `Svault` and relaunch the GUI in a loop). Failures non-fatal |
| Tray setup | Only if pref `show_tray` (default true), read at startup — changes take effect next launch |
| Close-to-tray | On main-window close: if `show_tray && close_to_tray` prefs, prevent close and hide; otherwise exit the app (so the hidden popover never keeps the process alive) |
| GUI state | `GuiState`: `unlocked_at` + `reauth_cap_secs` (mutex-held), purely for computing the re-auth deadline shown in the UI |

## 3. Shared conventions (commands/common.rs)

- **Vault identity is the directory leaf**, matching daemon keying; `meta.name`
  is display-only.
- **`require_master()`** — the single backend gate: master from the cached core
  session, else "sign in again". Note: the *GUI* sign-in flag is frontend-only
  (section 7); this core session is the real gate.
- **`open_vault(leaf)`** — re-derives the vault DEK from the master keyslot
  (never asks the daemon for raw keys), opens `vault.enc`.
- **`open_or_init_keyring()`** — open keyring from session; else unwrap its DEK
  under the master; else **create it on first use** and wrap it under the master.
- **`parse_tier(s)`** — "high" / "medium"|"med" / anything-else→**Low**.
  (Silent default-to-Low on a typo is a revisit candidate — see section 9.)
- Errors are plain `String`s (`CmdResult<T> = Result<T, String>`).

## 4. Full command inventory (71 commands)

Gate column: **M** = requires master session (`require_master`/`open_vault`/
`open_or_init_keyring`), **—** = ungated (reads disk/daemon state directly;
same-UID by-design, see G-5).

### Session & sign-in (session.rs)

| Command | Gate | Logic |
|---|---|---|
| `session_status` | — | `master_exists/unlocked`, daemon up, YubiKey/Touch ID enrolled+supported, unlocked vault leaves (daemon list ∪ file sessions), re-auth deadline (GUI-stamped unlock time + cap), soonest auto-lock across daemon vaults. Polled ~1/s by the shell |
| `unlock` (passphrase) | — | Argon2id off-main-thread (async); opens master, then **unlock-all**: keyring first (so the configured re-auth cap + judge config apply), then every master-wrapped vault → DEK into daemon memory if up, else 0600 file session; stamps usage `unlock` per vault; caches master session; stamps GUI re-auth deadline |
| `unlock_yubikey` | — | Same flow via FIDO2 hmac-secret (optional PIN) |
| `unlock_touchid` | — | Same flow via Touch ID keyslot (macOS biometric sheet, async) |
| `yubikey_present` | — | On-demand USB-HID scan, deliberately kept out of the 1s poll |
| `lock_all` | — | Daemon `lock_all` if up, else clear all file sessions; clears master + keyring sessions and the GUI unlock stamp. Distinct from sign-out (section 7) |

### Onboarding (onboarding.rs)

| Command | Gate | Logic |
|---|---|---|
| `init_master` | first-run only | Refuses if a master exists; Argon2id init, caches session (user lands signed in), writes + returns the **one-time master recovery code** (frontend must gate continuation on "I saved it") |
| `enroll_yubikey` / `remove_yubikey` | M / — | Add/remove the FIDO2 keyslot over the master. **Note: `remove_yubikey` is ungated** |
| `enroll_touchid` / `remove_touchid` | M / — | Add/remove the Touch ID keyslot (biometric sheet on enroll; remove deletes keyslot file + keychain item). **`remove_touchid` ungated** |

### Vaults (vaults.rs)

| Command | Gate | Logic |
|---|---|---|
| `list_vaults` | M | For every vault dir: meta (unverified load), **decrypts the policy via master keyslot** for rich columns (secret count excluding `*`, default tier, allow-agent mode, judge on/assigned, sealed count), last activity from usage log, unlocked state. Sorted by name |
| `create_vault` | M | Name required; **dir = `svault_dir()/name`** (no sanitization — see section 9); builds `VaultMeta` (autolock, timer, login method) + encrypted `VaultPolicyData` (allow-agent mode none/list/all, rate limit, default tier, judge enabled/assigned); new DEK, init vault, wrap under master, cache key (daemon else session), generate + write **one-time vault recovery code**, return it |
| `vault_settings` | M | Read-back of the same form fields from meta + decrypted policy |
| `save_settings` | M | Writes description/autolock/login into meta and allow-agent/rate-limit/tier/judge into the encrypted policy. Name not editable |
| `unlock_vault` / `lock_vault` | M / — | Per-vault DEK unwrap → daemon or file session; lock via daemon else session |
| `delete_vault` | M (via dir_for only — **no master needed**) | Lock then `remove_dir_all`. Confirm is **UI-only**; no step-up auth |

### Secrets (secrets.rs)

| Command | Gate | Logic |
|---|---|---|
| `list_secrets` | M | Names + per-secret rule (scope, tier, require_reason, description, required callers, time windows), sealed flag, last read from audit log |
| `add_secret` | M | Name ≠ ""/"*", value required, duplicate refused; writes value into `vault.enc` and the rule into the policy; validates window specs up front |
| `edit_secret` | M | Empty/absent value = keep existing value, rule always rewritten |
| `remove_secret` | M | Removes value + rule + any seal |
| `reveal_secret` | M (fallback path) | **Human path, no judge.** Prefers the daemon (audited there); daemon NotUnlocked falls through to direct vault open. Returns plaintext `String` across IPC (G-9 residue) |

### Judges & providers (judge.rs)

| Command | Gate | Logic |
|---|---|---|
| `keyring_state` | — | exists/unlocked, judge_enabled, mcp_enabled, default judge, counts (zeros when locked; `mcp_enabled` reports **true** when locked) |
| `judge_list` / `judge_names` | M / — | Registry read; `has_key` resolved through provider; names for the vault-config picker |
| `judge_save` | M | Add/update named judge (model, allow/high thresholds, criteria, own key or named provider — provider must exist; blank key keeps existing). First judge becomes default. Audited to global usage log |
| `judge_remove` / `judge_set_default` / `judge_toggle` | M | Registry maintenance; removing the default promotes an arbitrary next; global judge on/off switch. All audited |
| `judge_test` | M | **Live test bench**: materializes the judge (provider key fallback, `$SVAULT_OPENROUTER_KEY` env fallback), builds a `JudgeContext` from the form (vault="test", recent="no prior requests"), runs the real model, returns verdict/score/rationale/thresholds (G-7: the sample secret text goes to the provider) |
| `provider_kinds` | — | Static kinds + default base URLs + key-optional flags (local kinds) |
| `provider_list` | M | Name, kind, base_url, has_key (never the key), enabled, default, used-by judges |
| `provider_save` | M | Kind must be known; blank base_url → kind default, else trim + strip trailing `/` (**no HTTPS pinning — G-6**); blank key keeps existing; key required unless kind is key-optional; first becomes default. Audited |
| `provider_toggle` / `provider_set_default` / `provider_remove` | M | Disabled providers lend no credentials (judges fall back to static tier rules, enforced in core); remove refused while any judge references it; default reassigned on remove. Audited |
| `provider_models` | M | Live `/models` fetch with the provider's key, for the model picker; UI falls back to free text |

### Policy views (policy.rs) — read-only

| Command | Gate | Logic |
|---|---|---|
| `policy_surface` | M | Vault rate limit, allow-agent, default tier, per-caller rules (scopes, rate limit), conditioned secrets (windows / required callers), the static tier-gate explainer rows, seal threshold + window constants |
| `caller_access` | M | For one caller name: defined rule, scopes, rate limit, accessible secrets (policy `accessible()`), conditioned list, all seals, allow/deny totals from a **full audit-log scan** |

### MCP (mcp.rs)

| Command | Gate | Logic |
|---|---|---|
| `connected_agents` | — | Derived table: scan **all vaults' full audit logs** for `source = mcp`, group by caller → peer UID, last call, calls today. ("Connected" = has ever called) |
| `mcp_toggle` / `mcp_enabled` | M / — | Keyring flag, enforced server-side in `svault_get_secret`; reads true when keyring locked |
| `mcp_config_snippet` | — | Builds the `.mcp.json` JSON (command=bin, args=["mcp"], env.SVAULT_CALLER; blank caller → "my-agent") |
| `write_mcp_config` | — | **Merges** the svault server into a `.mcp.json` at a caller-supplied `path` without clobbering other servers; creates if absent (G-1: arbitrary path + content) |
| `store_path` | — | `SVAULT_HOME/.svault` display string |

### Pending approvals (pending.rs)

| Command | Gate | Logic |
|---|---|---|
| `pending` | M | Every sealed secret across all vaults: vault, secret, scope/tier from its rule, sealed_at, trigger, last caller, denial count |
| `approve_unseal` | M | Removes the seal from the encrypted policy + audits `seal.cleared`. **Cached session suffices — the CLI's fresh-master requirement (M9-2 fix) is NOT mirrored here**; "Keep denied" is a frontend dismiss, no state change |

### Audit (audit.rs)

| Command | Gate | Logic |
|---|---|---|
| `audit_events` | — | Reads every vault's append-only audit log (or one vault), maps to events with **real denial reasons + peer UID**, filters (result/judge/caller/source/time range), newest-first, truncates to limit. No file-level pagination — full scan per call |
| `activity_events` | — | The usage timeline: per-vault `usage.log` + the global one ("global" rows = provider/judge/MCP config changes), actor human/agent, source cli/tui/gui/mcp, newest-first, default limit 500 |
| `audit_callers` | — | Distinct caller names across all audit logs (filter dropdown) |
| `export_log` | — | Serializes a vault's full audit log to pretty JSON at a caller-supplied `path` (G-1) |

### Backup & recovery (backup.rs)

| Command | Gate | Logic |
|---|---|---|
| `export_vault` | — (dir_for only) | Portable encrypted bundle (carries the wrapped key) written **owner-only** to a caller-supplied path (G-1, least-bad) |
| `import_vault` | M (at re-wrap) | Parse bundle, unique-suffix the target name, import, **require its recovery file + code** to unwrap the DEK (cleanup on failure), rename meta if suffixed, re-wrap under this machine's master, cache session |
| `recover_master` | — (signed-out path) | Master recovery code + new passphrase → `master::recover`. The "lost passphrase" flow |
| `recovery_status` | — | Per vault: has a recovery file or not |
| `rotate_code` | M | New vault recovery code, re-wrap, old invalidated, returned once |

### Settings (settings.rs)

| Command | Gate | Logic |
|---|---|---|
| `get_prefs` / `set_prefs` | — | Opaque JSON at `.svault/gui-prefs.json` the frontend owns (theme, reduce-motion, show_tray, close_to_tray, launch_at_login…). `set_prefs` also **syncs the OS launch-at-login entry** to match the pref |
| `change_master` | M | Rekey to a new passphrase off the **cached session — no current-passphrase/step-up (G-3)**; data keys never move; re-caches session |
| `yubikey_status` / `touchid_status` | — | enrolled + present/supported |
| `daemon_info` | — | running, pid, limits from keyring (defaults 512 conns / 15 min idle / 6 h cap when locked), `supported = unix` |
| `daemon_start` / `daemon_stop` / `daemon_doctor` | — | Start via located sidecar/PATH binary (fork-bomb guard), stop, doctor (clean stale socket/pid) |
| `set_daemon_limits` | M | idle timeout, max connections, re-auth cap (clamped 15 min–7 d) into the keyring; daemon limits apply next start, cap applies from next sign-in |
| `diagnostics` | — | Copyable blob: version, OS/arch, store path, daemon/master/yubikey state. No secrets |
| `store_folder` | — | Store path for "open folder" |
| `install_cli` | — | Copies the bundled sidecar to `~/.local/bin/svault` (0755) — one install delivers CLI + TUI + MCP |

### Shell (mod.rs, tray.rs)

| Command | Gate | Logic |
|---|---|---|
| `app_info` | — | version, master_exists (drives onboarding vs sign-in), recovery_exists, yubikey_enrolled, store path |
| `open_main` / `hide_popover` | — | Window management from the tray popover |

## 5. Tray & popover (tray.rs)

- A second, borderless, always-on-top, hidden 340×480 webview window labeled
  `popover` loads the **same React bundle**; the frontend branches on the window
  label to render the compact tray view.
- Tray icon: left-click toggles the popover; menu = Open Svault / Lock all /
  Quit. "Lock all" calls the same `lock_all` command path.

## 6. The onboarding flow (frontend + backend split)

1. Disclaimer (frontend-only).
2. `init_master` → returns the one-time master recovery code.
3. Recovery-code display; continuation gated on a **frontend-only** "I saved it"
   checkbox.
4. Unlock methods: Touch ID enroll step, YubiKey enroll step (each optional,
   backend `enroll_*`).
`app_info().master_exists` decides onboarding vs sign-in at launch.

## 7. Frontend-only logic worth knowing

- **`signedIn` is a zustand flag, nothing more** (`store/session.ts`): the app
  always launches "locked"; sign-out flips the flag **without touching** the
  daemon, MCP, or vault sessions (deliberate — no backend `sign_out` exists).
  The real gate is the core master session; any walk-up protection the flag
  provides is theater for same-UID purposes (gui-1.1.0 G-3 discussion).
- **Sign-in favorite**: last-used unlock method remembered in
  `localStorage` (`svault.signin.favorite`), pre-selected next launch; fallback
  order favorite → Touch ID → passphrase.
- **Shell poll**: `session_status` polled about once a second for the sidebar
  status rows (Guardian / Key service / Agent gateway), re-auth countdown, and
  auto-lock timer.
- **Clipboard**: reveal, recovery codes, diagnostics, MCP snippet all
  `writeText` — no auto-clear (G-4).
- Screens (15): Start, Onboarding, SignIn, Recover, Vaults, VaultConfig,
  Secrets, Judges, Providers, Mcp, Pending, Audit, Backup, Settings,
  TrayPopover.

## 8. Invariants the new app must preserve

1. All crypto/policy/judge logic stays in core; the app layer only marshals.
2. Vaults are addressed by directory leaf everywhere (daemon parity).
3. Reveal is the human path — no judge — and prefers the daemon so the read is
   audited with a peer UID.
4. Agent denials stay generic; real reasons appear only in the audit view.
5. The keyring is created lazily under the master on first config write.
6. One-time codes (master + vault recovery, rotations) are returned exactly once
   and never stored in plaintext.
7. Unlock-all opens the keyring before stamping sessions (so the configured
   re-auth cap and judge config take effect in the same sign-in).
8. The daemon-autostart fork-bomb guard (exact-name + canonical-path-reject).
9. Sign-out (UI state) is distinct from Lock all (clears keys); closing the
   window is distinct from quitting (tray).
10. `mcp_enabled` and provider/judge config changes are audited to the global
    usage log.

## 9. Decisions to revisit in the rebuild (seed for the bad-decisions register)

Security items already on file: G-1 (arbitrary-path writes: `export_log`,
`write_mcp_config`, `export_vault`), G-2 (CSP null), G-3 (`change_master` no
step-up; frontend-only sign-in gate), G-4 (clipboard), G-5 (ungated reads),
G-6 (no HTTPS pinning). New observations from this extraction:

1. **`create_vault` uses the raw vault name as a path component** —
   `svault_dir().join(name)` with no separator/`..` validation in the GUI or in
   core `Vault::init_with_key`. A name like `../x` creates a vault outside the
   store. Same-UID model so not an escalation, but it's an input-validation bug
   (likely shared by the CLI). Candidate finding for the next review.
2. **`approve_unseal` accepts the cached session** while the CLI's `svault
   approve` was deliberately hardened to require a fresh master (M9-2). The GUI
   path undercuts that fix; the new app should mirror fresh re-auth (or Touch
   ID) for unseal — and for `change_master`, `remove_yubikey`, `remove_touchid`,
   `delete_vault`.
3. **`remove_yubikey` / `remove_touchid` are ungated** — they don't even require
   the master session; anyone at the app can strip unlock methods.
4. **`parse_tier` silently maps unknown → Low** — a typo in a tier label
   *downgrades* classification. Should be a validation error.
5. **Polling architecture** — 1 s `session_status` polling plus full
   audit-log scans per view (`audit_events`, `connected_agents`,
   `caller_access` re-read every log every call). Fine at current scale; the
   new app should consider push/events and incremental log reads.
6. **`list_vaults` decrypts every vault's policy on every call** — cost grows
   with vault count; consider caching keyed on file mtime.
7. **`delete_vault` is UI-confirm only** — no backend step-up for a permanent,
   unrecoverable deletion.
8. **Errors are bare `String`s** — no error codes, so the frontend string-matches
   for behavior. The new app's API should use typed errors.
9. **Prefs are an opaque JSON blob** the frontend owns but the backend partially
   interprets (`show_tray`, `close_to_tray`, `launch_at_login`) — split the
   schema or own it fully in the backend.
10. **`keyring_state.mcp_enabled` reports `true` when the keyring is locked**
    (matches enforcement default, but the UI can't distinguish "on" from
    "unknown").

## 10. What deprecation should look like

The command surface above (minus the revisits) is the contract. Recommended
path per [gui-redesign-plan.md](gui-redesign-plan.md): restructure this layer
into a frontend-agnostic Rust API first — same functions, typed errors,
validated inputs, step-up auth where flagged — and let the new app (Tauri or
SwiftUI shell) consume that. The `gui/` tree then retires whole, and the
security register for the new app starts from section 9 instead of rediscovering
it.
