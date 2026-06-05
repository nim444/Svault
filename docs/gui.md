# Svault Desktop GUI (Tauri)

The desktop GUI is the roadmap's **2.0.0** milestone: a cross-platform Tauri app
that sits beside the CLI, TUI, and MCP frontends and drives the **same**
`svault-cli` core and daemon. It never reimplements crypto, the policy engine, or
the AI judge — every screen is a thin Tauri command over the existing Rust APIs.

It develops on the **1.1.0** line and ships publicly as **2.0.0** (1.1.0 is not
released or tagged on its own). All 12 design-handoff screens are built; the work
remaining before tagging is release bundling, the sidecar wiring, tray icon-state
assets, and a manual QA pass.

**Typography:** the UI uses **IBM Plex Sans**; data (recovery codes, secrets,
paths, logs) uses **IBM Plex Mono**. Both are bundled via `@fontsource`, so the
app renders correctly offline.

## Layout

```
gui/                     # the Tauri desktop app (not published to crates.io)
  src/                       # React + TypeScript frontend (Vite + Tailwind v4)
    screens/                 # one file per screen (01–12)
    components/              # app shell + UI primitives
    lib/api.ts               # typed bridge — every Tauri command in one place
  src-tauri/                 # Rust backend (crate `svault-gui`)
    src/commands/            # command modules: session, onboarding, vaults,
                             #   secrets, judge, policy, mcp, pending, audit,
                             #   backup, settings
    src/tray.rs              # tray icon + popover window
    src/lib.rs               # builder: sets SVAULT_HOME=~, Source::Gui, tray
```

The `src-tauri` crate path-depends on `svault-cli` (`../..`); `tauri` is **not** a
dependency of the published library, so `cargo install svault-cli` stays lean.

At startup the backend defaults `SVAULT_HOME` to the user's home (one global store
at `~/.svault`, exactly like `cli::run`) and stamps the audit source as `gui`.

## Run it (development)

```sh
cd gui
bun install          # first time only
bun run tauri dev    # launches the app against the live frontend
```

First launch with no master set → a one-time splash → onboarding; thereafter →
the locked sign-in gate. The GUI shares `~/.svault` with the CLI/TUI/MCP, so a
vault made in one is visible in the others.

**Daemon auto-start.** On launch (macOS/Linux) the GUI starts the daemon if it
isn't already running, by spawning a `svault` binary — never its own executable.
In a packaged build that's the bundled sidecar; **in `bun run tauri dev` there is
no sidecar**, so auto-start needs `svault` on your `PATH` (e.g. `cargo install
--path .`, or the in-app *Install CLI to PATH*). If it can't find a distinct
`svault`, it safely skips and you can start the daemon from Settings. Keep the
installed `svault` at the same version as the GUI so the daemon and the GUI's
daemon client speak the same socket protocol.

## Build / lint

```sh
# Frontend
cd gui && bun run build          # tsc + vite

# Backend
cd gui/src-tauri
cargo build
cargo fmt --all --check
cargo clippy
```

## Screens

All 12 screens from `docs/design_handoff_svault_gui/` are implemented:

| # | Screen | Commands (in `src/commands/`) |
|---|--------|-------------------------------|
| 01 | Sign in / out | `session` (`unlock`, `unlock_yubikey`, `lock_all`, `session_status`) |
| 02 | Onboarding | `onboarding` (`init_master`, `enroll_yubikey`) |
| 03 | Vault list | `vaults::list_vaults`, `lock_vault`/`unlock_vault`, `delete_vault` |
| 04 | Vault config | `vaults::create_vault` / `vault_settings` / `save_settings` |
| 05 | Secrets | `secrets` (`list_secrets`, `add`/`edit`/`remove`, `reveal_secret`) |
| 06 | Judges & Policy | `judge` (registry + live test), `policy` (surface, caller access) |
| 07 | MCP | `mcp` (connected agents, enable toggle, wiring config) |
| 08 | Audit | `audit::audit_events` (real peer UID + real denial reason) |
| 09 | Pending | `pending` (`pending`, `approve_unseal`) |
| 10 | Backup & recovery | `backup` (export/import, recover_master, rotate_code) |
| 11 | Settings | `settings` (prefs, rekey, daemon, diagnostics, install_cli) |
| 12 | Tray popover | `tray` (`open_main`, `hide_popover`) |

## Security model (held by the GUI)

- **Sign out ≠ Lock all ≠ stopping services.** Sign-out is a frontend-only flag;
  it never locks vaults, stops the daemon, or stops MCP. Lock all clears keys but
  keeps you signed in. Daemon/MCP are explicit toggles.
- **Unlocking is human-only.** No agent path can unlock a vault.
- **Denials are generic to agents.** The real reason appears only in Audit / the
  MCP live log — never to the caller.
- The master passphrase is passed to core for the call that needs it and dropped;
  the GUI never persists it. Unlocked keys live only in the daemon's memory.

## Core additions for the GUI

Small, backward-compatible additions in `svault-cli`:

- `keyring`: an `mcp_enabled` flag (default `true`) — the human-controlled MCP
  door switch, **enforced server-side** in `mcp::call_get_secret` (a disabled
  door returns the same generic "not available").
- `daemon::client::vault_status()` — per-vault idle/hard countdowns for the
  sidebar auto-lock display.
- `daemon::start_quiet_with_exe(path)` — start the daemon from an explicit
  `svault` binary instead of the current executable, so the GUI can launch the
  bundled sidecar (used by daemon auto-start and the Settings daemon controls).

## Packaging & the bundled CLI

The one installer should deliver GUI + CLI + TUI + MCP. The plan: bundle the
existing `svault` binary as a Tauri **sidecar**, and offer **Settings →
Diagnostics → Install CLI to PATH** (`install_cli`), which copies the sidecar to
`~/.local/bin`.

To wire the sidecar before `bun run tauri build`:

1. Build the CLI and stage it per target triple:

   ```sh
   scripts/bundle-sidecar.sh        # builds svault, copies to
                                    # gui/src-tauri/binaries/svault-<triple>
   ```

2. Add to `gui/src-tauri/tauri.conf.json` under `bundle`:

   ```json
   "externalBin": ["binaries/svault"]
   ```

   (Left out of the committed config so a plain `cargo build` doesn't require the
   binary to be present. Add it in the release build.)

   **macOS naming caveat:** macOS (and Windows) filesystems are case-insensitive,
   so a sidecar literally named `svault` cannot coexist with the app binary
   `Svault` in the same directory (`Contents/MacOS/`). Give the sidecar a distinct
   name (e.g. the target-triple form Tauri already uses) and have the GUI locate
   it by that name. The GUI's sidecar lookup deliberately matches exact names and
   rejects its own executable by canonical path, so it can never launch itself as
   the daemon.

Live-streaming note: the Audit timeline and MCP live log poll the audit logs
(~1.5s) with Pause, rather than a push file-watcher — simpler and robust against
multi-process writers. A `notify`-based push tail is a possible later
optimization.
