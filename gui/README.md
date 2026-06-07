# Svault Desktop GUI

A cross-platform desktop app (Tauri + React + TypeScript) for managing Svault
vaults, secrets, policy, AI providers and judges, MCP wiring, audit, and
recovery. It drives
the **same** `svault-cli` core and daemon as the CLI/TUI/MCP — it never
reimplements crypto, the policy engine, or the judge. First sign-in lands on a
**getting-started checklist** (provider → optional judge → vault → secret)
until the store holds a secret.

This is the roadmap's **2.0.0** milestone. It develops on the **1.1.x** line and
ships publicly as 2.0.0 (1.1.x is not released on its own).

> Full documentation: [`../docs/gui.md`](../docs/gui.md).

## Develop

```sh
bun install          # first time only
bun run tauri dev    # launch the app against the live frontend
```

On macOS/Linux the app auto-starts the Svault daemon on launch. In dev there is
no bundled sidecar, so that needs `svault` on your `PATH` (e.g. `cargo install
--path ..` from the repo root, or the in-app *Settings → Install CLI to PATH*).
Keep that `svault` at the same version as the GUI.

## Build / lint

```sh
bun run build                 # frontend: tsc + vite
cd src-tauri && cargo build   # backend
cargo fmt --all --check
cargo clippy
```

## Layout

- `src/` — React + TypeScript frontend (Vite + Tailwind v4); `screens/` is one
  file per screen, `components/` the app shell + UI primitives, `lib/api.ts` the
  typed bridge to every Tauri command.
- `src-tauri/` — Rust backend (crate `svault-gui`), path-depending on `svault-cli`.
  `src/commands/` holds the command modules; `src/tray.rs` the tray popover;
  `src/lib.rs` the builder (sets `SVAULT_HOME=~`, `Source::Gui`, the tray —
  gated by the `show_tray` pref — close-to-tray handling, launch-at-login
  sync, and daemon auto-start).

## Recommended IDE setup

[VS Code](https://code.visualstudio.com/) +
[Tauri](https://marketplace.visualstudio.com/items?itemName=tauri-apps.tauri-vscode) +
[rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer).
