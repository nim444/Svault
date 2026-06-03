# Installation

Svault ships as a single native binary with no runtime dependencies.

## From crates.io (recommended)

```bash
cargo install svault-ai
svault --version
```

The crate is published as [`svault-ai`](https://crates.io/crates/svault-ai); the installed binary is named `svault`.

## From source

```bash
git clone https://github.com/nim444/Svault.git
cd Svault
cargo build --release
./target/release/svault --version
```

Optionally move it onto your `PATH`:

```bash
cp target/release/svault /usr/local/bin/   # Linux / macOS
```

## Where your secrets live

By default the encrypted store is **`~/.svault`** (the user's home directory), so
`svault` behaves the same from any working directory and the CLI, TUI, [daemon](daemon.md),
and [MCP server](mcp.md) all share one store. Set `SVAULT_HOME` to use
`$SVAULT_HOME/.svault` instead — for a project-scoped store, or to point an MCP server
at a non-home location:

```bash
export SVAULT_HOME=/path/to/project   # store at /path/to/project/.svault
```

`SVAULT_HOME` governs the whole store (vaults, master keyslots, keyring, sessions, and
the daemon socket), so export it consistently across every shell and MCP config that
should see the same vaults.

## Binary install (coming soon)

A one-line installer is planned (the hosting URL is not finalized yet):

```bash
curl -fsSL https://<install-host>/install.sh | sh
```

## Requirements

- **Rust** 1.74 or newer (only needed to build from source / `cargo install`).
- No external services — everything runs locally. The optional [daemon](daemon.md) (Unix only) is a local background process that holds keys in memory; it's opt-in and never required.

### Optional: YubiKey unlock

[YubiKey unlock](architecture.md#authentication-the-keyslot-model) is an **opt-in build feature** (`yubikey`), off by default — the default build and `cargo install svault-ai` have **no system dependencies** and no YubiKey code. The **prebuilt release binaries** (GitHub Releases) already include it. To get it from source / crates.io:

```bash
cargo install svault-ai --features yubikey
```

It talks to the key over USB-HID (FIDO2):

- **macOS / Windows** — nothing extra; uses the OS-native HID APIs.
- **Linux** — building the feature needs the `libudev` headers (`libudev-dev` on Debian/Ubuntu, `systemd-devel` on Fedora); at runtime the key's `/dev/hidraw*` node needs read/write access, granted by the standard FIDO udev rules (e.g. the `libfido2` / `yubikey-manager` package). `libudev.so.1` itself is present on any systemd-based distro.

A build without the feature runs fine — `svault master yubikey enroll` just reports that this build has no YubiKey support.

## Supported platforms

Svault's full test suite runs in CI on every push and pull request across all four supported platforms:

| Platform | Notes |
|---|---|
| Ubuntu  | Full daemon support |
| Fedora  | Full daemon support |
| macOS   | Full daemon support |
| Windows | All commands except the Unix-only [daemon](daemon.md) |
