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
git clone https://github.com/Soluzy/Svault.git
cd Svault
cargo build --release
./target/release/svault --version
```

Optionally move it onto your `PATH`:

```bash
cp target/release/svault /usr/local/bin/   # Linux / macOS
```

## Binary install (coming soon)

A one-line installer is planned:

```bash
curl -fsSL https://svault.soluzy.app/install.sh | sh
```

## Requirements

- **Rust** 1.74 or newer (only needed to build from source / `cargo install`).
- No external services — everything runs locally. The optional [daemon](daemon.md) (Unix only) is a local background process that holds keys in memory; it's opt-in and never required.

## Supported platforms

Svault's full test suite runs in CI on every push and pull request across all four supported platforms:

| Platform | Notes |
|---|---|
| Ubuntu  | Full daemon support |
| Fedora  | Full daemon support |
| macOS   | Full daemon support |
| Windows | All commands except the Unix-only [daemon](daemon.md) |
