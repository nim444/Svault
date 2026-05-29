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
curl -fsSL https://svault.soluzy.net/install.sh | bash
```

## Requirements

- **Rust** 1.74 or newer (only needed to build from source / `cargo install`).
- No external services — everything runs locally. The optional [daemon](daemon.md) (Unix only) is a local background process that holds keys in memory; it's opt-in and never required.

## Supported platforms

CI builds and tests on every push and pull request across:

| Platform | Status |
|---|---|
| Ubuntu  | Tested in CI |
| Fedora  | Tested in CI |
| macOS   | Tested in CI |
| Windows | Tested in CI |
