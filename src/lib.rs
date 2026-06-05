//! Svault — an AI-aware secret access layer.
//!
//! The crate is organized into a reusable [`core`] and a set of frontends that
//! drive it:
//!
//! - [`core`] — crypto, vault storage, the policy engine, the AI judge, and
//!   supporting primitives. Frontend-agnostic.
//! - [`daemon`] — the Unix unlock daemon and its client.
//! - [`tui`] — the interactive terminal UI.
//! - [`cli`] — the `svault` command-line interface (entry point: [`cli::run`]).
//! - [`mcp`] — the local Model Context Protocol server (`svault mcp`), a stdio
//!   JSON-RPC frontend that exposes gated secret access to AI agents.
//!
//! The desktop GUI is the separate `gui/` Tauri crate (`svault-gui`), which
//! drives this library — see `docs/gui.md`.
//!
//! The `svault` binary ([`main`](../main/index.html)) is a thin wrapper over
//! [`cli::run`]. Each frontend reuses [`core`] without touching the others.
//!
//! Note: the [`core`] module deliberately shadows the std `core` crate; the
//! source uses `std` throughout, so this is safe. Reach the std crate with
//! `::core` if ever needed.

pub mod cli;
pub mod core;
pub mod daemon;
pub mod mcp;
pub mod tui;
