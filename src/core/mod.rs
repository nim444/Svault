//! Core layer — the reusable, frontend-agnostic heart of Svault.
//!
//! Everything here is self-contained: crypto, vault storage, the policy engine,
//! the AI judge, metadata, keyring/master-key management, recovery, audit, and
//! the supporting file/session primitives. No module in `core` depends on a
//! frontend (`cli`, `tui`, `daemon`, `mcp`, `gui`) — frontends drive core, not
//! the other way around.

pub mod audit;
pub mod config;
pub mod crypto;
pub mod gate;
pub mod judge;
pub mod keyring;
pub mod master;
pub mod meta;
pub mod passphrase;
pub mod policy;
pub mod portable;
pub mod recovery;
pub mod secfile;
pub mod session;
pub mod touchid;
pub mod usage;
pub mod vault;
pub mod yubikey;

#[cfg(test)]
pub mod testlock;
