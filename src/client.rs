//! Thin client that routes CLI commands through a running daemon when one is
//! up, falling back to the file session otherwise. The functions return an
//! `Option`: `Some(..)` means the daemon handled it, `None` means "no daemon —
//! fall back to the file-session path." On non-Unix everything returns `None`.

/// Result of asking the daemon for a secret.
pub enum GetOutcome {
    /// The daemon returned the value.
    Value(String),
    /// The daemon is up but the vault isn't unlocked — caller should fall back.
    NotUnlocked,
    /// The daemon is up and the vault unlocked, but the secret doesn't exist.
    NotFound,
}

#[cfg(unix)]
mod imp {
    use super::GetOutcome;
    use crate::daemon::{self, Request, Response};
    use anyhow::{anyhow, Result};
    use std::path::PathBuf;

    fn base() -> PathBuf {
        daemon::base_dir()
    }

    /// True when a daemon is running for this project.
    pub fn available() -> bool {
        daemon::is_running(&base())
    }

    /// Cache a vault's key in the daemon. `None` = no daemon (fall back).
    pub fn unlock(vault: &str, passphrase: &str) -> Option<Result<()>> {
        if !available() {
            return None;
        }
        let req = Request::Unlock {
            vault: vault.to_string(),
            passphrase: passphrase.to_string(),
        };
        Some(match daemon::send(&base(), &req) {
            Ok(Response::Unlocked) => Ok(()),
            Ok(Response::Error { message }) => Err(anyhow!(message)),
            Ok(other) => Err(anyhow!("unexpected daemon response: {other:?}")),
            Err(e) => Err(e),
        })
    }

    /// Drop one vault's key. `None` = no daemon.
    pub fn lock(vault: &str) -> Option<usize> {
        if !available() {
            return None;
        }
        match daemon::send(
            &base(),
            &Request::Lock {
                vault: vault.to_string(),
            },
        ) {
            Ok(Response::Locked { count }) => Some(count),
            _ => Some(0),
        }
    }

    /// Drop every cached key. `None` = no daemon.
    pub fn lock_all() -> Option<usize> {
        if !available() {
            return None;
        }
        match daemon::send(&base(), &Request::LockAll) {
            Ok(Response::Locked { count }) => Some(count),
            _ => Some(0),
        }
    }

    /// Read a secret via the daemon. `None` = no daemon, or a protocol error
    /// the caller should treat as "fall back".
    pub fn get(vault: &str, secret: &str) -> Option<GetOutcome> {
        if !available() {
            return None;
        }
        let req = Request::Get {
            vault: vault.to_string(),
            secret: secret.to_string(),
        };
        match daemon::send(&base(), &req) {
            Ok(Response::Secret { value }) => Some(GetOutcome::Value(value)),
            Ok(Response::NotUnlocked) => Some(GetOutcome::NotUnlocked),
            Ok(Response::NotFound) => Some(GetOutcome::NotFound),
            _ => None,
        }
    }

    /// Names of vaults currently unlocked in the daemon (empty if none / down).
    pub fn unlocked_vaults() -> Vec<String> {
        if !available() {
            return Vec::new();
        }
        match daemon::send(&base(), &Request::Status) {
            Ok(Response::Status { vaults }) => vaults.into_iter().map(|v| v.name).collect(),
            _ => Vec::new(),
        }
    }
}

#[cfg(not(unix))]
mod imp {
    use super::GetOutcome;
    use anyhow::Result;

    pub fn unlock(_vault: &str, _passphrase: &str) -> Option<Result<()>> {
        None
    }
    pub fn lock(_vault: &str) -> Option<usize> {
        None
    }
    pub fn lock_all() -> Option<usize> {
        None
    }
    pub fn get(_vault: &str, _secret: &str) -> Option<GetOutcome> {
        None
    }
    pub fn unlocked_vaults() -> Vec<String> {
        Vec::new()
    }
}

pub use imp::{get, lock, lock_all, unlock, unlocked_vaults};
