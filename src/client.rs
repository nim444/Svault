//! Thin client that routes CLI commands through a running daemon when one is
//! up, falling back to the file session otherwise. The functions return an
//! `Option`: `Some(..)` means the daemon handled it, `None` means "no daemon —
//! fall back to the file-session path." On non-Unix everything returns `None`.

/// Result of asking the daemon for a secret (human path).
pub enum GetOutcome {
    /// The daemon returned the value.
    Value(String),
    /// The daemon is up but the vault isn't unlocked — caller should fall back.
    NotUnlocked,
    /// The daemon is up and the vault unlocked, but the secret doesn't exist.
    NotFound,
}

/// Result of a gated (agent-path) request to the daemon.
pub enum GatedOutcome {
    /// Policy + judge allowed it; carries the value and tier.
    Granted(String, crate::policy::Tier),
    /// Policy or the AI judge denied it.
    Denied(String),
    /// Daemon up but the vault isn't unlocked — caller should fall back.
    NotUnlocked,
    /// Vault unlocked but the secret doesn't exist.
    NotFound,
}

#[cfg(unix)]
mod imp {
    use super::{GatedOutcome, GetOutcome};
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
    ///
    /// The key is derived (and the passphrase validated) **client-side** by
    /// opening the vault here; only the 32-byte derived key crosses the socket,
    /// never the passphrase (finding #3). A wrong passphrase fails locally and
    /// never reaches the daemon.
    pub fn unlock(vault: &str, passphrase: &str) -> Option<Result<()>> {
        if !available() {
            return None;
        }
        let dir = base().join(vault);
        let key_hex = match crate::vault::Vault::open(&dir, passphrase) {
            Ok(v) => hex::encode(v.key().bytes()),
            Err(e) => return Some(Err(e)),
        };
        let req = Request::Unlock {
            vault: vault.to_string(),
            key: key_hex,
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

    /// Agent path: a gated request the daemon evaluates (policy + judge + audit).
    /// `None` = no daemon, so the caller runs the same gate locally instead.
    pub fn get_gated(
        vault: &str,
        secret: &str,
        caller: &str,
        scope: &str,
        reason: &str,
    ) -> Option<GatedOutcome> {
        if !available() {
            return None;
        }
        let req = Request::GetGated {
            vault: vault.to_string(),
            secret: secret.to_string(),
            caller: caller.to_string(),
            scope: scope.to_string(),
            reason: reason.to_string(),
        };
        match daemon::send(&base(), &req) {
            Ok(Response::Granted { value, tier }) => Some(GatedOutcome::Granted(value, tier)),
            Ok(Response::Denied { reason }) => Some(GatedOutcome::Denied(reason)),
            Ok(Response::NotUnlocked) => Some(GatedOutcome::NotUnlocked),
            Ok(Response::NotFound) => Some(GatedOutcome::NotFound),
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
    use super::{GatedOutcome, GetOutcome};
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
    pub fn get_gated(
        _vault: &str,
        _secret: &str,
        _caller: &str,
        _scope: &str,
        _reason: &str,
    ) -> Option<GatedOutcome> {
        None
    }
    pub fn unlocked_vaults() -> Vec<String> {
        Vec::new()
    }
}

pub use imp::{get, get_gated, lock, lock_all, unlock, unlocked_vaults};
