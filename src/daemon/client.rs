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
    Granted(String, crate::core::policy::Tier),
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

    /// Cache an already-unwrapped vault key (the unified-unlock path). The DEK
    /// was unwrapped from the vault's keyslot under the master key, so there is
    /// no passphrase to validate — only the 32-byte key crosses the socket.
    pub fn unlock_with_key(vault: &str, key: &[u8; 32]) -> Option<Result<()>> {
        if !available() {
            return None;
        }
        let req = Request::Unlock {
            vault: vault.to_string(),
            key: hex::encode(key),
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

    pub fn unlock_with_key(_vault: &str, _key: &[u8; 32]) -> Option<Result<()>> {
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

pub use imp::{get, get_gated, lock, lock_all, unlock_with_key, unlocked_vaults};
