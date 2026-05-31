//! Operational configuration types.
//!
//! These used to live in a plaintext `.svault/config.yaml`. As of 0.9.3 there
//! is no plaintext config file: these structs are carried inside the encrypted
//! [`crate::core::keyring`] (alongside the judge registry and API keys) so nothing
//! abusable is readable at rest. The type definitions stay here; the keyring
//! owns their storage and the daemon reads them at start.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockConfig {
    /// Re-lock after this many seconds of inactivity. Default: 15 minutes.
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
    /// Hard limit — re-lock unconditionally. Default: 8 hours.
    #[serde(default = "default_max_unlocked")]
    pub max_unlocked_secs: u64,
}

fn default_idle_timeout() -> u64 {
    15 * 60
}
fn default_max_unlocked() -> u64 {
    8 * 60 * 60
}

impl Default for LockConfig {
    fn default() -> Self {
        Self {
            idle_timeout_secs: default_idle_timeout(),
            max_unlocked_secs: default_max_unlocked(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// Hard ceiling on simultaneously-served connections. Bounds the
    /// thread-per-connection model so a runaway or hostile same-UID process
    /// can't spawn unbounded handler threads (finding #8). The default is
    /// generous enough that realistic single-user agent concurrency never hits
    /// it; lower it on small/shared hosts, raise it on big multi-agent boxes.
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
}

fn default_max_connections() -> usize {
    512
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            max_connections: default_max_connections(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    #[default]
    Svault,
    Vaultwarden,
    Infisical,
    Env,
}
