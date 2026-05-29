// Scaffolding for Step 3 daemon config — wired up later.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub fn config_path() -> PathBuf {
    PathBuf::from(".svault").join("config.yaml")
}

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SvaultConfig {
    #[serde(default)]
    pub backend: Backend,
    #[serde(default)]
    pub lock: LockConfig,
    #[serde(default)]
    pub daemon: DaemonConfig,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    #[default]
    Svault,
    Vaultwarden,
    Infisical,
    Env,
}

impl SvaultConfig {
    pub fn load() -> Self {
        let path = config_path();
        if !path.exists() {
            return Self::default();
        }
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_yaml::from_str(&s).ok())
            .unwrap_or_default()
    }
}
