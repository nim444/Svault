#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

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

/// AI-judge configuration (`.svault/config.yaml`, `[judge]`). Holds **no key** —
/// the OpenRouter key comes from `$SVAULT_OPENROUTER_KEY` or a `0600` key file.
/// Disabled by default, so upgrading never silently calls an external API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JudgeConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_model")]
    pub model: String,
    #[serde(default = "default_base_url")]
    pub base_url: String,
    #[serde(default = "default_judge_timeout")]
    pub timeout_secs: u64,
    /// Minimum judge score (0-100) to allow a medium-tier (or require_reason) get.
    #[serde(default = "default_allow_threshold")]
    pub allow_threshold: u8,
    /// Stricter minimum score for a high-tier get.
    #[serde(default = "default_high_threshold")]
    pub high_threshold: u8,
    /// Optional path to a `0600` file holding the OpenRouter API key. When unset,
    /// `$SVAULT_OPENROUTER_KEY` then `~/.config/svault/openrouter.key` are tried.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_file: Option<String>,
}

fn default_model() -> String {
    "google/gemini-2.5-flash".to_string()
}
fn default_base_url() -> String {
    "https://openrouter.ai/api/v1".to_string()
}
fn default_judge_timeout() -> u64 {
    6
}
fn default_allow_threshold() -> u8 {
    60
}
fn default_high_threshold() -> u8 {
    80
}

impl Default for JudgeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            model: default_model(),
            base_url: default_base_url(),
            timeout_secs: default_judge_timeout(),
            allow_threshold: default_allow_threshold(),
            high_threshold: default_high_threshold(),
            key_file: None,
        }
    }
}

pub const KEY_ENV: &str = "SVAULT_OPENROUTER_KEY";

/// Resolve the OpenRouter API key: `$SVAULT_OPENROUTER_KEY` first, else the
/// configured (or default `~/.config/svault/openrouter.key`) key file, which
/// must be `0600` on Unix. Returns `None` when no key is available.
pub fn openrouter_key(cfg: &JudgeConfig) -> Option<Zeroizing<String>> {
    if let Ok(k) = std::env::var(KEY_ENV) {
        let k = k.trim().to_string();
        if !k.is_empty() {
            return Some(Zeroizing::new(k));
        }
    }
    let path = key_file_path(cfg)?;
    read_key_file(&path)
}

fn default_key_file() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".config/svault/openrouter.key"))
}

/// The key-file location a get would read from: the configured `judge.key_file`
/// override, else the default `~/.config/svault/openrouter.key`.
pub fn key_file_path(cfg: &JudgeConfig) -> Option<PathBuf> {
    cfg.key_file
        .clone()
        .map(PathBuf::from)
        .or_else(default_key_file)
}

/// Where the OpenRouter key currently resolves from, for `svault judge key status`.
pub enum KeySource {
    /// `$SVAULT_OPENROUTER_KEY` is set (takes precedence over the file).
    Env,
    /// A readable, correctly-permissioned key file at this path.
    File(PathBuf),
    /// No key available.
    None,
}

/// Resolve the key *source* without exposing the key value.
pub fn key_source(cfg: &JudgeConfig) -> KeySource {
    if std::env::var(KEY_ENV)
        .map(|k| !k.trim().is_empty())
        .unwrap_or(false)
    {
        return KeySource::Env;
    }
    if let Some(path) = key_file_path(cfg) {
        if read_key_file(&path).is_some() {
            return KeySource::File(path);
        }
    }
    KeySource::None
}

/// Write `key` to the configured (or default) key file as an owner-only `0600`
/// file, creating the parent directory (`~/.config/svault/`) if needed. The key
/// is trimmed; never echoed. Returns the path written.
pub fn set_openrouter_key(cfg: &JudgeConfig, key: &str) -> std::io::Result<PathBuf> {
    let path = key_file_path(cfg).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no key-file location (set $HOME or judge.key_file)",
        )
    })?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            crate::secfile::create_dir_owner_only(parent)?;
        }
    }
    crate::secfile::write_owner_only(&path, key.trim().as_bytes())?;
    Ok(path)
}

/// Delete the configured (or default) key file. Returns the removed path, or
/// `None` if there was nothing to remove.
pub fn remove_openrouter_key(cfg: &JudgeConfig) -> std::io::Result<Option<PathBuf>> {
    let Some(path) = key_file_path(cfg) else {
        return Ok(None);
    };
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(Some(path)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn read_key_file(path: &Path) -> Option<Zeroizing<String>> {
    let meta = std::fs::metadata(path).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            eprintln!(
                "svault: refusing OpenRouter key file {} — it must be 0600 (owner-only)",
                path.display()
            );
            return None;
        }
    }
    let k = std::fs::read_to_string(path).ok()?.trim().to_string();
    if k.is_empty() {
        None
    } else {
        Some(Zeroizing::new(k))
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
    #[serde(default)]
    pub judge: JudgeConfig,
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    /// set-key writes a trimmed, 0600 key; status sees it; remove deletes it.
    #[test]
    fn set_status_remove_roundtrip() {
        // Make sure the env var doesn't shadow the file for this test.
        std::env::remove_var(KEY_ENV);
        let tmp = TempDir::new().unwrap();
        let key_path = tmp.path().join("nested/openrouter.key");
        let cfg = JudgeConfig {
            key_file: Some(key_path.to_string_lossy().into_owned()),
            ..JudgeConfig::default()
        };

        // No key yet.
        assert!(matches!(key_source(&cfg), KeySource::None));
        assert!(openrouter_key(&cfg).is_none());

        // Writing creates the parent dir and a 0600 file with the trimmed key.
        let written = set_openrouter_key(&cfg, "  sk-or-secret\n").unwrap();
        assert_eq!(written, key_path);
        let mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(&*openrouter_key(&cfg).unwrap(), "sk-or-secret");
        assert!(matches!(key_source(&cfg), KeySource::File(_)));

        // Removing reports the path, and a second remove is a clean no-op.
        assert_eq!(remove_openrouter_key(&cfg).unwrap(), Some(key_path.clone()));
        assert_eq!(remove_openrouter_key(&cfg).unwrap(), None);
        assert!(matches!(key_source(&cfg), KeySource::None));
    }
}
