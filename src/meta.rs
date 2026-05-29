use anyhow::{anyhow, Result};
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::Path;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AllowAgent {
    Bool(bool),
    List(Vec<String>),
}

impl Default for AllowAgent {
    fn default() -> Self {
        AllowAgent::Bool(true)
    }
}

impl std::fmt::Display for AllowAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AllowAgent::Bool(true) => write!(f, "all agents"),
            AllowAgent::Bool(false) => write!(f, "none"),
            AllowAgent::List(agents) => write!(f, "{}", agents.join(", ")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessConfig {
    #[serde(default)]
    pub allow_agent: AllowAgent,
    #[serde(default = "default_rate_limit")]
    pub rate_limit: String,
}

fn default_rate_limit() -> String {
    "10/hour".to_string()
}

impl Default for AccessConfig {
    fn default() -> Self {
        Self {
            allow_agent: AllowAgent::default(),
            rate_limit: default_rate_limit(),
        }
    }
}

/// How a vault is unlocked. Only passphrase is wired today; yubikey and
/// google_auth are reserved for later steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LoginMethod {
    #[default]
    Passphrase,
    Yubikey,
    GoogleAuth,
}

impl std::fmt::Display for LoginMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoginMethod::Passphrase => write!(f, "passphrase"),
            LoginMethod::Yubikey => write!(f, "yubikey"),
            LoginMethod::GoogleAuth => write!(f, "google auth"),
        }
    }
}

/// Per-vault behavioural settings (separate from access policy).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultSettings {
    /// Re-lock the vault when idle. Default: true.
    #[serde(default = "default_autolock")]
    pub autolock: bool,
    /// How long before an idle vault auto-locks (e.g. "1d", "12h", "30m").
    #[serde(default = "default_autolock_timer")]
    pub autolock_timer: String,
    /// How the vault is unlocked.
    #[serde(default)]
    pub login_method: LoginMethod,
}

fn default_autolock() -> bool {
    true
}

fn default_autolock_timer() -> String {
    "1d".to_string()
}

impl Default for VaultSettings {
    fn default() -> Self {
        Self {
            autolock: default_autolock(),
            autolock_timer: default_autolock_timer(),
            login_method: LoginMethod::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMeta {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Storage backend this vault targets — "local" today; "cloud",
    /// "self-hosted", "s3" are reserved (remote sync is coming soon).
    /// Used as a prefix so the same name on different backends can't collide.
    pub storage: String,
    pub created_at: String,
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub access: AccessConfig,
    #[serde(default)]
    pub settings: VaultSettings,
}

fn default_version() -> u32 {
    1
}

impl VaultMeta {
    pub fn new(
        name: String,
        description: String,
        access: AccessConfig,
        settings: VaultSettings,
    ) -> Self {
        Self {
            name,
            description,
            storage: "local".to_string(),
            created_at: Utc::now().to_rfc3339(),
            version: 1,
            access,
            settings,
        }
    }

    /// Serialize, sign with HMAC, write to meta.yaml.
    pub fn save(&self, vault_dir: &Path, vault_key: &[u8]) -> Result<()> {
        let body = serde_yaml::to_string(self)?;
        let sig = sign(vault_key, &body);
        let content = format!("# sig:{sig}\n{body}");
        std::fs::write(vault_dir.join("meta.yaml"), content)?;
        Ok(())
    }

    /// Load and verify HMAC signature. Fails if tampered.
    pub fn load_verified(vault_dir: &Path, vault_key: &[u8]) -> Result<Self> {
        let content = std::fs::read_to_string(vault_dir.join("meta.yaml"))?;
        let (sig_line, body) = split_meta(&content)?;
        let expected = sign(vault_key, body);
        if !constant_time_eq(sig_line, &expected) {
            return Err(anyhow!(
                "meta.yaml signature mismatch — file may have been tampered with"
            ));
        }
        Ok(serde_yaml::from_str(body)?)
    }

    /// Load without verifying — only for listing vaults before passphrase entry.
    pub fn load_unverified(vault_dir: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(vault_dir.join("meta.yaml"))?;
        let (_, body) = split_meta(&content)?;
        Ok(serde_yaml::from_str(body)?)
    }
}

fn sign(key: &[u8], content: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(content.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn split_meta(content: &str) -> Result<(&str, &str)> {
    let Some(first_newline) = content.find('\n') else {
        return Err(anyhow!("meta.yaml format invalid"));
    };
    let first_line = &content[..first_newline];
    if !first_line.starts_with("# sig:") {
        return Err(anyhow!(
            "meta.yaml has no signature — may have been tampered with"
        ));
    }
    let sig = &first_line["# sig:".len()..];
    let body = &content[first_newline + 1..];
    Ok((sig, body))
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[cfg(test)]
mod storage_check {
    use super::*;

    #[test]
    fn storage_roundtrips() {
        let mut meta = VaultMeta::new(
            "v".into(),
            "d".into(),
            AccessConfig::default(),
            VaultSettings::default(),
        );
        meta.storage = "cloud".into();
        let body = serde_yaml::to_string(&meta).unwrap();
        let back: VaultMeta = serde_yaml::from_str(&body).unwrap();
        assert_eq!(back.storage, "cloud");
    }
}
