//! The keyring — Svault's single encrypted store for global config.
//!
//! Everything that used to sit in the plaintext `.svault/config.yaml` and the
//! plaintext `~/.config/svault/openrouter.key` lives here instead, AES-256-GCM
//! encrypted at rest under its own passphrase (Argon2id, like a vault):
//!
//! - the **judge registry** — multiple named judges, each with its own model,
//!   thresholds, free-text *criteria*, and **API key**;
//! - the global judge on/off switch and the default judge;
//! - operational knobs (lock timers, daemon max-connections, backend).
//!
//! A same-UID agent can no longer read thresholds/criteria to tune a passing
//! request, nor steal the API key from a plaintext file. The keyring is unlocked
//! once per session (a `0600` session caches its derived key, exactly like a
//! vault) and held in the daemon's memory; until unlocked the judge is off and
//! the static tier rules apply.
//!
//! Honest boundary: the keyring is exactly as protected as a vault — it closes
//! the read-at-rest path, but is not a sandbox against a hostile same-UID
//! process reading the unlocked daemon's memory or the `0600` session.
#![allow(dead_code)]

use anyhow::{anyhow, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::config::{Backend, DaemonConfig, LockConfig};
use crate::crypto::{self, VaultKey, SALT_SIZE};
use crate::vault::SVAULT_DIR;

/// Current on-disk version of the encrypted keyring payload.
const KEYRING_VERSION: u32 = 1;

const KEYRING_FILE: &str = "keyring.enc";
const KEYRING_SESSION: &str = ".keyring.session";

/// Opt-in env override for a judge with no stored key (env, never a file).
pub const KEY_ENV: &str = "SVAULT_OPENROUTER_KEY";

pub fn keyring_path() -> PathBuf {
    PathBuf::from(SVAULT_DIR).join(KEYRING_FILE)
}

fn session_path() -> PathBuf {
    PathBuf::from(SVAULT_DIR).join(KEYRING_SESSION)
}

/// True if a keyring has been created on this machine.
pub fn exists() -> bool {
    keyring_path().exists()
}

/// One named judge: a model + thresholds + free-text criteria + its own API key.
/// The criteria are injected into the judge prompt; the key is encrypted at rest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JudgeDef {
    #[serde(default = "default_model")]
    pub model: String,
    #[serde(default = "default_base_url")]
    pub base_url: String,
    #[serde(default = "default_judge_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_allow_threshold")]
    pub allow_threshold: u8,
    #[serde(default = "default_high_threshold")]
    pub high_threshold: u8,
    /// Free-text rules added to the judge's prompt — what this judge should
    /// weigh when deciding. Sensitive recon material, so encrypted at rest.
    #[serde(default)]
    pub criteria: String,
    /// The OpenRouter API key for this judge. Empty means "fall back to
    /// `$SVAULT_OPENROUTER_KEY`" (an explicit, opt-in env override).
    #[serde(default)]
    pub api_key: String,
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

impl Default for JudgeDef {
    fn default() -> Self {
        Self {
            model: default_model(),
            base_url: default_base_url(),
            timeout_secs: default_judge_timeout(),
            allow_threshold: default_allow_threshold(),
            high_threshold: default_high_threshold(),
            criteria: String::new(),
            api_key: String::new(),
        }
    }
}

/// The decrypted plaintext of `keyring.enc`.
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyringData {
    #[serde(default = "default_keyring_version")]
    pub version: u32,
    // Operational knobs (formerly the plaintext config.yaml).
    #[serde(default)]
    pub lock: LockConfig,
    #[serde(default)]
    pub daemon: DaemonConfig,
    #[serde(default)]
    pub backend: Backend,
    // Judge registry.
    #[serde(default)]
    pub judge_enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_judge: Option<String>,
    #[serde(default)]
    pub judges: BTreeMap<String, JudgeDef>,
}

fn default_keyring_version() -> u32 {
    KEYRING_VERSION
}

impl Default for KeyringData {
    fn default() -> Self {
        Self {
            version: KEYRING_VERSION,
            lock: LockConfig::default(),
            daemon: DaemonConfig::default(),
            backend: Backend::default(),
            judge_enabled: false,
            default_judge: None,
            judges: BTreeMap::new(),
        }
    }
}

impl KeyringData {
    /// Resolve which judge a vault should use: an explicit name wins, else the
    /// default. Returns the def (and its resolved name) if present and the judge
    /// is globally enabled.
    pub fn resolve_judge(&self, assigned: Option<&str>) -> Option<(&str, &JudgeDef)> {
        if !self.judge_enabled {
            return None;
        }
        let name = assigned.or(self.default_judge.as_deref())?;
        self.judges
            .get_key_value(name)
            .map(|(k, d)| (k.as_str(), d))
    }
}

/// Wraps the decrypted JSON string and zeroes it from memory on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
struct SecretStore(String);

fn encrypt_data(key: &VaultKey, salt: &[u8; SALT_SIZE], data: &KeyringData) -> Result<Vec<u8>> {
    let json = SecretStore(serde_json::to_string(data)?);
    crypto::encrypt(key, salt, json.0.as_bytes())
}

fn decode_data(key: &VaultKey, encrypted: &[u8]) -> Result<KeyringData> {
    let plaintext = crypto::decrypt(key, encrypted)?;
    let store = SecretStore(String::from_utf8(plaintext)?);
    Ok(serde_json::from_str(&store.0)?)
}

/// An open keyring: the decrypted data plus the key that decrypted it.
pub struct Keyring {
    pub data: KeyringData,
    key: VaultKey,
}

impl Keyring {
    /// Create a fresh, empty keyring encrypted under `passphrase`. Errors if one
    /// already exists (callers should check [`exists`] first).
    pub fn init(passphrase: &str) -> Result<Self> {
        let path = keyring_path();
        if path.exists() {
            return Err(anyhow!("a keyring already exists at {}", path.display()));
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                crate::secfile::create_dir_owner_only(parent)?;
            }
        }
        let mut salt = [0u8; SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut salt);
        let key = VaultKey::derive(passphrase, &salt)?;
        let data = KeyringData::default();
        let blob = encrypt_data(&key, &salt, &data)?;
        crate::secfile::write_owner_only(&path, &blob)?;
        Ok(Self { data, key })
    }

    /// Open the keyring with its passphrase. Wrong passphrase → GCM tag fails.
    pub fn open(passphrase: &str) -> Result<Self> {
        let encrypted = std::fs::read(keyring_path())
            .map_err(|_| anyhow!("no keyring yet — run 'svault keyring init'"))?;
        if encrypted.len() < SALT_SIZE {
            return Err(anyhow!("keyring.enc is too short — may be corrupted"));
        }
        let salt = &encrypted[..SALT_SIZE];
        let key = VaultKey::derive(passphrase, salt)?;
        let data =
            decode_data(&key, &encrypted).map_err(|_| anyhow!("wrong keyring passphrase"))?;
        Ok(Self { data, key })
    }

    /// Open with an already-derived key (the daemon / session path).
    pub fn open_with_key(key: VaultKey) -> Result<Self> {
        let encrypted = std::fs::read(keyring_path())
            .map_err(|_| anyhow!("no keyring yet — run 'svault keyring init'"))?;
        let data = decode_data(&key, &encrypted)?;
        Ok(Self { data, key })
    }

    pub fn key(&self) -> &VaultKey {
        &self.key
    }

    /// Re-encrypt the keyring under the current key with its existing salt.
    pub fn save(&self) -> Result<()> {
        let path = keyring_path();
        let encrypted = std::fs::read(&path)?;
        if encrypted.len() < SALT_SIZE {
            return Err(anyhow!("keyring.enc is too short — may be corrupted"));
        }
        let salt: [u8; SALT_SIZE] = encrypted[..SALT_SIZE]
            .try_into()
            .expect("slice length checked against SALT_SIZE above");
        let blob = encrypt_data(&self.key, &salt, &self.data)?;
        crate::secfile::write_owner_only(&path, &blob)?;
        Ok(())
    }

    /// Re-encrypt the keyring under a new passphrase (fresh salt + key).
    pub fn rekey(&mut self, new_passphrase: &str) -> Result<()> {
        let mut salt = [0u8; SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut salt);
        let new_key = VaultKey::derive(new_passphrase, &salt)?;
        let blob = encrypt_data(&new_key, &salt, &self.data)?;
        crate::secfile::write_owner_only(&keyring_path(), &blob)?;
        self.key = new_key;
        Ok(())
    }
}

// ── Session caching (mirrors session.rs, for the keyring's derived key) ──────

/// Cache the keyring's derived key (hex, `0600`) so the CLI fallback and the
/// daemon can open it without re-prompting. Never stores the passphrase.
pub fn unlock_session(key: &[u8; 32]) -> Result<()> {
    let encoded = hex::encode(key);
    crate::secfile::write_owner_only(&session_path(), encoded.as_bytes())?;
    Ok(())
}

/// Clear the keyring session — judge goes back to off.
pub fn lock_session() -> Result<()> {
    let path = session_path();
    if path.exists() {
        let len = std::fs::metadata(&path)?.len() as usize;
        std::fs::write(&path, vec![0u8; len])?;
        std::fs::remove_file(&path)?;
    }
    Ok(())
}

/// The cached keyring key, if a valid session exists.
pub fn session_key() -> Option<[u8; 32]> {
    let contents = std::fs::read_to_string(session_path()).ok()?;
    let bytes = hex::decode(contents.trim()).ok()?;
    bytes.try_into().ok()
}

/// True if the keyring is unlocked (a usable session key is cached).
pub fn is_unlocked() -> bool {
    session_key().is_some()
}

/// Open the keyring from the cached session key, if unlocked.
pub fn open_from_session() -> Option<Keyring> {
    let bytes = session_key()?;
    Keyring::open_with_key(VaultKey::from_bytes(bytes)).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    // The keyring path is relative to the CWD (.svault/), so tests that touch
    // disk must not run concurrently. Serialize them and run each in a temp CWD.
    static CWD_LOCK: Mutex<()> = Mutex::new(());

    fn in_temp_cwd() -> (MutexGuard<'static, ()>, tempfile::TempDir, PathBuf) {
        let guard = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::TempDir::new().unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();
        (guard, tmp, prev)
    }

    fn sample_judge() -> JudgeDef {
        JudgeDef {
            model: "google/gemini-2.5-flash".into(),
            criteria: "Only allow billing-related reasons.".into(),
            api_key: "sk-or-secret-XYZ".into(),
            ..JudgeDef::default()
        }
    }

    #[test]
    fn init_open_roundtrips_and_wrong_passphrase_rejected() {
        let (_g, _tmp, prev) = in_temp_cwd();

        let mut kr = Keyring::init("Keyring!Pass#1").unwrap();
        kr.data.judge_enabled = true;
        kr.data.default_judge = Some("strict".into());
        kr.data.judges.insert("strict".into(), sample_judge());
        kr.save().unwrap();

        // Wrong passphrase is rejected.
        assert!(Keyring::open("nope").is_err());

        // Right passphrase reads everything back.
        let reopened = Keyring::open("Keyring!Pass#1").unwrap();
        assert!(reopened.data.judge_enabled);
        assert_eq!(reopened.data.default_judge.as_deref(), Some("strict"));
        let j = reopened.data.judges.get("strict").unwrap();
        assert_eq!(j.criteria, "Only allow billing-related reasons.");
        assert_eq!(j.api_key, "sk-or-secret-XYZ");

        std::env::set_current_dir(prev).unwrap();
    }

    #[test]
    fn nothing_sensitive_is_readable_at_rest() {
        let (_g, _tmp, prev) = in_temp_cwd();

        let mut kr = Keyring::init("Keyring!Pass#2").unwrap();
        kr.data.judges.insert("j".into(), sample_judge());
        kr.save().unwrap();

        // The encrypted file must not leak the key, criteria, or model.
        let raw = std::fs::read(keyring_path()).unwrap();
        for needle in [
            b"sk-or-secret-XYZ".as_slice(),
            b"billing-related".as_slice(),
            b"gemini-2.5-flash".as_slice(),
        ] {
            assert!(
                raw.windows(needle.len()).all(|w| w != needle),
                "keyring.enc leaked {:?} at rest",
                String::from_utf8_lossy(needle)
            );
        }

        std::env::set_current_dir(prev).unwrap();
    }

    #[test]
    fn rekey_changes_passphrase_keeps_data() {
        let (_g, _tmp, prev) = in_temp_cwd();

        let mut kr = Keyring::init("Old!Keyring#1").unwrap();
        kr.data.judges.insert("j".into(), sample_judge());
        kr.save().unwrap();
        kr.rekey("New!Keyring#2").unwrap();

        assert!(Keyring::open("Old!Keyring#1").is_err());
        let r = Keyring::open("New!Keyring#2").unwrap();
        assert!(r.data.judges.contains_key("j"));

        std::env::set_current_dir(prev).unwrap();
    }

    #[test]
    fn session_caches_key_then_lock_clears() {
        let (_g, _tmp, prev) = in_temp_cwd();
        crate::secfile::create_dir_owner_only(&PathBuf::from(SVAULT_DIR)).unwrap();

        assert!(!is_unlocked());
        unlock_session(&[9u8; 32]).unwrap();
        assert!(is_unlocked());
        assert_eq!(session_key(), Some([9u8; 32]));
        lock_session().unwrap();
        assert!(!is_unlocked());

        std::env::set_current_dir(prev).unwrap();
    }

    #[test]
    fn resolve_judge_prefers_assigned_then_default() {
        let mut data = KeyringData {
            judge_enabled: true,
            default_judge: Some("def".into()),
            ..KeyringData::default()
        };
        data.judges.insert("def".into(), JudgeDef::default());
        data.judges.insert("other".into(), JudgeDef::default());

        assert_eq!(data.resolve_judge(Some("other")).unwrap().0, "other");
        assert_eq!(data.resolve_judge(None).unwrap().0, "def");
        assert!(data.resolve_judge(Some("missing")).is_none());

        // Globally disabled → no judge regardless of assignment.
        data.judge_enabled = false;
        assert!(data.resolve_judge(Some("def")).is_none());
    }
}
