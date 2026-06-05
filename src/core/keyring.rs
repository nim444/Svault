//! The keyring — Svault's single encrypted store for global config.
//!
//! Everything that used to sit in the plaintext `.svault/config.yaml` and the
//! plaintext `~/.config/svault/openrouter.key` lives here instead, AES-256-GCM
//! encrypted at rest:
//!
//! - the **judge registry** — multiple named judges, each with its own model,
//!   thresholds, free-text *criteria*, and **API key**;
//! - the global judge on/off switch and the default judge;
//! - operational knobs (lock timers, daemon max-connections, backend).
//!
//! Since 0.9.5 the keyring is a keyslot-backed store exactly like a vault: it has
//! its own random 32-byte **data key (DEK)** that encrypts `keyring.enc`, and the
//! DEK is wrapped under the master key in `.svault/keyring.keyslot.enc` (see
//! [`crate::core::master`]). There is no separate keyring passphrase — the **master
//! passphrase opens the keyring along with every vault**. Unlocking the master
//! unwraps the DEK and caches it in a `0600` session (exactly like a vault); the
//! daemon reads that session. Until unlocked the judge is off and the static tier
//! rules apply.
//!
//! A same-UID agent can no longer read thresholds/criteria to tune a passing
//! request, nor steal the API key from a plaintext file.
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

use crate::core::config::{Backend, DaemonConfig, LockConfig};
use crate::core::crypto::{self, VaultKey, SALT_SIZE};
use crate::core::vault::svault_dir;

/// Current on-disk version of the encrypted keyring payload.
const KEYRING_VERSION: u32 = 1;

const KEYRING_FILE: &str = "keyring.enc";
const KEYRING_SESSION: &str = ".keyring.session";

/// Opt-in env override for a judge with no stored key (env, never a file).
pub const KEY_ENV: &str = "SVAULT_OPENROUTER_KEY";

pub fn keyring_path() -> PathBuf {
    svault_dir().join(KEYRING_FILE)
}

fn session_path() -> PathBuf {
    svault_dir().join(KEYRING_SESSION)
}

/// True if a keyring has been created on this machine.
pub fn exists() -> bool {
    keyring_path().exists()
}

/// The provider kinds Svault knows how to talk to. All four speak the
/// OpenAI-compatible `/chat/completions` + `GET /models` surface the judge
/// transport uses — a kind only decides the default base URL and auth headers.
pub const PROVIDER_KINDS: [&str; 4] = ["openrouter", "openai", "anthropic", "local"];

/// The default base URL for a provider kind. Anthropic is its
/// OpenAI-compatibility endpoint; `local` assumes an Ollama/LM Studio-style
/// server.
pub fn provider_kind_base_url(kind: &str) -> Option<&'static str> {
    match kind {
        "openrouter" => Some("https://openrouter.ai/api/v1"),
        "openai" => Some("https://api.openai.com/v1"),
        "anthropic" => Some("https://api.anthropic.com/v1"),
        "local" => Some("http://localhost:11434/v1"),
        _ => None,
    }
}

/// One named AI provider: an API account that judges draw their key and base
/// URL from. The key is encrypted at rest like everything else in the keyring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderDef {
    #[serde(default = "default_provider_kind")]
    pub kind: String,
    #[serde(default = "default_base_url")]
    pub base_url: String,
    #[serde(default)]
    pub api_key: String,
    /// A disabled provider lends no credentials: judges referencing it become
    /// keyless, so the gate falls back to the static tier rules (high =
    /// human-only) without deleting any config.
    #[serde(default = "default_provider_enabled")]
    pub enabled: bool,
}

fn default_provider_kind() -> String {
    "openrouter".to_string()
}

fn default_provider_enabled() -> bool {
    true
}

impl Default for ProviderDef {
    fn default() -> Self {
        Self {
            kind: default_provider_kind(),
            base_url: default_base_url(),
            api_key: String::new(),
            enabled: true,
        }
    }
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
    /// Named [`ProviderDef`] this judge draws its key and base URL from. When
    /// set and the provider exists, it wins over the judge's own `api_key` /
    /// `base_url` (see [`KeyringData::materialize_judge`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
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
            provider: None,
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
    /// Named AI providers (API accounts) that judges reference.
    #[serde(default)]
    pub providers: BTreeMap<String, ProviderDef>,
    /// The provider pre-selected for new judges. Purely a UI default — judge
    /// resolution always uses the judge's own explicit `provider` reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_provider: Option<String>,
    // Judge registry.
    #[serde(default)]
    pub judge_enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_judge: Option<String>,
    #[serde(default)]
    pub judges: BTreeMap<String, JudgeDef>,
    /// Master enable switch for the local MCP server (`svault mcp`). When false,
    /// the server still starts but refuses every tool call with a generic
    /// "not available" — a human-controlled door that an agent cannot reopen.
    /// Defaults to true so existing keyrings keep serving agents as before.
    #[serde(default = "default_mcp_enabled")]
    pub mcp_enabled: bool,
}

fn default_mcp_enabled() -> bool {
    true
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
            providers: BTreeMap::new(),
            default_provider: None,
            judge_enabled: false,
            default_judge: None,
            judges: BTreeMap::new(),
            mcp_enabled: true,
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

    /// Resolve a judge's effective credentials: if it references a named
    /// provider that exists, the provider's API key and base URL win over the
    /// judge's own fields. Returns an owned def ready for
    /// [`crate::core::judge::JudgeRuntime::from_def`].
    pub fn materialize_judge(&self, def: &JudgeDef) -> JudgeDef {
        let mut out = def.clone();
        if let Some(p) = def.provider.as_deref().and_then(|n| self.providers.get(n)) {
            // A disabled provider lends nothing — the judge stays on its own
            // (usually empty) key and the gate falls back to static tier rules.
            if !p.enabled {
                return out;
            }
            if !p.api_key.is_empty() {
                out.api_key = p.api_key.clone();
            } else if p.kind == "local" {
                // Local endpoints (Ollama/LM Studio) need no key, but the judge
                // runtime treats "no key" as "judge off" — send a harmless
                // placeholder bearer instead.
                out.api_key = "local".to_string();
            }
            out.base_url = p.base_url.clone();
        }
        out
    }

    /// Whether a judge would actually have an API key at runtime — its own,
    /// or its provider's.
    pub fn judge_has_key(&self, def: &JudgeDef) -> bool {
        !self.materialize_judge(def).api_key.is_empty()
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
    /// Create a fresh, empty keyring encrypted under a random data key (DEK).
    /// The caller wraps the DEK under the master (see
    /// [`crate::core::master::Master::wrap_keyring_dek`]). Errors if one already exists
    /// (callers should check [`exists`] first).
    pub fn init_with_key(dek: VaultKey) -> Result<Self> {
        let path = keyring_path();
        if path.exists() {
            return Err(anyhow!("a keyring already exists at {}", path.display()));
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                crate::core::secfile::create_dir_owner_only(parent)?;
            }
        }
        // The DEK is used directly; the salt is random filler kept only so the
        // on-disk shape matches the rest of the format (decrypt ignores it).
        let mut salt = [0u8; SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut salt);
        let data = KeyringData::default();
        let blob = encrypt_data(&dek, &salt, &data)?;
        crate::core::secfile::write_owner_only(&path, &blob)?;
        Ok(Self { data, key: dek })
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
        crate::core::secfile::write_owner_only(&path, &blob)?;
        Ok(())
    }
}

// ── Session caching (mirrors session.rs, for the keyring's derived key) ──────

/// Cache the keyring's derived key (`0600`, timestamped) so the CLI fallback and
/// the daemon can open it without re-prompting. Never stores the passphrase;
/// expires after [`crate::core::session::MAX_SESSION_SECS`].
pub fn unlock_session(key: &[u8; 32]) -> Result<()> {
    crate::core::session::write_session_key(&session_path(), key)
}

/// Clear the keyring session — judge goes back to off.
pub fn lock_session() -> Result<()> {
    crate::core::session::secure_remove(&session_path())?;
    Ok(())
}

/// The cached keyring key, if a valid (non-expired) session exists.
pub fn session_key() -> Option<[u8; 32]> {
    crate::core::session::read_session_key(&session_path())
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
    use crate::core::testlock::CWD_LOCK;
    use crate::core::vault::SVAULT_DIR;
    use std::sync::MutexGuard;

    fn in_temp_cwd() -> (MutexGuard<'static, ()>, tempfile::TempDir, PathBuf) {
        // The keyring path is relative to the CWD (.svault/), so disk-touching
        // tests must not run concurrently with any other chdir test — they all
        // share the one process-wide CWD lock.
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
    fn init_open_roundtrips_and_wrong_key_rejected() {
        let (_g, _tmp, prev) = in_temp_cwd();

        let dek = crate::core::master::new_dek();
        let dek_bytes = *dek.bytes();
        let mut kr = Keyring::init_with_key(dek).unwrap();
        kr.data.judge_enabled = true;
        kr.data.default_judge = Some("strict".into());
        kr.data.judges.insert("strict".into(), sample_judge());
        kr.save().unwrap();

        // A wrong key is rejected (the GCM tag fails).
        assert!(Keyring::open_with_key(VaultKey::from_bytes([0u8; 32])).is_err());

        // The right key reads everything back.
        let reopened = Keyring::open_with_key(VaultKey::from_bytes(dek_bytes)).unwrap();
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

        let mut kr = Keyring::init_with_key(crate::core::master::new_dek()).unwrap();
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
    fn keyring_stays_readable_after_master_rekey() {
        let (_g, _tmp, prev) = in_temp_cwd();

        // A keyring under a DEK that is wrapped under the master.
        let m = crate::core::master::Master::init("Old!Master#1").unwrap();
        let dek = crate::core::master::new_dek();
        let dek_bytes = *dek.bytes();
        let mut kr = Keyring::init_with_key(dek).unwrap();
        kr.data.judges.insert("j".into(), sample_judge());
        kr.save().unwrap();
        m.wrap_keyring_dek(&VaultKey::from_bytes(dek_bytes))
            .unwrap();

        // Changing the master passphrase never moves the DEK, so the same DEK
        // still opens the keyring afterwards.
        m.rekey("New!Master#2").unwrap();
        let reopened = crate::core::master::Master::open("New!Master#2").unwrap();
        let recovered = reopened.unwrap_keyring_dek().unwrap();
        assert_eq!(recovered.bytes(), &dek_bytes);
        let r = Keyring::open_with_key(recovered).unwrap();
        assert!(r.data.judges.contains_key("j"));

        std::env::set_current_dir(prev).unwrap();
    }

    #[test]
    fn session_caches_key_then_lock_clears() {
        let (_g, _tmp, prev) = in_temp_cwd();
        crate::core::secfile::create_dir_owner_only(&PathBuf::from(SVAULT_DIR)).unwrap();

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
