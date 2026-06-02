use anyhow::{anyhow, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::core::crypto::{self, VaultKey, SALT_SIZE};
use crate::core::meta::VaultMeta;
use crate::core::policy::VaultPolicyData;

pub const SVAULT_DIR: &str = ".svault";

/// The active `.svault` store directory.
///
/// By default this is `.svault` in the current working directory — fine for a
/// CLI you run inside a project. Set `SVAULT_HOME` to a **base directory** to
/// resolve `$SVAULT_HOME/.svault` instead, which is the robust way to point a
/// process whose CWD you don't control (notably the `svault mcp` server launched
/// by an MCP host) at a fixed store. All store paths — vaults, master keyslots,
/// keyring, sessions — go through here, so the whole store moves together.
pub fn svault_dir() -> PathBuf {
    match std::env::var_os("SVAULT_HOME") {
        Some(home) if !home.is_empty() => Path::new(&home).join(SVAULT_DIR),
        _ => PathBuf::from(SVAULT_DIR),
    }
}

/// Current on-disk version of the encrypted `vault.enc` payload.
const PAYLOAD_VERSION: u32 = 2;

/// The decrypted plaintext of `vault.enc`: the secret values **and** the full
/// policy surface. Keeping the policy here (rather than in the plaintext
/// `meta.yaml`) means it is AES-256-GCM encrypted at rest — a same-UID agent
/// can't read tiers/scopes/descriptions/caller rules to plan a request that
/// passes, and can't tamper with them without the vault key.
#[derive(Debug, Default, Serialize, Deserialize)]
struct VaultPayload {
    #[serde(default = "default_payload_version")]
    version: u32,
    #[serde(default)]
    secrets: HashMap<String, String>,
    #[serde(default)]
    policy: VaultPolicyData,
}

fn default_payload_version() -> u32 {
    PAYLOAD_VERSION
}

/// Encrypt a payload under `key` with the given `salt` (the salt is prefixed to
/// the ciphertext by [`crypto::encrypt`]).
fn encrypt_payload(
    key: &VaultKey,
    salt: &[u8; SALT_SIZE],
    payload: &VaultPayload,
) -> Result<Vec<u8>> {
    let json = SecretStore(serde_json::to_string(payload)?);
    crypto::encrypt(key, salt, json.0.as_bytes())
}

/// Decrypt and parse `vault.enc`. Decryption also authenticates the blob (GCM),
/// so a wrong key or any tampering is rejected here.
fn decode_payload(key: &VaultKey, encrypted: &[u8]) -> Result<VaultPayload> {
    let plaintext = crypto::decrypt(key, encrypted)?;
    let store = SecretStore(String::from_utf8(plaintext)?);
    Ok(serde_json::from_str(&store.0)?)
}

/// Wraps the decrypted JSON string and zeroes it from memory on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
struct SecretStore(String);

#[allow(dead_code)]
pub struct Vault {
    pub vault_dir: PathBuf,
    pub meta: VaultMeta,
    /// The decrypted policy, cached at open. Reads use this; writes go through
    /// [`Vault::save_policy`] (callers re-open to refresh the cache).
    pub policy: VaultPolicyData,
    key: VaultKey,
}

impl Vault {
    /// Create a new vault at the given directory path with its initial policy,
    /// keyed directly from a passphrase. Superseded in the unified-unlock model
    /// by [`Vault::init_with_key`] (a random data key wrapped under the master);
    /// retained for the legacy passphrase path and the crypto/vault tests.
    #[allow(dead_code)]
    pub fn init(
        vault_dir: &Path,
        passphrase: &str,
        meta_input: VaultMeta,
        policy: VaultPolicyData,
    ) -> Result<Self> {
        if vault_dir.exists() {
            return Err(anyhow!("Vault already exists at {}", vault_dir.display()));
        }
        // Owner-only .svault/ and vault dir so other local users can't even
        // traverse in to read the (encrypted) files or the session (#16).
        if let Some(parent) = vault_dir.parent() {
            crate::core::secfile::create_dir_owner_only(parent)?;
        }
        crate::core::secfile::create_dir_owner_only(vault_dir)?;

        // Write a local .gitignore so the session file and the logs can never be
        // accidentally committed even if the repo-level .gitignore is missing or wrong.
        std::fs::write(
            vault_dir.join(".gitignore"),
            ".session\naudit.log\nusage.log\n",
        )?;

        let mut salt = [0u8; SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut salt);
        let key = VaultKey::derive(passphrase, &salt)?;

        let payload = VaultPayload {
            version: PAYLOAD_VERSION,
            secrets: HashMap::new(),
            policy,
        };
        let encrypted = encrypt_payload(&key, &salt, &payload)?;
        std::fs::write(vault_dir.join("vault.enc"), &encrypted)?;

        meta_input.save(vault_dir, key.bytes())?;

        let meta = VaultMeta::load_verified(vault_dir, key.bytes())?;
        Ok(Self {
            vault_dir: vault_dir.to_path_buf(),
            meta,
            policy: payload.policy,
            key,
        })
    }

    /// Create a new vault encrypted under an already-chosen data key (DEK),
    /// rather than a passphrase-derived key. Used by the unified-unlock path:
    /// the DEK is random and wrapped under the master key in a keyslot, so the
    /// vault has no passphrase of its own. Mirrors [`Vault::init`] otherwise.
    pub fn init_with_key(
        vault_dir: &Path,
        key: VaultKey,
        meta_input: VaultMeta,
        policy: VaultPolicyData,
    ) -> Result<Self> {
        if vault_dir.exists() {
            return Err(anyhow!("Vault already exists at {}", vault_dir.display()));
        }
        if let Some(parent) = vault_dir.parent() {
            crate::core::secfile::create_dir_owner_only(parent)?;
        }
        crate::core::secfile::create_dir_owner_only(vault_dir)?;
        std::fs::write(
            vault_dir.join(".gitignore"),
            ".session\naudit.log\nusage.log\n",
        )?;

        let mut salt = [0u8; SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut salt);
        let payload = VaultPayload {
            version: PAYLOAD_VERSION,
            secrets: HashMap::new(),
            policy,
        };
        let encrypted = encrypt_payload(&key, &salt, &payload)?;
        std::fs::write(vault_dir.join("vault.enc"), &encrypted)?;
        meta_input.save(vault_dir, key.bytes())?;
        let meta = VaultMeta::load_verified(vault_dir, key.bytes())?;
        Ok(Self {
            vault_dir: vault_dir.to_path_buf(),
            meta,
            policy: payload.policy,
            key,
        })
    }

    /// Open an existing vault with passphrase.
    pub fn open(vault_dir: &Path, passphrase: &str) -> Result<Self> {
        let encrypted = std::fs::read(vault_dir.join("vault.enc"))?;
        if encrypted.len() < SALT_SIZE {
            return Err(anyhow!("vault.enc is too short — may be corrupted"));
        }
        let salt = &encrypted[..SALT_SIZE];
        let key = VaultKey::derive(passphrase, salt)?;

        // Decrypting authenticates the key and yields the secrets + policy.
        let payload = decode_payload(&key, &encrypted)?;

        let meta = VaultMeta::load_verified(vault_dir, key.bytes())?;
        Ok(Self {
            vault_dir: vault_dir.to_path_buf(),
            meta,
            policy: payload.policy,
            key,
        })
    }

    /// Open an existing vault directly from its derived key, skipping Argon2.
    /// Used by the recovery path (which unwraps the stored key) and the daemon
    /// (which holds the key in memory). Verifies the key by decrypting vault.enc.
    pub fn open_with_key(vault_dir: &Path, key: VaultKey) -> Result<Self> {
        let encrypted = std::fs::read(vault_dir.join("vault.enc"))?;
        let payload = decode_payload(&key, &encrypted)?;
        let meta = VaultMeta::load_verified(vault_dir, key.bytes())?;
        Ok(Self {
            vault_dir: vault_dir.to_path_buf(),
            meta,
            policy: payload.policy,
            key,
        })
    }

    /// The vault's derived key — needed to re-wrap the recovery file after a re-key.
    pub fn key(&self) -> &VaultKey {
        &self.key
    }

    /// Re-encrypt the vault under a new passphrase: fresh salt + key, re-write
    /// vault.enc (secrets + policy), re-sign meta.yaml. Legacy passphrase path
    /// (the unified model re-wraps the data key under the master instead);
    /// retained for the vault tests.
    #[allow(dead_code)]
    pub fn rekey(&mut self, new_passphrase: &str) -> Result<()> {
        let payload = self.load_payload()?;
        let mut salt = [0u8; SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut salt);
        let new_key = VaultKey::derive(new_passphrase, &salt)?;

        let data = encrypt_payload(&new_key, &salt, &payload)?;
        std::fs::write(self.vault_dir.join("vault.enc"), data)?;
        self.meta.save(&self.vault_dir, new_key.bytes())?;
        self.policy = payload.policy;
        self.key = new_key;
        Ok(())
    }

    /// Re-sign and persist updated public metadata (description, settings).
    /// Requires the vault to be open so the HMAC can be recomputed with the key.
    pub fn save_meta(&self, meta: &VaultMeta) -> Result<()> {
        meta.save(&self.vault_dir, self.key.bytes())
    }

    /// Persist updated policy (classification, access, judge overrides, callers).
    /// Re-encrypts vault.enc; the secret values are untouched. The in-memory
    /// `self.policy` cache is not updated — callers re-open to refresh it.
    pub fn save_policy(&self, policy: &VaultPolicyData) -> Result<()> {
        let mut payload = self.load_payload()?;
        payload.policy = policy.clone();
        self.save_payload(&payload)
    }

    pub fn add_secret(&self, name: &str, value: &str) -> Result<()> {
        let mut payload = self.load_payload()?;
        payload.secrets.insert(name.to_string(), value.to_string());
        self.save_payload(&payload)
    }

    /// Returns the value wrapped in `Zeroizing` so the caller's copy is wiped on
    /// drop (#6); the bulk decrypted store is already zeroized via `SecretStore`.
    pub fn get_secret(&self, name: &str) -> Result<Option<Zeroizing<String>>> {
        Ok(self
            .load_payload()?
            .secrets
            .get(name)
            .map(|v| Zeroizing::new(v.clone())))
    }

    pub fn list_secret_names(&self) -> Result<Vec<String>> {
        let mut names: Vec<String> = self.load_payload()?.secrets.into_keys().collect();
        names.sort();
        Ok(names)
    }

    pub fn remove_secret(&self, name: &str) -> Result<bool> {
        let mut payload = self.load_payload()?;
        let removed = payload.secrets.remove(name).is_some();
        if removed {
            self.save_payload(&payload)?;
        }
        Ok(removed)
    }

    fn load_payload(&self) -> Result<VaultPayload> {
        let encrypted = std::fs::read(self.vault_dir.join("vault.enc"))?;
        decode_payload(&self.key, &encrypted)
    }

    fn save_payload(&self, payload: &VaultPayload) -> Result<()> {
        let encrypted = std::fs::read(self.vault_dir.join("vault.enc"))?;
        if encrypted.len() < SALT_SIZE {
            return Err(anyhow!("vault.enc is too short — may be corrupted"));
        }
        let salt: [u8; SALT_SIZE] = encrypted[..SALT_SIZE]
            .try_into()
            .expect("slice length checked against SALT_SIZE above");
        let data = encrypt_payload(&self.key, &salt, payload)?;
        std::fs::write(self.vault_dir.join("vault.enc"), data)?;
        Ok(())
    }
}

/// List all vault directories under base/.svault/
pub fn list_vault_dirs() -> Vec<PathBuf> {
    list_vault_dirs_in(&svault_dir())
}

pub fn list_vault_dirs_in(base: &Path) -> Vec<PathBuf> {
    if !base.exists() {
        return vec![];
    }
    let Ok(entries) = std::fs::read_dir(base) else {
        return vec![];
    };
    let mut dirs: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir() && p.join("meta.yaml").exists())
        .collect();
    dirs.sort();
    dirs
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::meta::{VaultMeta, VaultSettings};
    use crate::core::policy::VaultPolicyData;
    use tempfile::TempDir;

    fn tmp_vault(dir: &TempDir, name: &str, passphrase: &str) -> Vault {
        let vault_dir = dir.path().join(name);
        let meta = VaultMeta::new(
            name.to_string(),
            "test vault".to_string(),
            VaultSettings::default(),
        );
        Vault::init(&vault_dir, passphrase, meta, VaultPolicyData::default()).expect("init failed")
    }

    #[test]
    fn create_and_open() {
        let dir = TempDir::new().unwrap();
        let v = tmp_vault(&dir, "test", "Str0ng!Pass#99");
        assert_eq!(v.meta.name, "test");

        let v2 = Vault::open(&dir.path().join("test"), "Str0ng!Pass#99").unwrap();
        assert_eq!(v2.meta.name, "test");
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let dir = TempDir::new().unwrap();
        tmp_vault(&dir, "test", "Str0ng!Pass#99");

        let result = Vault::open(&dir.path().join("test"), "wrong-passphrase");
        assert!(result.is_err());
        let msg = format!("{}", result.err().unwrap());
        assert!(msg.contains("Wrong passphrase") || msg.contains("Decryption failed"));
    }

    #[test]
    fn add_get_secret() {
        let dir = TempDir::new().unwrap();
        let v = tmp_vault(&dir, "test", "Str0ng!Pass#99");

        v.add_secret("API_KEY", "super-secret-value").unwrap();
        let val = v.get_secret("API_KEY").unwrap().map(|z| z.to_string());
        assert_eq!(val, Some("super-secret-value".to_string()));
    }

    #[test]
    fn list_secrets() {
        let dir = TempDir::new().unwrap();
        let v = tmp_vault(&dir, "test", "Str0ng!Pass#99");

        v.add_secret("B_KEY", "b").unwrap();
        v.add_secret("A_KEY", "a").unwrap();
        let names = v.list_secret_names().unwrap();
        // Sorted alphabetically
        assert_eq!(names, vec!["A_KEY", "B_KEY"]);
    }

    #[test]
    fn remove_secret() {
        let dir = TempDir::new().unwrap();
        let v = tmp_vault(&dir, "test", "Str0ng!Pass#99");

        v.add_secret("KEY", "value").unwrap();
        assert!(v.remove_secret("KEY").unwrap());
        assert_eq!(v.get_secret("KEY").unwrap(), None);
        // Remove again returns false (already gone)
        assert!(!v.remove_secret("KEY").unwrap());
    }

    #[test]
    fn secrets_persist_across_open() {
        let dir = TempDir::new().unwrap();
        let vault_dir = dir.path().join("test");

        {
            let v = tmp_vault(&dir, "test", "Str0ng!Pass#99");
            v.add_secret("DB_URL", "postgres://localhost/mydb").unwrap();
            v.add_secret("REDIS_URL", "redis://localhost:6379").unwrap();
        }

        // Re-open from disk
        let v2 = Vault::open(&vault_dir, "Str0ng!Pass#99").unwrap();
        assert_eq!(
            v2.get_secret("DB_URL").unwrap().map(|z| z.to_string()),
            Some("postgres://localhost/mydb".to_string())
        );
        assert_eq!(
            v2.get_secret("REDIS_URL").unwrap().map(|z| z.to_string()),
            Some("redis://localhost:6379".to_string())
        );
    }

    #[test]
    fn open_with_key_matches_passphrase_open() {
        let dir = TempDir::new().unwrap();
        let vault_dir = dir.path().join("test");
        let v = tmp_vault(&dir, "test", "Str0ng!Pass#99");
        v.add_secret("API_KEY", "value").unwrap();
        let key_bytes = *v.key().bytes();

        let reopened =
            Vault::open_with_key(&vault_dir, crypto::VaultKey::from_bytes(key_bytes)).unwrap();
        assert_eq!(reopened.meta.name, "test");
        assert_eq!(
            reopened
                .get_secret("API_KEY")
                .unwrap()
                .map(|z| z.to_string()),
            Some("value".to_string())
        );
    }

    #[test]
    fn rekey_preserves_secrets_and_changes_passphrase() {
        let dir = TempDir::new().unwrap();
        let vault_dir = dir.path().join("test");

        {
            let mut v = tmp_vault(&dir, "test", "Old!Pass#11");
            v.add_secret("DB_URL", "postgres://x").unwrap();
            v.rekey("New!Pass#22").unwrap();
        }

        // Old passphrase no longer opens the vault.
        assert!(Vault::open(&vault_dir, "Old!Pass#11").is_err());

        // New passphrase opens it and the secret survived the re-encryption.
        let v = Vault::open(&vault_dir, "New!Pass#22").unwrap();
        assert_eq!(
            v.get_secret("DB_URL").unwrap().map(|z| z.to_string()),
            Some("postgres://x".to_string())
        );
    }

    #[test]
    fn tampered_vault_enc_is_rejected() {
        let dir = TempDir::new().unwrap();
        let vault_dir = dir.path().join("test");
        tmp_vault(&dir, "test", "Str0ng!Pass#99");

        // Corrupt the vault.enc file
        let enc_path = vault_dir.join("vault.enc");
        let mut data = std::fs::read(&enc_path).unwrap();
        let mid = data.len() / 2;
        data[mid] ^= 0xFF; // flip bits in the middle
        std::fs::write(&enc_path, data).unwrap();

        let result = Vault::open(&vault_dir, "Str0ng!Pass#99");
        assert!(result.is_err());
    }

    #[test]
    fn truncated_vault_enc_errors_not_panics() {
        let dir = TempDir::new().unwrap();
        let vault_dir = dir.path().join("test");
        let v = tmp_vault(&dir, "test", "Str0ng!Pass#99");

        // Truncate vault.enc below SALT_SIZE so the salt slice can't be taken.
        let enc_path = vault_dir.join("vault.enc");
        std::fs::write(&enc_path, vec![0u8; SALT_SIZE - 1]).unwrap();

        // save_payload must return an error rather than panic on the short slice.
        let mut payload = VaultPayload::default();
        payload.secrets.insert("K".to_string(), "v".to_string());
        let result = v.save_payload(&payload);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn tampered_meta_yaml_is_rejected() {
        let dir = TempDir::new().unwrap();
        let vault_dir = dir.path().join("test");
        let v = tmp_vault(&dir, "test", "Str0ng!Pass#99");
        let key = v.key.bytes().to_vec();

        // Tamper with meta.yaml — change the (signed, public) description.
        let meta_path = vault_dir.join("meta.yaml");
        let content = std::fs::read_to_string(&meta_path).unwrap();
        let tampered = content.replace("test vault", "tampered vault");
        assert_ne!(tampered, content, "test must actually mutate meta.yaml");
        std::fs::write(&meta_path, tampered).unwrap();

        let result = VaultMeta::load_verified(&vault_dir, &key);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("tampered"));
    }

    /// Policy (classification, access, callers) survives a save + reopen via the
    /// encrypted payload.
    #[test]
    fn policy_roundtrips_through_encrypted_payload() {
        use crate::core::policy::{CallerRule, SecretRule, Tier};
        let dir = TempDir::new().unwrap();
        let vault_dir = dir.path().join("test");
        let v = tmp_vault(&dir, "test", "Str0ng!Pass#99");

        let mut pol = v.policy.clone();
        pol.secrets.insert(
            "DB_PW".into(),
            SecretRule {
                scope: "database".into(),
                tier: Tier::High,
                require_reason: true,
                description: "prod billing dsn".into(),
                ..Default::default()
            },
        );
        pol.callers.insert(
            "claude".into(),
            CallerRule {
                scopes: vec!["database".into()],
                rate_limit: "3/hour".into(),
            },
        );
        v.save_policy(&pol).unwrap();

        let reopened = Vault::open(&vault_dir, "Str0ng!Pass#99").unwrap();
        let rule = reopened.policy.classify("DB_PW").unwrap();
        assert_eq!(rule.tier, Tier::High);
        assert_eq!(rule.scope, "database");
        assert!(rule.require_reason);
        assert_eq!(
            reopened.policy.caller("claude").unwrap().rate_limit,
            "3/hour"
        );
    }

    /// The plaintext meta.yaml must leak no policy a same-UID agent could use to
    /// plan a bypass: no tier/scope/description/caller appears at rest.
    #[test]
    fn meta_yaml_leaks_no_classification_at_rest() {
        use crate::core::policy::{SecretRule, Tier};
        let dir = TempDir::new().unwrap();
        let vault_dir = dir.path().join("test");
        let v = tmp_vault(&dir, "test", "Str0ng!Pass#99");
        let mut pol = v.policy.clone();
        pol.secrets.insert(
            "STRIPE_KEY".into(),
            SecretRule {
                scope: "payments".into(),
                tier: Tier::High,
                require_reason: true,
                description: "secret-purpose-string".into(),
                ..Default::default()
            },
        );
        v.save_policy(&pol).unwrap();

        let meta_text = std::fs::read_to_string(vault_dir.join("meta.yaml")).unwrap();
        for needle in [
            "STRIPE_KEY",
            "payments",
            "high",
            "secret-purpose-string",
            "require_reason",
            "allow_agent",
        ] {
            assert!(
                !meta_text.contains(needle),
                "meta.yaml leaked policy token at rest: {needle}"
            );
        }
    }
}
