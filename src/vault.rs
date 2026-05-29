use anyhow::{anyhow, Result};
use rand::RngCore;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::{self, VaultKey, SALT_SIZE};
use crate::meta::VaultMeta;

pub const SVAULT_DIR: &str = ".svault";

/// Decrypted secrets — zeroed from memory on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
struct SecretStore(String);

#[allow(dead_code)]
pub struct Vault {
    pub vault_dir: PathBuf,
    pub meta: VaultMeta,
    key: VaultKey,
}

impl Vault {
    /// Create a new vault at the given directory path.
    pub fn init(vault_dir: &Path, passphrase: &str, meta_input: VaultMeta) -> Result<Self> {
        if vault_dir.exists() {
            return Err(anyhow!("Vault already exists at {}", vault_dir.display()));
        }
        std::fs::create_dir_all(vault_dir)?;

        // Write a local .gitignore so the session file and the logs can never be
        // accidentally committed even if the repo-level .gitignore is missing or wrong.
        std::fs::write(
            vault_dir.join(".gitignore"),
            ".session\naudit.log\nusage.log\n",
        )?;

        let mut salt = [0u8; SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut salt);
        let key = VaultKey::derive(passphrase, &salt)?;

        let empty = serde_json::to_vec(&HashMap::<String, String>::new())?;
        let encrypted = crypto::encrypt(&key, &salt, &empty)?;
        std::fs::write(vault_dir.join("vault.enc"), &encrypted)?;

        meta_input.save(vault_dir, key.bytes())?;

        let meta = VaultMeta::load_verified(vault_dir, key.bytes())?;
        Ok(Self {
            vault_dir: vault_dir.to_path_buf(),
            meta,
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

        // Verify correct passphrase by attempting decrypt
        crypto::decrypt(&key, &encrypted)?;

        let meta = VaultMeta::load_verified(vault_dir, key.bytes())?;
        Ok(Self {
            vault_dir: vault_dir.to_path_buf(),
            meta,
            key,
        })
    }

    /// Open an existing vault directly from its derived key, skipping Argon2.
    /// Used by the recovery path (which unwraps the stored key) and the daemon
    /// (which holds the key in memory). Verifies the key by decrypting vault.enc.
    pub fn open_with_key(vault_dir: &Path, key: VaultKey) -> Result<Self> {
        let encrypted = std::fs::read(vault_dir.join("vault.enc"))?;
        crypto::decrypt(&key, &encrypted)?;
        let meta = VaultMeta::load_verified(vault_dir, key.bytes())?;
        Ok(Self {
            vault_dir: vault_dir.to_path_buf(),
            meta,
            key,
        })
    }

    /// The vault's derived key — needed to re-wrap the recovery file after a re-key.
    pub fn key(&self) -> &VaultKey {
        &self.key
    }

    /// Re-encrypt the vault under a new passphrase: fresh salt + key, re-write
    /// vault.enc, re-sign meta.yaml. The caller re-wraps recovery.enc afterwards.
    pub fn rekey(&mut self, new_passphrase: &str) -> Result<()> {
        let secrets = self.load_secrets()?;
        let mut salt = [0u8; SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut salt);
        let new_key = VaultKey::derive(new_passphrase, &salt)?;

        let json = SecretStore(serde_json::to_string(&secrets)?);
        let data = crypto::encrypt(&new_key, &salt, json.0.as_bytes())?;
        std::fs::write(self.vault_dir.join("vault.enc"), data)?;
        self.meta.save(&self.vault_dir, new_key.bytes())?;
        self.key = new_key;
        Ok(())
    }

    /// Re-sign and persist updated metadata (settings, description, access).
    /// Requires the vault to be open so the HMAC can be recomputed with the key.
    pub fn save_meta(&self, meta: &VaultMeta) -> Result<()> {
        meta.save(&self.vault_dir, self.key.bytes())
    }

    pub fn add_secret(&self, name: &str, value: &str) -> Result<()> {
        let mut secrets = self.load_secrets()?;
        secrets.insert(name.to_string(), value.to_string());
        self.save_secrets(&secrets)
    }

    pub fn get_secret(&self, name: &str) -> Result<Option<String>> {
        Ok(self.load_secrets()?.get(name).cloned())
    }

    pub fn list_secret_names(&self) -> Result<Vec<String>> {
        let mut names: Vec<String> = self.load_secrets()?.into_keys().collect();
        names.sort();
        Ok(names)
    }

    pub fn remove_secret(&self, name: &str) -> Result<bool> {
        let mut secrets = self.load_secrets()?;
        let removed = secrets.remove(name).is_some();
        if removed {
            self.save_secrets(&secrets)?;
        }
        Ok(removed)
    }

    fn load_secrets(&self) -> Result<HashMap<String, String>> {
        let encrypted = std::fs::read(self.vault_dir.join("vault.enc"))?;
        let plaintext = crypto::decrypt(&self.key, &encrypted)?;
        let store = SecretStore(String::from_utf8(plaintext)?);
        Ok(serde_json::from_str(&store.0)?)
    }

    fn save_secrets(&self, secrets: &HashMap<String, String>) -> Result<()> {
        let json = SecretStore(serde_json::to_string(secrets)?);
        let encrypted = std::fs::read(self.vault_dir.join("vault.enc"))?;
        if encrypted.len() < SALT_SIZE {
            return Err(anyhow!("vault.enc is too short — may be corrupted"));
        }
        let salt: [u8; SALT_SIZE] = encrypted[..SALT_SIZE]
            .try_into()
            .expect("slice length checked against SALT_SIZE above");
        let data = crypto::encrypt(&self.key, &salt, json.0.as_bytes())?;
        std::fs::write(self.vault_dir.join("vault.enc"), data)?;
        Ok(())
    }
}

/// List all vault directories under base/.svault/
pub fn list_vault_dirs() -> Vec<PathBuf> {
    list_vault_dirs_in(Path::new(SVAULT_DIR))
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
    use crate::meta::{AccessConfig, VaultMeta, VaultSettings};
    use tempfile::TempDir;

    fn tmp_vault(dir: &TempDir, name: &str, passphrase: &str) -> Vault {
        let vault_dir = dir.path().join(name);
        let meta = VaultMeta::new(
            name.to_string(),
            "test vault".to_string(),
            AccessConfig::default(),
            VaultSettings::default(),
        );
        Vault::init(&vault_dir, passphrase, meta).expect("init failed")
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
        let val = v.get_secret("API_KEY").unwrap();
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
            v2.get_secret("DB_URL").unwrap(),
            Some("postgres://localhost/mydb".to_string())
        );
        assert_eq!(
            v2.get_secret("REDIS_URL").unwrap(),
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
            reopened.get_secret("API_KEY").unwrap(),
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
            v.get_secret("DB_URL").unwrap(),
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

        // save_secrets must return an error rather than panic on the short slice.
        let mut secrets = HashMap::new();
        secrets.insert("K".to_string(), "v".to_string());
        let result = v.save_secrets(&secrets);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn tampered_meta_yaml_is_rejected() {
        let dir = TempDir::new().unwrap();
        let vault_dir = dir.path().join("test");
        let v = tmp_vault(&dir, "test", "Str0ng!Pass#99");
        let key = v.key.bytes().to_vec();

        // Tamper with meta.yaml — change allow_agent to false
        let meta_path = vault_dir.join("meta.yaml");
        let content = std::fs::read_to_string(&meta_path).unwrap();
        let tampered = content.replace("allow_agent: true", "allow_agent: false");
        std::fs::write(&meta_path, tampered).unwrap();

        let result = VaultMeta::load_verified(&vault_dir, &key);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("tampered"));
    }
}
