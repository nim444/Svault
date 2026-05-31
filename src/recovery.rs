//! Recovery key — a second way into a vault if the passphrase is lost.
//!
//! At create time we generate a high-entropy recovery code (160 bits) and store
//! the vault key wrapped under a code-derived key in `recovery.enc`. The vault
//! key itself never changes, so recovery unlocks the *same* `vault.enc` without
//! re-keying. Because the wrapper is encrypted under a 160-bit random code,
//! `recovery.enc` is as safe to keep (and to ship in an export) as `vault.enc`.

use anyhow::{anyhow, Result};
use rand::RngCore;
use std::path::Path;

use crate::crypto::{self, VaultKey, SALT_SIZE};

const RECOVERY_FILE: &str = "recovery.enc";
const CODE_BYTES: usize = 20; // 160 bits

fn recovery_path(vault_dir: &Path) -> std::path::PathBuf {
    vault_dir.join(RECOVERY_FILE)
}

/// True if the vault has a recovery file.
pub fn exists(vault_dir: &Path) -> bool {
    recovery_path(vault_dir).exists()
}

/// Generate a fresh recovery code for display, e.g. `A1B2-C3D4-...` (10 groups).
/// The pretty form is what the user stores; derivation always normalizes first.
pub fn generate_code() -> String {
    let mut bytes = [0u8; CODE_BYTES];
    rand::thread_rng().fill_bytes(&mut bytes);
    let hex = hex::encode_upper(bytes);
    hex.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("-")
}

/// Strip formatting so `A1B2-C3D4` and `a1b2c3d4` derive the same key.
fn normalize(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// Wrap `vault_key` under a key derived from `code` and write `recovery.enc`.
pub fn write(vault_dir: &Path, vault_key: &VaultKey, code: &str) -> Result<()> {
    let mut salt = [0u8; SALT_SIZE];
    rand::thread_rng().fill_bytes(&mut salt);
    let kek = VaultKey::derive(&normalize(code), &salt)?;
    let blob = crypto::encrypt(&kek, &salt, vault_key.bytes())?;
    // recovery.enc wraps a key-equivalent — keep it owner-only (#14).
    crate::secfile::write_owner_only(&recovery_path(vault_dir), &blob)?;
    Ok(())
}

/// Recover the vault key from `recovery.enc` using the recovery code.
/// Wrong code → the GCM tag fails and this returns an error.
pub fn unlock_with_code(vault_dir: &Path, code: &str) -> Result<VaultKey> {
    let blob = std::fs::read(recovery_path(vault_dir))
        .map_err(|_| anyhow!("No recovery file for this vault"))?;
    if blob.len() < SALT_SIZE {
        return Err(anyhow!("recovery.enc is too short — may be corrupted"));
    }
    let salt = &blob[..SALT_SIZE];
    let kek = VaultKey::derive(&normalize(code), salt)?;
    let key_bytes = crypto::decrypt(&kek, &blob).map_err(|_| anyhow!("Invalid recovery code"))?;
    let key_bytes: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| anyhow!("recovery.enc holds an unexpected key length"))?;
    Ok(VaultKey::from_bytes(key_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_vault_enc(vault_dir: &Path, key: &VaultKey, plaintext: &[u8]) -> [u8; SALT_SIZE] {
        let mut salt = [0u8; SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut salt);
        let blob = crypto::encrypt(key, &salt, plaintext).unwrap();
        std::fs::write(vault_dir.join("vault.enc"), blob).unwrap();
        salt
    }

    #[test]
    fn code_is_grouped_and_normalizes_back() {
        let code = generate_code();
        assert!(code.contains('-'));
        // 20 bytes -> 40 hex chars after stripping the 9 dashes.
        assert_eq!(normalize(&code).len(), 40);
    }

    #[test]
    fn write_then_unlock_returns_the_same_key() {
        let dir = TempDir::new().unwrap();
        let vault_dir = dir.path();
        let salt = [7u8; SALT_SIZE];
        let key = VaultKey::derive("vault-pass-1!", &salt).unwrap();
        // Prove the recovered key actually decrypts the vault payload.
        write_vault_enc(vault_dir, &key, b"top secret");

        let code = generate_code();
        write(vault_dir, &key, &code).unwrap();

        let recovered = unlock_with_code(vault_dir, &code).unwrap();
        let enc = std::fs::read(vault_dir.join("vault.enc")).unwrap();
        assert_eq!(crypto::decrypt(&recovered, &enc).unwrap(), b"top secret");
    }

    #[test]
    fn unlock_accepts_unformatted_code() {
        let dir = TempDir::new().unwrap();
        let key = VaultKey::derive("p", &[1u8; SALT_SIZE]).unwrap();
        let code = generate_code();
        write(dir.path(), &key, &code).unwrap();

        // Same code, dashes stripped and lowercased, still works.
        let messy = normalize(&code);
        let recovered = unlock_with_code(dir.path(), &messy).unwrap();
        assert_eq!(recovered.bytes(), key.bytes());
    }

    #[test]
    fn wrong_code_is_rejected() {
        let dir = TempDir::new().unwrap();
        let key = VaultKey::derive("p", &[2u8; SALT_SIZE]).unwrap();
        write(dir.path(), &key, &generate_code()).unwrap();

        let result = unlock_with_code(dir.path(), "0000-0000-0000-0000-0000");
        assert!(result.is_err());
    }

    #[test]
    fn recovered_key_can_be_rewrapped_and_still_opens_the_vault() {
        use crate::meta::{VaultMeta, VaultSettings};
        use crate::policy::VaultPolicyData;
        use crate::vault::Vault;
        let dir = TempDir::new().unwrap();
        let vault_dir = dir.path().join("v");
        let meta = VaultMeta::new("v".to_string(), "d".to_string(), VaultSettings::default());
        // A vault under a random data key (the unified-unlock model).
        let dek = crate::master::new_dek();
        let vault =
            Vault::init_with_key(&vault_dir, dek, meta, VaultPolicyData::default()).unwrap();
        vault.add_secret("K", "val").unwrap();
        let code = generate_code();
        write(&vault_dir, vault.key(), &code).unwrap();
        drop(vault);

        // The recovery code returns the same data key, which still opens the vault.
        let recovered = unlock_with_code(&vault_dir, &code).unwrap();
        let v = Vault::open_with_key(&vault_dir, recovered).unwrap();
        assert_eq!(
            v.get_secret("K").unwrap().map(|z| z.to_string()),
            Some("val".to_string())
        );
    }
}
