use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const SALT_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;

// Argon2id params: 64MB memory, 3 iterations, 1 thread
const M_COST: u32 = 64 * 1024;
const T_COST: u32 = 3;
const P_COST: u32 = 1;

/// Derived vault key — zeroed from memory on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VaultKey([u8; 32]);

impl VaultKey {
    pub fn derive(passphrase: &str, salt: &[u8]) -> Result<Self> {
        let params = Params::new(M_COST, T_COST, P_COST, Some(32))
            .map_err(|e| anyhow!("Argon2 params error: {e}"))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key = [0u8; 32];
        argon2
            .hash_password_into(passphrase.as_bytes(), salt, &mut key)
            .map_err(|e| anyhow!("Key derivation failed: {e}"))?;
        Ok(VaultKey(key))
    }

    /// Build a key from raw bytes — used by the recovery path (which unwraps the
    /// stored vault key) and the daemon (which holds the derived key in memory),
    /// neither of which re-derives from a passphrase.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        VaultKey(bytes)
    }

    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Encrypt plaintext. Returns: [32-byte salt][12-byte nonce][AES-256-GCM ciphertext+tag]
pub fn encrypt(key: &VaultKey, salt: &[u8; SALT_SIZE], plaintext: &[u8]) -> Result<Vec<u8>> {
    let aes_key = Key::<Aes256Gcm>::from_slice(key.bytes());
    let cipher = Aes256Gcm::new(aes_key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| anyhow!("Encryption failed"))?;

    let mut out = Vec::with_capacity(SALT_SIZE + NONCE_SIZE + ciphertext.len());
    out.extend_from_slice(salt);
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt data produced by `encrypt`. Wrong key → clear error, no panic.
pub fn decrypt(key: &VaultKey, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < SALT_SIZE + NONCE_SIZE {
        return Err(anyhow!("Vault file is too short — may be corrupted"));
    }
    let nonce = Nonce::from_slice(&data[SALT_SIZE..SALT_SIZE + NONCE_SIZE]);
    let ciphertext = &data[SALT_SIZE + NONCE_SIZE..];

    let aes_key = Key::<Aes256Gcm>::from_slice(key.bytes());
    let cipher = Aes256Gcm::new(aes_key);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("Wrong passphrase or corrupted vault"))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let passphrase = "test-passphrase-123";
        let mut salt = [0u8; SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut salt);
        let key = VaultKey::derive(passphrase, &salt).unwrap();

        let plaintext = b"hello, svault!";
        let ciphertext = encrypt(&key, &salt, plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails_decrypt() {
        let mut salt = [0u8; SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut salt);

        let key1 = VaultKey::derive("correct-passphrase-X9!", &salt).unwrap();
        let key2 = VaultKey::derive("wrong-passphrase-Y8@", &salt).unwrap();

        let ciphertext = encrypt(&key1, &salt, b"secret data").unwrap();
        let result = decrypt(&key2, &ciphertext);

        assert!(result.is_err());
    }

    #[test]
    fn bit_flip_fails_authentication() {
        let mut salt = [0u8; SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut salt);
        let key = VaultKey::derive("passphrase-A1#", &salt).unwrap();

        let mut ciphertext = encrypt(&key, &salt, b"authentic data").unwrap();
        // Flip a bit in the ciphertext body
        let flip_pos = ciphertext.len() - 5;
        ciphertext[flip_pos] ^= 0xFF;

        let result = decrypt(&key, &ciphertext);
        assert!(
            result.is_err(),
            "tampered ciphertext should fail authentication"
        );
    }

    #[test]
    fn from_bytes_roundtrips_as_a_key() {
        let mut salt = [0u8; SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut salt);
        let derived = VaultKey::derive("passphrase-from-bytes-1!", &salt).unwrap();

        // Reconstructing a key from the same raw bytes decrypts the same data.
        let reconstructed = VaultKey::from_bytes(*derived.bytes());
        let ciphertext = encrypt(&derived, &salt, b"round trip").unwrap();
        let decrypted = decrypt(&reconstructed, &ciphertext).unwrap();

        assert_eq!(decrypted, b"round trip");
    }

    #[test]
    fn different_salts_produce_different_keys() {
        let passphrase = "same-passphrase-Z2$";
        let mut salt1 = [0u8; SALT_SIZE];
        let mut salt2 = [0u8; SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut salt1);
        rand::thread_rng().fill_bytes(&mut salt2);

        let key1 = VaultKey::derive(passphrase, &salt1).unwrap();
        let key2 = VaultKey::derive(passphrase, &salt2).unwrap();

        assert_ne!(key1.bytes(), key2.bytes());
    }
}
