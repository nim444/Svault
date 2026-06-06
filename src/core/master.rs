//! Master key + per-store keyslots — one passphrase that opens every vault.
//!
//! Before 0.9.4 each vault had its own passphrase (and the keyring a separate
//! one). That is up to N+1 secrets to remember. This module replaces that with a
//! single **master passphrase**, using the keyslot model that `recovery.rs`
//! already proved out:
//!
//! - A random 32-byte **master key (MK)** is generated once and wrapped under a
//!   passphrase-derived KEK (Argon2id) in `.svault/master.enc`. That file is a
//!   keyslot — exactly the `[salt][nonce][wrapped-MK]` shape as `recovery.enc`.
//! - Each vault has its own random 32-byte **data key (DEK)** that encrypts its
//!   `vault.enc`. The DEK is wrapped under MK (not under any passphrase) in
//!   `<vault_dir>/keyslot.enc`.
//!
//! Unlock the master once → unwrap MK → unwrap each vault's DEK → cache it in
//! that vault's existing `0600` session. Because every DEK is wrapped under the
//! *same* MK, one master passphrase opens everything; and because MK is the only
//! thing the passphrase wraps, future unlock methods (a YubiKey touch, a recovery
//! code) are just additional keyslots over MK — any one of them opens it all.
//!
//! Honest boundary: this is the same-UID trust model as the rest of Svault. The
//! keyslots close the read-the-files path; they are not a sandbox against a
//! hostile same-UID process reading the unlocked daemon's memory or a `0600`
//! session.
#![allow(dead_code)]

use anyhow::{anyhow, Result};
use rand::RngCore;
use std::path::{Path, PathBuf};

use crate::core::crypto::{self, VaultKey, SALT_SIZE};
use crate::core::vault::svault_dir;

const MASTER_FILE: &str = "master.enc";
const MASTER_SESSION: &str = ".master.session";
/// Recovery keyslot wrapping the master key under a 160-bit code — the way back
/// in if the master passphrase is forgotten (opens every store).
const MASTER_RECOVERY: &str = "master.recovery.enc";
/// Per-vault keyslot wrapping that vault's DEK under the master key.
pub const VAULT_KEYSLOT: &str = "keyslot.enc";
/// Keyslot wrapping the keyring's DEK under the master key. The keyring lives at
/// `.svault/keyring.enc` (not in a vault subdir), so its slot needs its own name.
pub const KEYRING_KEYSLOT: &str = "keyring.keyslot.enc";
/// YubiKey keyslot: the master key wrapped under a FIDO2 hmac-secret-derived KEK
/// — an alternative way in, the same shape as the recovery slot.
const MASTER_YUBIKEY: &str = "master.yubikey.enc";
/// Non-secret companion to the YubiKey slot: the FIDO2 credential id and the
/// hmac-secret salt needed to re-derive that KEK. JSON, owner-only.
const MASTER_YUBIKEY_META: &str = "master.yubikey.meta";
/// Touch ID keyslot (macOS): the master key wrapped under a random KEK that
/// lives in the login keychain, released only after a successful Touch ID
/// check — the same shape as the YubiKey and recovery slots.
const MASTER_TOUCHID: &str = "master.touchid.enc";

fn master_path() -> PathBuf {
    svault_dir().join(MASTER_FILE)
}

fn session_path() -> PathBuf {
    svault_dir().join(MASTER_SESSION)
}

fn keyslot_path(vault_dir: &Path) -> PathBuf {
    vault_dir.join(VAULT_KEYSLOT)
}

fn keyring_keyslot_path() -> PathBuf {
    svault_dir().join(KEYRING_KEYSLOT)
}

fn master_recovery_path() -> PathBuf {
    svault_dir().join(MASTER_RECOVERY)
}

fn yubikey_path() -> PathBuf {
    svault_dir().join(MASTER_YUBIKEY)
}

fn yubikey_meta_path() -> PathBuf {
    svault_dir().join(MASTER_YUBIKEY_META)
}

fn touchid_path() -> PathBuf {
    svault_dir().join(MASTER_TOUCHID)
}

/// True if a master recovery code has been written for this machine.
pub fn master_recovery_exists() -> bool {
    master_recovery_path().exists()
}

/// True if a YubiKey is enrolled as a master keyslot on this machine.
pub fn yubikey_enrolled() -> bool {
    yubikey_path().exists() && yubikey_meta_path().exists()
}

/// True if Touch ID is enrolled as a master keyslot on this machine.
pub fn touchid_enrolled() -> bool {
    touchid_path().exists()
}

/// True once a master passphrase has been set on this machine.
pub fn exists() -> bool {
    master_path().exists()
}

/// True if the given vault is wrapped under the master key (has a keyslot).
pub fn vault_has_keyslot(vault_dir: &Path) -> bool {
    keyslot_path(vault_dir).exists()
}

/// True if the keyring is wrapped under the master key (has a keyslot).
pub fn keyring_has_keyslot() -> bool {
    keyring_keyslot_path().exists()
}

/// An open master: the master key (MK) held in memory, used to wrap/unwrap the
/// per-vault data keys. Zeroized on drop via the inner [`VaultKey`].
pub struct Master {
    mk: VaultKey,
}

impl Master {
    /// Create the master: generate a random MK and wrap it under `passphrase`.
    /// Errors if a master already exists (callers check [`exists`] first).
    pub fn init(passphrase: &str) -> Result<Self> {
        let path = master_path();
        if path.exists() {
            return Err(anyhow!("a master passphrase is already set"));
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                crate::core::secfile::create_dir_owner_only(parent)?;
            }
        }
        let mut mk_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut mk_bytes);
        let mk = VaultKey::from_bytes(mk_bytes);
        write_master_slot(&path, &mk, passphrase)?;
        Ok(Self { mk })
    }

    /// Open the master with its passphrase. Wrong passphrase → the GCM tag fails.
    pub fn open(passphrase: &str) -> Result<Self> {
        let blob = std::fs::read(master_path())
            .map_err(|_| anyhow!("no master passphrase set — run 'svault master init'"))?;
        if blob.len() < SALT_SIZE {
            return Err(anyhow!("master.enc is too short — may be corrupted"));
        }
        let salt = &blob[..SALT_SIZE];
        let kek = VaultKey::derive(passphrase, salt)?;
        let mk_bytes =
            crypto::decrypt(&kek, &blob).map_err(|_| anyhow!("wrong master passphrase"))?;
        let mk_bytes: [u8; 32] = mk_bytes
            .try_into()
            .map_err(|_| anyhow!("master.enc holds an unexpected key length"))?;
        Ok(Self {
            mk: VaultKey::from_bytes(mk_bytes),
        })
    }

    /// Open from the cached master session key (the daemon / CLI fallback path).
    pub fn open_with_key(mk: [u8; 32]) -> Self {
        Self {
            mk: VaultKey::from_bytes(mk),
        }
    }

    /// Re-wrap MK under a new passphrase (fresh salt). The MK — and therefore
    /// every vault's DEK and ciphertext — is untouched; only the slot changes.
    pub fn rekey(&self, new_passphrase: &str) -> Result<()> {
        write_master_slot(&master_path(), &self.mk, new_passphrase)
    }

    /// Generate a recovery code, wrap MK under it, and write the recovery slot.
    /// Shown once at master creation; any later master-passphrase reset uses it
    /// (see [`recover`]). Because it wraps MK directly, this one code opens every
    /// store (all vaults + the keyring).
    pub fn write_recovery(&self) -> Result<String> {
        let code = crate::core::recovery::generate_code();
        crate::core::recovery::write_at(&master_recovery_path(), &self.mk, &code)?;
        Ok(code)
    }

    /// The raw master key bytes — for caching the session. Never written to a
    /// non-owner-only file.
    pub fn key_bytes(&self) -> &[u8; 32] {
        self.mk.bytes()
    }

    /// Enroll a YubiKey as an alternative master keyslot. Creates a FIDO2
    /// credential, derives a stable hmac-secret from it, and wraps MK under that
    /// secret in `master.yubikey.enc` (with its `.meta` companion). Needs an open
    /// master (MK in hand) plus two touches. `pin` is the YubiKey PIN if one is
    /// set. Because it wraps MK directly, the key then opens every store — and the
    /// passphrase keeps working (this is an *or*, never a 2FA requirement).
    pub fn enroll_yubikey(&self, pin: Option<&str>) -> Result<()> {
        let credential_id = crate::core::yubikey::enroll(pin)?;
        let mut hmac_salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut hmac_salt);
        let secret = crate::core::yubikey::derive_secret(&credential_id, &hmac_salt, pin)?;

        // The hmac-secret is already 32 high-entropy bytes, so it is the KEK
        // directly (no Argon2) — same reasoning as wrap_dek_at over MK.
        let kek = VaultKey::from_bytes(secret);
        let mut aes_salt = [0u8; SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut aes_salt);
        let blob = crypto::encrypt(&kek, &aes_salt, self.mk.bytes())?;
        crate::core::secfile::write_owner_only(&yubikey_path(), &blob)?;

        let meta = YubiMeta {
            credential_id: hex::encode(&credential_id),
            hmac_salt: hex::encode(hmac_salt),
        };
        let json = serde_json::to_vec(&meta)?;
        crate::core::secfile::write_owner_only(&yubikey_meta_path(), &json)?;
        Ok(())
    }

    /// Enroll Touch ID as an alternative master keyslot (macOS). Verifies a
    /// touch first, then generates a random KEK, stores it in the login
    /// keychain, and wraps MK under it in `master.touchid.enc`. Needs an open
    /// master (MK in hand). Like the YubiKey slot, this wraps MK directly —
    /// touch *or* passphrase, never a 2FA requirement.
    pub fn enroll_touchid(&self) -> Result<()> {
        // Authenticate up front so a slot is never written for a finger that
        // can't actually unlock it.
        crate::core::touchid::authenticate("enroll Touch ID as a Svault unlock method")?;

        let mut kek_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut kek_bytes);
        crate::core::touchid::store_kek(&kek_bytes)?;

        // The KEK is 32 high-entropy random bytes, so it is the AES key
        // directly (no Argon2) — same reasoning as the YubiKey slot.
        let kek = VaultKey::from_bytes(kek_bytes);
        let mut aes_salt = [0u8; SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut aes_salt);
        let blob = crypto::encrypt(&kek, &aes_salt, self.mk.bytes())?;
        crate::core::secfile::write_owner_only(&touchid_path(), &blob)?;
        Ok(())
    }

    /// Wrap a vault's data key under MK and write `<vault_dir>/keyslot.enc`.
    pub fn wrap_dek(&self, vault_dir: &Path, dek: &VaultKey) -> Result<()> {
        self.wrap_dek_at(&keyslot_path(vault_dir), dek)
    }

    /// Unwrap a vault's data key from its keyslot using MK.
    pub fn unwrap_dek(&self, vault_dir: &Path) -> Result<VaultKey> {
        self.unwrap_dek_at(
            &keyslot_path(vault_dir),
            "vault is not wrapped under the master key (no keyslot.enc)",
        )
    }

    /// Wrap the keyring's data key under MK and write `.svault/keyring.keyslot.enc`.
    pub fn wrap_keyring_dek(&self, dek: &VaultKey) -> Result<()> {
        self.wrap_dek_at(&keyring_keyslot_path(), dek)
    }

    /// Unwrap the keyring's data key from its keyslot using MK.
    pub fn unwrap_keyring_dek(&self) -> Result<VaultKey> {
        self.unwrap_dek_at(
            &keyring_keyslot_path(),
            "keyring is not wrapped under the master key (no keyring.keyslot.enc)",
        )
    }

    /// Wrap a DEK under MK and write the keyslot at `path`.
    fn wrap_dek_at(&self, path: &Path, dek: &VaultKey) -> Result<()> {
        let mut salt = [0u8; SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut salt);
        // MK is 32 random bytes already — high entropy, so AES-GCM under MK
        // directly is enough (no second Argon2 pass). The salt is stored only to
        // keep the on-disk shape identical to the other keyslots.
        let blob = crypto::encrypt(&self.mk, &salt, dek.bytes())?;
        crate::core::secfile::write_owner_only(path, &blob)?;
        Ok(())
    }

    /// Unwrap a DEK from the keyslot at `path` using MK. `missing` is the error
    /// shown when the slot file does not exist.
    fn unwrap_dek_at(&self, path: &Path, missing: &str) -> Result<VaultKey> {
        let blob = std::fs::read(path).map_err(|_| anyhow!("{missing}"))?;
        let dek_bytes = crypto::decrypt(&self.mk, &blob)
            .map_err(|_| anyhow!("could not unwrap the data key with this master"))?;
        let dek_bytes: [u8; 32] = dek_bytes
            .try_into()
            .map_err(|_| anyhow!("keyslot holds an unexpected key length"))?;
        Ok(VaultKey::from_bytes(dek_bytes))
    }
}

/// Reset the master passphrase using the recovery code: unwrap MK from the
/// recovery slot, then re-wrap it under `new_passphrase` (the recovery slot
/// itself is left unchanged, so the code keeps working). MK never changes, so
/// every vault and the keyring stay accessible.
pub fn recover(code: &str, new_passphrase: &str) -> Result<Master> {
    let path = master_recovery_path();
    if !path.exists() {
        return Err(anyhow!(
            "no master recovery code on this machine (master.recovery.enc missing)"
        ));
    }
    let mk = crate::core::recovery::unlock_at(&path, code)?;
    write_master_slot(&master_path(), &mk, new_passphrase)?;
    Ok(Master { mk })
}

/// Non-secret metadata for the YubiKey keyslot: enough to re-derive the KEK.
#[derive(serde::Serialize, serde::Deserialize)]
struct YubiMeta {
    credential_id: String,
    hmac_salt: String,
}

/// Open the master via an enrolled YubiKey: re-derive the hmac-secret from the
/// stored credential id + salt (touch, + PIN if set), then unwrap MK from
/// `master.yubikey.enc`. MK never changes, so every store stays accessible —
/// this is an alternative to typing the master passphrase, not a second factor.
pub fn open_with_yubikey(pin: Option<&str>) -> Result<Master> {
    if !yubikey_enrolled() {
        return Err(anyhow!(
            "no YubiKey is enrolled on this machine (run 'svault master yubikey enroll')"
        ));
    }
    let meta: YubiMeta = serde_json::from_slice(&std::fs::read(yubikey_meta_path())?)
        .map_err(|_| anyhow!("master.yubikey.meta is corrupted"))?;
    let credential_id = hex::decode(&meta.credential_id)
        .map_err(|_| anyhow!("bad credential id in YubiKey meta"))?;
    let salt: [u8; 32] = hex::decode(&meta.hmac_salt)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("bad hmac salt in YubiKey meta"))?;

    let secret = crate::core::yubikey::derive_secret(&credential_id, &salt, pin)?;
    let kek = VaultKey::from_bytes(secret);
    let blob = std::fs::read(yubikey_path())?;
    let mk_bytes = crypto::decrypt(&kek, &blob)
        .map_err(|_| anyhow!("this YubiKey did not unwrap the master key"))?;
    let mk_bytes: [u8; 32] = mk_bytes
        .try_into()
        .map_err(|_| anyhow!("master.yubikey.enc holds an unexpected key length"))?;
    Ok(Master {
        mk: VaultKey::from_bytes(mk_bytes),
    })
}

/// Remove the enrolled YubiKey keyslot (the passphrase and recovery code still
/// open the master). Both the slot and its meta are securely removed.
pub fn remove_yubikey() -> Result<()> {
    crate::core::session::secure_remove(&yubikey_path())?;
    crate::core::session::secure_remove(&yubikey_meta_path())?;
    Ok(())
}

/// Open the master via Touch ID (macOS): authenticate with the system biometric
/// sheet, read the KEK from the login keychain, and unwrap MK from
/// `master.touchid.enc`. MK never changes, so every store stays accessible —
/// an alternative to typing the master passphrase, not a second factor.
pub fn open_with_touchid() -> Result<Master> {
    if !touchid_enrolled() {
        return Err(anyhow!(
            "Touch ID is not enrolled on this machine (run 'svault master touchid enroll')"
        ));
    }
    crate::core::touchid::authenticate("unlock Svault")?;
    let kek = VaultKey::from_bytes(crate::core::touchid::load_kek()?);
    let blob = std::fs::read(touchid_path())?;
    let mk_bytes = crypto::decrypt(&kek, &blob)
        .map_err(|_| anyhow!("the keychain Touch ID key did not unwrap the master key — re-enroll with 'svault master touchid enroll'"))?;
    let mk_bytes: [u8; 32] = mk_bytes
        .try_into()
        .map_err(|_| anyhow!("master.touchid.enc holds an unexpected key length"))?;
    Ok(Master {
        mk: VaultKey::from_bytes(mk_bytes),
    })
}

/// Remove the Touch ID keyslot: the slot file is securely removed and the KEK
/// is deleted from the login keychain. The master passphrase and recovery code
/// still open everything.
pub fn remove_touchid() -> Result<()> {
    crate::core::session::secure_remove(&touchid_path())?;
    crate::core::touchid::delete_kek()?;
    Ok(())
}

/// Generate a random DEK for a new store. The caller wraps it under the master
/// and uses it to encrypt the store.
pub fn new_dek() -> VaultKey {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    VaultKey::from_bytes(bytes)
}

/// Wrap `mk` under a key derived from `passphrase` and write the master slot.
fn write_master_slot(path: &Path, mk: &VaultKey, passphrase: &str) -> Result<()> {
    let mut salt = [0u8; SALT_SIZE];
    rand::thread_rng().fill_bytes(&mut salt);
    let kek = VaultKey::derive(passphrase, &salt)?;
    let blob = crypto::encrypt(&kek, &salt, mk.bytes())?;
    crate::core::secfile::write_owner_only(path, &blob)?;
    Ok(())
}

// ── Session caching (mirrors session.rs / keyring.rs) ────────────────────────

/// Cache MK (`0600`, timestamped) so `create` / `enroll` don't re-prompt within
/// a session. Never stores the passphrase; expires after
/// [`crate::core::session::MAX_SESSION_SECS`] so the master must be re-entered.
pub fn unlock_session(mk: &[u8; 32]) -> Result<()> {
    crate::core::session::write_session_key(&session_path(), mk)
}

/// Clear the cached master session.
pub fn lock_session() -> Result<()> {
    crate::core::session::secure_remove(&session_path())?;
    Ok(())
}

/// The cached MK, if a valid (non-expired) master session exists.
pub fn session_key() -> Option<[u8; 32]> {
    crate::core::session::read_session_key(&session_path())
}

/// True if the master is unlocked (a usable session key is cached).
pub fn is_unlocked() -> bool {
    session_key().is_some()
}

/// Open the master from its cached session, if unlocked.
pub fn open_from_session() -> Option<Master> {
    Some(Master::open_with_key(session_key()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::testlock::CWD_LOCK;
    use crate::core::vault::SVAULT_DIR;
    use std::sync::MutexGuard;

    fn in_temp_cwd() -> (MutexGuard<'static, ()>, tempfile::TempDir, PathBuf) {
        // master.enc lives under .svault/ relative to the CWD, so disk-touching
        // tests must not run concurrently with any other chdir test — they all
        // share the one process-wide CWD lock.
        let guard = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::TempDir::new().unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();
        (guard, tmp, prev)
    }

    #[test]
    fn init_then_open_recovers_the_same_master_key() {
        let (_g, _tmp, prev) = in_temp_cwd();

        let m = Master::init("Master!Pass#1").unwrap();
        let mk = *m.key_bytes();
        drop(m);

        // Wrong passphrase is rejected; the right one returns the same MK.
        assert!(Master::open("nope").is_err());
        let reopened = Master::open("Master!Pass#1").unwrap();
        assert_eq!(reopened.key_bytes(), &mk);

        std::env::set_current_dir(prev).unwrap();
    }

    #[test]
    fn dek_wraps_under_master_and_unwraps_back() {
        let (_g, _tmp, prev) = in_temp_cwd();
        let m = Master::init("Master!Pass#2").unwrap();

        let vault_dir = PathBuf::from(SVAULT_DIR).join("v");
        crate::core::secfile::create_dir_owner_only(&vault_dir).unwrap();
        let dek = new_dek();
        let dek_bytes = *dek.bytes();
        m.wrap_dek(&vault_dir, &dek).unwrap();
        assert!(vault_has_keyslot(&vault_dir));

        let unwrapped = m.unwrap_dek(&vault_dir).unwrap();
        assert_eq!(unwrapped.bytes(), &dek_bytes);

        std::env::set_current_dir(prev).unwrap();
    }

    #[test]
    fn keyring_dek_wraps_under_master_and_unwraps_back() {
        let (_g, _tmp, prev) = in_temp_cwd();
        let m = Master::init("Master!Pass#KR").unwrap();
        crate::core::secfile::create_dir_owner_only(&PathBuf::from(SVAULT_DIR)).unwrap();

        let dek = new_dek();
        let dek_bytes = *dek.bytes();
        m.wrap_keyring_dek(&dek).unwrap();
        assert!(keyring_has_keyslot());

        let unwrapped = m.unwrap_keyring_dek().unwrap();
        assert_eq!(unwrapped.bytes(), &dek_bytes);

        std::env::set_current_dir(prev).unwrap();
    }

    #[test]
    fn rekey_keeps_master_key_and_keeps_unwrapping_vaults() {
        let (_g, _tmp, prev) = in_temp_cwd();
        let m = Master::init("Old!Master#1").unwrap();
        let vault_dir = PathBuf::from(SVAULT_DIR).join("v");
        crate::core::secfile::create_dir_owner_only(&vault_dir).unwrap();
        let dek = new_dek();
        let dek_bytes = *dek.bytes();
        m.wrap_dek(&vault_dir, &dek).unwrap();

        m.rekey("New!Master#2").unwrap();

        // Old passphrase no longer opens the master; the new one does and still
        // unwraps the same vault DEK (the DEK was never re-wrapped).
        assert!(Master::open("Old!Master#1").is_err());
        let reopened = Master::open("New!Master#2").unwrap();
        assert_eq!(reopened.unwrap_dek(&vault_dir).unwrap().bytes(), &dek_bytes);

        std::env::set_current_dir(prev).unwrap();
    }

    #[test]
    fn wrong_master_cannot_unwrap_a_dek() {
        let (_g, _tmp, prev) = in_temp_cwd();
        let m = Master::init("Right!Master#1").unwrap();
        let vault_dir = PathBuf::from(SVAULT_DIR).join("v");
        crate::core::secfile::create_dir_owner_only(&vault_dir).unwrap();
        m.wrap_dek(&vault_dir, &new_dek()).unwrap();

        // A different MK (from a fresh init in another dir) must not unwrap it.
        let other = Master::open_with_key([0x11u8; 32]);
        assert!(other.unwrap_dek(&vault_dir).is_err());

        std::env::set_current_dir(prev).unwrap();
    }

    #[test]
    fn recovery_code_resets_the_master_and_keeps_unwrapping_stores() {
        let (_g, _tmp, prev) = in_temp_cwd();
        let m = Master::init("Old!Master#R").unwrap();
        let vault_dir = PathBuf::from(SVAULT_DIR).join("v");
        crate::core::secfile::create_dir_owner_only(&vault_dir).unwrap();
        let dek = new_dek();
        let dek_bytes = *dek.bytes();
        m.wrap_dek(&vault_dir, &dek).unwrap();
        let code = m.write_recovery().unwrap();
        assert!(master_recovery_exists());
        drop(m);

        // Forgot the master passphrase: the recovery code resets it to a new one,
        // and the same MK still unwraps the vault DEK (nothing was re-encrypted).
        let recovered = recover(&code, "New!Master#R").unwrap();
        assert_eq!(
            recovered.unwrap_dek(&vault_dir).unwrap().bytes(),
            &dek_bytes
        );
        // The new passphrase now opens the master; a wrong code is rejected.
        assert!(Master::open("New!Master#R").is_ok());
        assert!(recover("0000-0000-0000-0000-0000-0000-0000-0000-0000-0000", "X").is_err());

        std::env::set_current_dir(prev).unwrap();
    }

    #[test]
    fn session_caches_mk_then_lock_clears() {
        let (_g, _tmp, prev) = in_temp_cwd();
        crate::core::secfile::create_dir_owner_only(&PathBuf::from(SVAULT_DIR)).unwrap();

        assert!(!is_unlocked());
        unlock_session(&[5u8; 32]).unwrap();
        assert!(is_unlocked());
        assert_eq!(session_key(), Some([5u8; 32]));
        lock_session().unwrap();
        assert!(!is_unlocked());

        std::env::set_current_dir(prev).unwrap();
    }
}
