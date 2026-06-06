//! Touch ID unlock via macOS LocalAuthentication + the login keychain.
//!
//! An enrolled Touch ID is an **independent keyslot** over the master key,
//! exactly like the YubiKey and recovery slots: a random 32-byte KEK wraps the
//! master key in `.svault/master.touchid.enc`, and the KEK itself lives as a
//! generic-password item in the user's **login keychain** (ACL'd to the svault
//! binary by macOS). Unlocking shows the system Touch ID sheet
//! (`LAContext::evaluatePolicy`, biometrics-only policy) and only on success
//! reads the KEK back. Passphrase **or** touch — a convenience alternative
//! slot, never a second factor.
//!
//! Honest boundary: the biometric check is enforced **in-process** by svault.
//! A real biometry-bound keychain ACL (`kSecAccessControlBiometryAny` in the
//! data-protection keychain) needs Apple-signed entitlements that a
//! cargo-installed CLI binary does not have — probed and confirmed
//! (`errSecMissingEntitlement`). The login-keychain item is still encrypted at
//! rest and gated by the OS keychain ACL (another binary touching it triggers
//! a user-facing prompt), but this is the same same-UID-cooperative trust
//! model as the rest of Svault — not a sandbox against a hostile process
//! running as you.
//!
//! Compiled only on macOS; elsewhere the functions are stubs ([`is_supported`]
//! returns `false`, the rest return a clear "macOS only" error), so the
//! default build stays dependency-free on Linux/Windows.
#![allow(dead_code)]

use anyhow::Result;

/// Keychain coordinates of the Touch ID KEK. The service is namespaced so the
/// item is recognisable in Keychain Access; the account names the slot.
pub const KEYCHAIN_SERVICE: &str = "svault";
pub const KEYCHAIN_ACCOUNT: &str = "master-touchid-kek";

/// True if this machine can evaluate the biometrics policy right now (macOS
/// with Touch ID available and enrolled fingers). Always `false` off-macOS.
pub fn is_supported() -> bool {
    imp::is_supported()
}

/// Show the system Touch ID sheet with `reason` ("svault is trying to
/// <reason>") and block until the user authenticates or cancels. Errors on
/// cancel/failure — never silently passes.
pub fn authenticate(reason: &str) -> Result<()> {
    imp::authenticate(reason)
}

/// Store the Touch ID KEK in the login keychain (replaces any previous item).
pub fn store_kek(kek: &[u8; 32]) -> Result<()> {
    imp::store_kek(kek)
}

/// Read the Touch ID KEK back from the login keychain.
pub fn load_kek() -> Result<[u8; 32]> {
    imp::load_kek()
}

/// Remove the KEK item from the login keychain (idempotent).
pub fn delete_kek() -> Result<()> {
    imp::delete_kek()
}

#[cfg(target_os = "macos")]
mod imp {
    use anyhow::{anyhow, Result};
    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password,
    };
    use std::sync::mpsc;
    use zeroize::Zeroize;

    use super::{KEYCHAIN_ACCOUNT, KEYCHAIN_SERVICE};

    pub fn is_supported() -> bool {
        let ctx = unsafe { LAContext::new() };
        unsafe { ctx.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics) }
            .is_ok()
    }

    pub fn authenticate(reason: &str) -> Result<()> {
        let ctx = unsafe { LAContext::new() };
        unsafe { ctx.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics) }
            .map_err(|e| anyhow!("Touch ID is not available: {e}"))?;

        // The reply block fires on a private queue, so a channel is enough to
        // turn the async callback into a blocking wait — no runloop needed.
        let (tx, rx) = mpsc::channel::<Result<(), String>>();
        let block = RcBlock::new(move |ok: Bool, err: *mut NSError| {
            let res = if ok.as_bool() {
                Ok(())
            } else if err.is_null() {
                Err("authentication failed".to_string())
            } else {
                // SAFETY: non-null NSError pointer from the framework callback.
                Err(unsafe { &*err }.localizedDescription().to_string())
            };
            let _ = tx.send(res);
        });
        unsafe {
            ctx.evaluatePolicy_localizedReason_reply(
                LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
                &NSString::from_str(reason),
                &block,
            );
        }
        rx.recv()
            .map_err(|_| anyhow!("Touch ID prompt was interrupted"))?
            .map_err(|e| anyhow!("Touch ID failed: {e}"))
    }

    pub fn store_kek(kek: &[u8; 32]) -> Result<()> {
        // set_generic_password upserts: it updates the existing item in place,
        // so re-enrollment never leaves a stale duplicate behind.
        set_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, kek)
            .map_err(|e| anyhow!("could not store the Touch ID key in the keychain: {e}"))
    }

    pub fn load_kek() -> Result<[u8; 32]> {
        let mut bytes = get_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT).map_err(|_| {
            anyhow!(
                "no Touch ID key in the keychain — re-enroll with 'svault master touchid enroll'"
            )
        })?;
        let kek: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("the keychain Touch ID key has an unexpected length"))?;
        bytes.zeroize();
        Ok(kek)
    }

    pub fn delete_kek() -> Result<()> {
        match delete_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT) {
            Ok(()) => Ok(()),
            // Item not found is fine — delete is idempotent.
            Err(e) if e.code() == security_framework_sys_err_item_not_found() => Ok(()),
            Err(e) => Err(anyhow!("could not remove the Touch ID keychain item: {e}")),
        }
    }

    /// `errSecItemNotFound` without pulling in security-framework-sys directly.
    const fn security_framework_sys_err_item_not_found() -> i32 {
        -25300
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use anyhow::{anyhow, Result};

    fn unsupported<T>() -> Result<T> {
        Err(anyhow!("Touch ID unlock is only available on macOS"))
    }

    pub fn is_supported() -> bool {
        false
    }

    pub fn authenticate(_reason: &str) -> Result<()> {
        unsupported()
    }

    pub fn store_kek(_kek: &[u8; 32]) -> Result<()> {
        unsupported()
    }

    pub fn load_kek() -> Result<[u8; 32]> {
        unsupported()
    }

    pub fn delete_kek() -> Result<()> {
        unsupported()
    }
}
