//! YubiKey unlock via the FIDO2 hmac-secret extension.
//!
//! An enrolled YubiKey is an **independent keyslot** over the master key: a
//! stable 32-byte secret derived from the key (gated by a physical touch, and the
//! YubiKey PIN if one is set) wraps the master key in `.svault/master.yubikey.enc`,
//! exactly like the recovery code wraps it in `master.recovery.enc`. Either the
//! master passphrase **or** the YubiKey opens everything — this is a convenience
//! alternative slot, not a second factor.
//!
//! Pure-Rust CTAP2 over USB HID (no system libfido2). Every call needs the key
//! plugged in and a touch; this module takes the PIN as a parameter so the
//! `core` layer never prompts (the CLI/TUI do).
#![allow(dead_code)]

use anyhow::{anyhow, Result};
use ctap_hid_fido2::fidokey::get_assertion::get_assertion_params::Extension as Gext;
use ctap_hid_fido2::fidokey::make_credential::make_credential_params::Extension as Mext;
use ctap_hid_fido2::fidokey::{GetAssertionArgsBuilder, MakeCredentialArgsBuilder};
use ctap_hid_fido2::{Cfg, FidoKeyHid, FidoKeyHidFactory};

/// Relying-party id stamped on Svault's FIDO2 credential.
const RP_ID: &str = "svault.local";

/// A fixed, non-secret challenge. We use the credential only for its stable
/// hmac-secret output, never for attestation/assertion signature verification,
/// so the challenge value is irrelevant — it just has to be present.
const CHALLENGE: [u8; 32] = [0u8; 32];

/// True if at least one FIDO authenticator is currently connected.
pub fn is_present() -> bool {
    !ctap_hid_fido2::get_fidokey_devices().is_empty()
}

/// Library config with all of ctap-hid-fido2's terminal chatter silenced. The
/// crate otherwise prints "- Touch the sensor on the authenticator" (and debug
/// lines) straight to stdout, which corrupts the raw-mode TUI. We render our own
/// "touch now" prompt instead, so every callout here is muted.
fn cfg() -> Cfg {
    let mut cfg = Cfg::init();
    cfg.enable_log = false;
    cfg.enable_keep_alive_msg = false;
    cfg.keep_alive_msg = String::new();
    cfg
}

fn open_device() -> Result<FidoKeyHid> {
    if !is_present() {
        return Err(anyhow!(
            "no YubiKey / FIDO2 device found — plug it in and try again"
        ));
    }
    FidoKeyHidFactory::create(&cfg()).map_err(|e| anyhow!("could not open the FIDO2 device: {e:?}"))
}

/// Enroll: create a FIDO2 credential carrying the hmac-secret extension. Returns
/// the credential id (non-secret) to store alongside the keyslot. Prompts a touch
/// (and uses `pin` if the key has one set). An empty/`None` pin uses no PIN/UV.
pub fn enroll(pin: Option<&str>) -> Result<Vec<u8>> {
    let device = open_device()?;
    let builder = MakeCredentialArgsBuilder::new(RP_ID, &CHALLENGE)
        .extensions(&[Mext::HmacSecret(Some(true))]);
    let builder = match pin {
        Some(p) if !p.is_empty() => builder.pin(p),
        _ => builder.without_pin_and_uv(),
    };
    let att = device
        .make_credential_with_args(&builder.build())
        .map_err(|e| anyhow!("YubiKey enrollment failed (is the hmac-secret extension supported, and the PIN correct?): {e:?}"))?;
    Ok(att.credential_descriptor.id)
}

/// Derive the stable 32-byte secret for `(credential_id, salt)`. The same inputs
/// always yield the same secret on the same physical key. Prompts a touch (+ PIN
/// if set). This is the KEK that wraps the master key in the YubiKey keyslot.
pub fn derive_secret(credential_id: &[u8], salt: &[u8; 32], pin: Option<&str>) -> Result<[u8; 32]> {
    let device = open_device()?;
    let builder = GetAssertionArgsBuilder::new(RP_ID, &CHALLENGE)
        .credential_id(credential_id)
        .extensions(&[Gext::HmacSecret(Some(*salt))]);
    let builder = match pin {
        Some(p) if !p.is_empty() => builder.pin(p),
        _ => builder.without_pin_and_uv(),
    };
    let assertions = device
        .get_assertion_with_args(&builder.build())
        .map_err(|e| anyhow!("YubiKey unlock failed (wrong key or PIN?): {e:?}"))?;
    let assertion = assertions
        .first()
        .ok_or_else(|| anyhow!("YubiKey returned no assertion"))?;
    for ext in &assertion.extensions {
        if let Gext::HmacSecret(Some(out)) = ext {
            return Ok(*out);
        }
    }
    Err(anyhow!(
        "YubiKey did not return an hmac-secret value — the credential may lack the extension"
    ))
}
