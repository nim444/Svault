//! First-run onboarding (02). The disclaimer (step 1) and the recovery-code
//! gating checkbox (step 3) are frontend-only; these commands cover the steps
//! that touch core: setting the master passphrase + showing the one-time
//! recovery code (step 2/3) and the optional YubiKey enrollment (step 4).

use serde::Serialize;
use tauri::State;
use zeroize::Zeroizing;

use crate::commands::session::stamp_unlock;
use crate::error::{emsg, CmdResult};
use crate::state::GuiState;

use svault_cli::core::master;

#[derive(Serialize)]
pub struct InitResult {
    /// The one-time 160-bit master recovery code. Shown once, never stored in
    /// plaintext — the frontend must gate continuation on the user confirming
    /// they've saved it.
    pub recovery_code: String,
    pub reauth_deadline: i64,
}

/// Set the master passphrase (first run only). Caches the master session so the
/// user lands signed-in, and returns the one-time recovery code to display.
#[tauri::command]
pub async fn init_master(passphrase: String, state: State<'_, GuiState>) -> CmdResult<InitResult> {
    if master::exists() {
        return Err("a master passphrase is already set".into());
    }
    let pp = Zeroizing::new(passphrase);
    let m = master::Master::init(&pp).map_err(emsg)?;
    master::unlock_session(m.key_bytes()).map_err(emsg)?;
    let recovery_code = m.write_recovery().map_err(emsg)?;
    Ok(InitResult {
        recovery_code,
        reauth_deadline: stamp_unlock(&state),
    })
}

/// Enroll a YubiKey (FIDO2 hmac-secret) as an additional unlock slot over the
/// master key. Requires the master to be unlocked (it is, right after init).
/// Used by both onboarding step 4 and Settings.
#[tauri::command]
pub fn enroll_yubikey(pin: Option<String>) -> CmdResult<()> {
    let m = master::open_from_session().ok_or("master is locked — sign in first")?;
    let pin = pin.map(Zeroizing::new);
    m.enroll_yubikey(pin.as_deref().map(|p| p.as_str()))
        .map_err(emsg)?;
    Ok(())
}

/// Remove the enrolled YubiKey slot (Settings). The passphrase and recovery code
/// still open everything.
#[tauri::command]
pub fn remove_yubikey() -> CmdResult<()> {
    master::remove_yubikey().map_err(emsg)
}
