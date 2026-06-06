//! Session screen (01) commands: sign-in (passphrase / YubiKey), Lock all, and
//! the status the app shell + daemon block render. Sign-out is a frontend-only
//! action — it must not touch the daemon, MCP, or vault-unlock state — so there
//! is deliberately no `sign_out` command here.

use serde::Serialize;
use std::path::Path;
use tauri::State;
use zeroize::Zeroizing;

use crate::error::{emsg, CmdResult};
use crate::state::GuiState;

use svault_cli::core::session::MAX_SESSION_SECS;
use svault_cli::core::{keyring, master, session, touchid, usage, vault, yubikey};
use svault_cli::daemon::{self, client};

/// The leaf directory name a vault is keyed under in the daemon / session.
fn leaf(dir: &Path) -> String {
    dir.file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn daemon_up() -> bool {
    daemon::is_running(&daemon::base_dir())
}

#[derive(Serialize)]
pub struct UnlockResult {
    pub unlocked: usize,
    pub already: usize,
    pub keyring_unlocked: bool,
    pub vaults: Vec<String>,
    pub reauth_deadline: Option<i64>,
}

#[derive(Serialize)]
pub struct SessionStatus {
    pub master_exists: bool,
    /// A valid (non-expired) master session is cached in core.
    pub master_unlocked: bool,
    pub daemon_up: bool,
    pub yubikey_enrolled: bool,
    /// A Touch ID keyslot is enrolled (macOS).
    pub touchid_enrolled: bool,
    /// This machine can evaluate Touch ID right now (macOS, fingers enrolled).
    pub touchid_supported: bool,
    /// Vault leaf names currently unlocked (daemon memory or file session).
    pub unlocked_vaults: Vec<String>,
    /// Unix seconds at which the GUI must re-authenticate (last unlock + 6h).
    pub reauth_deadline: Option<i64>,
    /// Seconds until the next vault auto-locks (soonest idle/hard timer across
    /// unlocked vaults, daemon-reported). `None` when no daemon or none unlocked.
    pub next_autolock_secs: Option<u64>,
}

/// The set of vaults currently unlocked, however the key is cached.
fn unlocked_vault_names() -> Vec<String> {
    let mut names = client::unlocked_vaults();
    for dir in vault::list_vault_dirs() {
        let l = leaf(&dir);
        if !names.contains(&l) && session::is_unlocked(&dir) {
            names.push(l);
        }
    }
    names
}

/// Unify-unlock: with the master in hand, unwrap and cache every vault's data
/// key (daemon memory if up, else a 0600 file session) and open the keyring.
/// Mirrors `cli::cmd_unlock`.
fn unlock_all_with_master(m: &master::Master) -> CmdResult<UnlockResult> {
    let mut unlocked = 0usize;
    let mut already = 0usize;

    for dir in vault::list_vault_dirs() {
        let l = leaf(&dir);
        if client::unlocked_vaults().iter().any(|n| n == &l) || session::is_unlocked(&dir) {
            already += 1;
            continue;
        }
        if !master::vault_has_keyslot(&dir) {
            continue; // not wrapped under the master — skip silently
        }
        let dek = match m.unwrap_dek(&dir) {
            Ok(k) => k,
            Err(_) => continue,
        };
        match client::unlock_with_key(&l, dek.bytes()) {
            Some(Ok(())) => {}
            Some(Err(_)) => continue,
            None => session::unlock_with_key(&dir, dek.bytes()).map_err(emsg)?,
        }
        usage::human(&dir, "unlock", None);
        unlocked += 1;
    }

    // A full unlock also opens the keyring (judges + their keys) under the same
    // master, so the AI judge is live without a second prompt.
    let mut keyring_unlocked = false;
    if keyring::exists() && master::keyring_has_keyslot() && !keyring::is_unlocked() {
        if let Ok(dek) = m.unwrap_keyring_dek() {
            keyring::unlock_session(dek.bytes()).map_err(emsg)?;
            keyring_unlocked = true;
        }
    }

    Ok(UnlockResult {
        unlocked,
        already,
        keyring_unlocked,
        vaults: unlocked_vault_names(),
        reauth_deadline: None, // filled by the caller after stamping the session
    })
}

pub(crate) fn stamp_unlock(state: &State<GuiState>) -> i64 {
    let now = chrono::Utc::now().timestamp();
    *state.unlocked_at.lock().unwrap() = Some(now);
    now + MAX_SESSION_SECS as i64
}

#[tauri::command]
pub fn session_status(state: State<GuiState>) -> SessionStatus {
    let unlocked = *state.unlocked_at.lock().unwrap();
    let next_autolock_secs = client::vault_status()
        .iter()
        .map(|v| v.idle_remaining_secs.min(v.hard_remaining_secs))
        .min();
    SessionStatus {
        master_exists: master::exists(),
        master_unlocked: master::is_unlocked(),
        daemon_up: daemon_up(),
        yubikey_enrolled: master::yubikey_enrolled(),
        touchid_enrolled: master::touchid_enrolled(),
        touchid_supported: touchid::is_supported(),
        unlocked_vaults: unlocked_vault_names(),
        reauth_deadline: unlocked.map(|t| t + MAX_SESSION_SECS as i64),
        next_autolock_secs,
    }
}

/// Sign in with the master passphrase. Always re-verifies the passphrase (the
/// GUI launches locked and every entry re-authenticates), then unlocks all.
///
/// `async` so the Argon2id (64 MB) key derivation runs off the main thread and
/// the UI stays responsive instead of freezing on "Unlocking…".
#[tauri::command]
pub async fn unlock(passphrase: String, state: State<'_, GuiState>) -> CmdResult<UnlockResult> {
    let pp = Zeroizing::new(passphrase);
    let m = master::Master::open(&pp).map_err(emsg)?;
    master::unlock_session(m.key_bytes()).map_err(emsg)?;
    let mut res = unlock_all_with_master(&m)?;
    res.reauth_deadline = Some(stamp_unlock(&state));
    Ok(res)
}

/// Sign in by touching an enrolled YubiKey (FIDO2 hmac-secret). `pin` is optional
/// (blank when the key has no PIN). Same effect as the passphrase path.
#[tauri::command]
pub async fn unlock_yubikey(
    pin: Option<String>,
    state: State<'_, GuiState>,
) -> CmdResult<UnlockResult> {
    let pin = pin.map(Zeroizing::new);
    let m = master::open_with_yubikey(pin.as_deref().map(|p| p.as_str())).map_err(emsg)?;
    master::unlock_session(m.key_bytes()).map_err(emsg)?;
    let mut res = unlock_all_with_master(&m)?;
    res.reauth_deadline = Some(stamp_unlock(&state));
    Ok(res)
}

/// Sign in via Touch ID (macOS). Shows the system biometric sheet, unwraps the
/// master from its Touch ID keyslot, and unlocks everything — same effect as
/// the passphrase path. `async` so the sheet never blocks the main thread.
#[tauri::command]
pub async fn unlock_touchid(state: State<'_, GuiState>) -> CmdResult<UnlockResult> {
    let m = master::open_with_touchid().map_err(emsg)?;
    master::unlock_session(m.key_bytes()).map_err(emsg)?;
    let mut res = unlock_all_with_master(&m)?;
    res.reauth_deadline = Some(stamp_unlock(&state));
    Ok(res)
}

/// On-demand YubiKey presence check (a USB-HID scan). Kept out of the
/// once-a-second `session_status` poll so the scan never blocks the UI.
#[tauri::command]
pub async fn yubikey_present() -> bool {
    yubikey::is_present()
}

/// Lock all: clear every cached key and the master + keyring sessions. Keeps the
/// GUI signed in (the frontend stays on the dashboard); distinct from sign-out.
#[tauri::command]
pub fn lock_all(state: State<GuiState>) -> CmdResult<usize> {
    let count = match client::lock_all() {
        Some(n) => n,
        // No daemon: clear every vault's 0600 file session.
        None => session::lock_all(&vault::svault_dir()).map_err(emsg)?,
    };
    let _ = master::lock_session();
    let _ = keyring::lock_session();
    *state.unlocked_at.lock().unwrap() = None;
    Ok(count)
}
