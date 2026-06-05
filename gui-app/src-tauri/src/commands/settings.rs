//! Settings (11). Appearance/startup prefs are GUI-only (a JSON file in the
//! store); security/daemon and diagnostics drive core + the daemon.

use serde::Serialize;
use zeroize::Zeroizing;

use crate::commands::common::{open_or_init_keyring, require_master};
use crate::error::{emsg, CmdResult};

use svault_ai::core::{master, vault, yubikey};
use svault_ai::daemon;

fn prefs_path() -> std::path::PathBuf {
    vault::svault_dir().join("gui-prefs.json")
}

/// GUI appearance/startup preferences — opaque JSON the frontend owns.
#[tauri::command]
pub fn get_prefs() -> serde_json::Value {
    std::fs::read_to_string(prefs_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| serde_json::json!({}))
}

#[tauri::command]
pub fn set_prefs(prefs: serde_json::Value) -> CmdResult<()> {
    let body = serde_json::to_string_pretty(&prefs).map_err(emsg)?;
    std::fs::write(prefs_path(), body).map_err(emsg)?;
    Ok(())
}

/// Change the master passphrase (rekey). No vault is re-encrypted — the data keys
/// never move. Requires the current session (the GUI is signed in).
#[tauri::command]
pub async fn change_master(new_passphrase: String) -> CmdResult<()> {
    let m = require_master()?;
    let new = Zeroizing::new(new_passphrase);
    m.rekey(&new).map_err(emsg)?;
    master::unlock_session(m.key_bytes()).map_err(emsg)?;
    Ok(())
}

#[derive(Serialize)]
pub struct YubikeyStatus {
    pub enrolled: bool,
    pub present: bool,
}

#[tauri::command]
pub fn yubikey_status() -> YubikeyStatus {
    YubikeyStatus {
        enrolled: master::yubikey_enrolled(),
        present: yubikey::is_present(),
    }
}

#[derive(Serialize)]
pub struct DaemonInfo {
    pub running: bool,
    pub pid: Option<u32>,
    pub max_connections: usize,
    pub idle_timeout_secs: u64,
    pub max_unlocked_secs: u64,
    /// Windows has no daemon (0600 session fallback).
    pub supported: bool,
}

#[tauri::command]
pub fn daemon_info() -> DaemonInfo {
    let base = daemon::base_dir();
    let running = daemon::is_running(&base);
    let pid = std::fs::read_to_string(base.join("daemon.pid"))
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok());
    // Config lives in the keyring; fall back to defaults when locked.
    let (max_connections, idle_timeout_secs, max_unlocked_secs) =
        match svault_ai::core::keyring::open_from_session() {
            Some(kr) => (
                kr.data.daemon.max_connections,
                kr.data.lock.idle_timeout_secs,
                kr.data.lock.max_unlocked_secs,
            ),
            None => (512, 15 * 60, 6 * 60 * 60),
        };
    DaemonInfo {
        running,
        pid,
        max_connections,
        idle_timeout_secs,
        max_unlocked_secs,
        supported: cfg!(unix),
    }
}

/// Locate the `svault` binary that runs the daemon: the bundled sidecar if
/// present (release), otherwise `svault` on PATH (dev / after Install CLI). The
/// GUI's own executable can't run the daemon, so this never returns it.
pub fn locate_svault_bin() -> std::path::PathBuf {
    locate_sidecar().unwrap_or_else(|| std::path::PathBuf::from(svault_bin_name()))
}

#[tauri::command]
pub fn daemon_start() -> CmdResult<String> {
    daemon::start_quiet_with_exe(&locate_svault_bin()).map_err(emsg)
}

#[tauri::command]
pub fn daemon_stop() -> CmdResult<String> {
    daemon::stop_quiet().map_err(emsg)
}

/// Run the daemon doctor (clean up stale socket/pid). Returns running state after.
#[tauri::command]
pub fn daemon_doctor() -> CmdResult<bool> {
    daemon::doctor(true).map_err(emsg)?;
    Ok(daemon::is_running(&daemon::base_dir()))
}

/// Persist daemon/lock limits into the keyring. Takes effect on the next daemon
/// start.
#[tauri::command]
pub fn set_daemon_limits(idle_timeout_secs: u64, max_connections: usize) -> CmdResult<()> {
    let mut kr = open_or_init_keyring()?;
    kr.data.lock.idle_timeout_secs = idle_timeout_secs;
    kr.data.daemon.max_connections = max_connections;
    kr.save().map_err(emsg)
}

/// A copyable diagnostics blob — versions, platform, store, daemon state. No
/// secrets.
#[tauri::command]
pub fn diagnostics() -> String {
    let base = daemon::base_dir();
    format!(
        "Svault GUI {}\nplatform: {} {}\nstore: {}\ndaemon: {}\nmaster: {}\nyubikey: {}",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH,
        vault::svault_dir().display(),
        if daemon::is_running(&base) {
            "running"
        } else {
            "stopped"
        },
        if master::exists() { "set" } else { "unset" },
        if master::yubikey_enrolled() {
            "enrolled"
        } else {
            "none"
        },
    )
}

/// The store folder path, for an "open log folder" affordance.
#[tauri::command]
pub fn store_folder() -> String {
    vault::svault_dir().to_string_lossy().into_owned()
}

/// The `svault` binary name for this platform.
fn svault_bin_name() -> &'static str {
    if cfg!(windows) {
        "svault.exe"
    } else {
        "svault"
    }
}

/// Locate the bundled `svault` sidecar (shipped next to the app executable).
///
/// Must never return the GUI's own binary. macOS/Windows filesystems are
/// case-insensitive, so a naive `dir.join("svault").exists()` would `stat`-match
/// our `Svault` executable — running which as the daemon just relaunches the GUI,
/// which auto-starts the daemon again: a fork bomb. So we match only against the
/// real on-disk file names (case-sensitive) and explicitly reject the current
/// executable by canonical path.
fn locate_sidecar() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let exe_canon = exe.canonicalize().ok();
    let dir = exe.parent()?;
    // Tauri places sidecars next to the main binary, possibly with a target-triple
    // suffix; accept either form. Compare the actual directory-entry name so we
    // don't rely on a case-insensitive filesystem lookup.
    std::fs::read_dir(dir).ok()?.flatten().find_map(|e| {
        let p = e.path();
        let name = p.file_name()?.to_string_lossy().into_owned();
        // Match the exact sidecar name only. A loose prefix match (e.g.
        // "svault-*") would also catch sibling build artifacts like the GUI's own
        // `svault-gui`, and running that as the daemon relaunches the GUI.
        if name != "svault" && name != "svault.exe" {
            return None;
        }
        // Never our own executable (defends against a case-insensitive match).
        if let (Some(ec), Ok(pc)) = (&exe_canon, p.canonicalize()) {
            if &pc == ec {
                return None;
            }
        }
        Some(p)
    })
}

/// Install the bundled CLI (`svault`, which also provides the TUI + MCP) onto the
/// user's PATH. Copies the sidecar to `~/.local/bin` (Unix) so the same one
/// install delivers GUI + CLI + TUI + MCP. Returns the destination path.
#[tauri::command]
pub fn install_cli() -> CmdResult<String> {
    let src = locate_sidecar().ok_or("could not find the bundled svault binary next to the app")?;
    let home = vault::user_home().ok_or("could not resolve your home directory")?;
    let dest_dir = home.join(".local").join("bin");
    std::fs::create_dir_all(&dest_dir).map_err(emsg)?;
    let dest = dest_dir.join(svault_bin_name());
    std::fs::copy(&src, &dest).map_err(emsg)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755));
    }
    Ok(dest.to_string_lossy().into_owned())
}
