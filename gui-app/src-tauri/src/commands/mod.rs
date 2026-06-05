//! Tauri command layer — thin wrappers over `svault_cli::core` and the daemon
//! client. No crypto, policy, or judge logic lives here; these commands only
//! marshal data between the React frontend and the existing Rust core.

pub mod audit;
pub mod backup;
pub mod common;
pub mod judge;
pub mod mcp;
pub mod onboarding;
pub mod pending;
pub mod policy;
pub mod secrets;
pub mod session;
pub mod settings;
pub mod vaults;

use serde::Serialize;

/// Smoke-test payload proving the GUI ↔ core bridge works end to end.
#[derive(Serialize)]
pub struct AppInfo {
    /// Desktop app version.
    pub version: String,
    /// Whether a master passphrase has been set (drives onboarding vs sign-in).
    pub master_exists: bool,
    /// Whether a master recovery code has been written.
    pub recovery_exists: bool,
    /// Whether a YubiKey keyslot is enrolled.
    pub yubikey_enrolled: bool,
    /// The resolved store path (`SVAULT_HOME/.svault`).
    pub store_path: String,
}

#[tauri::command]
pub fn app_info() -> AppInfo {
    AppInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        master_exists: svault_cli::core::master::exists(),
        recovery_exists: svault_cli::core::master::master_recovery_exists(),
        yubikey_enrolled: svault_cli::core::master::yubikey_enrolled(),
        store_path: svault_cli::core::vault::svault_dir()
            .to_string_lossy()
            .into_owned(),
    }
}
