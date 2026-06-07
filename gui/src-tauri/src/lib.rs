//! Svault desktop GUI — Tauri backend.
//!
//! This crate is the `gui` frontend from the Svault roadmap. It links the
//! `svault-cli` library and drives the exact same `core` + `daemon` code paths
//! the CLI uses, so there is one trust model and one policy engine. All
//! secret-handling stays in Rust; the React frontend only sends structured
//! commands and renders the results.

mod commands;
mod error;
mod state;
mod tray;

#[cfg(test)]
mod tests;

/// Configure the process the way every Svault frontend does at its entry point:
///
/// 1. Default `SVAULT_HOME` to the user's home so the desktop app manages one
///    global store at `~/.svault` (mirrors `svault_cli::cli::run`). An explicit
///    `SVAULT_HOME` is always honoured.
/// 2. Stamp this process's audit source as `gui`.
fn init_process() {
    let unset = match std::env::var_os("SVAULT_HOME") {
        Some(v) => v.is_empty(),
        None => true,
    };
    if unset {
        if let Some(home) = svault_cli::core::vault::user_home() {
            std::env::set_var("SVAULT_HOME", home);
        }
    }
    svault_cli::core::usage::set_source(svault_cli::core::usage::Source::Gui);
}

/// Start the Svault daemon if the platform supports it and it isn't already
/// running. The daemon is the secret choke point: starting it on launch means
/// the app behaves like a running service (keys live only in its memory, and
/// only after a human unlock). On Windows there is no daemon — core falls back
/// to the 0600 session file — so this is a no-op there. Failures are non-fatal:
/// the app still runs, and Settings surfaces daemon state.
fn autostart_daemon() {
    if !cfg!(unix) {
        return;
    }
    if svault_cli::daemon::is_running(&svault_cli::daemon::base_dir()) {
        return;
    }
    let bin = commands::settings::locate_svault_bin();
    // Hard safety net: never run our own executable as the daemon. Doing so would
    // relaunch the GUI, which would auto-start again — a fork bomb. If we can't
    // find a distinct `svault` binary, skip autostart (Settings can start it).
    if let (Ok(bin_c), Ok(exe_c)) = (
        std::fs::canonicalize(&bin),
        std::env::current_exe().and_then(std::fs::canonicalize),
    ) {
        if bin_c == exe_c {
            eprintln!("svault daemon autostart skipped: no separate svault binary found");
            return;
        }
    }
    match svault_cli::daemon::start_quiet_with_exe(&bin) {
        Ok(msg) => eprintln!("svault daemon: {msg}"),
        Err(e) => eprintln!("svault daemon autostart skipped: {e}"),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    init_process();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .manage(state::GuiState::default())
        .setup(|app| {
            // The "Show in menu bar / system tray" pref — read at startup, which
            // is why the Settings copy says it takes effect on the next start.
            if commands::settings::pref_bool("show_tray", true) {
                tray::setup(app)?;
            }
            autostart_daemon();
            Ok(())
        })
        .on_window_event(|window, event| {
            // "Close to tray": hide the main window instead of quitting — but
            // only when there is a tray to come back from. Otherwise actually
            // exit (the hidden popover window would keep the process alive).
            if window.label() != "main" {
                return;
            }
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                use tauri::Manager;
                let to_tray = commands::settings::pref_bool("show_tray", true)
                    && commands::settings::pref_bool("close_to_tray", true);
                if to_tray {
                    api.prevent_close();
                    let _ = window.hide();
                } else {
                    window.app_handle().exit(0);
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::session::session_status,
            commands::session::unlock,
            commands::session::unlock_yubikey,
            commands::session::unlock_touchid,
            commands::session::yubikey_present,
            commands::session::lock_all,
            commands::onboarding::init_master,
            commands::onboarding::enroll_yubikey,
            commands::onboarding::remove_yubikey,
            commands::onboarding::enroll_touchid,
            commands::onboarding::remove_touchid,
            commands::vaults::list_vaults,
            commands::vaults::create_vault,
            commands::vaults::vault_settings,
            commands::vaults::save_settings,
            commands::vaults::unlock_vault,
            commands::vaults::lock_vault,
            commands::vaults::delete_vault,
            commands::secrets::list_secrets,
            commands::secrets::add_secret,
            commands::secrets::edit_secret,
            commands::secrets::remove_secret,
            commands::secrets::reveal_secret,
            commands::judge::keyring_state,
            commands::judge::judge_list,
            commands::judge::judge_save,
            commands::judge::judge_remove,
            commands::judge::judge_set_default,
            commands::judge::judge_toggle,
            commands::judge::judge_test,
            commands::judge::judge_names,
            commands::judge::provider_list,
            commands::judge::provider_save,
            commands::judge::provider_remove,
            commands::judge::provider_kinds,
            commands::judge::provider_toggle,
            commands::judge::provider_set_default,
            commands::judge::provider_models,
            commands::policy::policy_surface,
            commands::policy::caller_access,
            commands::mcp::connected_agents,
            commands::mcp::mcp_toggle,
            commands::mcp::mcp_enabled,
            commands::mcp::mcp_config_snippet,
            commands::mcp::write_mcp_config,
            commands::mcp::store_path,
            commands::pending::pending,
            commands::pending::approve_unseal,
            commands::audit::audit_events,
            commands::audit::activity_events,
            commands::audit::audit_callers,
            commands::audit::export_log,
            commands::backup::export_vault,
            commands::backup::import_vault,
            commands::backup::recover_master,
            commands::backup::recovery_status,
            commands::backup::rotate_code,
            commands::settings::get_prefs,
            commands::settings::set_prefs,
            commands::settings::change_master,
            commands::settings::yubikey_status,
            commands::settings::touchid_status,
            commands::settings::daemon_info,
            commands::settings::daemon_start,
            commands::settings::daemon_stop,
            commands::settings::daemon_doctor,
            commands::settings::set_daemon_limits,
            commands::settings::diagnostics,
            commands::settings::store_folder,
            commands::settings::install_cli,
            tray::open_main,
            tray::hide_popover,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
