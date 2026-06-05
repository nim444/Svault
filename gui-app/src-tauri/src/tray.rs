//! System-tray / menu-bar icon + popover (screen 12). The popover is a second,
//! borderless webview window that loads the same frontend; the React side detects
//! the window label "popover" and renders the compact tray view. Left-clicking
//! the tray toggles the popover; the tray menu offers Open / Lock all / Quit.

use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{App, Manager, WebviewUrl, WebviewWindowBuilder};

use crate::state::GuiState;

pub fn setup(app: &App) -> tauri::Result<()> {
    // The hidden popover window. Loads the same bundle; the frontend renders the
    // compact view based on the window label.
    WebviewWindowBuilder::new(app, "popover", WebviewUrl::App("index.html".into()))
        .title("Svault")
        .decorations(false)
        .always_on_top(true)
        .visible(false)
        .resizable(false)
        .skip_taskbar(true)
        .inner_size(340.0, 480.0)
        .build()?;

    let open_i = MenuItem::with_id(app, "open", "Open Svault", true, None::<&str>)?;
    let lock_i = MenuItem::with_id(app, "lock_all", "Lock all", true, None::<&str>)?;
    let quit_i = PredefinedMenuItem::quit(app, Some("Quit"))?;
    let menu = Menu::with_items(app, &[&open_i, &lock_i, &quit_i])?;

    TrayIconBuilder::with_id("main")
        .icon(app.default_window_icon().unwrap().clone())
        .tooltip("Svault")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => show_main(app),
            "lock_all" => {
                let _ = crate::commands::session::lock_all(app.state::<GuiState>());
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                let app = tray.app_handle();
                if let Some(p) = app.get_webview_window("popover") {
                    if p.is_visible().unwrap_or(false) {
                        let _ = p.hide();
                    } else {
                        let _ = p.show();
                        let _ = p.set_focus();
                    }
                }
            }
        })
        .build(app)?;

    Ok(())
}

fn show_main(app: &tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

/// Show + focus the main window (from the popover's "Open Svault" button) and
/// hide the popover.
#[tauri::command]
pub fn open_main(app: tauri::AppHandle) {
    show_main(&app);
    if let Some(p) = app.get_webview_window("popover") {
        let _ = p.hide();
    }
}

/// Hide the popover window (from the popover itself).
#[tauri::command]
pub fn hide_popover(app: tauri::AppHandle) {
    if let Some(p) = app.get_webview_window("popover") {
        let _ = p.hide();
    }
}
