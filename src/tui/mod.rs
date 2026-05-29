//! Interactive terminal UI (Ratatui) — launched when `svault` is run with no
//! subcommand. Covers the full Step 1 workflow without leaving the keyboard:
//! list vaults, create, lock/unlock, edit settings, and add/view/delete secrets.
//!
//! Lock awareness is central: secret screens and the settings editor require an
//! unlocked vault (cached session passphrase). When a locked vault is selected,
//! the action is routed through the unlock prompt and resumed on success.

mod theme;
mod ui;

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use ratatui::widgets::{ListState, TableState};
use std::path::{Path, PathBuf};

use crate::meta::{AccessConfig, AllowAgent, LoginMethod, VaultMeta, VaultSettings};
use crate::session;
use crate::vault::{list_vault_dirs, Vault, SVAULT_DIR};

/// Enter the alternate screen, run the event loop, restore the terminal.
pub fn run() -> Result<()> {
    // Everything recorded from here on is a TUI action.
    crate::usage::set_source(crate::usage::Source::Tui);
    let mut terminal = ratatui::init();
    // Bracketed paste lets us receive a whole pasted string (passphrases,
    // recovery codes, bundle paths) as one event instead of key-by-key.
    let _ = crossterm::execute!(std::io::stdout(), crossterm::event::EnableBracketedPaste);
    let mut app = App::new();
    let result = app.event_loop(&mut terminal);
    let _ = crossterm::execute!(std::io::stdout(), crossterm::event::DisableBracketedPaste);
    ratatui::restore();
    result
}

// ── Status messages ────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
pub enum MsgKind {
    Info,
    Ok,
    Warn,
    Error,
}

pub struct Status {
    pub kind: MsgKind,
    pub text: String,
}

// ── Vault rows ───────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct VaultRow {
    pub name: String,
    pub storage: String,
    pub dir: PathBuf,
    pub description: String,
    pub created: String,
    pub unlocked: bool,
}

fn load_vaults() -> Vec<VaultRow> {
    list_vault_dirs()
        .into_iter()
        .filter_map(|dir| {
            let meta = VaultMeta::load_unverified(&dir).ok()?;
            let unlocked = session::is_unlocked(&dir);
            Some(VaultRow {
                name: meta.name,
                storage: meta.storage,
                dir,
                description: meta.description,
                created: short_date(&meta.created_at),
                unlocked,
            })
        })
        .collect()
}

/// Format an RFC 3339 timestamp as a local `YYYY-MM-DD` date for display.
/// Falls back to the first 10 chars (the date part) if parsing fails.
fn short_date(rfc3339: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(rfc3339)
        .map(|t| {
            t.with_timezone(&chrono::Local)
                .format("%Y-%m-%d")
                .to_string()
        })
        .unwrap_or_else(|_| rfc3339.chars().take(10).collect())
}

// ── Screens ────────────────────────────────────────────────────────────────────

/// What to do after a successful unlock prompt.
#[derive(Clone, Copy)]
pub enum Pending {
    List,
    Secrets,
    Settings,
}

/// The focusable fields of the create form, in display order. Handlers match on
/// the field (not a bare index) so the draw order and the key logic can never
/// drift apart. Storage and login method are fixed (local / passphrase) today,
/// so they are shown as a static note rather than a pickable field.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CreateField {
    Name,
    Description,
    AllowMode,
    AllowList,
    RateLimit,
    Autolock,
    AutolockTimer,
    Passphrase,
    Confirm,
}

impl CreateField {
    pub const ORDER: [CreateField; 9] = [
        CreateField::Name,
        CreateField::Description,
        CreateField::AllowMode,
        CreateField::AllowList,
        CreateField::RateLimit,
        CreateField::Autolock,
        CreateField::AutolockTimer,
        CreateField::Passphrase,
        CreateField::Confirm,
    ];
}

pub struct CreateForm {
    pub name: String,
    pub description: String,
    pub allow_mode: usize, // 0 all · 1 none · 2 list
    pub allow_list: String,
    pub rate_limit: String,
    pub autolock: bool,
    pub autolock_timer: String,
    pub passphrase: String,
    pub confirm: String,
    pub focus: usize,
    pub error: Option<String>,
}

impl CreateForm {
    const FIELDS: usize = CreateField::ORDER.len();

    fn new() -> Self {
        let default_name = std::env::current_dir()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .unwrap_or_else(|| "my-vault".to_string());
        Self {
            name: default_name,
            description: String::new(),
            allow_mode: 0,
            allow_list: String::new(),
            rate_limit: "10/hour".to_string(),
            autolock: true,
            autolock_timer: "1d".to_string(),
            passphrase: String::new(),
            confirm: String::new(),
            focus: 0,
            error: None,
        }
    }

    pub fn current(&self) -> CreateField {
        CreateField::ORDER[self.focus]
    }

    /// Whether the focused field accepts typed/pasted text (drives the caret).
    pub fn focus_is_text(&self) -> bool {
        !matches!(
            self.current(),
            CreateField::AllowMode | CreateField::Autolock
        )
    }

    /// The editable string behind the focused field, if it is a text field.
    fn text_field(&mut self) -> Option<&mut String> {
        Some(match self.current() {
            CreateField::Name => &mut self.name,
            CreateField::Description => &mut self.description,
            CreateField::AllowList => &mut self.allow_list,
            CreateField::RateLimit => &mut self.rate_limit,
            CreateField::AutolockTimer => &mut self.autolock_timer,
            CreateField::Passphrase => &mut self.passphrase,
            CreateField::Confirm => &mut self.confirm,
            _ => return None,
        })
    }
}

/// Focusable fields of the settings form, in display order. See [`CreateField`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SettingsField {
    Description,
    AllowMode,
    AllowList,
    RateLimit,
    Autolock,
    AutolockTimer,
}

impl SettingsField {
    pub const ORDER: [SettingsField; 6] = [
        SettingsField::Description,
        SettingsField::AllowMode,
        SettingsField::AllowList,
        SettingsField::RateLimit,
        SettingsField::Autolock,
        SettingsField::AutolockTimer,
    ];
}

pub struct SettingsForm {
    pub vault_dir: PathBuf,
    pub name: String,
    pub description: String,
    pub allow_mode: usize,
    pub allow_list: String,
    pub rate_limit: String,
    pub autolock: bool,
    pub autolock_timer: String,
    pub focus: usize,
    pub error: Option<String>,
}

impl SettingsForm {
    const FIELDS: usize = SettingsField::ORDER.len();

    fn from_meta(vault_dir: PathBuf, meta: VaultMeta) -> Self {
        let (allow_mode, allow_list) = match &meta.access.allow_agent {
            AllowAgent::Bool(true) => (0, String::new()),
            AllowAgent::Bool(false) => (1, String::new()),
            AllowAgent::List(v) => (2, v.join(", ")),
        };
        Self {
            vault_dir,
            name: meta.name,
            description: meta.description,
            allow_mode,
            allow_list,
            rate_limit: meta.access.rate_limit,
            autolock: meta.settings.autolock,
            autolock_timer: meta.settings.autolock_timer,
            focus: 0,
            error: None,
        }
    }

    pub fn current(&self) -> SettingsField {
        SettingsField::ORDER[self.focus]
    }

    pub fn focus_is_text(&self) -> bool {
        !matches!(
            self.current(),
            SettingsField::AllowMode | SettingsField::Autolock
        )
    }

    fn text_field(&mut self) -> Option<&mut String> {
        Some(match self.current() {
            SettingsField::Description => &mut self.description,
            SettingsField::AllowList => &mut self.allow_list,
            SettingsField::RateLimit => &mut self.rate_limit,
            SettingsField::AutolockTimer => &mut self.autolock_timer,
            _ => return None,
        })
    }
}

pub struct UnlockForm {
    pub vault_dir: PathBuf,
    pub name: String,
    pub passphrase: String,
    pub error: Option<String>,
    pub pending: Pending,
}

pub struct Reveal {
    pub name: String,
    pub value: String,
    pub masked: bool,
}

pub struct SecretScreen {
    pub vault_dir: PathBuf,
    pub name: String,
    pub secrets: Vec<String>,
    pub list_state: ListState,
    pub reveal: Option<Reveal>,
    pub pending_delete: Option<String>,
}

impl SecretScreen {
    fn selected_name(&self) -> Option<String> {
        self.list_state
            .selected()
            .and_then(|i| self.secrets.get(i).cloned())
    }
}

pub struct SecretAddForm {
    pub vault_dir: PathBuf,
    pub vault_name: String,
    pub name: String,
    pub value: String,
    pub focus: usize, // 0 name · 1 value
    pub error: Option<String>,
}

pub struct ImportForm {
    pub path: String,
    pub error: Option<String>,
}

pub struct RecoverForm {
    pub vault_dir: PathBuf,
    pub name: String,
    pub code: String,
    pub new_pass: String,
    pub confirm: String,
    pub focus: usize, // 0 code · 1 new passphrase · 2 confirm
    pub error: Option<String>,
}

impl RecoverForm {
    const FIELDS: usize = 3;

    fn field_mut(&mut self) -> &mut String {
        match self.focus {
            0 => &mut self.code,
            1 => &mut self.new_pass,
            _ => &mut self.confirm,
        }
    }
}

/// A read-only view of a vault's recent usage events (human + agent activity).
pub struct ActivityScreen {
    pub name: String,
    pub events: Vec<crate::usage::Event>,
    pub state: TableState,
}

pub enum Screen {
    List,
    Create(CreateForm),
    Settings(SettingsForm),
    Unlock(UnlockForm),
    Secrets(SecretScreen),
    SecretAdd(SecretAddForm),
    /// Shows the one-time recovery code after a vault is created. Dismissed only
    /// by an explicit 'y' confirmation that the code has been saved.
    RecoveryCode(String),
    /// Import a vault from a bundle file (path entry).
    Import(ImportForm),
    /// Recover a vault: enter the code + a new passphrase.
    Recover(RecoverForm),
    /// Recent usage timeline for the selected vault.
    Activity(ActivityScreen),
}

// ── App ────────────────────────────────────────────────────────────────────────

pub struct App {
    pub screen: Screen,
    pub vaults: Vec<VaultRow>,
    pub list_state: TableState,
    pub status: Option<Status>,
    pub should_quit: bool,
    /// When set, the help overlay is shown over the current screen.
    pub show_help: bool,
    /// When set, a "quit?" confirmation popup is shown.
    pub confirm_quit: bool,
    /// Whether a background daemon is currently running (Unix). Shown in the
    /// header; refreshed on startup, after a vault refresh, and after toggling.
    pub daemon_running: bool,
}

impl App {
    fn new() -> Self {
        let vaults = load_vaults();
        let mut list_state = TableState::default();
        if !vaults.is_empty() {
            list_state.select(Some(0));
        }
        let daemon_running = crate::daemon::is_running(&crate::daemon::base_dir());
        Self {
            screen: Screen::List,
            vaults,
            list_state,
            status: None,
            should_quit: false,
            show_help: false,
            confirm_quit: false,
            daemon_running,
        }
    }

    fn event_loop(&mut self, terminal: &mut ratatui::DefaultTerminal) -> Result<()> {
        while !self.should_quit {
            terminal.draw(|frame| ui::draw(frame, self))?;
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => self.on_key(key)?,
                Event::Paste(text) => self.on_paste(text),
                _ => {}
            }
        }
        Ok(())
    }

    /// Append a pasted string to the focused text field of the current screen.
    /// Newlines are stripped so a multi-line paste can't break field layout.
    fn on_paste(&mut self, text: String) {
        if self.show_help {
            return;
        }
        let text = text.replace(['\n', '\r'], "");
        if text.is_empty() {
            return;
        }
        match &mut self.screen {
            Screen::Create(form) => {
                if let Some(s) = form.text_field() {
                    s.push_str(&text);
                    form.error = None;
                }
            }
            Screen::Settings(form) => {
                if let Some(s) = form.text_field() {
                    s.push_str(&text);
                    form.error = None;
                }
            }
            Screen::Unlock(form) => {
                form.passphrase.push_str(&text);
                form.error = None;
            }
            Screen::SecretAdd(form) => {
                if form.focus == 0 {
                    form.name.push_str(&text);
                } else {
                    form.value.push_str(&text);
                }
                form.error = None;
            }
            Screen::Import(form) => {
                form.path.push_str(&text);
                form.error = None;
            }
            Screen::Recover(form) => {
                form.field_mut().push_str(&text);
                form.error = None;
            }
            _ => {}
        }
    }

    // ── Status helpers ──────────────────────────────────────────────────────

    fn set_status(&mut self, kind: MsgKind, text: impl Into<String>) {
        self.status = Some(Status {
            kind,
            text: text.into(),
        });
    }

    // ── Vault list helpers ────────────────────────────────────────────────────

    fn refresh_vaults(&mut self) {
        self.vaults = load_vaults();
        if self.vaults.is_empty() {
            self.list_state.select(None);
        } else {
            let i = self
                .list_state
                .selected()
                .unwrap_or(0)
                .min(self.vaults.len() - 1);
            self.list_state.select(Some(i));
        }
        self.refresh_daemon();
    }

    fn refresh_daemon(&mut self) {
        self.daemon_running = crate::daemon::is_running(&crate::daemon::base_dir());
    }

    /// Start the daemon if it's stopped, stop it if it's running, then refresh
    /// the indicator. Uses the quiet variants so nothing is printed over the TUI;
    /// the outcome goes to the status line.
    fn toggle_daemon(&mut self) {
        let result = if self.daemon_running {
            crate::daemon::stop_quiet()
        } else {
            crate::daemon::start_quiet()
        };
        match result {
            Ok(msg) => self.set_status(MsgKind::Ok, msg),
            Err(e) => self.set_status(MsgKind::Error, format!("{e}")),
        }
        self.refresh_daemon();
    }

    fn selected_vault(&self) -> Option<VaultRow> {
        self.list_state
            .selected()
            .and_then(|i| self.vaults.get(i).cloned())
    }

    fn select_next(&mut self) {
        if self.vaults.is_empty() {
            return;
        }
        let i = self
            .list_state
            .selected()
            .map_or(0, |i| (i + 1) % self.vaults.len());
        self.list_state.select(Some(i));
    }

    fn select_prev(&mut self) {
        if self.vaults.is_empty() {
            return;
        }
        let len = self.vaults.len();
        let i = self
            .list_state
            .selected()
            .map_or(0, |i| (i + len - 1) % len);
        self.list_state.select(Some(i));
    }

    // ── Key dispatch ────────────────────────────────────────────────────────

    fn on_key(&mut self, key: KeyEvent) -> Result<()> {
        // The quit popup takes the next key: enter confirms, anything else cancels.
        if self.confirm_quit {
            match key.code {
                KeyCode::Enter => self.should_quit = true,
                _ => self.confirm_quit = false,
            }
            return Ok(());
        }
        // The help overlay swallows the next key (any key closes it).
        if self.show_help {
            self.show_help = false;
            return Ok(());
        }
        // Take ownership of the current screen so handlers can move its form
        // state freely; each handler is responsible for setting the next screen.
        let screen = std::mem::replace(&mut self.screen, Screen::List);
        match screen {
            Screen::List => self.key_list(key)?,
            Screen::Create(form) => self.key_create(form, key)?,
            Screen::Settings(form) => self.key_settings(form, key)?,
            Screen::Unlock(form) => self.key_unlock(form, key)?,
            Screen::Secrets(scr) => self.key_secrets(scr, key)?,
            Screen::SecretAdd(form) => self.key_secret_add(form, key)?,
            Screen::RecoveryCode(code) => self.key_recovery_code(code, key),
            Screen::Import(form) => self.key_import(form, key)?,
            Screen::Recover(form) => self.key_recover(form, key),
            Screen::Activity(scr) => self.key_activity(scr, key),
        }
        Ok(())
    }

    // ── Activity screen ─────────────────────────────────────────────────────────

    fn key_activity(&mut self, mut scr: ActivityScreen, key: KeyEvent) {
        match key.code {
            KeyCode::Esc | KeyCode::Char('b') => {
                self.screen = Screen::List;
                return;
            }
            KeyCode::Char('q') => self.confirm_quit = true,
            KeyCode::Down | KeyCode::Char('j') => activity_move(&mut scr, true),
            KeyCode::Up | KeyCode::Char('k') => activity_move(&mut scr, false),
            _ => {}
        }
        self.screen = Screen::Activity(scr);
    }

    /// Open the read-only activity timeline for the selected vault. The usage
    /// log isn't a secret (it holds no values), so no unlock is required.
    fn start_activity(&mut self) {
        let Some(v) = self.selected_vault() else {
            return;
        };
        let events = crate::usage::recent(&v.dir, 200);
        let mut state = TableState::default();
        if !events.is_empty() {
            state.select(Some(0));
        }
        self.screen = Screen::Activity(ActivityScreen {
            name: v.name,
            events,
            state,
        });
    }

    /// The recovery-code screen requires an explicit confirmation ('y') that the
    /// code was saved — any other key keeps it on screen, so it can't be
    /// dismissed by accident before the user has written it down.
    fn key_recovery_code(&mut self, code: String, key: KeyEvent) {
        if matches!(key.code, KeyCode::Char('y') | KeyCode::Char('Y')) {
            self.screen = Screen::List;
        } else {
            self.screen = Screen::RecoveryCode(code);
        }
    }

    // ── Import screen ─────────────────────────────────────────────────────────

    fn key_import(&mut self, mut form: ImportForm, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Esc => self.screen = Screen::List,
            KeyCode::Backspace => {
                form.path.pop();
                form.error = None;
                self.screen = Screen::Import(form);
            }
            KeyCode::Char(c) => {
                form.path.push(c);
                form.error = None;
                self.screen = Screen::Import(form);
            }
            KeyCode::Enter => {
                let path = form.path.trim();
                if path.is_empty() {
                    form.error = Some("Enter a path to a .svault-export.json file".into());
                    self.screen = Screen::Import(form);
                    return Ok(());
                }
                match std::fs::read_to_string(path)
                    .map_err(|e| anyhow::anyhow!("cannot read {path}: {e}"))
                    .and_then(|raw| {
                        crate::portable::import_bundle(&raw, std::path::Path::new(SVAULT_DIR))
                    }) {
                    Ok(name) => {
                        let dir = std::path::Path::new(SVAULT_DIR).join(&name);
                        crate::usage::human(&dir, "import", None);
                        self.refresh_vaults();
                        self.set_status(MsgKind::Ok, format!("Imported '{name}'"));
                        self.screen = Screen::List;
                    }
                    Err(e) => {
                        form.error = Some(format!("{e}"));
                        self.screen = Screen::Import(form);
                    }
                }
            }
            _ => self.screen = Screen::Import(form),
        }
        Ok(())
    }

    // ── Recover screen ──────────────────────────────────────────────────────────

    fn key_recover(&mut self, mut form: RecoverForm, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => self.screen = Screen::List,
            KeyCode::Tab | KeyCode::Down => {
                form.focus = (form.focus + 1) % RecoverForm::FIELDS;
                self.screen = Screen::Recover(form);
            }
            KeyCode::Up => {
                form.focus = (form.focus + RecoverForm::FIELDS - 1) % RecoverForm::FIELDS;
                self.screen = Screen::Recover(form);
            }
            KeyCode::Backspace => {
                form.field_mut().pop();
                form.error = None;
                self.screen = Screen::Recover(form);
            }
            KeyCode::Char(c) => {
                form.field_mut().push(c);
                form.error = None;
                self.screen = Screen::Recover(form);
            }
            KeyCode::Enter => {
                // Advance through fields; submit from the last one.
                if form.focus < RecoverForm::FIELDS - 1 {
                    form.focus += 1;
                    self.screen = Screen::Recover(form);
                    return;
                }
                self.submit_recover(form);
            }
            _ => self.screen = Screen::Recover(form),
        }
    }

    fn submit_recover(&mut self, mut form: RecoverForm) {
        if form.new_pass != form.confirm {
            form.error = Some("Passphrases do not match".into());
            form.new_pass.clear();
            form.confirm.clear();
            form.focus = 1;
            self.screen = Screen::Recover(form);
            return;
        }
        match crate::recovery::recover_and_rekey(&form.vault_dir, &form.code, &form.new_pass) {
            Ok(_) => {
                crate::usage::human(&form.vault_dir, "recover", None);
                session::lock(&form.vault_dir).ok();
                self.refresh_vaults();
                self.set_status(
                    MsgKind::Ok,
                    format!(
                        "Passphrase reset for '{}'. Recovery code unchanged.",
                        form.name
                    ),
                );
                self.screen = Screen::List;
            }
            Err(e) => {
                form.error = Some(format!("{e}"));
                form.code.clear();
                form.focus = 0;
                self.screen = Screen::Recover(form);
            }
        }
    }

    // ── List screen ─────────────────────────────────────────────────────────

    fn key_list(&mut self, key: KeyEvent) -> Result<()> {
        self.screen = Screen::List;
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.confirm_quit = true,
            KeyCode::Down | KeyCode::Char('j') => self.select_next(),
            KeyCode::Up | KeyCode::Char('k') => self.select_prev(),
            KeyCode::Char('c') => self.screen = Screen::Create(CreateForm::new()),
            KeyCode::Char('u') => self.unlock_selected()?,
            KeyCode::Char('l') => self.lock_selected()?,
            KeyCode::Char('s') => self.open_settings()?,
            KeyCode::Char('e') => self.export_selected(),
            KeyCode::Char('i') => {
                self.screen = Screen::Import(ImportForm {
                    path: String::new(),
                    error: None,
                })
            }
            KeyCode::Char('r') => self.start_recover(),
            KeyCode::Char('v') => self.start_activity(),
            KeyCode::Char('d') => self.toggle_daemon(),
            KeyCode::Char('?') => self.show_help = true,
            KeyCode::Enter => self.open_secrets()?,
            _ => {}
        }
        Ok(())
    }

    /// Export the selected vault to a timestamped bundle in the CWD, so repeated
    /// exports never clobber an earlier one: `<name>-<YYYYMMDD-HHMMSS>.svault-export.json`.
    fn export_selected(&mut self) {
        let Some(v) = self.selected_vault() else {
            return;
        };
        let meta = match VaultMeta::load_unverified(&v.dir) {
            Ok(m) => m,
            Err(e) => {
                self.set_status(MsgKind::Error, format!("Cannot read vault: {e}"));
                return;
            }
        };
        match crate::portable::build_bundle(&v.dir, &meta.name, &meta.storage) {
            Ok(json) => {
                let ts = chrono::Local::now().format("%Y%m%d-%H%M%S");
                let out = format!("{}-{}.svault-export.json", meta.name, ts);
                match std::fs::write(&out, json) {
                    Ok(_) => {
                        // Keep the bundle out of git so it can't be pushed by mistake.
                        crate::portable::ensure_export_gitignored(Path::new("."));
                        // Show the absolute path so the file is easy to find — a
                        // bare filename leaves the user guessing which directory.
                        let shown = std::fs::canonicalize(&out)
                            .map(|p| p.display().to_string())
                            .unwrap_or(out);
                        crate::usage::human(&v.dir, "export", None);
                        self.set_status(MsgKind::Ok, format!("Exported '{}' to {shown}", v.name))
                    }
                    Err(e) => self.set_status(MsgKind::Error, format!("Export failed: {e}")),
                }
            }
            Err(e) => self.set_status(MsgKind::Error, format!("Export failed: {e}")),
        }
    }

    /// Open the recover form for the selected vault (must have a recovery file).
    fn start_recover(&mut self) {
        let Some(v) = self.selected_vault() else {
            return;
        };
        if !crate::recovery::exists(&v.dir) {
            self.set_status(
                MsgKind::Error,
                format!("Vault '{}' has no recovery file", v.name),
            );
            return;
        }
        self.screen = Screen::Recover(RecoverForm {
            vault_dir: v.dir,
            name: v.name,
            code: String::new(),
            new_pass: String::new(),
            confirm: String::new(),
            focus: 0,
            error: None,
        });
    }

    fn unlock_selected(&mut self) -> Result<()> {
        let Some(v) = self.selected_vault() else {
            return Ok(());
        };
        if v.unlocked {
            self.set_status(
                MsgKind::Info,
                format!("Vault '{}' is already unlocked", v.name),
            );
        } else {
            self.screen = Screen::Unlock(UnlockForm {
                vault_dir: v.dir,
                name: v.name,
                passphrase: String::new(),
                error: None,
                pending: Pending::List,
            });
        }
        Ok(())
    }

    fn lock_selected(&mut self) -> Result<()> {
        let Some(v) = self.selected_vault() else {
            return Ok(());
        };
        if !v.unlocked {
            self.set_status(
                MsgKind::Info,
                format!("Vault '{}' is already locked", v.name),
            );
            return Ok(());
        }
        session::lock(&v.dir)?;
        crate::usage::human(&v.dir, "lock", None);
        self.set_status(MsgKind::Ok, format!("Vault '{}' locked", v.name));
        self.refresh_vaults();
        Ok(())
    }

    fn open_secrets(&mut self) -> Result<()> {
        let Some(v) = self.selected_vault() else {
            return Ok(());
        };
        if v.unlocked {
            self.enter_secrets(&v.dir, &v.name)?;
        } else {
            self.screen = Screen::Unlock(UnlockForm {
                vault_dir: v.dir,
                name: v.name,
                passphrase: String::new(),
                error: None,
                pending: Pending::Secrets,
            });
        }
        Ok(())
    }

    fn open_settings(&mut self) -> Result<()> {
        let Some(v) = self.selected_vault() else {
            return Ok(());
        };
        if !v.unlocked {
            self.screen = Screen::Unlock(UnlockForm {
                vault_dir: v.dir,
                name: v.name,
                passphrase: String::new(),
                error: None,
                pending: Pending::Settings,
            });
            return Ok(());
        }
        let meta = VaultMeta::load_unverified(&v.dir)?;
        self.screen = Screen::Settings(SettingsForm::from_meta(v.dir, meta));
        Ok(())
    }

    /// Open the vault with the cached passphrase and show its secret list.
    fn enter_secrets(&mut self, dir: &Path, name: &str) -> Result<()> {
        let Some(pass) = session::get_passphrase(dir) else {
            self.screen = Screen::Unlock(UnlockForm {
                vault_dir: dir.to_path_buf(),
                name: name.to_string(),
                passphrase: String::new(),
                error: None,
                pending: Pending::Secrets,
            });
            return Ok(());
        };
        match Vault::open(dir, &pass) {
            Ok(vault) => {
                let secrets = vault.list_secret_names().unwrap_or_default();
                let mut list_state = ListState::default();
                if !secrets.is_empty() {
                    list_state.select(Some(0));
                }
                self.screen = Screen::Secrets(SecretScreen {
                    vault_dir: dir.to_path_buf(),
                    name: name.to_string(),
                    secrets,
                    list_state,
                    reveal: None,
                    pending_delete: None,
                });
            }
            Err(e) => self.set_status(MsgKind::Error, format!("Cannot open vault: {e}")),
        }
        Ok(())
    }

    // ── Create screen ───────────────────────────────────────────────────────

    fn key_create(&mut self, mut form: CreateForm, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Esc => {
                self.screen = Screen::List;
                return Ok(());
            }
            KeyCode::Tab | KeyCode::Down => form.focus = (form.focus + 1) % CreateForm::FIELDS,
            KeyCode::BackTab | KeyCode::Up => {
                form.focus = (form.focus + CreateForm::FIELDS - 1) % CreateForm::FIELDS
            }
            KeyCode::Enter => {
                if form.focus == CreateForm::FIELDS - 1 {
                    return self.submit_create(form);
                }
                form.focus += 1;
            }
            KeyCode::Left => create_adjust(&mut form, false),
            KeyCode::Right => create_adjust(&mut form, true),
            KeyCode::Backspace => {
                if let Some(s) = form.text_field() {
                    s.pop();
                }
            }
            KeyCode::Char(c) => {
                if form.current() == CreateField::Autolock && c == ' ' {
                    form.autolock = !form.autolock; // space toggles auto-lock
                } else if let Some(s) = form.text_field() {
                    s.push(c);
                    form.error = None;
                }
            }
            _ => {}
        }
        self.screen = Screen::Create(form);
        Ok(())
    }

    fn submit_create(&mut self, mut form: CreateForm) -> Result<()> {
        let name = form.name.trim().to_string();
        if name.is_empty() {
            form.error = Some("Name is required".into());
            self.screen = Screen::Create(form);
            return Ok(());
        }
        let vault_dir = PathBuf::from(SVAULT_DIR).join(&name);
        if vault_dir.exists() {
            let existing = VaultMeta::load_unverified(&vault_dir)
                .map(|m| m.storage)
                .unwrap_or_else(|_| "local".to_string());
            form.error = Some(format!(
                "a vault named '{name}' already exists ({existing}:{name}) — names must be unique across storage"
            ));
            self.screen = Screen::Create(form);
            return Ok(());
        }
        if form.passphrase.is_empty() {
            form.error = Some("Passphrase is required".into());
            self.screen = Screen::Create(form);
            return Ok(());
        }
        if form.passphrase != form.confirm {
            form.error = Some("Passphrases do not match".into());
            self.screen = Screen::Create(form);
            return Ok(());
        }

        let allow_agent = match form.allow_mode {
            0 => AllowAgent::Bool(true),
            1 => AllowAgent::Bool(false),
            _ => AllowAgent::List(parse_agents(&form.allow_list)),
        };
        // Storage is local and login is passphrase today; VaultMeta defaults to
        // "local" storage, so we only carry the wired settings forward.
        let meta = VaultMeta::new(
            name.clone(),
            form.description.clone(),
            AccessConfig {
                allow_agent,
                rate_limit: form.rate_limit.clone(),
            },
            VaultSettings {
                autolock: form.autolock,
                autolock_timer: form.autolock_timer.clone(),
                login_method: LoginMethod::Passphrase,
            },
        );

        match Vault::init(&vault_dir, &form.passphrase, meta) {
            Ok(vault) => {
                // Generate and store the recovery code, then show it once.
                let code = crate::recovery::generate_code();
                if let Err(e) = crate::recovery::write(&vault_dir, vault.key(), &code) {
                    self.refresh_vaults();
                    self.set_status(
                        MsgKind::Warn,
                        format!(
                            "Vault '{name}' created, but recovery code could not be saved: {e}"
                        ),
                    );
                    self.screen = Screen::List;
                    return Ok(());
                }
                crate::usage::human(&vault_dir, "vault.create", None);
                self.refresh_vaults();
                self.set_status(MsgKind::Ok, format!("Vault '{name}' created"));
                self.screen = Screen::RecoveryCode(code);
            }
            Err(e) => {
                form.error = Some(format!("{e}"));
                self.screen = Screen::Create(form);
            }
        }
        Ok(())
    }

    // ── Settings screen ─────────────────────────────────────────────────────

    fn key_settings(&mut self, mut form: SettingsForm, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Esc => {
                self.screen = Screen::List;
                return Ok(());
            }
            KeyCode::Tab | KeyCode::Down => form.focus = (form.focus + 1) % SettingsForm::FIELDS,
            KeyCode::BackTab | KeyCode::Up => {
                form.focus = (form.focus + SettingsForm::FIELDS - 1) % SettingsForm::FIELDS
            }
            KeyCode::Enter => {
                if form.focus == SettingsForm::FIELDS - 1 {
                    return self.submit_settings(form);
                }
                form.focus += 1;
            }
            KeyCode::Left => settings_adjust(&mut form, false),
            KeyCode::Right => settings_adjust(&mut form, true),
            KeyCode::Backspace => {
                if let Some(s) = form.text_field() {
                    s.pop();
                }
            }
            KeyCode::Char(c) => {
                if form.current() == SettingsField::Autolock && c == ' ' {
                    form.autolock = !form.autolock;
                } else if let Some(s) = form.text_field() {
                    s.push(c);
                    form.error = None;
                }
            }
            _ => {}
        }
        self.screen = Screen::Settings(form);
        Ok(())
    }

    fn submit_settings(&mut self, mut form: SettingsForm) -> Result<()> {
        let Some(pass) = session::get_passphrase(&form.vault_dir) else {
            self.set_status(
                MsgKind::Error,
                "Vault is locked — unlock before editing settings",
            );
            self.screen = Screen::List;
            return Ok(());
        };
        let vault = match Vault::open(&form.vault_dir, &pass) {
            Ok(v) => v,
            Err(e) => {
                form.error = Some(format!("{e}"));
                self.screen = Screen::Settings(form);
                return Ok(());
            }
        };

        let allow_agent = match form.allow_mode {
            0 => AllowAgent::Bool(true),
            1 => AllowAgent::Bool(false),
            _ => AllowAgent::List(parse_agents(&form.allow_list)),
        };

        // Carry the existing login method forward untouched — only the wired
        // fields are editable here.
        let mut meta = vault.meta.clone();
        meta.description = form.description.clone();
        meta.access.allow_agent = allow_agent;
        meta.access.rate_limit = form.rate_limit.clone();
        meta.settings.autolock = form.autolock;
        meta.settings.autolock_timer = form.autolock_timer.clone();

        match vault.save_meta(&meta) {
            Ok(_) => {
                crate::usage::human(&form.vault_dir, "settings.update", None);
                self.refresh_vaults();
                self.set_status(MsgKind::Ok, format!("Settings for '{}' saved", form.name));
                self.screen = Screen::List;
            }
            Err(e) => {
                form.error = Some(format!("{e}"));
                self.screen = Screen::Settings(form);
            }
        }
        Ok(())
    }

    // ── Unlock screen ───────────────────────────────────────────────────────

    fn key_unlock(&mut self, mut form: UnlockForm, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Esc => {
                self.screen = Screen::List;
            }
            KeyCode::Backspace => {
                form.passphrase.pop();
                self.screen = Screen::Unlock(form);
            }
            KeyCode::Enter => match Vault::open(&form.vault_dir, &form.passphrase) {
                Ok(_) => {
                    session::unlock(&form.vault_dir, &form.passphrase)?;
                    crate::usage::human(&form.vault_dir, "unlock", None);
                    self.refresh_vaults();
                    self.set_status(MsgKind::Ok, format!("Vault '{}' unlocked", form.name));
                    match form.pending {
                        Pending::List => self.screen = Screen::List,
                        Pending::Secrets => self.enter_secrets(&form.vault_dir, &form.name)?,
                        Pending::Settings => {
                            let meta = VaultMeta::load_unverified(&form.vault_dir)?;
                            self.screen =
                                Screen::Settings(SettingsForm::from_meta(form.vault_dir, meta));
                        }
                    }
                }
                Err(_) => {
                    form.error = Some("Wrong passphrase".into());
                    form.passphrase.clear();
                    self.screen = Screen::Unlock(form);
                }
            },
            KeyCode::Char(c) => {
                form.passphrase.push(c);
                form.error = None;
                self.screen = Screen::Unlock(form);
            }
            _ => self.screen = Screen::Unlock(form),
        }
        Ok(())
    }

    // ── Secret list screen ────────────────────────────────────────────────────

    fn key_secrets(&mut self, mut scr: SecretScreen, key: KeyEvent) -> Result<()> {
        // Reveal modal takes priority.
        if scr.reveal.is_some() {
            match key.code {
                KeyCode::Char(' ') => {
                    if let Some(r) = scr.reveal.as_mut() {
                        r.masked = !r.masked;
                    }
                }
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => scr.reveal = None,
                _ => {}
            }
            self.screen = Screen::Secrets(scr);
            return Ok(());
        }

        // Delete confirmation takes priority.
        if let Some(target) = scr.pending_delete.clone() {
            match key.code {
                KeyCode::Char('y') => {
                    self.delete_secret(&mut scr, &target);
                    scr.pending_delete = None;
                }
                _ => scr.pending_delete = None,
            }
            self.screen = Screen::Secrets(scr);
            return Ok(());
        }

        match key.code {
            KeyCode::Esc | KeyCode::Char('b') => {
                self.screen = Screen::List;
                return Ok(());
            }
            KeyCode::Char('q') => {
                self.confirm_quit = true;
            }
            KeyCode::Down | KeyCode::Char('j') => secrets_next(&mut scr),
            KeyCode::Up | KeyCode::Char('k') => secrets_prev(&mut scr),
            KeyCode::Char('a') => {
                self.screen = Screen::SecretAdd(SecretAddForm {
                    vault_dir: scr.vault_dir.clone(),
                    vault_name: scr.name.clone(),
                    name: String::new(),
                    value: String::new(),
                    focus: 0,
                    error: None,
                });
                return Ok(());
            }
            KeyCode::Enter | KeyCode::Char('g') => self.reveal_secret(&mut scr),
            KeyCode::Char('d') => {
                if let Some(name) = scr.selected_name() {
                    scr.pending_delete = Some(name);
                }
            }
            KeyCode::Char('l') => {
                session::lock(&scr.vault_dir)?;
                crate::usage::human(&scr.vault_dir, "lock", None);
                self.set_status(MsgKind::Ok, format!("Vault '{}' locked", scr.name));
                self.refresh_vaults();
                self.screen = Screen::List;
                return Ok(());
            }
            KeyCode::Char('?') => self.show_help = true,
            _ => {}
        }
        self.screen = Screen::Secrets(scr);
        Ok(())
    }

    fn reveal_secret(&mut self, scr: &mut SecretScreen) {
        let Some(name) = scr.selected_name() else {
            return;
        };
        let Some(pass) = session::get_passphrase(&scr.vault_dir) else {
            self.set_status(MsgKind::Error, "Vault is locked");
            return;
        };
        match Vault::open(&scr.vault_dir, &pass).and_then(|v| v.get_secret(&name)) {
            Ok(Some(value)) => {
                crate::usage::human(&scr.vault_dir, "secret.reveal", Some(&name));
                scr.reveal = Some(Reveal {
                    name,
                    value,
                    masked: true,
                })
            }
            Ok(None) => self.set_status(MsgKind::Error, format!("Secret '{name}' not found")),
            Err(e) => self.set_status(MsgKind::Error, format!("{e}")),
        }
    }

    fn delete_secret(&mut self, scr: &mut SecretScreen, name: &str) {
        let Some(pass) = session::get_passphrase(&scr.vault_dir) else {
            self.set_status(MsgKind::Error, "Vault is locked");
            return;
        };
        match Vault::open(&scr.vault_dir, &pass) {
            Ok(vault) => match vault.remove_secret(name) {
                Ok(true) => {
                    scr.secrets = vault.list_secret_names().unwrap_or_default();
                    let sel = if scr.secrets.is_empty() {
                        None
                    } else {
                        Some(
                            scr.list_state
                                .selected()
                                .unwrap_or(0)
                                .min(scr.secrets.len() - 1),
                        )
                    };
                    scr.list_state.select(sel);
                    crate::usage::human(&scr.vault_dir, "secret.remove", Some(name));
                    self.set_status(MsgKind::Ok, format!("Secret '{name}' removed"));
                }
                Ok(false) => self.set_status(MsgKind::Error, format!("Secret '{name}' not found")),
                Err(e) => self.set_status(MsgKind::Error, format!("{e}")),
            },
            Err(e) => self.set_status(MsgKind::Error, format!("{e}")),
        }
    }

    // ── Secret add screen ───────────────────────────────────────────────────

    fn key_secret_add(&mut self, mut form: SecretAddForm, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Esc => {
                let (dir, name) = (form.vault_dir.clone(), form.vault_name.clone());
                self.enter_secrets(&dir, &name)?;
                return Ok(());
            }
            KeyCode::Tab | KeyCode::Down => form.focus = (form.focus + 1) % 2,
            KeyCode::BackTab | KeyCode::Up => form.focus = (form.focus + 1) % 2, // 2 fields: same target
            KeyCode::Enter => {
                if form.focus == 0 {
                    form.focus = 1;
                } else {
                    return self.submit_secret_add(form);
                }
            }
            KeyCode::Backspace => {
                if form.focus == 0 {
                    form.name.pop();
                } else {
                    form.value.pop();
                }
            }
            KeyCode::Char(c) => {
                if form.focus == 0 {
                    form.name.push(c);
                } else {
                    form.value.push(c);
                }
                form.error = None;
            }
            _ => {}
        }
        self.screen = Screen::SecretAdd(form);
        Ok(())
    }

    fn submit_secret_add(&mut self, mut form: SecretAddForm) -> Result<()> {
        if form.name.trim().is_empty() {
            form.error = Some("Secret name is required".into());
            self.screen = Screen::SecretAdd(form);
            return Ok(());
        }
        let Some(pass) = session::get_passphrase(&form.vault_dir) else {
            self.set_status(MsgKind::Error, "Vault is locked");
            self.screen = Screen::List;
            return Ok(());
        };
        match Vault::open(&form.vault_dir, &pass) {
            Ok(vault) => match vault.add_secret(form.name.trim(), &form.value) {
                Ok(_) => {
                    crate::usage::human(&form.vault_dir, "secret.add", Some(form.name.trim()));
                    self.set_status(MsgKind::Ok, format!("Secret '{}' added", form.name.trim()));
                    let (dir, name) = (form.vault_dir.clone(), form.vault_name.clone());
                    self.enter_secrets(&dir, &name)?;
                }
                Err(e) => {
                    form.error = Some(format!("{e}"));
                    self.screen = Screen::SecretAdd(form);
                }
            },
            Err(e) => {
                form.error = Some(format!("{e}"));
                self.screen = Screen::SecretAdd(form);
            }
        }
        Ok(())
    }
}

// ── Free helpers ───────────────────────────────────────────────────────────────

fn parse_agents(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn create_adjust(form: &mut CreateForm, forward: bool) {
    match form.current() {
        CreateField::AllowMode => form.allow_mode = cycle(form.allow_mode, 3, forward),
        CreateField::Autolock => form.autolock = !form.autolock,
        _ => {}
    }
}

fn settings_adjust(form: &mut SettingsForm, forward: bool) {
    match form.current() {
        SettingsField::AllowMode => form.allow_mode = cycle(form.allow_mode, 3, forward),
        SettingsField::Autolock => form.autolock = !form.autolock,
        _ => {}
    }
}

fn cycle(current: usize, len: usize, forward: bool) -> usize {
    if forward {
        (current + 1) % len
    } else {
        (current + len - 1) % len
    }
}

fn secrets_next(scr: &mut SecretScreen) {
    if scr.secrets.is_empty() {
        return;
    }
    let i = scr
        .list_state
        .selected()
        .map_or(0, |i| (i + 1) % scr.secrets.len());
    scr.list_state.select(Some(i));
}

fn secrets_prev(scr: &mut SecretScreen) {
    if scr.secrets.is_empty() {
        return;
    }
    let len = scr.secrets.len();
    let i = scr.list_state.selected().map_or(0, |i| (i + len - 1) % len);
    scr.list_state.select(Some(i));
}

/// Move the activity cursor (which also scrolls the table). Clamps at the ends
/// rather than wrapping, so paging through a long history feels natural.
fn activity_move(scr: &mut ActivityScreen, down: bool) {
    if scr.events.is_empty() {
        return;
    }
    let last = scr.events.len() - 1;
    let i = scr.state.selected().unwrap_or(0);
    let next = if down {
        (i + 1).min(last)
    } else {
        i.saturating_sub(1)
    };
    scr.state.select(Some(next));
}

// ── Tests ────────────────────────────────────────────────────────────────────────
//
// These exercise key dispatch and field logic directly — no terminal needed —
// which is what the field-enum refactor unlocked. They lock in the bug fixes so
// the focus indices can't silently drift again.

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn bare_app(screen: Screen) -> App {
        App {
            screen,
            vaults: Vec::new(),
            list_state: TableState::default(),
            status: None,
            should_quit: false,
            show_help: false,
            confirm_quit: false,
            daemon_running: false,
        }
    }

    fn press(app: &mut App, code: KeyCode) {
        app.on_key(KeyEvent::new(code, KeyModifiers::empty()))
            .unwrap();
    }

    fn idx(field: CreateField) -> usize {
        CreateField::ORDER.iter().position(|f| *f == field).unwrap()
    }

    fn create_at(field: CreateField) -> Screen {
        let mut form = CreateForm::new();
        form.focus = idx(field);
        Screen::Create(form)
    }

    /// Regression: space in the rate-limit field must type a space, not flip
    /// auto-lock (the original off-by-one). See CreateField wiring.
    #[test]
    fn space_in_rate_limit_types_a_space_and_leaves_autolock_alone() {
        let mut app = bare_app(create_at(CreateField::RateLimit));
        press(&mut app, KeyCode::Char(' '));
        let Screen::Create(form) = &app.screen else {
            panic!("expected create screen")
        };
        assert!(form.rate_limit.ends_with(' '));
        assert!(form.autolock, "auto-lock must not toggle from rate-limit");
    }

    #[test]
    fn space_on_the_autolock_field_toggles_it() {
        let mut app = bare_app(create_at(CreateField::Autolock));
        press(&mut app, KeyCode::Char(' '));
        let Screen::Create(form) = &app.screen else {
            panic!("expected create screen")
        };
        assert!(!form.autolock);
    }

    #[test]
    fn create_field_order_matches_field_count() {
        assert_eq!(CreateField::ORDER.len(), CreateForm::FIELDS);
        assert_eq!(SettingsField::ORDER.len(), SettingsForm::FIELDS);
    }

    #[test]
    fn focus_is_text_excludes_pickers_and_toggles() {
        let mut form = CreateForm::new();
        form.focus = idx(CreateField::AllowMode);
        assert!(!form.focus_is_text());
        form.focus = idx(CreateField::Autolock);
        assert!(!form.focus_is_text());
        form.focus = idx(CreateField::Passphrase);
        assert!(form.focus_is_text());
    }

    #[test]
    fn down_wraps_from_last_create_field_to_first() {
        let mut form = CreateForm::new();
        form.focus = CreateForm::FIELDS - 1;
        let mut app = bare_app(Screen::Create(form));
        press(&mut app, KeyCode::Down);
        let Screen::Create(form) = &app.screen else {
            panic!("expected create screen")
        };
        assert_eq!(form.focus, 0);
    }

    #[test]
    fn paste_appends_to_the_focused_field() {
        let mut app = bare_app(create_at(CreateField::Passphrase));
        app.on_paste("Str0ng!Pass#99".to_string());
        let Screen::Create(form) = &app.screen else {
            panic!("expected create screen")
        };
        assert_eq!(form.passphrase, "Str0ng!Pass#99");
    }

    #[test]
    fn paste_strips_newlines() {
        let mut app = bare_app(Screen::Import(ImportForm {
            path: String::new(),
            error: None,
        }));
        app.on_paste("/tmp/v.svault-export.json\n".to_string());
        let Screen::Import(form) = &app.screen else {
            panic!("expected import screen")
        };
        assert_eq!(form.path, "/tmp/v.svault-export.json");
    }

    #[test]
    fn help_opens_from_list_and_any_key_closes_it() {
        let mut app = bare_app(Screen::List);
        press(&mut app, KeyCode::Char('?'));
        assert!(app.show_help);
        press(&mut app, KeyCode::Char('x'));
        assert!(!app.show_help);
    }

    #[test]
    fn quit_from_list_asks_for_confirmation_then_enter_quits() {
        let mut app = bare_app(Screen::List);
        press(&mut app, KeyCode::Char('q'));
        assert!(app.confirm_quit, "q should open the quit confirmation");
        assert!(!app.should_quit, "q alone must not quit");
        press(&mut app, KeyCode::Enter);
        assert!(app.should_quit, "enter confirms the quit");
    }

    #[test]
    fn any_key_other_than_enter_cancels_the_quit_popup() {
        let mut app = bare_app(Screen::List);
        app.confirm_quit = true;
        press(&mut app, KeyCode::Esc);
        assert!(!app.confirm_quit, "esc cancels");
        assert!(!app.should_quit);
    }

    #[test]
    fn recovery_code_screen_needs_y_to_dismiss() {
        let mut app = bare_app(Screen::RecoveryCode("AAAA-BBBB-CCCC".into()));
        press(&mut app, KeyCode::Char('x'));
        assert!(
            matches!(app.screen, Screen::RecoveryCode(_)),
            "a non-y key keeps the code on screen"
        );
        press(&mut app, KeyCode::Char('y'));
        assert!(
            matches!(app.screen, Screen::List),
            "y confirms and returns to the list"
        );
    }
}
