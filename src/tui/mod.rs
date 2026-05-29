//! Interactive terminal UI (Ratatui) — launched when `svault` is run with no
//! subcommand. Covers the full Step 1 workflow without leaving the keyboard:
//! list vaults, create, lock/unlock, edit settings, and add/view/delete secrets.
//!
//! Lock awareness is central: secret screens and the settings editor require an
//! unlocked vault (cached session passphrase). When a locked vault is selected,
//! the action is routed through the unlock prompt and resumed on success.

mod ui;

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use ratatui::widgets::ListState;
use std::path::{Path, PathBuf};

use crate::meta::{AccessConfig, AllowAgent, LoginMethod, VaultMeta, VaultSettings};
use crate::session;
use crate::vault::{list_vault_dirs, Vault, SVAULT_DIR};

/// Enter the alternate screen, run the event loop, restore the terminal.
pub fn run() -> Result<()> {
    let mut terminal = ratatui::init();
    let mut app = App::new();
    let result = app.event_loop(&mut terminal);
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
                unlocked,
            })
        })
        .collect()
}

// ── Screens ────────────────────────────────────────────────────────────────────

/// What to do after a successful unlock prompt.
#[derive(Clone, Copy)]
pub enum Pending {
    List,
    Secrets,
    Settings,
}

pub struct CreateForm {
    pub storage: usize, // 0 local · 1 remote (coming soon)
    pub name: String,
    pub description: String,
    pub allow_mode: usize, // 0 all · 1 none · 2 list
    pub allow_list: String,
    pub rate_limit: String,
    pub autolock: bool,
    pub autolock_timer: String,
    pub login_method: usize, // 0 passphrase · 1 yubikey · 2 google
    pub passphrase: String,
    pub confirm: String,
    pub focus: usize,
    pub error: Option<String>,
}

impl CreateForm {
    const FIELDS: usize = 11;

    fn new() -> Self {
        let default_name = std::env::current_dir()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .unwrap_or_else(|| "my-vault".to_string());
        Self {
            storage: 0,
            name: default_name,
            description: String::new(),
            allow_mode: 0,
            allow_list: String::new(),
            rate_limit: "10/hour".to_string(),
            autolock: true,
            autolock_timer: "1d".to_string(),
            login_method: 0,
            passphrase: String::new(),
            confirm: String::new(),
            focus: 0,
            error: None,
        }
    }

    fn text_field(&mut self) -> Option<&mut String> {
        Some(match self.focus {
            1 => &mut self.name,
            2 => &mut self.description,
            4 => &mut self.allow_list,
            5 => &mut self.rate_limit,
            7 => &mut self.autolock_timer,
            9 => &mut self.passphrase,
            10 => &mut self.confirm,
            _ => return None,
        })
    }
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
    pub login_method: usize,
    pub focus: usize,
    pub error: Option<String>,
}

impl SettingsForm {
    const FIELDS: usize = 7;

    fn from_meta(vault_dir: PathBuf, meta: VaultMeta) -> Self {
        let (allow_mode, allow_list) = match &meta.access.allow_agent {
            AllowAgent::Bool(true) => (0, String::new()),
            AllowAgent::Bool(false) => (1, String::new()),
            AllowAgent::List(v) => (2, v.join(", ")),
        };
        let login_method = match meta.settings.login_method {
            LoginMethod::Passphrase => 0,
            LoginMethod::Yubikey => 1,
            LoginMethod::GoogleAuth => 2,
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
            login_method,
            focus: 0,
            error: None,
        }
    }

    fn text_field(&mut self) -> Option<&mut String> {
        Some(match self.focus {
            0 => &mut self.description,
            2 => &mut self.allow_list,
            3 => &mut self.rate_limit,
            5 => &mut self.autolock_timer,
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
}

// ── App ────────────────────────────────────────────────────────────────────────

pub struct App {
    pub screen: Screen,
    pub vaults: Vec<VaultRow>,
    pub list_state: ListState,
    pub status: Option<Status>,
    pub should_quit: bool,
}

impl App {
    fn new() -> Self {
        let vaults = load_vaults();
        let mut list_state = ListState::default();
        if !vaults.is_empty() {
            list_state.select(Some(0));
        }
        Self {
            screen: Screen::List,
            vaults,
            list_state,
            status: None,
            should_quit: false,
        }
    }

    fn event_loop(&mut self, terminal: &mut ratatui::DefaultTerminal) -> Result<()> {
        while !self.should_quit {
            terminal.draw(|frame| ui::draw(frame, self))?;
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    self.on_key(key)?;
                }
            }
        }
        Ok(())
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
        }
        Ok(())
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
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
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
                        self.set_status(MsgKind::Ok, format!("Exported '{}' to {out}", v.name))
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
                if form.focus == 5 && c == ' ' {
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
        let login_note = form.login_method != 0;
        let storage_note = form.storage != 0;
        let mut meta = VaultMeta::new(
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
        meta.storage = storage_id(form.storage).to_string();

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
                self.refresh_vaults();
                if storage_note {
                    self.set_status(
                        MsgKind::Warn,
                        format!("Vault '{name}' created (remote storage is coming soon — stored locally)"),
                    );
                } else if login_note {
                    self.set_status(
                        MsgKind::Warn,
                        format!("Vault '{name}' created (only passphrase is wired today)"),
                    );
                } else {
                    self.set_status(MsgKind::Ok, format!("Vault '{name}' created"));
                }
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
                if form.focus == 4 && c == ' ' {
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
        let login_note = form.login_method != 0;

        let mut meta = vault.meta.clone();
        meta.description = form.description.clone();
        meta.access.allow_agent = allow_agent;
        meta.access.rate_limit = form.rate_limit.clone();
        meta.settings.autolock = form.autolock;
        meta.settings.autolock_timer = form.autolock_timer.clone();
        meta.settings.login_method = LoginMethod::Passphrase;

        match vault.save_meta(&meta) {
            Ok(_) => {
                self.refresh_vaults();
                if login_note {
                    self.set_status(
                        MsgKind::Warn,
                        format!(
                            "Settings for '{}' saved (only passphrase is wired today)",
                            form.name
                        ),
                    );
                } else {
                    self.set_status(MsgKind::Ok, format!("Settings for '{}' saved", form.name));
                }
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
                self.should_quit = true;
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
                self.set_status(MsgKind::Ok, format!("Vault '{}' locked", scr.name));
                self.refresh_vaults();
                self.screen = Screen::List;
                return Ok(());
            }
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
            KeyCode::BackTab | KeyCode::Up => form.focus = (form.focus + 1) % 2,
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

/// Map the storage picker index to a backend id stored in meta.yaml.
/// Only "local" is wired today; the rest are reserved placeholders.
fn storage_id(idx: usize) -> &'static str {
    match idx {
        0 => "local",
        1 => "cloud",
        2 => "self-hosted",
        _ => "s3",
    }
}

fn parse_agents(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn create_adjust(form: &mut CreateForm, forward: bool) {
    match form.focus {
        0 => form.storage = cycle(form.storage, 4, forward),
        3 => form.allow_mode = cycle(form.allow_mode, 3, forward),
        6 => form.autolock = !form.autolock,
        8 => form.login_method = cycle(form.login_method, 3, forward),
        _ => {}
    }
}

fn settings_adjust(form: &mut SettingsForm, forward: bool) {
    match form.focus {
        1 => form.allow_mode = cycle(form.allow_mode, 3, forward),
        4 => form.autolock = !form.autolock,
        6 => form.login_method = cycle(form.login_method, 3, forward),
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
