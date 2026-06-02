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
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::widgets::TableState;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::core::crypto::VaultKey;
use crate::core::meta::{AccessConfig, AllowAgent, LoginMethod, VaultMeta, VaultSettings};
use crate::core::policy::SecretRule;
use crate::core::session;
use crate::core::vault::{list_vault_dirs, svault_dir, Vault};

/// Enter the alternate screen, run the event loop, restore the terminal.
pub fn run() -> Result<()> {
    // Everything recorded from here on is a TUI action.
    crate::core::usage::set_source(crate::core::usage::Source::Tui);
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

/// A blocking YubiKey (FIDO2) operation queued by a key handler and run by the
/// event loop *after* a redraw — so a "Touch your YubiKey…" frame is on screen
/// while the (multi-second, touch-gated) call blocks, and the screen is cleared
/// afterwards. Running it inline in the handler would freeze on a stale frame.
pub enum PendingFido {
    /// Enroll the YubiKey during onboarding (needs the open master session).
    Enroll { pin: Option<String> },
    /// Sign in (app-level login) via the enrolled YubiKey.
    Login { pin: Option<String> },
    /// Unlock a vault via the enrolled YubiKey.
    Unlock {
        vault_dir: PathBuf,
        name: String,
        pending: Pending,
        pin: Option<String>,
    },
}

/// The focusable fields of the create form, in display order. Handlers match on
/// the field (not a bare index) so the draw order and the key logic can never
/// drift apart. Storage and login method are fixed (local / passphrase), so
/// they are shown as a static note rather than a pickable field.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CreateField {
    Name,
    Description,
    AllowMode,
    AllowList,
    RateLimit,
    Autolock,
    AutolockTimer,
    DefaultTier,
    Judge,
    /// Which keyring judge gates this vault (default = keyring default).
    JudgeName,
    /// First-time master passphrase (set-on-create) + its confirmation.
    MasterNew,
    MasterConfirm,
    /// Existing master passphrase, when a master is set but locked.
    MasterUnlock,
}

/// The master-passphrase tail of the create form depends on machine state.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MasterStep {
    /// Master already unlocked this session — no passphrase fields needed.
    Ready,
    /// A master is set but locked — ask for it (one field).
    Unlock,
    /// First run, no master yet — set one (passphrase + confirm).
    Set,
}

pub struct CreateForm {
    pub name: String,
    pub description: String,
    pub allow_mode: usize, // 0 all · 1 none · 2 list
    pub allow_list: String,
    pub rate_limit: String,
    pub autolock: bool,
    pub autolock_timer: String,
    pub default_tier: usize, // 0 low · 1 medium · 2 high
    pub judge: bool,
    /// Which keyring judge gates this vault. `None` = the keyring default judge.
    pub judge_name: Option<String>,
    /// Names of judges available to pick from (empty if the keyring is locked).
    pub judge_choices: Vec<String>,
    pub passphrase: String,
    pub confirm: String,
    pub focus: usize,
    pub error: Option<String>,
    /// What the master tail must do (computed once when the form opens).
    pub master_step: MasterStep,
    /// The full field order including the master tail, in display order.
    pub order: Vec<CreateField>,
}

impl CreateForm {
    fn new() -> Self {
        let default_name = std::env::current_dir()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .unwrap_or_else(|| "my-vault".to_string());
        let master_step = if crate::core::master::is_unlocked() {
            MasterStep::Ready
        } else if crate::core::master::exists() {
            MasterStep::Unlock
        } else {
            MasterStep::Set
        };
        let order = Self::order_for(master_step);
        Self {
            name: default_name,
            description: String::new(),
            allow_mode: 0,
            allow_list: String::new(),
            rate_limit: "10/hour".to_string(),
            autolock: true,
            autolock_timer: "1d".to_string(),
            default_tier: 0,
            judge: false,
            judge_name: None,
            judge_choices: available_judge_names(),
            passphrase: String::new(),
            confirm: String::new(),
            focus: 0,
            error: None,
            master_step,
            order,
        }
    }

    /// The field order for a given master step: the nine base fields plus the
    /// master tail (none / one unlock field / set + confirm).
    pub fn order_for(step: MasterStep) -> Vec<CreateField> {
        let mut order = vec![
            CreateField::Name,
            CreateField::Description,
            CreateField::AllowMode,
            CreateField::AllowList,
            CreateField::RateLimit,
            CreateField::Autolock,
            CreateField::AutolockTimer,
            CreateField::DefaultTier,
            CreateField::Judge,
            CreateField::JudgeName,
        ];
        match step {
            MasterStep::Ready => {}
            MasterStep::Unlock => order.push(CreateField::MasterUnlock),
            MasterStep::Set => {
                order.push(CreateField::MasterNew);
                order.push(CreateField::MasterConfirm);
            }
        }
        order
    }

    fn fields(&self) -> usize {
        self.order.len()
    }

    pub fn current(&self) -> CreateField {
        self.order[self.focus]
    }

    /// Whether the focused field accepts typed/pasted text (drives the caret).
    pub fn focus_is_text(&self) -> bool {
        !matches!(
            self.current(),
            CreateField::AllowMode
                | CreateField::Autolock
                | CreateField::DefaultTier
                | CreateField::Judge
                | CreateField::JudgeName
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
            CreateField::MasterNew | CreateField::MasterUnlock => &mut self.passphrase,
            CreateField::MasterConfirm => &mut self.confirm,
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
    DefaultTier,
    Judge,
    JudgeName,
}

impl SettingsField {
    pub const ORDER: [SettingsField; 9] = [
        SettingsField::Description,
        SettingsField::AllowMode,
        SettingsField::AllowList,
        SettingsField::RateLimit,
        SettingsField::Autolock,
        SettingsField::AutolockTimer,
        SettingsField::DefaultTier,
        SettingsField::Judge,
        SettingsField::JudgeName,
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
    pub default_tier: usize,
    pub judge: bool,
    /// Which keyring judge gates this vault. `None` = the keyring default judge.
    pub judge_name: Option<String>,
    /// Names of judges available to pick from (empty if the keyring is locked).
    pub judge_choices: Vec<String>,
    pub focus: usize,
    pub error: Option<String>,
}

impl SettingsForm {
    const FIELDS: usize = SettingsField::ORDER.len();

    fn from_meta(
        vault_dir: PathBuf,
        meta: VaultMeta,
        policy: &crate::core::policy::VaultPolicyData,
    ) -> Self {
        let (allow_mode, allow_list) = match &policy.access.allow_agent {
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
            rate_limit: policy.access.rate_limit.clone(),
            autolock: meta.settings.autolock,
            autolock_timer: meta.settings.autolock_timer,
            default_tier: tier_idx(policy.default_tier),
            judge: policy.judge.enabled.unwrap_or(false),
            judge_name: policy.judge.judge.clone(),
            judge_choices: available_judge_names(),
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
            SettingsField::AllowMode
                | SettingsField::Autolock
                | SettingsField::DefaultTier
                | SettingsField::Judge
                | SettingsField::JudgeName
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
    /// True if a YubiKey is enrolled and connected — gates the Ctrl+Y unlock
    /// hint/path. Computed once at construction so we don't enumerate USB on
    /// every redraw.
    pub yubikey: bool,
}

impl UnlockForm {
    fn new(vault_dir: PathBuf, name: String, pending: Pending) -> Self {
        let yubikey = crate::core::master::yubikey_enrolled() && crate::core::yubikey::is_present();
        Self {
            vault_dir,
            name,
            passphrase: String::new(),
            error: None,
            pending,
            yubikey,
        }
    }
}

pub struct Reveal {
    pub name: String,
    /// Wrapped so a revealed secret is wiped from memory when the modal closes (#6).
    pub value: zeroize::Zeroizing<String>,
    pub masked: bool,
}

pub struct SecretScreen {
    pub vault_dir: PathBuf,
    pub name: String,
    pub secrets: Vec<String>,
    /// Per-secret classification from the encrypted policy, shown alongside each
    /// name (tier/scope/require-reason/description) so the policy that governs an
    /// agent `get` is visible without leaving the browser.
    pub classifications: BTreeMap<String, SecretRule>,
    /// Sealed secrets (anomaly-escalated) from the encrypted policy, so the browser
    /// can mark them and a human can clear the seal in place (`A`).
    pub seals: BTreeMap<String, crate::core::policy::Seal>,
    /// The vault's default tier (from the decrypted policy), used to prefill the
    /// add/classify forms.
    pub default_tier: usize,
    pub list_state: TableState,
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
    pub scope: String,
    pub description: String,
    pub tier: usize, // 0 low · 1 medium · 2 high
    pub require_reason: bool,
    pub focus: usize, // 0 name · 1 value · 2 scope · 3 description · 4 tier · 5 require_reason
    pub error: Option<String>,
}

impl SecretAddForm {
    const FIELDS: usize = 6;
    /// Text-entry fields (name/value/scope/description) show a caret; tier/require_reason don't.
    fn focus_is_text(&self) -> bool {
        self.focus < 4
    }
}

/// Reclassify an existing secret: edit the scope/tier/require-reason/description
/// stored in the signed `meta.yaml`. The secret *value* is never touched here —
/// this only edits the policy classification the gate reads.
pub struct ClassifyForm {
    pub vault_dir: PathBuf,
    pub vault_name: String,
    pub secret: String,
    pub scope: String,
    pub description: String,
    /// Conditional access: access windows, one spec per line/comma, e.g.
    /// `mon-fri 09:00-18:00`. Blank = any time.
    pub windows: String,
    /// Conditional access: required callers, comma-separated. Blank = no restriction.
    pub require_callers: String,
    pub tier: usize, // 0 low · 1 medium · 2 high
    pub require_reason: bool,
    pub focus: usize, // 0 scope · 1 description · 2 windows · 3 require_callers · 4 tier · 5 require_reason
    pub error: Option<String>,
}

impl ClassifyForm {
    const FIELDS: usize = 6;
    /// Text-entry fields (scope/description/windows/require_callers) show a caret;
    /// tier/require_reason don't.
    fn focus_is_text(&self) -> bool {
        self.focus < 4
    }
}

/// Split a comma/semicolon/newline list into trimmed, non-empty items.
fn split_list(s: &str) -> Vec<String> {
    s.split([',', ';', '\n'])
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect()
}

/// One judge as shown in the manager list (and its detail view).
pub struct JudgeRow {
    pub name: String,
    pub model: String,
    pub base_url: String,
    pub timeout_secs: u64,
    pub allow: u8,
    pub high: u8,
    pub criteria: String,
    pub has_key: bool,
}

/// Create a brand-new keyring from the TUI (own passphrase + confirm).
pub struct InitForm {
    pub pass: String,
    pub confirm: String,
    pub focus: usize, // 0 passphrase · 1 confirm
    pub error: Option<String>,
}

impl InitForm {
    fn new() -> Self {
        Self {
            pass: String::new(),
            confirm: String::new(),
            focus: 0,
            error: None,
        }
    }
}

/// Add or edit one judge's fields. `original` is `None` when adding, or the
/// prior name when editing (rename-safe). The API key is set separately (`k`),
/// so it is preserved across an edit.
pub struct JudgeEditForm {
    pub original: Option<String>,
    pub name: String,
    pub model: String,
    pub base_url: String,
    pub timeout: String,
    pub allow: String,
    pub high: String,
    pub criteria: String,
    pub focus: usize, // 0 name · 1 model · 2 url · 3 timeout · 4 allow · 5 high · 6 criteria
    pub error: Option<String>,
}

impl JudgeEditForm {
    const FIELDS: usize = 7;

    fn add() -> Self {
        let d = crate::core::keyring::JudgeDef::default();
        Self {
            original: None,
            name: String::new(),
            model: d.model,
            base_url: d.base_url,
            timeout: d.timeout_secs.to_string(),
            allow: d.allow_threshold.to_string(),
            high: d.high_threshold.to_string(),
            criteria: String::new(),
            focus: 0,
            error: None,
        }
    }

    fn edit(name: &str, d: &crate::core::keyring::JudgeDef) -> Self {
        Self {
            original: Some(name.to_string()),
            name: name.to_string(),
            model: d.model.clone(),
            base_url: d.base_url.clone(),
            timeout: d.timeout_secs.to_string(),
            allow: d.allow_threshold.to_string(),
            high: d.high_threshold.to_string(),
            criteria: d.criteria.clone(),
            focus: 0,
            error: None,
        }
    }

    /// The string field currently under the cursor.
    fn field_mut(&mut self) -> Option<&mut String> {
        match self.focus {
            0 => Some(&mut self.name),
            1 => Some(&mut self.model),
            2 => Some(&mut self.base_url),
            3 => Some(&mut self.timeout),
            4 => Some(&mut self.allow),
            5 => Some(&mut self.high),
            6 => Some(&mut self.criteria),
            _ => None,
        }
    }
}

/// A sub-mode overlaid on the judge screen: unlocking or creating the keyring,
/// typing a judge's API key, adding/editing a judge, or viewing one's detail.
pub enum JudgeEntry {
    Passphrase(String),
    Init(InitForm),
    Key { judge: String, buf: String },
    Edit(JudgeEditForm),
    View(String),
}

/// Status line shown after the keyring is opened: created on first use, else just
/// unlocked.
fn keyring_done_msg(created: bool) -> &'static str {
    if created {
        "Keyring unlocked"
    } else {
        "Keyring created and unlocked"
    }
}

/// The AI-judge manager (`shift-J`), backed by the encrypted [`crate::core::keyring`].
/// Shows the global on/off switch, the default judge, and the registry, and
/// supports the common actions: unlock, toggle, set default, set/clear a judge's
/// key, test, remove. Adding or editing a judge's model/criteria/thresholds is
/// done with `svault judge add|edit <name>` (multi-field entry lives at the CLI).
pub struct JudgeForm {
    pub created: bool,
    pub unlocked: bool,
    pub enabled: bool,
    pub default_judge: Option<String>,
    pub judges: Vec<JudgeRow>,
    /// 0 = the global Enabled row; `1..=judges.len()` = a judge row.
    pub focus: usize,
    pub error: Option<String>,
    /// Result of the last `test` action (kind + message), shown under the list.
    pub test_result: Option<(MsgKind, String)>,
    pub entry: Option<JudgeEntry>,
}

impl JudgeForm {
    /// Build the snapshot from the keyring session (if it's unlocked).
    fn load() -> Self {
        let created = crate::core::keyring::exists();
        match crate::core::keyring::open_from_session() {
            Some(kr) => {
                let judges = kr
                    .data
                    .judges
                    .iter()
                    .map(|(n, d)| JudgeRow {
                        name: n.clone(),
                        model: d.model.clone(),
                        base_url: d.base_url.clone(),
                        timeout_secs: d.timeout_secs,
                        allow: d.allow_threshold,
                        high: d.high_threshold,
                        criteria: d.criteria.clone(),
                        has_key: !d.api_key.trim().is_empty(),
                    })
                    .collect();
                Self {
                    created,
                    unlocked: true,
                    enabled: kr.data.judge_enabled,
                    default_judge: kr.data.default_judge.clone(),
                    judges,
                    focus: 0,
                    error: None,
                    test_result: None,
                    entry: None,
                }
            }
            None => Self {
                created,
                unlocked: false,
                enabled: false,
                default_judge: None,
                judges: Vec::new(),
                focus: 0,
                error: None,
                test_result: None,
                entry: None,
            },
        }
    }

    /// Number of selectable rows (the Enabled row + one per judge).
    fn rows(&self) -> usize {
        1 + self.judges.len()
    }

    /// The judge under the cursor (focus `1..`), if any.
    pub fn selected_judge(&self) -> Option<&JudgeRow> {
        if self.focus == 0 {
            None
        } else {
            self.judges.get(self.focus - 1)
        }
    }
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
    pub events: Vec<crate::core::usage::Event>,
    pub state: TableState,
}

/// One or more one-time recovery codes to show after a create/set action, plus
/// where to return once the user confirms they've saved them.
pub struct RecoveryShow {
    /// (label, code) pairs — e.g. ("Master passphrase", code), ("Vault 'x'", code).
    pub codes: Vec<(String, String)>,
    /// Return to the judge screen on confirm (keyring flow) instead of the list.
    pub to_judge: bool,
}

/// First-run onboarding steps, shown only when no master passphrase exists yet:
/// an honest disclaimer the user accepts, then setting the master passphrase,
/// then the one-time recovery code, then an optional YubiKey enrollment.
#[derive(Clone, Copy, PartialEq)]
pub enum OnboardStep {
    Disclaimer,
    Passphrase,
    Recovery,
    Yubikey,
}

pub struct OnboardForm {
    pub step: OnboardStep,
    /// Master passphrase entry (Passphrase step).
    pub passphrase: String,
    pub confirm: String,
    /// 0 = passphrase field focused, 1 = confirm field focused.
    pub focus: usize,
    /// The one-time master recovery code, generated when the master is set and
    /// shown on the Recovery step.
    pub recovery_code: Option<String>,
    /// Optional YubiKey PIN typed on the Yubikey step (blank = no PIN).
    pub pin: String,
    /// Whether a FIDO device is connected — checked when the Yubikey step opens.
    pub yubikey_present: bool,
    pub error: Option<String>,
}

impl OnboardForm {
    fn new() -> Self {
        Self {
            step: OnboardStep::Disclaimer,
            passphrase: String::new(),
            confirm: String::new(),
            focus: 0,
            recovery_code: None,
            pin: String::new(),
            yubikey_present: false,
            error: None,
        }
    }
}

/// The app-level login gate: enter the master passphrase (or touch an enrolled
/// YubiKey) to sign in. Shown at startup when a master exists but its session is
/// not active (never signed in this run, or expired past the 6h cap), and after
/// `logout`. Distinct from [`UnlockForm`], which unlocks a single vault.
pub struct LoginForm {
    pub passphrase: String,
    pub error: Option<String>,
    /// True if a YubiKey is enrolled and connected — gates the Ctrl+Y hint/path.
    pub yubikey: bool,
}

impl LoginForm {
    fn new() -> Self {
        let yubikey = crate::core::master::yubikey_enrolled() && crate::core::yubikey::is_present();
        Self {
            passphrase: String::new(),
            error: None,
            yubikey,
        }
    }
}

pub enum Screen {
    List,
    /// App-level login gate (master passphrase / YubiKey) — see [`LoginForm`].
    Login(LoginForm),
    /// First-run onboarding (disclaimer → master passphrase → recovery → YubiKey).
    Onboard(OnboardForm),
    Create(CreateForm),
    Settings(SettingsForm),
    Unlock(UnlockForm),
    Secrets(SecretScreen),
    SecretAdd(SecretAddForm),
    /// Shows the one-time recovery code(s) after a vault/master is created.
    /// Dismissed only by an explicit 'y' confirmation that they've been saved.
    RecoveryCode(RecoveryShow),
    /// Import a vault from a bundle file (path entry).
    Import(ImportForm),
    /// Recover a vault: enter the code + a new passphrase.
    Recover(RecoverForm),
    /// Recent usage timeline for the selected vault.
    Activity(ActivityScreen),
    /// Reclassify a secret's policy (scope/tier/require-reason/description).
    Classify(ClassifyForm),
    /// Manage the global AI judge (config + OpenRouter key + dry-run test).
    Judge(JudgeForm),
    /// MCP server status + wiring: readiness, the `svault mcp` config snippet, and
    /// a one-key writer for the local `.mcp.json`.
    Mcp,
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
    /// A blocking YubiKey operation to run after the next redraw (see
    /// [`PendingFido`]). The event loop drains it so the "touch now" frame shows.
    pub pending_fido: Option<PendingFido>,
}

impl App {
    fn new() -> Self {
        let vaults = load_vaults();
        let mut list_state = TableState::default();
        if !vaults.is_empty() {
            list_state.select(Some(0));
        }
        let daemon_running = crate::daemon::is_running(&crate::daemon::base_dir());
        // No master yet → onboarding. Master set but not signed in this run (or the
        // login session expired past the 6h cap) → the login gate. Otherwise the list.
        let screen = if !crate::core::master::exists() {
            Screen::Onboard(OnboardForm::new())
        } else if crate::core::master::is_unlocked() {
            Screen::List
        } else {
            Screen::Login(LoginForm::new())
        };
        Self {
            screen,
            vaults,
            list_state,
            status: None,
            should_quit: false,
            show_help: false,
            confirm_quit: false,
            daemon_running,
            pending_fido: None,
        }
    }

    fn event_loop(&mut self, terminal: &mut ratatui::DefaultTerminal) -> Result<()> {
        while !self.should_quit {
            terminal.draw(|frame| ui::draw(frame, self))?;
            // A queued YubiKey op runs here — the draw above already painted the
            // "Touch your YubiKey…" modal (pending_fido was still Some at draw
            // time). The library's touch chatter is silenced in core::yubikey, so
            // the blocking call stays inside the TUI; we clear afterwards to wipe
            // any stray output before the next frame repaints.
            if let Some(action) = self.pending_fido.take() {
                self.run_fido(action);
                let _ = terminal.clear();
                continue;
            }
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => self.on_key(key)?,
                Event::Paste(text) => self.on_paste(text),
                _ => {}
            }
        }
        Ok(())
    }

    /// Run a blocking YubiKey operation (drained from `pending_fido` by the event
    /// loop) and route to the next screen on success/failure.
    fn run_fido(&mut self, action: PendingFido) {
        match action {
            PendingFido::Enroll { pin } => {
                let result = match crate::core::master::open_from_session() {
                    Some(m) => m.enroll_yubikey(pin.as_deref()),
                    None => Err(anyhow::anyhow!("master session expired — reopen Svault")),
                };
                match result {
                    Ok(()) => {
                        self.set_status(
                            MsgKind::Ok,
                            "YubiKey enrolled — touch it to unlock next time".to_string(),
                        );
                        self.finish_onboarding();
                    }
                    Err(e) => {
                        let mut form = OnboardForm::new();
                        form.step = OnboardStep::Yubikey;
                        form.yubikey_present = crate::core::yubikey::is_present();
                        form.error = Some(format!("{e}"));
                        self.screen = Screen::Onboard(form);
                    }
                }
            }
            PendingFido::Login { pin } => {
                match crate::core::master::open_with_yubikey(pin.as_deref()) {
                    Ok(m) => {
                        let _ = crate::core::master::unlock_session(m.key_bytes());
                        self.refresh_vaults();
                        self.set_status(MsgKind::Ok, "Signed in with YubiKey.".to_string());
                        self.screen = Screen::List;
                    }
                    Err(e) => {
                        let mut form = LoginForm::new();
                        form.error = Some(format!("{e}"));
                        self.screen = Screen::Login(form);
                    }
                }
            }
            PendingFido::Unlock {
                vault_dir,
                name,
                pending,
                pin,
            } => match self.unlock_via_yubikey(&vault_dir, pin.as_deref()) {
                Ok(vault) => {
                    let mut form = UnlockForm::new(vault_dir, name, pending);
                    form.yubikey = true;
                    let _ = self.after_unlock(form, vault);
                }
                Err(e) => {
                    let mut form = UnlockForm::new(vault_dir, name, pending);
                    form.error = Some(e);
                    self.screen = Screen::Unlock(form);
                }
            },
        }
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
            Screen::Classify(form) => {
                match form.focus {
                    0 => form.scope.push_str(&text),
                    1 => form.description.push_str(&text),
                    _ => {}
                }
                form.error = None;
            }
            Screen::Judge(form) => match form.entry.as_mut() {
                Some(JudgeEntry::Passphrase(buf)) => buf.push_str(&text),
                Some(JudgeEntry::Key { buf, .. }) => buf.push_str(&text),
                Some(JudgeEntry::Init(init)) => {
                    if init.focus == 0 {
                        init.pass.push_str(&text);
                    } else {
                        init.confirm.push_str(&text);
                    }
                }
                Some(JudgeEntry::Edit(ed)) => {
                    if let Some(f) = ed.field_mut() {
                        f.push_str(&text);
                    }
                }
                Some(JudgeEntry::View(_)) | None => {}
            },
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
            Screen::Login(form) => self.key_login(form, key)?,
            Screen::Onboard(form) => self.key_onboard(form, key),
            Screen::Create(form) => self.key_create(form, key)?,
            Screen::Settings(form) => self.key_settings(form, key)?,
            Screen::Unlock(form) => self.key_unlock(form, key)?,
            Screen::Secrets(scr) => self.key_secrets(scr, key)?,
            Screen::SecretAdd(form) => self.key_secret_add(form, key)?,
            Screen::RecoveryCode(show) => self.key_recovery_code(show, key),
            Screen::Import(form) => self.key_import(form, key)?,
            Screen::Recover(form) => self.key_recover(form, key),
            Screen::Activity(scr) => self.key_activity(scr, key),
            Screen::Classify(form) => self.key_classify(form, key)?,
            Screen::Judge(form) => self.key_judge(form, key)?,
            Screen::Mcp => self.key_mcp(key),
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
    ///
    /// Global, vault-independent events (judge config + OpenRouter key changes,
    /// recorded at the `.svault` base) are folded in and sorted with the vault's
    /// own events, so a policy/judge change made from the `J` screen is visible
    /// in the audit timeline too.
    fn start_activity(&mut self) {
        let Some(v) = self.selected_vault() else {
            return;
        };
        let mut events = crate::core::usage::recent(&v.dir, 200);
        events.extend(crate::core::usage::recent(&svault_dir(), 200));
        // RFC 3339 UTC timestamps sort correctly lexicographically; newest first.
        events.sort_by(|a, b| b.ts.cmp(&a.ts));
        events.truncate(200);
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
    fn key_recovery_code(&mut self, show: RecoveryShow, key: KeyEvent) {
        if matches!(key.code, KeyCode::Char('y') | KeyCode::Char('Y')) {
            if show.to_judge {
                self.screen = Screen::Judge(JudgeForm::load());
            } else {
                self.screen = Screen::List;
            }
        } else {
            self.screen = Screen::RecoveryCode(show);
        }
    }

    // ── First-run onboarding ──────────────────────────────────────────────────

    fn key_onboard(&mut self, mut form: OnboardForm, key: KeyEvent) {
        match form.step {
            OnboardStep::Disclaimer => match key.code {
                KeyCode::Esc => self.should_quit = true,
                KeyCode::Enter => {
                    form.step = OnboardStep::Passphrase;
                    self.screen = Screen::Onboard(form);
                }
                _ => self.screen = Screen::Onboard(form),
            },
            OnboardStep::Passphrase => self.key_onboard_passphrase(form, key),
            OnboardStep::Recovery => {
                // Require an explicit 'y' that the code was saved before moving on.
                if matches!(key.code, KeyCode::Char('y') | KeyCode::Char('Y')) {
                    form.yubikey_present = crate::core::yubikey::is_present();
                    form.error = None;
                    form.step = OnboardStep::Yubikey;
                    self.screen = Screen::Onboard(form);
                } else {
                    self.screen = Screen::Onboard(form);
                }
            }
            OnboardStep::Yubikey => self.key_onboard_yubikey(form, key),
        }
    }

    fn key_onboard_passphrase(&mut self, mut form: OnboardForm, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => self.should_quit = true,
            KeyCode::Tab | KeyCode::Up | KeyCode::Down => {
                form.focus = 1 - form.focus;
                self.screen = Screen::Onboard(form);
            }
            KeyCode::Backspace => {
                if form.focus == 0 {
                    form.passphrase.pop();
                } else {
                    form.confirm.pop();
                }
                form.error = None;
                self.screen = Screen::Onboard(form);
            }
            KeyCode::Char(c) => {
                if form.focus == 0 {
                    form.passphrase.push(c);
                } else {
                    form.confirm.push(c);
                }
                form.error = None;
                self.screen = Screen::Onboard(form);
            }
            KeyCode::Enter => {
                // Enter advances from the passphrase field to confirm; from the
                // confirm field it submits.
                if form.focus == 0 {
                    form.focus = 1;
                    self.screen = Screen::Onboard(form);
                    return;
                }
                if let Err(e) = crate::core::passphrase::meets_floor(&form.passphrase) {
                    form.error = Some(e);
                    self.screen = Screen::Onboard(form);
                    return;
                }
                if form.passphrase != form.confirm {
                    form.error = Some("Passphrases do not match".into());
                    form.confirm.clear();
                    form.focus = 1;
                    self.screen = Screen::Onboard(form);
                    return;
                }
                match crate::core::master::Master::init(&form.passphrase) {
                    Ok(m) => {
                        let _ = crate::core::master::unlock_session(m.key_bytes());
                        form.recovery_code = m.write_recovery().ok();
                        form.passphrase.clear();
                        form.confirm.clear();
                        form.error = None;
                        form.step = OnboardStep::Recovery;
                        self.screen = Screen::Onboard(form);
                    }
                    Err(e) => {
                        form.error = Some(format!("{e}"));
                        self.screen = Screen::Onboard(form);
                    }
                }
            }
            _ => self.screen = Screen::Onboard(form),
        }
    }

    fn key_onboard_yubikey(&mut self, mut form: OnboardForm, key: KeyEvent) {
        match key.code {
            // Esc skips the optional step and finishes onboarding.
            KeyCode::Esc => self.finish_onboarding(),
            KeyCode::Enter => {
                // Re-check at the moment of action so a key removed while sitting
                // on this screen is caught here rather than as a confusing error.
                form.yubikey_present = crate::core::yubikey::is_present();
                if !form.yubikey_present {
                    form.error =
                        Some("No YubiKey detected — plug one in, or press Esc to skip".into());
                    self.screen = Screen::Onboard(form);
                    return;
                }
                // The blocking enroll (two touches) runs in the event loop after
                // this "touch now" frame draws — see run_fido.
                let pin = if form.pin.is_empty() {
                    None
                } else {
                    Some(form.pin.clone())
                };
                self.set_status(
                    MsgKind::Info,
                    "Touch your YubiKey now (twice to enroll)…".to_string(),
                );
                self.pending_fido = Some(PendingFido::Enroll { pin });
                form.error = None;
                self.screen = Screen::Onboard(form);
            }
            KeyCode::Backspace => {
                form.pin.pop();
                form.error = None;
                self.screen = Screen::Onboard(form);
            }
            KeyCode::Char(c) => {
                form.pin.push(c);
                form.error = None;
                self.screen = Screen::Onboard(form);
            }
            _ => self.screen = Screen::Onboard(form),
        }
    }

    fn finish_onboarding(&mut self) {
        self.refresh_vaults();
        self.set_status(
            MsgKind::Ok,
            "Master passphrase set. Press 'c' to create your first vault.".to_string(),
        );
        self.screen = Screen::List;
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
                let base = svault_dir();
                let base = base.as_path();
                let result = std::fs::read_to_string(path)
                    .map_err(|e| anyhow::anyhow!("cannot read {path}: {e}"))
                    .and_then(|raw| {
                        let bundle = crate::core::portable::parse_bundle(&raw)?;
                        let target = crate::core::portable::unique_vault_name(base, &bundle.name);
                        crate::core::portable::import_bundle_as(&raw, base, &target)?;
                        Ok((bundle.name, target))
                    });
                match result {
                    Ok((orig, target)) => {
                        let dir = base.join(&target);
                        crate::core::usage::human(&dir, "import", None);
                        if target == orig {
                            self.refresh_vaults();
                            self.set_status(MsgKind::Ok, format!("Imported '{target}'"));
                            self.screen = Screen::List;
                        } else {
                            // Name collided. The import is keyed by a random data
                            // key and its machine-specific keyslot is not bundled —
                            // bring it under the master via its recovery code, which
                            // also re-signs meta.name to match the new directory.
                            self.set_status(
                                MsgKind::Info,
                                format!("'{orig}' exists — importing as '{target}'; enter its recovery code to finish"),
                            );
                            self.screen = Screen::Recover(RecoverForm {
                                vault_dir: dir,
                                name: target,
                                code: String::new(),
                                new_pass: String::new(),
                                confirm: String::new(),
                                focus: 0,
                                error: None,
                            });
                        }
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
        // The recovery code unwraps the vault's data key directly (it never
        // changed). We then re-attach the vault to the master.
        let dek = match crate::core::recovery::unlock_with_code(&form.vault_dir, &form.code) {
            Ok(k) => k,
            Err(e) => {
                form.error = Some(format!("{e}"));
                form.code.clear();
                form.focus = 0;
                self.screen = Screen::Recover(form);
                return;
            }
        };
        // The passphrase fields set the master on first run, or open the
        // existing one to wrap the recovered key under it.
        let setting = !crate::core::master::exists();
        if setting {
            if let Err(e) = crate::core::passphrase::meets_floor(&form.new_pass) {
                form.error = Some(e);
                form.new_pass.clear();
                form.confirm.clear();
                form.focus = 1;
                self.screen = Screen::Recover(form);
                return;
            }
            if form.new_pass != form.confirm {
                form.error = Some("Master passphrases do not match".into());
                form.new_pass.clear();
                form.confirm.clear();
                form.focus = 1;
                self.screen = Screen::Recover(form);
                return;
            }
        }
        let master = if setting {
            match crate::core::master::Master::init(&form.new_pass) {
                Ok(m) => m,
                Err(e) => {
                    form.error = Some(format!("{e}"));
                    self.screen = Screen::Recover(form);
                    return;
                }
            }
        } else {
            match crate::core::master::Master::open(&form.new_pass) {
                Ok(m) => m,
                Err(_) => {
                    form.error = Some("Wrong master passphrase".into());
                    form.new_pass.clear();
                    form.confirm.clear();
                    form.focus = 1;
                    self.screen = Screen::Recover(form);
                    return;
                }
            }
        };
        let _ = crate::core::master::unlock_session(master.key_bytes());
        // Open with the recovered key so a renamed import can re-sign meta.name
        // to match its directory (a no-op for a normal recover), then wrap the
        // key under the master and cache the session.
        let vault = match Vault::open_with_key(&form.vault_dir, dek) {
            Ok(v) => v,
            Err(e) => {
                form.error = Some(format!("{e}"));
                self.screen = Screen::Recover(form);
                return;
            }
        };
        let leaf = form
            .vault_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        if !leaf.is_empty() && vault.meta.name != leaf {
            let mut meta = vault.meta.clone();
            meta.name = leaf;
            let _ = vault.save_meta(&meta);
        }
        if let Err(e) = master.wrap_dek(&form.vault_dir, vault.key()) {
            form.error = Some(format!("{e}"));
            self.screen = Screen::Recover(form);
            return;
        }
        let _ = session::unlock_with_key(&form.vault_dir, vault.key().bytes());
        crate::core::usage::human(&form.vault_dir, "recover", None);
        self.refresh_vaults();
        self.set_status(
            MsgKind::Ok,
            format!(
                "'{}' re-attached to your master passphrase. Recovery code unchanged.",
                form.name
            ),
        );
        self.screen = Screen::List;
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
            KeyCode::Char('o') => self.logout(),
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
            KeyCode::Char('J') => self.screen = Screen::Judge(JudgeForm::load()),
            KeyCode::Char('m') => self.screen = Screen::Mcp,
            KeyCode::Char('?') | KeyCode::Char('h') => self.show_help = true,
            KeyCode::Enter => self.open_secrets()?,
            _ => {}
        }
        Ok(())
    }

    /// MCP screen keys: write the client config, toggle the daemon precondition,
    /// or go back. The server itself is launched by the agent platform (it owns a
    /// stdio pipe), so there is nothing to "start" here — only to wire and arm.
    fn key_mcp(&mut self, key: KeyEvent) {
        self.screen = Screen::Mcp;
        match key.code {
            KeyCode::Esc | KeyCode::Char('b') | KeyCode::Char('q') => self.screen = Screen::List,
            KeyCode::Char('d') => self.toggle_daemon(),
            KeyCode::Char('w') => match write_mcp_config() {
                Ok(path) => self.set_status(MsgKind::Ok, format!("Wrote MCP config to {path}")),
                Err(e) => {
                    self.set_status(MsgKind::Error, format!("Could not write .mcp.json: {e}"))
                }
            },
            KeyCode::Char('?') | KeyCode::Char('h') => self.show_help = true,
            _ => {}
        }
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
        match crate::core::portable::build_bundle(&v.dir, &meta.name, &meta.storage) {
            Ok(json) => {
                let ts = chrono::Local::now().format("%Y%m%d-%H%M%S");
                let out = format!("{}-{}.svault-export.json", meta.name, ts);
                // The bundle wraps the vault key — write it owner-only, matching
                // the CLI export path. A default-umask write would be world-readable.
                match crate::core::secfile::write_owner_only(Path::new(&out), json.as_bytes()) {
                    Ok(_) => {
                        // Keep the bundle out of git so it can't be pushed by mistake.
                        crate::core::portable::ensure_export_gitignored(Path::new("."));
                        // Show the absolute path so the file is easy to find — a
                        // bare filename leaves the user guessing which directory.
                        let shown = std::fs::canonicalize(&out)
                            .map(|p| p.display().to_string())
                            .unwrap_or(out);
                        crate::core::usage::human(&v.dir, "export", None);
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
        if !crate::core::recovery::exists(&v.dir) {
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
            self.screen = Screen::Unlock(UnlockForm::new(v.dir, v.name, Pending::List));
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
        crate::core::usage::human(&v.dir, "lock", None);
        self.set_status(MsgKind::Ok, format!("Vault '{}' locked", v.name));
        self.refresh_vaults();
        Ok(())
    }

    /// Log out: clear the master "login" session and return to the login gate, so
    /// the master passphrase (or YubiKey) is required to use the TUI again.
    /// Deliberately leaves the vaults' own locked/unlocked state, the keyring, the
    /// daemon, the judge, and all data unchanged — this signs out, it doesn't lock
    /// or wipe anything.
    fn logout(&mut self) {
        let _ = crate::core::master::lock_session();
        self.set_status(
            MsgKind::Info,
            "Logged out. Enter your master passphrase to sign back in.".to_string(),
        );
        self.screen = Screen::Login(LoginForm::new());
    }

    /// Login gate: master passphrase entry, with `Ctrl+Y` for an enrolled YubiKey.
    /// On success the master session is cached and the vault list opens; the vaults
    /// keep whatever locked/unlocked state they already had.
    fn key_login(&mut self, mut form: LoginForm, key: KeyEvent) -> Result<()> {
        match key.code {
            // There is nothing behind the login gate, so Esc quits the app.
            KeyCode::Esc => self.confirm_quit = true,
            KeyCode::Enter => match crate::core::master::Master::open(&form.passphrase) {
                Ok(m) => {
                    let _ = crate::core::master::unlock_session(m.key_bytes());
                    self.refresh_vaults();
                    self.set_status(MsgKind::Ok, "Signed in.".to_string());
                    self.screen = Screen::List;
                }
                Err(_) => {
                    form.error = Some("Wrong master passphrase".into());
                    form.passphrase.clear();
                    self.screen = Screen::Login(form);
                }
            },
            // Ctrl+Y: sign in with the enrolled YubiKey. Any typed text is the
            // optional PIN. The blocking touch runs in the event loop (run_fido).
            KeyCode::Char('y') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                if !form.yubikey {
                    form.error = Some("No YubiKey enrolled or connected".into());
                    self.screen = Screen::Login(form);
                    return Ok(());
                }
                let pin = if form.passphrase.is_empty() {
                    None
                } else {
                    Some(form.passphrase.clone())
                };
                self.set_status(MsgKind::Info, "Touch your YubiKey now…".to_string());
                self.pending_fido = Some(PendingFido::Login { pin });
                form.error = None;
                self.screen = Screen::Login(form);
            }
            KeyCode::Backspace => {
                form.passphrase.pop();
                form.error = None;
                self.screen = Screen::Login(form);
            }
            KeyCode::Char(c) => {
                form.passphrase.push(c);
                form.error = None;
                self.screen = Screen::Login(form);
            }
            _ => self.screen = Screen::Login(form),
        }
        Ok(())
    }

    fn open_secrets(&mut self) -> Result<()> {
        let Some(v) = self.selected_vault() else {
            return Ok(());
        };
        if v.unlocked {
            self.enter_secrets(&v.dir, &v.name)?;
        } else {
            self.screen = Screen::Unlock(UnlockForm::new(v.dir, v.name, Pending::Secrets));
        }
        Ok(())
    }

    fn open_settings(&mut self) -> Result<()> {
        let Some(v) = self.selected_vault() else {
            return Ok(());
        };
        if !v.unlocked {
            self.screen = Screen::Unlock(UnlockForm::new(v.dir, v.name, Pending::Settings));
            return Ok(());
        }
        // Access + judge config are encrypted, so open the vault (it's unlocked)
        // to read the policy rather than the public meta.yaml.
        let Some(key) = session::get_key(&v.dir) else {
            self.screen = Screen::Unlock(UnlockForm::new(v.dir, v.name, Pending::Settings));
            return Ok(());
        };
        match Vault::open_with_key(&v.dir, VaultKey::from_bytes(key)) {
            Ok(vault) => {
                self.screen = Screen::Settings(SettingsForm::from_meta(
                    v.dir,
                    vault.meta.clone(),
                    &vault.policy,
                ));
            }
            Err(e) => self.set_status(MsgKind::Error, format!("Cannot open vault: {e}")),
        }
        Ok(())
    }

    /// Open the vault with the cached passphrase and show its secret list.
    fn enter_secrets(&mut self, dir: &Path, name: &str) -> Result<()> {
        let Some(key) = session::get_key(dir) else {
            self.screen = Screen::Unlock(UnlockForm::new(
                dir.to_path_buf(),
                name.to_string(),
                Pending::Secrets,
            ));
            return Ok(());
        };
        match Vault::open_with_key(dir, VaultKey::from_bytes(key)) {
            Ok(vault) => {
                let secrets = vault.list_secret_names().unwrap_or_default();
                let mut list_state = TableState::default();
                if !secrets.is_empty() {
                    list_state.select(Some(0));
                }
                self.screen = Screen::Secrets(SecretScreen {
                    vault_dir: dir.to_path_buf(),
                    name: name.to_string(),
                    classifications: vault.policy.secrets.clone(),
                    seals: vault.policy.seals.clone(),
                    default_tier: tier_idx(vault.policy.default_tier),
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

    /// Clear a seal on `secret` in `scr`'s vault and refresh the screen's view.
    /// Human-only: uses the unlocked session key to rewrite the encrypted policy.
    fn approve_seal(&mut self, scr: &mut SecretScreen, secret: &str) {
        let Some(key) = session::get_key(&scr.vault_dir) else {
            self.set_status(MsgKind::Error, "Vault is locked");
            return;
        };
        match Vault::open_with_key(&scr.vault_dir, VaultKey::from_bytes(key)) {
            Ok(vault) => {
                let mut policy = vault.policy.clone();
                policy.seals.remove(secret);
                match vault.save_policy(&policy) {
                    Ok(_) => {
                        crate::core::usage::human(&scr.vault_dir, "seal.cleared", Some(secret));
                        scr.seals.remove(secret);
                        self.set_status(
                            MsgKind::Ok,
                            format!("Cleared the seal on '{secret}' — agents may request it again"),
                        );
                    }
                    Err(e) => self.set_status(MsgKind::Error, format!("Could not save: {e}")),
                }
            }
            Err(e) => self.set_status(MsgKind::Error, format!("Cannot open vault: {e}")),
        }
    }

    // ── Create screen ───────────────────────────────────────────────────────

    fn key_create(&mut self, mut form: CreateForm, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Esc => {
                self.screen = Screen::List;
                return Ok(());
            }
            KeyCode::Tab | KeyCode::Down => form.focus = (form.focus + 1) % form.fields(),
            KeyCode::BackTab | KeyCode::Up => {
                form.focus = (form.focus + form.fields() - 1) % form.fields()
            }
            KeyCode::Enter => {
                if form.focus == form.fields() - 1 {
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
                if c == ' ' && form.current() == CreateField::Autolock {
                    form.autolock = !form.autolock; // space toggles auto-lock
                } else if c == ' ' && form.current() == CreateField::Judge {
                    form.judge = !form.judge;
                } else if c == ' ' && form.current() == CreateField::JudgeName {
                    form.judge_name = cycle_judge_name(&form.judge_name, &form.judge_choices, true);
                } else if c == ' ' && form.current() == CreateField::DefaultTier {
                    form.default_tier = cycle(form.default_tier, 3, true);
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
        // First-run create also sets the master, which gets its own recovery code.
        let setting_master = form.master_step == MasterStep::Set;
        let vault_dir = svault_dir().join(&name);
        if vault_dir.exists() {
            let existing = VaultMeta::load_unverified(&vault_dir)
                .map(|m| m.storage)
                .unwrap_or_else(|_| "local".to_string());
            form.error = Some(format!(
                "a vault named '{name}' already exists ({existing}:{name}) — vault names must be unique"
            ));
            self.screen = Screen::Create(form);
            return Ok(());
        }
        // Resolve the master passphrase that wraps this vault's data key:
        // reuse the session, prompt the existing master, or set one on first run.
        let master = match form.master_step {
            MasterStep::Ready => match crate::core::master::open_from_session() {
                Some(m) => m,
                None => {
                    form.error = Some("master session expired — reopen the create screen".into());
                    self.screen = Screen::Create(form);
                    return Ok(());
                }
            },
            MasterStep::Unlock => {
                if form.passphrase.is_empty() {
                    form.error = Some("Master passphrase is required".into());
                    self.screen = Screen::Create(form);
                    return Ok(());
                }
                match crate::core::master::Master::open(&form.passphrase) {
                    Ok(m) => {
                        let _ = crate::core::master::unlock_session(m.key_bytes());
                        m
                    }
                    Err(_) => {
                        form.error = Some("Wrong master passphrase".into());
                        form.passphrase.clear();
                        self.screen = Screen::Create(form);
                        return Ok(());
                    }
                }
            }
            MasterStep::Set => {
                if form.passphrase.is_empty() {
                    form.error = Some("Master passphrase is required".into());
                    self.screen = Screen::Create(form);
                    return Ok(());
                }
                if let Err(e) = crate::core::passphrase::meets_floor(&form.passphrase) {
                    form.error = Some(e);
                    self.screen = Screen::Create(form);
                    return Ok(());
                }
                if form.passphrase != form.confirm {
                    form.error = Some("Master passphrases do not match".into());
                    self.screen = Screen::Create(form);
                    return Ok(());
                }
                match crate::core::master::Master::init(&form.passphrase) {
                    Ok(m) => {
                        let _ = crate::core::master::unlock_session(m.key_bytes());
                        m
                    }
                    Err(e) => {
                        form.error = Some(format!("{e}"));
                        self.screen = Screen::Create(form);
                        return Ok(());
                    }
                }
            }
        };

        let allow_agent = match form.allow_mode {
            0 => AllowAgent::Bool(true),
            1 => AllowAgent::Bool(false),
            _ => AllowAgent::List(parse_agents(&form.allow_list)),
        };
        // Storage is local and login is passphrase; VaultMeta defaults to
        // "local" storage, so we only carry the wired settings forward.
        let meta = VaultMeta::new(
            name.clone(),
            form.description.clone(),
            VaultSettings {
                autolock: form.autolock,
                autolock_timer: form.autolock_timer.clone(),
                login_method: LoginMethod::Passphrase,
            },
        );
        // The access rules, default tier, and judge override are encrypted in
        // the vault payload, not the plaintext meta.yaml.
        let mut vault_policy = crate::core::policy::VaultPolicyData {
            access: AccessConfig {
                allow_agent,
                rate_limit: form.rate_limit.clone(),
            },
            default_tier: tier_at(form.default_tier),
            ..crate::core::policy::VaultPolicyData::default()
        };
        vault_policy.judge.enabled = Some(form.judge);
        vault_policy.judge.judge = form.judge_name.clone();

        // Random data key encrypts the vault; wrap it under the master so the
        // single master passphrase opens it.
        let dek = crate::core::master::new_dek();
        match Vault::init_with_key(&vault_dir, dek, meta, vault_policy) {
            Ok(vault) => {
                if let Err(e) = master.wrap_dek(&vault_dir, vault.key()) {
                    form.error = Some(format!("could not wrap vault under master: {e}"));
                    self.screen = Screen::Create(form);
                    return Ok(());
                }
                let _ = session::unlock_with_key(&vault_dir, vault.key().bytes());
                // Generate and store the recovery code(s), then show them once.
                let mut codes: Vec<(String, String)> = Vec::new();
                // If this create just set the master, surface the master recovery
                // code too — it's the way back in if the master is forgotten.
                if setting_master {
                    match master.write_recovery() {
                        Ok(mc) => codes.push(("Master passphrase".to_string(), mc)),
                        Err(e) => self.set_status(
                            MsgKind::Warn,
                            format!("master recovery code could not be saved: {e}"),
                        ),
                    }
                }
                let code = crate::core::recovery::generate_code();
                if let Err(e) = crate::core::recovery::write(&vault_dir, vault.key(), &code) {
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
                codes.push((format!("Vault '{name}'"), code));
                crate::core::usage::human(&vault_dir, "vault.create", None);
                self.refresh_vaults();
                self.set_status(MsgKind::Ok, format!("Vault '{name}' created"));
                self.screen = Screen::RecoveryCode(RecoveryShow {
                    codes,
                    to_judge: false,
                });
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
                if c == ' ' && form.current() == SettingsField::Autolock {
                    form.autolock = !form.autolock;
                } else if c == ' ' && form.current() == SettingsField::Judge {
                    form.judge = !form.judge;
                } else if c == ' ' && form.current() == SettingsField::JudgeName {
                    form.judge_name = cycle_judge_name(&form.judge_name, &form.judge_choices, true);
                } else if c == ' ' && form.current() == SettingsField::DefaultTier {
                    form.default_tier = cycle(form.default_tier, 3, true);
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
        let Some(key) = session::get_key(&form.vault_dir) else {
            self.set_status(
                MsgKind::Error,
                "Vault is locked — unlock before editing settings",
            );
            self.screen = Screen::List;
            return Ok(());
        };
        let vault = match Vault::open_with_key(&form.vault_dir, VaultKey::from_bytes(key)) {
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

        // Public meta gets the description + behavioural settings; the policy
        // surface (access, default tier, judge override) is written encrypted.
        let mut meta = vault.meta.clone();
        meta.description = form.description.clone();
        meta.settings.autolock = form.autolock;
        meta.settings.autolock_timer = form.autolock_timer.clone();

        let mut vault_policy = vault.policy.clone();
        vault_policy.access.allow_agent = allow_agent;
        vault_policy.access.rate_limit = form.rate_limit.clone();
        vault_policy.default_tier = tier_at(form.default_tier);
        vault_policy.judge.enabled = Some(form.judge);
        vault_policy.judge.judge = form.judge_name.clone();

        match vault
            .save_meta(&meta)
            .and_then(|_| vault.save_policy(&vault_policy))
        {
            Ok(_) => {
                crate::core::usage::human(&form.vault_dir, "settings.update", None);
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
            KeyCode::Enter => match self.unlock_via_master(&form.vault_dir, &form.passphrase) {
                Ok(vault) => self.after_unlock(form, vault)?,
                Err(e) => {
                    form.error = Some(e);
                    form.passphrase.clear();
                    self.screen = Screen::Unlock(form);
                }
            },
            // Ctrl+Y: unlock with the enrolled YubiKey. Any text typed into the
            // field is treated as the (optional) YubiKey PIN; empty means none.
            KeyCode::Char('y') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                if !form.yubikey {
                    form.error = Some("No YubiKey enrolled or connected".into());
                    self.screen = Screen::Unlock(form);
                    return Ok(());
                }
                // The blocking touch runs in the event loop (see run_fido) after
                // this "touch now" frame draws — never inline on a stale frame.
                let pin = if form.passphrase.is_empty() {
                    None
                } else {
                    Some(form.passphrase.clone())
                };
                self.set_status(MsgKind::Info, "Touch your YubiKey now…".to_string());
                self.pending_fido = Some(PendingFido::Unlock {
                    vault_dir: form.vault_dir.clone(),
                    name: form.name.clone(),
                    pending: form.pending,
                    pin,
                });
                form.error = None;
                self.screen = Screen::Unlock(form);
            }
            KeyCode::Char(c) => {
                form.passphrase.push(c);
                form.error = None;
                self.screen = Screen::Unlock(form);
            }
            _ => self.screen = Screen::Unlock(form),
        }
        Ok(())
    }

    /// Post-unlock dispatch shared by the passphrase and YubiKey paths: record
    /// usage, refresh, and route to the pending screen.
    fn after_unlock(&mut self, form: UnlockForm, vault: Vault) -> Result<()> {
        crate::core::usage::human(&form.vault_dir, "unlock", None);
        self.refresh_vaults();
        self.set_status(MsgKind::Ok, format!("Vault '{}' unlocked", form.name));
        match form.pending {
            Pending::List => self.screen = Screen::List,
            Pending::Secrets => self.enter_secrets(&form.vault_dir, &form.name)?,
            Pending::Settings => {
                self.screen = Screen::Settings(SettingsForm::from_meta(
                    form.vault_dir,
                    vault.meta.clone(),
                    &vault.policy,
                ));
            }
        }
        Ok(())
    }

    /// Open a vault via the enrolled YubiKey (touch + optional PIN): derive the
    /// master from the hardware slot, then unwrap the vault's data key — the
    /// hardware analogue of [`Self::unlock_via_master`].
    fn unlock_via_yubikey(
        &mut self,
        vault_dir: &Path,
        pin: Option<&str>,
    ) -> std::result::Result<Vault, String> {
        let master = crate::core::master::open_with_yubikey(pin).map_err(|e| format!("{e}"))?;
        let _ = crate::core::master::unlock_session(master.key_bytes());
        if !crate::core::master::vault_has_keyslot(vault_dir) {
            return Err("vault is not wrapped under the master (no keyslot)".to_string());
        }
        let dek = master
            .unwrap_dek(vault_dir)
            .map_err(|_| "could not unwrap the vault key with this master".to_string())?;
        session::unlock_with_key(vault_dir, dek.bytes())
            .map_err(|e| format!("could not cache session: {e}"))?;
        Vault::open_with_key(vault_dir, dek).map_err(|e| format!("{e}"))
    }

    /// Open a vault via the master passphrase: open (or set) the master, unwrap
    /// the vault's data key from its keyslot, cache the session, and return the
    /// open vault. The single place the TUI turns a typed master passphrase into
    /// an unlocked vault. Returns a user-facing error string on failure.
    fn unlock_via_master(
        &mut self,
        vault_dir: &Path,
        passphrase: &str,
    ) -> std::result::Result<Vault, String> {
        let master = if crate::core::master::exists() {
            crate::core::master::Master::open(passphrase)
                .map_err(|_| "Wrong master passphrase".to_string())?
        } else {
            // No master yet (e.g. a legacy/imported vault on a fresh machine):
            // set one now from the typed passphrase.
            crate::core::passphrase::meets_floor(passphrase)?;
            crate::core::master::Master::init(passphrase).map_err(|e| format!("{e}"))?
        };
        let _ = crate::core::master::unlock_session(master.key_bytes());

        if !crate::core::master::vault_has_keyslot(vault_dir) {
            return Err("vault is not wrapped under the master (no keyslot)".to_string());
        }
        let dek = master
            .unwrap_dek(vault_dir)
            .map_err(|_| "could not unwrap the vault key with this master".to_string())?;
        session::unlock_with_key(vault_dir, dek.bytes())
            .map_err(|e| format!("could not cache session: {e}"))?;
        Vault::open_with_key(vault_dir, dek).map_err(|e| format!("{e}"))
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
                // Default the tier to the vault's default tier (from the policy).
                let default_tier = scr.default_tier;
                self.screen = Screen::SecretAdd(SecretAddForm {
                    vault_dir: scr.vault_dir.clone(),
                    vault_name: scr.name.clone(),
                    name: String::new(),
                    value: String::new(),
                    scope: "misc".to_string(),
                    description: String::new(),
                    tier: default_tier,
                    require_reason: false,
                    focus: 0,
                    error: None,
                });
                return Ok(());
            }
            KeyCode::Char('c') => {
                if let Some(name) = scr.selected_name() {
                    // Prefill from the existing classification, or the vault's
                    // default tier when the secret has none yet.
                    let rule = scr.classifications.get(&name).cloned();
                    let default_tier = scr.default_tier;
                    self.screen = Screen::Classify(ClassifyForm {
                        vault_dir: scr.vault_dir.clone(),
                        vault_name: scr.name.clone(),
                        secret: name.clone(),
                        scope: rule
                            .as_ref()
                            .map(|r| r.scope.clone())
                            .filter(|s| !s.is_empty())
                            .unwrap_or_else(|| "misc".to_string()),
                        description: rule
                            .as_ref()
                            .map(|r| r.description.clone())
                            .unwrap_or_default(),
                        windows: rule
                            .as_ref()
                            .map(|r| {
                                r.windows
                                    .iter()
                                    .map(|w| w.to_string())
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            })
                            .unwrap_or_default(),
                        require_callers: rule
                            .as_ref()
                            .map(|r| r.require_callers.join(", "))
                            .unwrap_or_default(),
                        tier: rule
                            .as_ref()
                            .map(|r| tier_idx(r.tier))
                            .unwrap_or(default_tier),
                        require_reason: rule.as_ref().map(|r| r.require_reason).unwrap_or(false),
                        focus: 0,
                        error: None,
                    });
                    return Ok(());
                }
            }
            KeyCode::Enter | KeyCode::Char('g') => self.reveal_secret(&mut scr),
            // Approve: clear the seal on the selected secret (human-only).
            KeyCode::Char('A') => {
                if let Some(name) = scr.selected_name() {
                    if scr.seals.contains_key(&name) {
                        self.approve_seal(&mut scr, &name);
                    } else {
                        self.set_status(MsgKind::Info, format!("'{name}' is not sealed"));
                    }
                }
            }
            KeyCode::Char('d') => {
                if let Some(name) = scr.selected_name() {
                    scr.pending_delete = Some(name);
                }
            }
            KeyCode::Char('l') => {
                session::lock(&scr.vault_dir)?;
                crate::core::usage::human(&scr.vault_dir, "lock", None);
                self.set_status(MsgKind::Ok, format!("Vault '{}' locked", scr.name));
                self.refresh_vaults();
                self.screen = Screen::List;
                return Ok(());
            }
            KeyCode::Char('?') | KeyCode::Char('h') => self.show_help = true,
            _ => {}
        }
        self.screen = Screen::Secrets(scr);
        Ok(())
    }

    fn reveal_secret(&mut self, scr: &mut SecretScreen) {
        let Some(name) = scr.selected_name() else {
            return;
        };
        let Some(key) = session::get_key(&scr.vault_dir) else {
            self.set_status(MsgKind::Error, "Vault is locked");
            return;
        };
        match Vault::open_with_key(&scr.vault_dir, VaultKey::from_bytes(key))
            .and_then(|v| v.get_secret(&name))
        {
            Ok(Some(value)) => {
                crate::core::usage::human(&scr.vault_dir, "secret.reveal", Some(&name));
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
        let Some(key) = session::get_key(&scr.vault_dir) else {
            self.set_status(MsgKind::Error, "Vault is locked");
            return;
        };
        match Vault::open_with_key(&scr.vault_dir, VaultKey::from_bytes(key)) {
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
                    crate::core::usage::human(&scr.vault_dir, "secret.remove", Some(name));
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
            KeyCode::Tab | KeyCode::Down => form.focus = (form.focus + 1) % SecretAddForm::FIELDS,
            KeyCode::BackTab | KeyCode::Up => {
                form.focus = (form.focus + SecretAddForm::FIELDS - 1) % SecretAddForm::FIELDS
            }
            KeyCode::Left => secret_add_adjust(&mut form, false),
            KeyCode::Right => secret_add_adjust(&mut form, true),
            KeyCode::Enter => {
                if form.focus == SecretAddForm::FIELDS - 1 {
                    return self.submit_secret_add(form);
                }
                form.focus += 1;
            }
            KeyCode::Backspace => match form.focus {
                0 => {
                    form.name.pop();
                }
                1 => {
                    form.value.pop();
                }
                2 => {
                    form.scope.pop();
                }
                3 => {
                    form.description.pop();
                }
                _ => {}
            },
            KeyCode::Char(c) => match form.focus {
                0 => {
                    form.name.push(c);
                    form.error = None;
                }
                1 => {
                    form.value.push(c);
                    form.error = None;
                }
                2 => {
                    form.scope.push(c);
                    form.error = None;
                }
                3 => {
                    form.description.push(c);
                    form.error = None;
                }
                4 if c == ' ' => form.tier = cycle(form.tier, 3, true),
                5 if c == ' ' => form.require_reason = !form.require_reason,
                _ => {}
            },
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
        let Some(key) = session::get_key(&form.vault_dir) else {
            self.set_status(MsgKind::Error, "Vault is locked");
            self.screen = Screen::List;
            return Ok(());
        };
        match Vault::open_with_key(&form.vault_dir, VaultKey::from_bytes(key)) {
            Ok(vault) => match vault.add_secret(form.name.trim(), &form.value) {
                Ok(_) => {
                    // Classify in the encrypted policy so the gate applies to
                    // TUI-added secrets too (scope/tier/require_reason from the form).
                    let scope = if form.scope.trim().is_empty() {
                        "misc".to_string()
                    } else {
                        form.scope.trim().to_string()
                    };
                    let mut vault_policy = vault.policy.clone();
                    vault_policy.secrets.insert(
                        form.name.trim().to_string(),
                        crate::core::policy::SecretRule {
                            scope,
                            tier: tier_at(form.tier),
                            require_reason: form.require_reason,
                            description: form.description.trim().to_string(),
                            ..Default::default()
                        },
                    );
                    let _ = vault.save_policy(&vault_policy);
                    crate::core::usage::human(
                        &form.vault_dir,
                        "secret.add",
                        Some(form.name.trim()),
                    );
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

    // ── Classify screen ───────────────────────────────────────────────────────

    fn key_classify(&mut self, mut form: ClassifyForm, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Esc => {
                let (dir, name) = (form.vault_dir.clone(), form.vault_name.clone());
                self.enter_secrets(&dir, &name)?;
                return Ok(());
            }
            KeyCode::Tab | KeyCode::Down => form.focus = (form.focus + 1) % ClassifyForm::FIELDS,
            KeyCode::BackTab | KeyCode::Up => {
                form.focus = (form.focus + ClassifyForm::FIELDS - 1) % ClassifyForm::FIELDS
            }
            KeyCode::Left => classify_adjust(&mut form, false),
            KeyCode::Right => classify_adjust(&mut form, true),
            KeyCode::Enter => {
                if form.focus == ClassifyForm::FIELDS - 1 {
                    return self.submit_classify(form);
                }
                form.focus += 1;
            }
            KeyCode::Backspace => match form.focus {
                0 => {
                    form.scope.pop();
                }
                1 => {
                    form.description.pop();
                }
                2 => {
                    form.windows.pop();
                }
                3 => {
                    form.require_callers.pop();
                }
                _ => {}
            },
            KeyCode::Char(c) => match form.focus {
                0 => {
                    form.scope.push(c);
                    form.error = None;
                }
                1 => {
                    form.description.push(c);
                    form.error = None;
                }
                2 => {
                    form.windows.push(c);
                    form.error = None;
                }
                3 => {
                    form.require_callers.push(c);
                    form.error = None;
                }
                4 if c == ' ' => form.tier = cycle(form.tier, 3, true),
                5 if c == ' ' => form.require_reason = !form.require_reason,
                _ => {}
            },
            _ => {}
        }
        self.screen = Screen::Classify(form);
        Ok(())
    }

    fn submit_classify(&mut self, mut form: ClassifyForm) -> Result<()> {
        let Some(key) = session::get_key(&form.vault_dir) else {
            self.set_status(MsgKind::Error, "Vault is locked");
            self.screen = Screen::List;
            return Ok(());
        };
        match Vault::open_with_key(&form.vault_dir, VaultKey::from_bytes(key)) {
            Ok(vault) => {
                let scope = if form.scope.trim().is_empty() {
                    "misc".to_string()
                } else {
                    form.scope.trim().to_string()
                };
                // Parse conditional-access fields; a bad window spec re-shows the
                // form with the error rather than silently dropping it.
                let mut windows = Vec::new();
                for spec in split_list(&form.windows) {
                    match crate::core::policy::AccessWindow::parse(&spec) {
                        Ok(w) => windows.push(w),
                        Err(e) => {
                            form.error = Some(format!("window '{spec}': {e}"));
                            form.focus = 2;
                            self.screen = Screen::Classify(form);
                            return Ok(());
                        }
                    }
                }
                let require_callers = split_list(&form.require_callers);
                let mut vault_policy = vault.policy.clone();
                vault_policy.secrets.insert(
                    form.secret.clone(),
                    SecretRule {
                        scope,
                        tier: tier_at(form.tier),
                        require_reason: form.require_reason,
                        description: form.description.trim().to_string(),
                        windows,
                        require_callers,
                    },
                );
                match vault.save_policy(&vault_policy) {
                    Ok(_) => {
                        crate::core::usage::human(
                            &form.vault_dir,
                            "secret.classify",
                            Some(&form.secret),
                        );
                        self.set_status(
                            MsgKind::Ok,
                            format!("Classification for '{}' saved", form.secret),
                        );
                        let (dir, name) = (form.vault_dir.clone(), form.vault_name.clone());
                        self.enter_secrets(&dir, &name)?;
                    }
                    Err(e) => {
                        form.error = Some(format!("{e}"));
                        self.screen = Screen::Classify(form);
                    }
                }
            }
            Err(e) => {
                form.error = Some(format!("{e}"));
                self.screen = Screen::Classify(form);
            }
        }
        Ok(())
    }

    // ── Judge management screen ─────────────────────────────────────────────────

    fn key_judge(&mut self, mut form: JudgeForm, key: KeyEvent) -> Result<()> {
        // Overlaid sub-mode: unlock/create keyring, key entry, add/edit, view.
        if let Some(entry) = form.entry.take() {
            return match entry {
                JudgeEntry::Passphrase(buf) => self.key_judge_passphrase(form, buf, key),
                JudgeEntry::Init(init) => self.key_judge_init(form, init, key),
                JudgeEntry::Key { judge, buf } => self.key_judge_key(form, judge, buf, key),
                JudgeEntry::Edit(ed) => self.key_judge_edit(form, ed, key),
                JudgeEntry::View(name) => {
                    // `e` jumps to the editor; any other key closes the view.
                    if key.code == KeyCode::Char('e') {
                        if let Some(ed) = crate::core::keyring::open_from_session().and_then(|kr| {
                            kr.data
                                .judges
                                .get(&name)
                                .map(|d| JudgeEditForm::edit(&name, d))
                        }) {
                            form.entry = Some(JudgeEntry::Edit(ed));
                        }
                    }
                    self.screen = Screen::Judge(form);
                    Ok(())
                }
            };
        }

        if key.code == KeyCode::Esc {
            self.screen = Screen::List;
            return Ok(());
        }
        // Locked: Enter unlocks an existing keyring, or creates one — both under
        // the master passphrase (there is no separate keyring passphrase).
        if !form.unlocked {
            if key.code == KeyCode::Enter {
                form.error = None;
                // Master already unlocked → do it now, no prompt.
                if crate::core::master::is_unlocked() {
                    return self.keyring_via_session(form);
                }
                // Otherwise prompt the master passphrase. A created keyring always
                // has a master; only first-ever use (no keyring, no master) sets
                // one (pass + confirm) before creating the keyring.
                form.entry = Some(if form.created || crate::core::master::exists() {
                    JudgeEntry::Passphrase(String::new())
                } else {
                    JudgeEntry::Init(InitForm::new())
                });
            }
            self.screen = Screen::Judge(form);
            return Ok(());
        }

        match key.code {
            KeyCode::Up | KeyCode::BackTab => {
                let n = form.rows();
                form.focus = (form.focus + n - 1) % n;
            }
            KeyCode::Down | KeyCode::Tab => {
                let n = form.rows();
                form.focus = (form.focus + 1) % n;
            }
            KeyCode::Char(' ') | KeyCode::Left | KeyCode::Right | KeyCode::Enter
                if form.focus == 0 =>
            {
                self.toggle_judge_enabled(&mut form);
            }
            KeyCode::Char('a') => {
                form.entry = Some(JudgeEntry::Edit(JudgeEditForm::add()));
                form.error = None;
            }
            KeyCode::Char('e') if form.selected_judge().is_some() => {
                let name = form.selected_judge().unwrap().name.clone();
                match crate::core::keyring::open_from_session().and_then(|kr| {
                    kr.data
                        .judges
                        .get(&name)
                        .map(|d| JudgeEditForm::edit(&name, d))
                }) {
                    Some(ed) => {
                        form.entry = Some(JudgeEntry::Edit(ed));
                        form.error = None;
                    }
                    None => form.error = Some("keyring is locked".into()),
                }
            }
            KeyCode::Enter | KeyCode::Char('v') if form.selected_judge().is_some() => {
                let name = form.selected_judge().unwrap().name.clone();
                form.entry = Some(JudgeEntry::View(name));
                form.error = None;
            }
            KeyCode::Char('k') if form.selected_judge().is_some() => {
                let name = form.selected_judge().unwrap().name.clone();
                form.entry = Some(JudgeEntry::Key {
                    judge: name,
                    buf: String::new(),
                });
                form.error = None;
            }
            KeyCode::Char('d') if form.selected_judge().is_some() => {
                let name = form.selected_judge().unwrap().name.clone();
                self.set_judge_default(&mut form, &name);
            }
            KeyCode::Char('t') if form.selected_judge().is_some() => {
                let name = form.selected_judge().unwrap().name.clone();
                self.run_judge_test(&mut form, &name);
            }
            KeyCode::Char('x') | KeyCode::Delete if form.selected_judge().is_some() => {
                let name = form.selected_judge().unwrap().name.clone();
                self.remove_judge(&mut form, &name);
            }
            _ => {}
        }
        self.screen = Screen::Judge(form);
        Ok(())
    }

    /// Open the master from a typed passphrase, then unlock (or create) the
    /// keyring under it. The keyring has no passphrase of its own.
    fn key_judge_passphrase(
        &mut self,
        mut form: JudgeForm,
        mut buf: String,
        key: KeyEvent,
    ) -> Result<()> {
        match key.code {
            KeyCode::Esc => {
                self.screen = Screen::List;
                return Ok(());
            }
            KeyCode::Backspace => {
                buf.pop();
                form.entry = Some(JudgeEntry::Passphrase(buf));
            }
            KeyCode::Char(c) => {
                buf.push(c);
                form.entry = Some(JudgeEntry::Passphrase(buf));
            }
            KeyCode::Enter => {
                let created = form.created;
                match crate::core::master::Master::open(&buf) {
                    Ok(master) => {
                        let _ = crate::core::master::unlock_session(master.key_bytes());
                        match self.keyring_with_master(&master, created) {
                            Ok(()) => {
                                form = JudgeForm::load();
                                self.set_status(MsgKind::Ok, keyring_done_msg(created));
                            }
                            Err(e) => {
                                form.error = Some(e);
                                form.entry = Some(JudgeEntry::Passphrase(buf));
                            }
                        }
                    }
                    Err(_) => {
                        form.error = Some("wrong master passphrase".into());
                        form.entry = Some(JudgeEntry::Passphrase(buf));
                    }
                }
            }
            _ => form.entry = Some(JudgeEntry::Passphrase(buf)),
        }
        self.screen = Screen::Judge(form);
        Ok(())
    }

    /// With an already-unlocked master session, unlock or create the keyring with
    /// no further prompt.
    fn keyring_via_session(&mut self, mut form: JudgeForm) -> Result<()> {
        let created = form.created;
        match crate::core::master::open_from_session() {
            Some(master) => match self.keyring_with_master(&master, created) {
                Ok(()) => {
                    let f = JudgeForm::load();
                    self.set_status(MsgKind::Ok, keyring_done_msg(created));
                    self.screen = Screen::Judge(f);
                }
                Err(e) => {
                    form.error = Some(e);
                    self.screen = Screen::Judge(form);
                }
            },
            None => {
                form.error = Some("master session expired — press Enter again".into());
                self.screen = Screen::Judge(form);
            }
        }
        Ok(())
    }

    /// Given an open master, unlock the existing keyring (unwrap its DEK) or
    /// create a fresh one wrapped under the master; cache the keyring session.
    fn keyring_with_master(
        &mut self,
        master: &crate::core::master::Master,
        created: bool,
    ) -> std::result::Result<(), String> {
        if created {
            if !crate::core::master::keyring_has_keyslot() {
                return Err("the keyring has no master keyslot — wipe .svault/ and re-init".into());
            }
            let dek = master.unwrap_keyring_dek().map_err(|e| format!("{e}"))?;
            crate::core::keyring::unlock_session(dek.bytes()).map_err(|e| format!("{e}"))?;
        } else {
            let dek = crate::core::master::new_dek();
            let kr =
                crate::core::keyring::Keyring::init_with_key(dek).map_err(|e| format!("{e}"))?;
            master
                .wrap_keyring_dek(kr.key())
                .map_err(|e| format!("{e}"))?;
            crate::core::keyring::unlock_session(kr.key().bytes()).map_err(|e| format!("{e}"))?;
        }
        Ok(())
    }

    /// Set a brand-new master passphrase (pass + confirm), then create the
    /// keyring under it. Only reached on first use when no master exists yet.
    fn key_judge_init(
        &mut self,
        mut form: JudgeForm,
        mut init: InitForm,
        key: KeyEvent,
    ) -> Result<()> {
        match key.code {
            KeyCode::Esc => {
                self.screen = Screen::List;
                return Ok(());
            }
            KeyCode::Tab | KeyCode::Down | KeyCode::Up | KeyCode::BackTab => {
                init.focus ^= 1;
            }
            KeyCode::Backspace => {
                if init.focus == 0 {
                    init.pass.pop();
                } else {
                    init.confirm.pop();
                }
            }
            KeyCode::Char(c) => {
                if init.focus == 0 {
                    init.pass.push(c);
                } else {
                    init.confirm.push(c);
                }
            }
            KeyCode::Enter => {
                if init.focus == 0 {
                    init.focus = 1;
                } else {
                    return self.submit_keyring_init(form, init);
                }
            }
            _ => {}
        }
        form.entry = Some(JudgeEntry::Init(init));
        self.screen = Screen::Judge(form);
        Ok(())
    }

    fn submit_keyring_init(&mut self, mut form: JudgeForm, mut init: InitForm) -> Result<()> {
        if let Err(e) = crate::core::passphrase::meets_floor(&init.pass) {
            init.error = Some(e);
            init.focus = 0;
        } else if init.pass != init.confirm {
            init.error = Some("passphrases do not match".into());
            init.focus = 1;
        } else {
            match crate::core::master::Master::init(&init.pass) {
                Ok(master) => {
                    let _ = crate::core::master::unlock_session(master.key_bytes());
                    match self.keyring_with_master(&master, false) {
                        Ok(()) => {
                            self.set_status(
                                MsgKind::Ok,
                                "Master set · keyring created and unlocked",
                            );
                            // Show the master recovery code once, then return to
                            // the (now unlocked) judge screen.
                            self.screen = match master.write_recovery() {
                                Ok(mc) => Screen::RecoveryCode(RecoveryShow {
                                    codes: vec![("Master passphrase".to_string(), mc)],
                                    to_judge: true,
                                }),
                                Err(_) => Screen::Judge(JudgeForm::load()),
                            };
                            return Ok(());
                        }
                        Err(e) => init.error = Some(e),
                    }
                }
                Err(e) => init.error = Some(format!("could not set master passphrase: {e}")),
            }
        }
        form.entry = Some(JudgeEntry::Init(init));
        self.screen = Screen::Judge(form);
        Ok(())
    }

    /// Type (or clear) the selected judge's API key.
    fn key_judge_key(
        &mut self,
        mut form: JudgeForm,
        judge: String,
        mut buf: String,
        key: KeyEvent,
    ) -> Result<()> {
        match key.code {
            KeyCode::Esc => {}
            KeyCode::Backspace => {
                buf.pop();
                form.entry = Some(JudgeEntry::Key { judge, buf });
            }
            KeyCode::Char(c) => {
                buf.push(c);
                form.entry = Some(JudgeEntry::Key { judge, buf });
            }
            KeyCode::Enter => self.set_judge_key(&mut form, &judge, &buf),
            _ => form.entry = Some(JudgeEntry::Key { judge, buf }),
        }
        self.screen = Screen::Judge(form);
        Ok(())
    }

    /// Add or edit a judge's fields. Enter saves; Esc cancels.
    fn key_judge_edit(
        &mut self,
        mut form: JudgeForm,
        mut ed: JudgeEditForm,
        key: KeyEvent,
    ) -> Result<()> {
        match key.code {
            KeyCode::Esc => {
                self.screen = Screen::Judge(form);
                return Ok(());
            }
            KeyCode::Enter => return self.submit_judge_edit(form, ed),
            KeyCode::Tab | KeyCode::Down => ed.focus = (ed.focus + 1) % JudgeEditForm::FIELDS,
            KeyCode::BackTab | KeyCode::Up => {
                ed.focus = (ed.focus + JudgeEditForm::FIELDS - 1) % JudgeEditForm::FIELDS
            }
            KeyCode::Backspace => {
                if let Some(f) = ed.field_mut() {
                    f.pop();
                }
            }
            KeyCode::Char(c) => {
                if let Some(f) = ed.field_mut() {
                    f.push(c);
                }
            }
            _ => {}
        }
        form.entry = Some(JudgeEntry::Edit(ed));
        self.screen = Screen::Judge(form);
        Ok(())
    }

    /// Validate and persist an add/edit. On error, the entry stays open with the
    /// message; on success the registry is reloaded and the saved judge focused.
    fn submit_judge_edit(&mut self, mut form: JudgeForm, mut ed: JudgeEditForm) -> Result<()> {
        macro_rules! reject {
            ($focus:expr, $msg:expr) => {{
                ed.error = Some($msg);
                ed.focus = $focus;
                form.entry = Some(JudgeEntry::Edit(ed));
                self.screen = Screen::Judge(form);
                return Ok(());
            }};
        }

        let name = ed.name.trim().to_string();
        if name.is_empty() {
            reject!(0, "name is required".into());
        }
        if ed.model.trim().is_empty() {
            reject!(1, "model is required".into());
        }
        let timeout = match ed.timeout.trim().parse::<u64>() {
            Ok(v) if v > 0 => v,
            _ => reject!(3, "timeout must be a positive number of seconds".into()),
        };
        let allow = match ed.allow.trim().parse::<u8>() {
            Ok(v) if v <= 100 => v,
            _ => reject!(4, "allow threshold must be 0–100".into()),
        };
        let high = match ed.high.trim().parse::<u8>() {
            Ok(v) if v <= 100 => v,
            _ => reject!(5, "high threshold must be 0–100".into()),
        };

        let Some(mut kr) = crate::core::keyring::open_from_session() else {
            form.error = Some("keyring is locked".into());
            self.screen = Screen::Judge(form);
            return Ok(());
        };

        let collides = match &ed.original {
            Some(orig) => orig != &name && kr.data.judges.contains_key(&name),
            None => kr.data.judges.contains_key(&name),
        };
        if collides {
            reject!(0, format!("a judge named '{name}' already exists"));
        }

        // Preserve the existing key across an edit (it is set separately).
        let prior_key = ed
            .original
            .as_ref()
            .and_then(|o| kr.data.judges.get(o))
            .map(|d| d.api_key.clone())
            .unwrap_or_default();

        // On rename, drop the old entry and carry the default pointer over.
        if let Some(orig) = &ed.original {
            if orig != &name {
                kr.data.judges.remove(orig);
                if kr.data.default_judge.as_deref() == Some(orig.as_str()) {
                    kr.data.default_judge = Some(name.clone());
                }
            }
        }

        let adding = ed.original.is_none();
        let first = kr.data.judges.is_empty();
        kr.data.judges.insert(
            name.clone(),
            crate::core::keyring::JudgeDef {
                model: ed.model.trim().to_string(),
                base_url: ed.base_url.trim().to_string(),
                timeout_secs: timeout,
                allow_threshold: allow,
                high_threshold: high,
                criteria: ed.criteria.clone(),
                api_key: prior_key,
            },
        );
        if first {
            kr.data.default_judge = Some(name.clone());
        }

        match kr.save() {
            Ok(()) => {
                log_judge(if adding { "judge.add" } else { "judge.edit" }, Some(&name));
                form = JudgeForm::load();
                if let Some(pos) = form.judges.iter().position(|j| j.name == name) {
                    form.focus = pos + 1;
                }
                let msg = if adding {
                    format!("Judge '{name}' added — press k to set its API key")
                } else {
                    format!("Judge '{name}' updated")
                };
                self.set_status(MsgKind::Ok, msg);
            }
            Err(e) => reject!(ed.focus, format!("could not save: {e}")),
        }
        self.screen = Screen::Judge(form);
        Ok(())
    }

    /// Re-open the keyring from the session, mutate it, save, and reload the
    /// screen snapshot. Returns false (with an error set) if locked or save fails.
    fn with_keyring<F: FnOnce(&mut crate::core::keyring::KeyringData)>(
        &mut self,
        form: &mut JudgeForm,
        f: F,
    ) -> bool {
        let Some(mut kr) = crate::core::keyring::open_from_session() else {
            form.error = Some("keyring is locked".into());
            return false;
        };
        f(&mut kr.data);
        match kr.save() {
            Ok(()) => {
                let focus = form.focus;
                *form = JudgeForm::load();
                form.focus = focus.min(form.rows().saturating_sub(1));
                true
            }
            Err(e) => {
                form.error = Some(format!("could not save: {e}"));
                false
            }
        }
    }

    fn toggle_judge_enabled(&mut self, form: &mut JudgeForm) {
        let want = !form.enabled;
        if self.with_keyring(form, |d| d.judge_enabled = want) {
            log_judge(
                "judge.config",
                Some(if want { "enabled" } else { "disabled" }),
            );
            self.set_status(
                MsgKind::Ok,
                format!(
                    "AI judge {} (global)",
                    if want { "enabled" } else { "disabled" }
                ),
            );
        }
    }

    fn set_judge_default(&mut self, form: &mut JudgeForm, name: &str) {
        let n = name.to_string();
        if self.with_keyring(form, |d| d.default_judge = Some(n)) {
            self.set_status(MsgKind::Ok, format!("Default judge: {name}"));
        }
    }

    fn remove_judge(&mut self, form: &mut JudgeForm, name: &str) {
        let n = name.to_string();
        if self.with_keyring(form, |d| {
            d.judges.remove(&n);
            if d.default_judge.as_deref() == Some(n.as_str()) {
                d.default_judge = d.judges.keys().next().cloned();
            }
        }) {
            self.set_status(MsgKind::Ok, format!("Removed judge '{name}'"));
        }
    }

    /// Store (or clear, when empty) the selected judge's API key.
    fn set_judge_key(&mut self, form: &mut JudgeForm, name: &str, key: &str) {
        let n = name.to_string();
        let k = key.trim().to_string();
        let empty = k.is_empty();
        if self.with_keyring(form, |d| {
            if let Some(def) = d.judges.get_mut(&n) {
                def.api_key = k;
            }
        }) {
            log_judge("judge.key.set", Some(name));
            self.set_status(
                MsgKind::Ok,
                if empty {
                    format!("Cleared key for '{name}'")
                } else {
                    format!("Stored key for '{name}'")
                },
            );
        }
    }

    /// Dry-run the selected judge against a sample request (the TUI equivalent of
    /// `svault judge test`). Blocks the UI briefly for the HTTP round-trip.
    fn run_judge_test(&mut self, form: &mut JudgeForm, name: &str) {
        let Some(kr) = crate::core::keyring::open_from_session() else {
            form.error = Some("keyring is locked".into());
            return;
        };
        let Some(def) = kr.data.judges.get(name) else {
            form.error = Some(format!("no judge named '{name}'"));
            return;
        };
        let Some(rt) = crate::core::judge::JudgeRuntime::from_def(def) else {
            form.test_result = Some((
                MsgKind::Error,
                format!("judge '{name}' has no key — press k to set one"),
            ));
            return;
        };
        let model = rt.model.clone();
        let ctx = crate::core::judge::JudgeContext {
            caller: "claude-code",
            scope: "database",
            reason: "run the nightly database migration to apply pending changes",
            secret: "DB_URL",
            tier: crate::core::policy::Tier::Medium,
            vault: "demo-vault",
            vault_description: "",
            secret_description: "",
            recent: "no prior requests in the last hour",
        };
        form.test_result = Some(match crate::core::judge::evaluate(&rt, &model, &ctx) {
            crate::core::judge::JudgeVerdict::Allow { score, rationale } => {
                (MsgKind::Ok, format!("ALLOW (score {score}) — {rationale}"))
            }
            crate::core::judge::JudgeVerdict::Deny { score, rationale } => {
                (MsgKind::Warn, format!("DENY (score {score}) — {rationale}"))
            }
            crate::core::judge::JudgeVerdict::Unavailable { err } => {
                (MsgKind::Error, format!("unavailable: {err}"))
            }
        });
    }
}

// ── Free helpers ───────────────────────────────────────────────────────────────

/// The `svault mcp` server entry for an MCP client config, as Claude Code, Cursor,
/// and most clients expect it.
fn svault_server_entry() -> serde_json::Value {
    serde_json::json!({
        "command": "svault",
        "args": ["mcp"],
        "env": { "SVAULT_CALLER": "claude-code" }
    })
}

/// Write — or merge into — `./.mcp.json` an `mcpServers.svault` entry that launches
/// `svault mcp`. Preserves any other servers already configured. Returns the
/// absolute path written.
fn write_mcp_config() -> anyhow::Result<String> {
    let path = Path::new(".mcp.json");
    let mut root: serde_json::Value = if path.exists() {
        serde_json::from_slice(&std::fs::read(path)?).unwrap_or_else(|_| serde_json::json!({}))
    } else {
        serde_json::json!({})
    };
    if !root.is_object() {
        root = serde_json::json!({});
    }
    let servers = root
        .as_object_mut()
        .unwrap()
        .entry("mcpServers")
        .or_insert_with(|| serde_json::json!({}));
    if !servers.is_object() {
        *servers = serde_json::json!({});
    }
    servers
        .as_object_mut()
        .unwrap()
        .insert("svault".to_string(), svault_server_entry());
    std::fs::write(path, serde_json::to_string_pretty(&root)? + "\n")?;
    Ok(std::fs::canonicalize(path)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| ".mcp.json".to_string()))
}

/// Names of the judges in the unlocked keyring (sorted), for the vault
/// judge-assignment picker. Empty when the keyring is locked or has no judges —
/// the picker then offers only "default".
fn available_judge_names() -> Vec<String> {
    match crate::core::keyring::open_from_session() {
        Some(kr) => {
            let mut names: Vec<String> = kr.data.judges.keys().cloned().collect();
            names.sort();
            names
        }
        None => Vec::new(),
    }
}

/// Cycle the vault's assigned judge through `default` (None) then each available
/// judge. The vault's current judge is always reachable even if it is no longer
/// in `choices` (e.g. the keyring is locked, or the judge was renamed).
fn cycle_judge_name(current: &Option<String>, choices: &[String], forward: bool) -> Option<String> {
    let mut opts: Vec<Option<String>> = vec![None];
    opts.extend(choices.iter().cloned().map(Some));
    if let Some(c) = current {
        if !choices.iter().any(|j| j == c) {
            opts.push(Some(c.clone()));
        }
    }
    let pos = opts.iter().position(|o| o == current).unwrap_or(0);
    opts[cycle(pos, opts.len(), forward)].clone()
}

/// Display label for the assigned-judge picker: the judge name, or `default` for
/// the keyring default.
fn judge_name_label(name: &Option<String>) -> String {
    name.clone().unwrap_or_else(|| "default".to_string())
}

fn parse_agents(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Tier <-> picker-index helpers (0 low · 1 medium · 2 high).
fn tier_at(idx: usize) -> crate::core::policy::Tier {
    match idx {
        1 => crate::core::policy::Tier::Medium,
        2 => crate::core::policy::Tier::High,
        _ => crate::core::policy::Tier::Low,
    }
}
fn tier_idx(t: crate::core::policy::Tier) -> usize {
    match t {
        crate::core::policy::Tier::Low => 0,
        crate::core::policy::Tier::Medium => 1,
        crate::core::policy::Tier::High => 2,
    }
}
pub fn tier_label(idx: usize) -> &'static str {
    match idx {
        1 => "medium",
        2 => "high",
        _ => "low",
    }
}

fn create_adjust(form: &mut CreateForm, forward: bool) {
    match form.current() {
        CreateField::AllowMode => form.allow_mode = cycle(form.allow_mode, 3, forward),
        CreateField::Autolock => form.autolock = !form.autolock,
        CreateField::DefaultTier => form.default_tier = cycle(form.default_tier, 3, forward),
        CreateField::Judge => form.judge = !form.judge,
        CreateField::JudgeName => {
            form.judge_name = cycle_judge_name(&form.judge_name, &form.judge_choices, forward)
        }
        _ => {}
    }
}

fn settings_adjust(form: &mut SettingsForm, forward: bool) {
    match form.current() {
        SettingsField::AllowMode => form.allow_mode = cycle(form.allow_mode, 3, forward),
        SettingsField::Autolock => form.autolock = !form.autolock,
        SettingsField::DefaultTier => form.default_tier = cycle(form.default_tier, 3, forward),
        SettingsField::Judge => form.judge = !form.judge,
        SettingsField::JudgeName => {
            form.judge_name = cycle_judge_name(&form.judge_name, &form.judge_choices, forward)
        }
        _ => {}
    }
}

fn secret_add_adjust(form: &mut SecretAddForm, forward: bool) {
    match form.focus {
        4 => form.tier = cycle(form.tier, 3, forward),
        5 => form.require_reason = !form.require_reason,
        _ => {}
    }
}

fn classify_adjust(form: &mut ClassifyForm, forward: bool) {
    match form.focus {
        4 => form.tier = cycle(form.tier, 3, forward),
        5 => form.require_reason = !form.require_reason,
        _ => {}
    }
}

/// Record a global (vault-independent) judge/policy change to `.svault/usage.log`
/// so it shows in the audit timeline. The judge config + OpenRouter key are
/// global, so they aren't tied to any one vault. Best-effort; never blocks the
/// action (it's a no-op when `.svault/` doesn't exist yet).
fn log_judge(action: &str, detail: Option<&str>) {
    crate::core::usage::human(&svault_dir(), action, detail);
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
            pending_fido: None,
        }
    }

    fn press(app: &mut App, code: KeyCode) {
        app.on_key(KeyEvent::new(code, KeyModifiers::empty()))
            .unwrap();
    }

    /// Run in a fresh temp working directory with no `.svault/`, so the keyring
    /// entry branch sees a deterministic "no master" state. Takes the shared
    /// process-wide CWD lock (the keyring screen now reads `master::exists()` /
    /// `is_unlocked()`, which are relative to the CWD, so it must not race the
    /// other chdir tests).
    fn in_clean_cwd() -> (
        std::sync::MutexGuard<'static, ()>,
        tempfile::TempDir,
        std::path::PathBuf,
    ) {
        let guard = crate::core::testlock::CWD_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::TempDir::new().unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();
        (guard, tmp, prev)
    }

    // Tests force the first-run "set master" step so the field order is
    // deterministic (the live order depends on whether a master exists on disk).
    fn idx(field: CreateField) -> usize {
        CreateForm::order_for(MasterStep::Set)
            .iter()
            .position(|f| *f == field)
            .unwrap()
    }

    fn create_at(field: CreateField) -> Screen {
        let mut form = CreateForm::new();
        form.master_step = MasterStep::Set;
        form.order = CreateForm::order_for(MasterStep::Set);
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
    fn create_field_order_has_the_right_master_tail() {
        // Ten base fields (incl. the assigned-judge picker), plus the master tail.
        assert_eq!(CreateForm::order_for(MasterStep::Ready).len(), 10);
        let unlock = CreateForm::order_for(MasterStep::Unlock);
        assert_eq!(unlock.len(), 11);
        assert_eq!(unlock.last(), Some(&CreateField::MasterUnlock));
        let set = CreateForm::order_for(MasterStep::Set);
        assert_eq!(set.len(), 12);
        assert_eq!(
            &set[10..],
            &[CreateField::MasterNew, CreateField::MasterConfirm]
        );
        assert_eq!(SettingsField::ORDER.len(), SettingsForm::FIELDS);
    }

    #[test]
    fn focus_is_text_excludes_pickers_and_toggles() {
        let mut form = CreateForm::new();
        form.focus = idx(CreateField::AllowMode);
        assert!(!form.focus_is_text());
        form.focus = idx(CreateField::Autolock);
        assert!(!form.focus_is_text());
        form.focus = idx(CreateField::DefaultTier);
        assert!(!form.focus_is_text());
        form.focus = idx(CreateField::Judge);
        assert!(!form.focus_is_text());
        form.focus = idx(CreateField::JudgeName);
        assert!(!form.focus_is_text());
        form.master_step = MasterStep::Set;
        form.order = CreateForm::order_for(MasterStep::Set);
        form.focus = idx(CreateField::MasterNew);
        assert!(form.focus_is_text());
    }

    #[test]
    fn space_on_judge_field_toggles_it() {
        let mut app = bare_app(create_at(CreateField::Judge));
        press(&mut app, KeyCode::Char(' '));
        let Screen::Create(form) = &app.screen else {
            panic!("expected create screen")
        };
        assert!(form.judge, "space must toggle the AI judge on");
    }

    #[test]
    fn assigned_judge_cycles_default_then_choices_and_wraps() {
        let choices = vec!["alpha".to_string(), "beta".to_string()];
        // default -> alpha -> beta -> default
        let a = cycle_judge_name(&None, &choices, true);
        assert_eq!(a.as_deref(), Some("alpha"));
        let b = cycle_judge_name(&a, &choices, true);
        assert_eq!(b.as_deref(), Some("beta"));
        assert_eq!(cycle_judge_name(&b, &choices, true), None);
        // backward from default wraps to the last choice
        assert_eq!(
            cycle_judge_name(&None, &choices, false).as_deref(),
            Some("beta")
        );
        // a judge no longer in the list (renamed / keyring locked) stays reachable
        let orphan = Some("gone".to_string());
        assert_eq!(judge_name_label(&orphan), "gone");
        assert_eq!(cycle_judge_name(&orphan, &choices, true), None);
    }

    #[test]
    fn mcp_screen_renders_status_command_and_config() {
        use ratatui::{backend::TestBackend, Terminal};
        let mut app = bare_app(Screen::Mcp);
        app.daemon_running = true;
        let mut terminal = Terminal::new(TestBackend::new(110, 40)).unwrap();
        terminal.draw(|f| super::ui::draw(f, &mut app)).unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(text.contains("MCP"), "title");
        assert!(text.contains("mcpServers"), "config snippet");
        assert!(text.contains("Daemon"), "status block");
        // No vaults unlocked in a bare app → the not-ready hint shows.
        assert!(text.contains("Not ready"), "readiness");
    }

    #[test]
    fn write_mcp_config_creates_then_merges_preserving_other_servers() {
        let _cwd = crate::core::testlock::CWD_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();

        // Fresh write creates the svault server entry.
        let path = write_mcp_config().unwrap();
        assert!(path.ends_with(".mcp.json"));
        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(".mcp.json").unwrap()).unwrap();
        assert_eq!(v["mcpServers"]["svault"]["command"], "svault");
        assert_eq!(v["mcpServers"]["svault"]["args"][0], "mcp");

        // An unrelated server already in the file is preserved on the next write.
        std::fs::write(
            ".mcp.json",
            serde_json::to_string(&serde_json::json!({
                "mcpServers": { "other": { "command": "x" } }
            }))
            .unwrap(),
        )
        .unwrap();
        write_mcp_config().unwrap();
        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(".mcp.json").unwrap()).unwrap();
        assert_eq!(v["mcpServers"]["other"]["command"], "x");
        assert_eq!(v["mcpServers"]["svault"]["command"], "svault");

        std::env::set_current_dir(prev).unwrap();
    }

    #[test]
    fn secret_add_tier_cycles_and_classifies() {
        let form = SecretAddForm {
            vault_dir: PathBuf::from("."),
            vault_name: "v".into(),
            name: String::new(),
            value: String::new(),
            scope: "misc".into(),
            description: String::new(),
            tier: 0,
            require_reason: false,
            focus: 4, // tier picker
            error: None,
        };
        let mut app = bare_app(Screen::SecretAdd(form));
        press(&mut app, KeyCode::Right);
        let Screen::SecretAdd(f) = &app.screen else {
            panic!("expected secret-add screen")
        };
        assert_eq!(f.tier, 1, "right arrow cycles tier low → medium");
        assert_eq!(tier_at(f.tier), crate::core::policy::Tier::Medium);
    }

    #[test]
    fn classify_form_cycles_tier_and_toggles_reason() {
        let form = ClassifyForm {
            vault_dir: PathBuf::from("."),
            vault_name: "v".into(),
            secret: "DB_URL".into(),
            scope: "database".into(),
            description: String::new(),
            windows: String::new(),
            require_callers: String::new(),
            tier: 0,
            require_reason: false,
            focus: 4, // tier picker
            error: None,
        };
        let mut app = bare_app(Screen::Classify(form));
        press(&mut app, KeyCode::Right);
        let Screen::Classify(f) = &app.screen else {
            panic!("expected classify screen")
        };
        assert_eq!(f.tier, 1, "right arrow cycles tier low → medium");
        // Move to the require-reason row and toggle it with space.
        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Char(' '));
        let Screen::Classify(f) = &app.screen else {
            panic!("expected classify screen")
        };
        assert!(f.require_reason, "space toggles require-reason on");
    }

    #[test]
    fn judge_screen_locked_prompts_unlock_then_esc_returns() {
        // A locked, already-created keyring: Enter prompts the master passphrase
        // (a created keyring always has a master); Esc backs out.
        let (_g, _tmp, prev) = in_clean_cwd();
        let form = JudgeForm {
            created: true,
            unlocked: false,
            enabled: false,
            default_judge: None,
            judges: Vec::new(),
            focus: 0,
            error: None,
            test_result: None,
            entry: None,
        };
        let mut app = bare_app(Screen::Judge(form));
        press(&mut app, KeyCode::Enter);
        let Screen::Judge(f) = &app.screen else {
            panic!("expected judge screen")
        };
        assert!(
            matches!(f.entry, Some(JudgeEntry::Passphrase(_))),
            "enter on a locked keyring opens the master-passphrase prompt"
        );
        // Esc out of the entry returns to the vault list.
        press(&mut app, KeyCode::Esc);
        assert!(
            matches!(app.screen, Screen::List),
            "esc returns to the list"
        );
        std::env::set_current_dir(prev).unwrap();
    }

    #[test]
    fn judge_screen_without_keyring_offers_init() {
        // No keyring and no master on disk: Enter opens the set-master prompt
        // (InitForm: passphrase + confirm) before creating the keyring.
        let (_g, _tmp, prev) = in_clean_cwd();
        let form = JudgeForm {
            created: false,
            unlocked: false,
            enabled: false,
            default_judge: None,
            judges: Vec::new(),
            focus: 0,
            error: None,
            test_result: None,
            entry: None,
        };
        let mut app = bare_app(Screen::Judge(form));
        press(&mut app, KeyCode::Enter);
        let Screen::Judge(f) = &app.screen else {
            panic!("expected judge screen")
        };
        assert!(
            matches!(f.entry, Some(JudgeEntry::Init(_))),
            "enter with no keyring and no master opens the set-master prompt"
        );
        std::env::set_current_dir(prev).unwrap();
    }

    #[test]
    fn judge_add_form_types_into_focused_field_and_tabs() {
        // An add form: typing fills the name, Tab advances to the model field.
        let mut form = JudgeForm {
            created: true,
            unlocked: true,
            enabled: false,
            default_judge: None,
            judges: Vec::new(),
            focus: 0,
            error: None,
            test_result: None,
            entry: Some(JudgeEntry::Edit(JudgeEditForm::add())),
        };
        // Sanity: the picker defaults the model so the form is usable as-is.
        if let Some(JudgeEntry::Edit(ed)) = &form.entry {
            assert!(!ed.model.is_empty());
        }
        form.focus = 0;
        let mut app = bare_app(Screen::Judge(form));
        press(&mut app, KeyCode::Char('p'));
        press(&mut app, KeyCode::Char('g'));
        press(&mut app, KeyCode::Tab);
        let Screen::Judge(f) = &app.screen else {
            panic!("expected judge screen")
        };
        let Some(JudgeEntry::Edit(ed)) = &f.entry else {
            panic!("expected an open edit form")
        };
        assert_eq!(ed.name, "pg", "chars land in the focused name field");
        assert_eq!(ed.focus, 1, "tab advances to the model field");
    }

    #[test]
    fn down_wraps_from_last_create_field_to_first() {
        let mut form = CreateForm::new();
        form.focus = form.order.len() - 1;
        let mut app = bare_app(Screen::Create(form));
        press(&mut app, KeyCode::Down);
        let Screen::Create(form) = &app.screen else {
            panic!("expected create screen")
        };
        assert_eq!(form.focus, 0);
    }

    #[test]
    fn paste_appends_to_the_focused_field() {
        let mut app = bare_app(create_at(CreateField::MasterNew));
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
    fn help_also_opens_with_h() {
        let mut app = bare_app(Screen::List);
        press(&mut app, KeyCode::Char('h'));
        assert!(app.show_help);
        press(&mut app, KeyCode::Esc);
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
        let mut app = bare_app(Screen::RecoveryCode(RecoveryShow {
            codes: vec![("Vault 'x'".to_string(), "AAAA-BBBB-CCCC".to_string())],
            to_judge: false,
        }));
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
