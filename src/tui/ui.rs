//! Rendering for the Svault TUI. Each screen draws into a three-row layout:
//! a header (title + status), a body, and a footer with context key hints.

use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, Wrap},
    Frame,
};

use super::theme;
use super::{
    judge_name_label, tier_label, App, ClassifyForm, CreateForm, InitForm, JudgeEditForm,
    JudgeEntry, JudgeForm, LoginForm, MsgKind, OnboardForm, OnboardStep, Screen, SecretAddForm,
    SecretScreen, SettingsForm, UnlockForm, VaultRow,
};

const CYAN: Color = theme::ACCENT;
const DIM: Color = theme::MUTED;

pub fn draw(frame: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Min(0),    // body
            Constraint::Length(1), // status line
            Constraint::Length(3), // footer / key hints
        ])
        .split(frame.area());

    draw_header(frame, chunks[0], app.daemon_running);

    match &mut app.screen {
        Screen::List => draw_list(frame, chunks[1], &app.vaults, &mut app.list_state),
        Screen::Login(form) => draw_login(frame, chunks[1], form),
        Screen::Onboard(form) => draw_onboard(frame, chunks[1], form),
        Screen::Create(form) => draw_create(frame, chunks[1], form),
        Screen::Settings(form) => draw_settings(frame, chunks[1], form),
        Screen::Unlock(form) => draw_unlock(frame, chunks[1], form),
        Screen::Secrets(scr) => draw_secrets(frame, chunks[1], scr),
        Screen::SecretAdd(form) => draw_secret_add(frame, chunks[1], form),
        Screen::RecoveryCode(show) => draw_recovery_code(frame, chunks[1], show),
        Screen::Import(form) => draw_import(frame, chunks[1], form),
        Screen::Recover(form) => draw_recover(frame, chunks[1], form),
        Screen::Activity(scr) => draw_activity(frame, chunks[1], scr),
        Screen::Classify(form) => draw_classify(frame, chunks[1], form),
        Screen::Judge(form) => draw_judge(frame, chunks[1], form),
        Screen::Mcp => draw_mcp(frame, chunks[1], app.daemon_running, &app.vaults),
    }

    draw_status(frame, chunks[2], app);
    draw_footer(frame, chunks[3], app);

    // Overlays sit on top of everything when toggled.
    if app.show_help {
        draw_help(frame, chunks[1], &app.screen);
    }
    if app.confirm_quit {
        draw_quit(frame, chunks[1]);
    }
    // A blocking YubiKey op is queued (run right after this frame) — show a modal
    // so the user knows to touch the key while the call blocks the TUI.
    if app.pending_fido.is_some() {
        draw_touch(frame, chunks[1]);
    }
}

// ── YubiKey touch prompt ─────────────────────────────────────────────────────

fn draw_touch(frame: &mut Frame, area: Rect) {
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Touch your YubiKey",
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  The key is blinking — tap the sensor to continue.",
            Style::default().fg(theme::TEXT),
        )),
        Line::from(Span::styled(
            "  (enrolling asks for a second tap)",
            Style::default().fg(DIM),
        )),
    ];
    let popup = centered_rect(54, 32, area);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" YubiKey ")
        .border_style(Style::default().fg(CYAN));
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        popup,
    );
}

// ── Quit confirmation ────────────────────────────────────────────────────────────

fn draw_quit(frame: &mut Frame, area: Rect) {
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled("  Quit Svault?", theme::title())),
        Line::from(""),
        Line::from(Span::styled(
            "  enter  quit        esc / any key  stay",
            theme::label_dim(),
        )),
    ];
    let popup = centered_rect(44, 30, area);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Confirm ")
        .border_style(Style::default().fg(theme::WARN));
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        popup,
    );
}

// ── Header ─────────────────────────────────────────────────────────────────────

fn draw_header(frame: &mut Frame, area: Rect, daemon_running: bool) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::border());
    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Left: title + subtitle.
    let title = Line::from(vec![
        Span::styled(" Svault ", theme::title()),
        Span::styled("— secret access for AI agents", theme::label_dim()),
    ]);
    frame.render_widget(Paragraph::new(title), inner);

    // Right: daemon indicator (green when running, dim when off).
    let (label, color) = if daemon_running {
        ("daemon running ", theme::OK)
    } else {
        ("daemon off ", theme::MUTED)
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(label, Style::default().fg(color))))
            .alignment(Alignment::Right),
        inner,
    );
}

// ── Status line ──────────────────────────────────────────────────────────────────

/// A single dedicated line for the most recent status message, below the body.
fn draw_status(frame: &mut Frame, area: Rect, app: &App) {
    let Some(status) = &app.status else {
        return;
    };
    let (color, prefix) = match status.kind {
        MsgKind::Ok => (theme::OK, "ok: "),
        MsgKind::Warn => (theme::WARN, "warning: "),
        MsgKind::Error => (theme::ERR, "error: "),
        MsgKind::Info => (theme::ACCENT, "note: "),
    };
    let line = Line::from(vec![
        Span::raw(" "),
        Span::styled(
            format!("{prefix}{}", status.text),
            Style::default().fg(color),
        ),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

// ── Footer ─────────────────────────────────────────────────────────────────────

fn draw_footer(frame: &mut Frame, area: Rect, app: &App) {
    // Each screen has a full hint and a compact fallback. On a narrow terminal
    // the single-line footer would clip the full hint from the right — losing
    // the "help" and "quit" hints entirely — so we drop to the compact form,
    // which always keeps "h/? help" discoverable. Press h or ? for the full
    // keybinding overlay.
    let (full, compact): (&str, &str) = if app.confirm_quit {
        (
            "enter  quit        esc / any key  stay",
            "enter quit  esc stay",
        )
    } else if app.show_help {
        ("any key / esc  close help", "any key  close")
    } else {
        match &app.screen {
            Screen::List => (
                "↑/↓ move   enter open   c create   u unlock   l lock   o logout   s settings   shift-J judge   m mcp   v activity   e export   i import   r recover   d daemon   h/? help   q quit",
                "↑/↓ move   enter open   u unlock   o logout   shift-J judge   h/? help   q quit",
            ),
            Screen::Login(form) => (
                if form.yubikey {
                    "type master passphrase   enter sign in   ctrl+y yubikey   esc quit"
                } else {
                    "type master passphrase   enter sign in   esc quit"
                },
                "enter sign in   esc quit",
            ),
            Screen::Onboard(form) => match form.step {
                super::OnboardStep::Disclaimer => (
                    "enter  I understand — continue        esc  quit",
                    "enter continue   esc quit",
                ),
                super::OnboardStep::Passphrase => (
                    "type passphrase   ↑/↓ or tab  switch field   enter  next / confirm   esc  quit",
                    "enter next   esc quit",
                ),
                super::OnboardStep::Recovery => (
                    "y  I've saved the recovery code — continue",
                    "y continue",
                ),
                super::OnboardStep::Yubikey => (
                    "type PIN if your key has one   enter  enroll YubiKey   esc  skip",
                    "enter enroll   esc skip",
                ),
            },
            Screen::Activity(_) => ("↑/↓ scroll   esc / b back   q quit", "↑/↓ scroll   esc back"),
            Screen::Create(_) => (
                "↑/↓ field   ←/→ change   space toggle   enter next/create   esc cancel",
                "↑/↓ field   enter next   esc cancel",
            ),
            Screen::Settings(_) => (
                "↑/↓ field   ←/→ change   space toggle   enter next/save   esc cancel",
                "↑/↓ field   enter next   esc cancel",
            ),
            Screen::Unlock(form) => (
                if form.yubikey {
                    "type master passphrase   enter unlock   ctrl+y yubikey   esc cancel"
                } else {
                    "type master passphrase   enter unlock   esc cancel"
                },
                "enter unlock   esc cancel",
            ),
            Screen::Secrets(scr) => {
                if scr.reveal.is_some() {
                    ("space reveal/hide   esc close", "space hide   esc close")
                } else if scr.pending_delete.is_some() {
                    ("y confirm delete   n cancel", "y delete   n cancel")
                } else {
                    (
                        "↑/↓ move   enter view   a add   c classify   d delete   l lock   h/? help   esc back",
                        "↑/↓ move   enter view   c classify   h/? help   esc back",
                    )
                }
            }
            Screen::SecretAdd(_) => (
                "↑/↓ field   enter next/save   esc cancel",
                "↑/↓ field   enter save   esc cancel",
            ),
            Screen::Classify(_) => (
                "↑/↓ field   ←/→ change   space toggle   enter next/save   esc cancel",
                "↑/↓ field   enter save   esc cancel",
            ),
            Screen::Judge(form) => {
                if form.entry.is_some() {
                    (
                        "type/paste   tab move   enter confirm   esc cancel",
                        "enter confirm   esc cancel",
                    )
                } else if !form.unlocked {
                    (
                        "enter unlock / create the keyring   esc back",
                        "enter unlock   esc back",
                    )
                } else {
                    (
                        "↑/↓ move   space toggle   a add   e edit   v view   k key   d default   t test   x remove   esc back",
                        "↑/↓ move   a add   e edit   esc back",
                    )
                }
            }
            Screen::RecoveryCode(_) => (
                "press 'y' to confirm you have saved the code",
                "'y' to confirm saved",
            ),
            Screen::Import(_) => (
                "type/paste path to bundle   enter import   esc cancel",
                "enter import   esc cancel",
            ),
            Screen::Recover(_) => (
                "↑/↓ field   enter next/recover   esc cancel",
                "↑/↓ field   enter next   esc cancel",
            ),
            Screen::Mcp => (
                "w write .mcp.json   d toggle daemon   h/? help   esc back   q quit",
                "w write   d daemon   esc back",
            ),
        }
    };
    // Inner width = area minus the two vertical border columns.
    let avail = area.width.saturating_sub(2) as usize;
    let hint = if full.chars().count() <= avail {
        full
    } else {
        compact
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::border());
    let p = Paragraph::new(Span::styled(hint, theme::hint())).block(block);
    frame.render_widget(p, area);
}

// ── Help overlay ─────────────────────────────────────────────────────────────────

fn draw_help(frame: &mut Frame, area: Rect, screen: &Screen) {
    let mut lines = vec![
        Line::from(Span::styled("  Keybindings", theme::title())),
        Line::from(""),
    ];
    let rows: &[(&str, &str)] = match screen {
        Screen::Secrets(_) => &[
            ("↑/↓ or j/k", "move selection"),
            ("enter or g", "reveal secret value"),
            ("a", "add a secret"),
            ("c", "classify (tier / scope / reason / description)"),
            ("d", "delete the selected secret"),
            ("l", "lock the vault"),
            ("h or ?", "show this help"),
            ("esc or b", "back to vault list"),
        ],
        Screen::Judge(_) => &[
            ("↑/↓", "move between rows"),
            ("enter", "unlock / create the keyring · view a judge"),
            ("space / ←→", "toggle the judge on/off (global)"),
            ("a / e", "add a judge · edit the selected judge"),
            ("v / k", "view detail · set the selected judge's API key"),
            ("d / t / x", "set default · test · remove judge"),
            ("esc", "back to vault list"),
        ],
        Screen::Mcp => &[
            ("w", "write the svault entry into ./.mcp.json"),
            ("d", "start / stop the daemon (so keys stay in memory)"),
            ("esc or b", "back to vault list"),
        ],
        // Default to the list bindings — the main hub.
        _ => &[
            ("↑/↓ or j/k", "move selection"),
            ("enter", "open a vault's secrets"),
            ("c", "create a new vault"),
            ("u / l", "unlock / lock the selected vault"),
            (
                "o",
                "log out of all vaults (locks them); unlocking re-prompts the master",
            ),
            (
                "s",
                "edit settings (description, agents, rate limit, auto-lock)",
            ),
            (
                "shift-J",
                "manage the AI judge (key, model, thresholds, test)",
            ),
            ("m", "MCP server — status + wiring for AI agents"),
            ("v", "view the activity timeline (human + agent)"),
            ("e / i", "export / import an encrypted bundle"),
            ("r", "recover a vault with its recovery code"),
            ("d", "start / stop the background daemon (Unix)"),
            ("h or ?", "show this help"),
            ("q", "quit"),
        ],
    };
    for (keys, desc) in rows {
        lines.push(Line::from(vec![
            Span::styled(format!("  {keys:<14}"), theme::label_focused()),
            Span::styled((*desc).to_string(), Style::default().fg(theme::TEXT)),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Press any key to close.",
        theme::label_dim(),
    )));

    let popup = centered_rect(70, 70, area);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Help ")
        .border_style(theme::title());
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        popup,
    );
}

// ── List ───────────────────────────────────────────────────────────────────────

fn draw_list(
    frame: &mut Frame,
    area: Rect,
    vaults: &[super::VaultRow],
    state: &mut ratatui::widgets::TableState,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Vaults ")
        .border_style(theme::border());

    if vaults.is_empty() {
        let p = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "  No vaults yet.",
                Style::default()
                    .fg(theme::WARN)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                "  Press 'c' to create your first vault.",
                Style::default().fg(theme::TEXT),
            )),
        ])
        .block(block);
        frame.render_widget(p, area);
        return;
    }

    let header =
        Row::new(["STORAGE", "VAULT", "STATUS", "CREATED", "DESCRIPTION"]).style(theme::header());

    let rows: Vec<Row> = vaults
        .iter()
        .map(|v| {
            let (status, status_style) = if v.unlocked {
                ("unlocked", Style::default().fg(theme::OK))
            } else {
                ("locked", Style::default().fg(theme::MUTED))
            };
            let desc = if v.description.is_empty() {
                "-".to_string()
            } else {
                v.description.clone()
            };
            Row::new(vec![
                Cell::from(v.storage.clone()).style(Style::default().fg(theme::TEXT)),
                Cell::from(v.name.clone()).style(theme::title()),
                Cell::from(status).style(status_style),
                Cell::from(v.created.clone()).style(Style::default().fg(theme::MUTED)),
                Cell::from(desc).style(Style::default().fg(theme::TEXT)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(12),
        Constraint::Length(22),
        Constraint::Length(10),
        Constraint::Length(12),
        Constraint::Min(10),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(block)
        .column_spacing(2)
        .row_highlight_style(theme::selected_row())
        .highlight_symbol("> ");
    frame.render_stateful_widget(table, area, state);
}

// ── Activity ───────────────────────────────────────────────────────────────────

fn draw_activity(frame: &mut Frame, area: Rect, scr: &mut super::ActivityScreen) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" Activity · {} ", scr.name))
        .border_style(theme::border());

    if scr.events.is_empty() {
        let p = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "  No activity recorded yet.",
                Style::default()
                    .fg(theme::WARN)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                "  Unlocks, reveals, edits, and agent 'get' requests will show up here.",
                Style::default().fg(theme::TEXT),
            )),
        ])
        .block(block);
        frame.render_widget(p, area);
        return;
    }

    let header = Row::new(["WHEN", "ACTOR", "VIA", "ACTION", "TARGET"]).style(theme::header());
    let rows: Vec<Row> = scr
        .events
        .iter()
        .map(|e| {
            let when = e
                .timestamp()
                .map(|t| {
                    t.with_timezone(&chrono::Local)
                        .format("%m-%d %H:%M")
                        .to_string()
                })
                .unwrap_or_else(|| e.ts.chars().take(16).collect());
            // Agents stand out in yellow; humans in the accent color.
            let actor_style = if e.actor == crate::core::usage::AGENT {
                Style::default().fg(theme::WARN)
            } else {
                Style::default().fg(theme::ACCENT)
            };
            let actor = format!("{} {}", e.actor, e.actor_id);
            // Surface the action came through (cli / tui / gui / mcp); older
            // events recorded before sources existed show "-".
            let via = if e.source.is_empty() {
                "-".to_string()
            } else {
                e.source.clone()
            };
            let target = e.target.clone().unwrap_or_else(|| "-".to_string());
            Row::new(vec![
                Cell::from(when).style(Style::default().fg(theme::MUTED)),
                Cell::from(actor).style(actor_style),
                Cell::from(via).style(Style::default().fg(theme::MUTED)),
                Cell::from(e.action.clone()).style(Style::default().fg(theme::TEXT)),
                Cell::from(target).style(Style::default().fg(theme::MUTED)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(12),
        Constraint::Length(16),
        Constraint::Length(4),
        Constraint::Length(14),
        Constraint::Min(8),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .block(block)
        .column_spacing(2)
        .row_highlight_style(theme::selected_row())
        .highlight_symbol("> ");
    frame.render_stateful_widget(table, area, &mut scr.state);
}

// ── Form rendering ───────────────────────────────────────────────────────────

fn allow_label(mode: usize, list: &str) -> String {
    match mode {
        0 => "all agents".to_string(),
        1 => "none".to_string(),
        _ => format!(
            "specific list  ({})",
            if list.is_empty() { "—" } else { list }
        ),
    }
}

fn yes_no(v: bool) -> &'static str {
    if v {
        "yes"
    } else {
        "no"
    }
}

fn mask(s: &str) -> String {
    "*".repeat(s.chars().count())
}

/// Render a list of (label, value) field rows, highlighting the focused one.
/// When `caret` is set, a caret is drawn after the focused field's value so the
/// user can see exactly where typed/pasted text will land (text fields only).
fn field_lines<'a>(fields: &'a [(&'a str, String)], focus: usize, caret: bool) -> Vec<Line<'a>> {
    let mut lines = vec![Line::from("")];
    for (i, (label, value)) in fields.iter().enumerate() {
        let focused = i == focus;
        let marker = if focused { "> " } else { "  " };
        let label_style = if focused {
            theme::label_focused()
        } else {
            theme::label_dim()
        };
        let value_style = if focused {
            theme::value_focused()
        } else {
            Style::default()
        };
        let mut spans = vec![
            Span::raw(marker),
            Span::styled(format!("{label:<18}"), label_style),
            Span::styled(value.clone(), value_style),
        ];
        if focused && caret {
            // A reversed-space block reads as a solid terminal cursor, so it's
            // obvious the field is ready for typing even when it's empty.
            spans.push(Span::styled(
                " ",
                Style::default().add_modifier(Modifier::REVERSED),
            ));
        }
        lines.push(Line::from(spans));
    }
    lines
}

fn draw_create(frame: &mut Frame, area: Rect, form: &CreateForm) {
    use super::{CreateField, MasterStep};
    // Built from the form's dynamic field order so the master tail (set / unlock
    // / none) and the key logic can never drift apart.
    let fields: Vec<(&str, String)> = form
        .order
        .iter()
        .map(|f| match f {
            CreateField::Name => ("Name", form.name.clone()),
            CreateField::Description => ("Description", form.description.clone()),
            CreateField::AllowMode => (
                "Allow agent",
                allow_label(form.allow_mode, &form.allow_list),
            ),
            CreateField::AllowList => (
                "Agent list",
                if form.allow_list.is_empty() {
                    "—".into()
                } else {
                    form.allow_list.clone()
                },
            ),
            CreateField::RateLimit => ("Rate limit", form.rate_limit.clone()),
            CreateField::Autolock => ("Auto-lock", yes_no(form.autolock).to_string()),
            CreateField::AutolockTimer => ("Auto-lock timer", form.autolock_timer.clone()),
            CreateField::DefaultTier => ("Default tier", tier_label(form.default_tier).to_string()),
            CreateField::Judge => ("AI judge", yes_no(form.judge).to_string()),
            CreateField::JudgeName => ("Assigned judge", judge_name_label(&form.judge_name)),
            CreateField::MasterNew => ("Master passphrase", mask(&form.passphrase)),
            CreateField::MasterConfirm => ("Confirm master passphrase", mask(&form.confirm)),
            CreateField::MasterUnlock => ("Master passphrase", mask(&form.passphrase)),
        })
        .collect();
    let mut lines = field_lines(&fields, form.focus, form.focus_is_text());
    lines.push(Line::from(""));
    let note = match form.master_step {
        MasterStep::Set => "  First run: set a master passphrase — one secret unlocks every vault.",
        MasterStep::Unlock => "  Enter your master passphrase to create this vault under it.",
        MasterStep::Ready => "  Storage: local   Unlock: master passphrase",
    };
    lines.push(Line::from(Span::styled(note, Style::default().fg(DIM))));
    lines.push(Line::from(Span::styled(
        "  (space/←→ cycles tier, judge & assigned judge)",
        Style::default().fg(DIM),
    )));
    if let Some(err) = &form.error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  error: {err}"),
            Style::default().fg(Color::Red),
        )));
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Create vault ")
        .border_style(Style::default().fg(DIM));
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_settings(frame: &mut Frame, area: Rect, form: &SettingsForm) {
    let fields = [
        ("Description", form.description.clone()),
        (
            "Allow agent",
            allow_label(form.allow_mode, &form.allow_list),
        ),
        (
            "Agent list",
            if form.allow_list.is_empty() {
                "—".into()
            } else {
                form.allow_list.clone()
            },
        ),
        ("Rate limit", form.rate_limit.clone()),
        ("Auto-lock", yes_no(form.autolock).to_string()),
        ("Auto-lock timer", form.autolock_timer.clone()),
        ("Default tier", tier_label(form.default_tier).to_string()),
        ("AI judge", yes_no(form.judge).to_string()),
        ("Assigned judge", judge_name_label(&form.judge_name)),
    ];
    let mut lines = field_lines(&fields, form.focus, form.focus_is_text());
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Login: passphrase   (space/←→ cycles tier, judge & assigned judge)",
        Style::default().fg(DIM),
    )));
    if let Some(err) = &form.error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  error: {err}"),
            Style::default().fg(Color::Red),
        )));
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" Settings · {} ", form.name))
        .border_style(Style::default().fg(DIM));
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_secret_add(frame: &mut Frame, area: Rect, form: &SecretAddForm) {
    let fields = [
        ("Name", form.name.clone()),
        ("Value", mask(&form.value)),
        ("Scope", form.scope.clone()),
        ("Description", form.description.clone()),
        ("Tier", tier_label(form.tier).to_string()),
        ("Require reason", yes_no(form.require_reason).to_string()),
    ];
    let mut lines = field_lines(&fields, form.focus, form.focus_is_text());
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  space/←→ cycles tier & toggles require-reason",
        Style::default().fg(DIM),
    )));
    if let Some(err) = &form.error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  error: {err}"),
            Style::default().fg(Color::Red),
        )));
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" Add secret · {} ", form.vault_name))
        .border_style(Style::default().fg(DIM));
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_classify(frame: &mut Frame, area: Rect, form: &ClassifyForm) {
    let fields = [
        ("Scope", form.scope.clone()),
        ("Description", form.description.clone()),
        ("Tier", tier_label(form.tier).to_string()),
        ("Require reason", yes_no(form.require_reason).to_string()),
    ];
    let mut lines = field_lines(&fields, form.focus, form.focus_is_text());
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Edits the signed policy for this secret — the value is not touched.",
        Style::default().fg(DIM),
    )));
    lines.push(Line::from(Span::styled(
        "  space/←→ cycles tier & toggles require-reason",
        Style::default().fg(DIM),
    )));
    if let Some(err) = &form.error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  error: {err}"),
            Style::default().fg(Color::Red),
        )));
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" Classify · {} ", form.secret))
        .border_style(Style::default().fg(DIM));
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

/// MCP screen: readiness (daemon + unlocked vaults), the launch command, and the
/// client config snippet, with a one-key writer for `./.mcp.json`.
fn draw_mcp(frame: &mut Frame, area: Rect, daemon_running: bool, vaults: &[VaultRow]) {
    let unlocked: Vec<&str> = vaults
        .iter()
        .filter(|v| v.unlocked)
        .map(|v| v.name.as_str())
        .collect();

    let mut lines: Vec<Line> = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Local MCP server — gated secret access for AI agents (Claude Code, Cursor, …).",
            Style::default().fg(DIM),
        )),
        Line::from(Span::styled(
            "  The agent platform launches `svault mcp`; you keep a vault unlocked here.",
            Style::default().fg(DIM),
        )),
        Line::from(""),
    ];

    // Preconditions: the daemon (optional) and at least one unlocked vault.
    let (dlabel, dcolor) = if daemon_running {
        ("running", theme::OK)
    } else {
        (
            "off (optional — keys then live in the session file)",
            theme::WARN,
        )
    };
    lines.push(Line::from(vec![
        Span::styled("  Daemon:          ", Style::default().fg(DIM)),
        Span::styled(dlabel, Style::default().fg(dcolor)),
    ]));

    let (uvalue, ucolor) = if unlocked.is_empty() {
        ("(none — unlock a vault first)".to_string(), theme::WARN)
    } else {
        (unlocked.join(", "), theme::OK)
    };
    lines.push(Line::from(vec![
        Span::styled("  Unlocked vaults: ", Style::default().fg(DIM)),
        Span::styled(uvalue, Style::default().fg(ucolor)),
    ]));
    lines.push(Line::from(""));

    if unlocked.is_empty() {
        lines.push(Line::from(Span::styled(
            "  Not ready — press esc, then u to unlock a vault so the server has something to serve.",
            Style::default().fg(theme::WARN),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            "  Ready — agents can fetch from the unlocked vault(s) through the policy + judge gate.",
            Style::default().fg(theme::OK),
        )));
    }
    lines.push(Line::from(""));

    lines.push(Line::from(Span::styled(
        "  Claude Code / Cursor config — add to .mcp.json (press w to write it here):",
        Style::default().fg(DIM),
    )));
    for s in [
        "    {",
        "      \"mcpServers\": {",
        "        \"svault\": {",
        "          \"command\": \"svault\",",
        "          \"args\": [\"mcp\"],",
        "          \"env\": { \"SVAULT_CALLER\": \"claude-code\" }",
        "        }",
        "      }",
        "    }",
    ] {
        lines.push(Line::from(Span::styled(s, Style::default().fg(CYAN))));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  w write .mcp.json into this folder    d toggle daemon    esc back",
        Style::default().fg(DIM),
    )));

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" MCP ")
        .border_style(Style::default().fg(DIM));
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_judge(frame: &mut Frame, area: Rect, form: &JudgeForm) {
    let mut lines: Vec<Line> = Vec::new();
    if !form.created {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  No keyring yet.",
            Style::default().fg(theme::WARN),
        )));
        lines.push(Line::from(Span::styled(
            "  Press enter to create it — your master passphrase encrypts your judges + keys.",
            Style::default().fg(DIM),
        )));
    } else if !form.unlocked {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  Keyring is locked.",
            Style::default().fg(theme::WARN),
        )));
        lines.push(Line::from(Span::styled(
            "  Press enter to unlock and manage judges.",
            Style::default().fg(DIM),
        )));
    } else {
        // A judge can authenticate with its own stored key or, failing that, the
        // opt-in $SVAULT_OPENROUTER_KEY env override. Knowing whether that env is
        // set lets us label "no stored key" honestly instead of cryptic "env/none".
        let env_present = std::env::var(crate::core::keyring::KEY_ENV)
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);
        let sel = |i: usize| if form.focus == i { ">" } else { " " };
        lines.push(Line::from(vec![
            Span::raw(format!(" {} ", sel(0))),
            Span::styled("AI judge (global)   ", Style::default().fg(theme::ACCENT)),
            Span::styled(
                yes_no(form.enabled).to_string(),
                Style::default().add_modifier(Modifier::BOLD),
            ),
        ]));
        lines.push(Line::from(Span::styled(
            format!(
                "      default judge: {}",
                form.default_judge.as_deref().unwrap_or("(none)")
            ),
            Style::default().fg(DIM),
        )));
        // The common confusing case: the judge is ON but the judge that would run
        // has no usable key, so every medium/high gate silently fails. Call it out.
        let default_has_key = form
            .default_judge
            .as_ref()
            .and_then(|dn| form.judges.iter().find(|j| &j.name == dn))
            .map(|j| j.has_key)
            .unwrap_or(false);
        if form.enabled && !default_has_key && !env_present {
            lines.push(Line::from(Span::styled(
                "      ! judge is ON but has no API key — set one with k, or export $SVAULT_OPENROUTER_KEY (else medium/high requests fail)",
                Style::default().fg(theme::WARN),
            )));
        }
        lines.push(Line::from(""));
        if form.judges.is_empty() {
            lines.push(Line::from(Span::styled(
                "  No judges yet — press a to add one.",
                Style::default().fg(DIM),
            )));
        } else {
            lines.push(Line::from(Span::styled(
                format!(
                    "    {:<16} {:<24} {:>6} {:>5}  KEY",
                    "NAME", "MODEL", "ALLOW", "HIGH"
                ),
                Style::default().fg(DIM),
            )));
            for (i, j) in form.judges.iter().enumerate() {
                let focused = form.focus == i + 1;
                let mark = if focused { ">" } else { " " };
                let def = if form.default_judge.as_deref() == Some(j.name.as_str()) {
                    "*"
                } else {
                    " "
                };
                // Key state, color-coded: stored key (ok), env fallback (warn), or
                // nothing (err) — so a keyless judge stands out at a glance.
                let (key_label, key_color) = if j.has_key {
                    ("key set", theme::OK)
                } else if env_present {
                    ("env key", theme::WARN)
                } else {
                    ("no key", theme::ERR)
                };
                let row_style = if focused {
                    Style::default()
                        .fg(theme::ACCENT)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                let key_style = if focused {
                    Style::default().fg(key_color).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(key_color)
                };
                lines.push(Line::from(vec![
                    Span::styled(
                        format!(
                            " {}{}{:<15} {:<24} {:>6} {:>5}  ",
                            mark, def, j.name, j.model, j.allow, j.high
                        ),
                        row_style,
                    ),
                    Span::styled(key_label, key_style),
                ]));
            }
        }
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  key: 'key set' = stored · 'env key' = $SVAULT_OPENROUTER_KEY · 'no key' = none (press k to set)",
            Style::default().fg(DIM),
        )));
        lines.push(Line::from(Span::styled(
            "  space on/off   a add   e edit   v view   k key   d default   t test   x remove",
            Style::default().fg(DIM),
        )));
    }
    if let Some((kind, msg)) = &form.test_result {
        let color = match kind {
            MsgKind::Ok => theme::OK,
            MsgKind::Warn => theme::WARN,
            MsgKind::Error => theme::ERR,
            MsgKind::Info => theme::ACCENT,
        };
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  test: {msg}"),
            Style::default().fg(color),
        )));
    }
    if let Some(err) = &form.error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  error: {err}"),
            Style::default().fg(Color::Red),
        )));
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" AI judge ")
        .border_style(Style::default().fg(DIM));
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );

    // Sub-mode overlay on top.
    match &form.entry {
        Some(JudgeEntry::Passphrase(b)) => {
            draw_masked_popup(frame, area, " Unlock keyring ", "  Master passphrase", b)
        }
        Some(JudgeEntry::Key { judge, buf }) => draw_masked_popup(
            frame,
            area,
            " Set judge key ",
            &format!("  OpenRouter key for '{judge}' (sk-or-…, blank clears)"),
            buf,
        ),
        Some(JudgeEntry::Init(init)) => draw_judge_init(frame, area, init),
        Some(JudgeEntry::Edit(ed)) => draw_judge_edit(frame, area, ed),
        Some(JudgeEntry::View(name)) => draw_judge_view(frame, area, form, name),
        None => {}
    }
}

/// A single masked-input popup (unlock passphrase, judge API key).
fn draw_masked_popup(frame: &mut Frame, area: Rect, title: &str, label: &str, buf: &str) {
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            label.to_string(),
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::raw("  > "),
            Span::styled(mask(buf), Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(" ", Style::default().add_modifier(Modifier::REVERSED)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  enter  confirm    esc  cancel",
            Style::default().fg(DIM),
        )),
    ];
    let popup = centered_rect(64, 40, area);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title.to_string())
        .border_style(Style::default().fg(CYAN));
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        popup,
    );
}

/// One labelled, focusable input row used by the judge add/edit and init popups.
fn entry_row(label: &str, value: String, focused: bool, masked: bool) -> Line<'static> {
    let cursor = if focused { ">" } else { " " };
    let shown = if masked { mask(&value) } else { value };
    let label_style = if focused {
        Style::default()
            .fg(theme::ACCENT)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(DIM)
    };
    let mut spans = vec![
        Span::raw(format!("  {cursor} ")),
        Span::styled(format!("{label:<11}"), label_style),
        Span::styled(shown, Style::default().add_modifier(Modifier::BOLD)),
    ];
    if focused {
        spans.push(Span::styled(
            " ",
            Style::default().add_modifier(Modifier::REVERSED),
        ));
    }
    Line::from(spans)
}

/// Create-a-keyring popup: passphrase + confirm.
fn draw_judge_init(frame: &mut Frame, area: Rect, init: &InitForm) {
    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  No master passphrase yet — set one. It unlocks the keyring and every vault.",
            Style::default().fg(DIM),
        )),
        Line::from(""),
        entry_row("Passphrase", init.pass.clone(), init.focus == 0, true),
        entry_row("Confirm", init.confirm.clone(), init.focus == 1, true),
        Line::from(""),
    ];
    if let Some(err) = &init.error {
        lines.push(Line::from(Span::styled(
            format!("  {err}"),
            Style::default().fg(Color::Red),
        )));
    }
    lines.push(Line::from(Span::styled(
        "  tab switch    enter create    esc cancel",
        Style::default().fg(DIM),
    )));
    let popup = centered_rect(66, 46, area);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Set master passphrase ")
        .border_style(Style::default().fg(CYAN));
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        popup,
    );
}

/// Add/edit-a-judge popup: name, model, url, timeout, thresholds, criteria.
fn draw_judge_edit(frame: &mut Frame, area: Rect, ed: &JudgeEditForm) {
    let title = if ed.original.is_some() {
        " Edit judge "
    } else {
        " Add judge "
    };
    let mut lines = vec![
        Line::from(""),
        entry_row("Name", ed.name.clone(), ed.focus == 0, false),
        entry_row("Model", ed.model.clone(), ed.focus == 1, false),
        entry_row("Base URL", ed.base_url.clone(), ed.focus == 2, false),
        entry_row("Timeout s", ed.timeout.clone(), ed.focus == 3, false),
        entry_row("Allow ≥", ed.allow.clone(), ed.focus == 4, false),
        entry_row("High ≥", ed.high.clone(), ed.focus == 5, false),
        entry_row("Criteria", ed.criteria.clone(), ed.focus == 6, false),
        Line::from(""),
        Line::from(Span::styled(
            "  Criteria: extra rules added to this judge's prompt (optional).",
            Style::default().fg(DIM),
        )),
        Line::from(Span::styled(
            "  API key: set it with k after saving, or export $SVAULT_OPENROUTER_KEY.",
            Style::default().fg(DIM),
        )),
        Line::from(""),
    ];
    if let Some(err) = &ed.error {
        lines.push(Line::from(Span::styled(
            format!("  {err}"),
            Style::default().fg(Color::Red),
        )));
    }
    lines.push(Line::from(Span::styled(
        "  tab/↑↓ move    enter save    esc cancel",
        Style::default().fg(DIM),
    )));
    let popup = centered_rect(72, 70, area);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(Style::default().fg(CYAN));
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        popup,
    );
}

/// Read-only detail of one judge (includes its criteria).
fn draw_judge_view(frame: &mut Frame, area: Rect, form: &JudgeForm, name: &str) {
    let row = form.judges.iter().find(|j| j.name == name);
    let mut lines = vec![Line::from("")];
    if let Some(j) = row {
        let field = |k: &str, v: String| {
            Line::from(vec![
                Span::styled(format!("  {k:<11}"), Style::default().fg(DIM)),
                Span::styled(v, Style::default().add_modifier(Modifier::BOLD)),
            ])
        };
        let is_default = form.default_judge.as_deref() == Some(j.name.as_str());
        lines.push(field("name", j.name.clone()));
        lines.push(field(
            "default",
            if is_default { "yes" } else { "no" }.to_string(),
        ));
        lines.push(field("model", j.model.clone()));
        lines.push(field("base url", j.base_url.clone()));
        lines.push(field("timeout", format!("{}s", j.timeout_secs)));
        lines.push(field("allow ≥", j.allow.to_string()));
        lines.push(field("high ≥", j.high.to_string()));
        let env_present = std::env::var(crate::core::keyring::KEY_ENV)
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);
        let key_desc = if j.has_key {
            "set (stored, encrypted)".to_string()
        } else if env_present {
            format!("from ${} (env)", crate::core::keyring::KEY_ENV)
        } else {
            format!(
                "not set — press k, or export ${}",
                crate::core::keyring::KEY_ENV
            )
        };
        lines.push(field("api key", key_desc));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  criteria",
            Style::default().fg(DIM),
        )));
        let criteria = if j.criteria.trim().is_empty() {
            "(none)".to_string()
        } else {
            j.criteria.clone()
        };
        lines.push(Line::from(Span::styled(
            format!("  {criteria}"),
            Style::default(),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            format!("  no judge named '{name}'"),
            Style::default().fg(Color::Red),
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  e edit    any other key to close",
        Style::default().fg(DIM),
    )));
    let popup = centered_rect(72, 70, area);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" Judge: {name} "))
        .border_style(Style::default().fg(CYAN));
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        popup,
    );
}

fn draw_recovery_code(frame: &mut Frame, area: Rect, show: &super::RecoveryShow) {
    let mut lines = vec![Line::from("")];
    let plural = if show.codes.len() > 1 {
        "codes"
    } else {
        "code"
    };
    lines.push(Line::from(Span::styled(
        format!("  Recovery {plural}"),
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    )));
    for (label, code) in &show.codes {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  {label}"),
            Style::default().fg(DIM),
        )));
        lines.push(Line::from(Span::styled(
            format!("    {code}"),
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        )));
    }
    lines.extend([
        Line::from(""),
        Line::from(Span::styled(
            "  This is the ONLY time these are shown — they are not stored in plaintext.",
            Style::default().fg(Color::Yellow),
        )),
        Line::from(Span::styled(
            "  Save them in a password manager (or on paper, offline). They are the only",
            Style::default().fg(DIM),
        )),
        Line::from(Span::styled(
            "  way back in if you forget your passphrase — 'svault recover' (a vault) or",
            Style::default().fg(DIM),
        )),
        Line::from(Span::styled(
            "  'svault master recover' (the master).",
            Style::default().fg(DIM),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  Press 'y' to confirm you have saved them.",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
    ]);
    let title = if show.codes.len() > 1 {
        " Save your recovery codes "
    } else {
        " Save your recovery code "
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(Style::default().fg(Color::Yellow));
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_import(frame: &mut Frame, area: Rect, form: &super::ImportForm) {
    let fields = [("Bundle path", form.path.clone())];
    let mut lines = field_lines(&fields, 0, true);
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Path to a .svault-export.json file created by 'svault export'.",
        Style::default().fg(DIM),
    )));
    if let Some(err) = &form.error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  error: {err}"),
            Style::default().fg(Color::Red),
        )));
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Import vault ")
        .border_style(Style::default().fg(DIM));
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_recover(frame: &mut Frame, area: Rect, form: &super::RecoverForm) {
    // The recovery code is shown as typed (not masked): the user is copying it
    // from paper or a password manager, so visible text prevents silent typos.
    let fields = [
        ("Recovery code", form.code.clone()),
        ("New passphrase", mask(&form.new_pass)),
        ("Confirm passphrase", mask(&form.confirm)),
    ];
    let mut lines = field_lines(&fields, form.focus, true);
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Resets a lost passphrase. The recovery code stays the same.",
        Style::default().fg(DIM),
    )));
    if let Some(err) = &form.error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  error: {err}"),
            Style::default().fg(Color::Red),
        )));
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" Recover · {} ", form.name))
        .border_style(Style::default().fg(DIM));
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

// ── Unlock ─────────────────────────────────────────────────────────────────────

fn draw_unlock(frame: &mut Frame, area: Rect, form: &UnlockForm) {
    let mut lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::raw("  Master passphrase to unlock "),
            Span::styled(
                form.name.clone(),
                Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::raw("  > "),
            Span::styled(
                mask(&form.passphrase),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(" ", Style::default().add_modifier(Modifier::REVERSED)),
        ]),
    ];
    if form.yubikey {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  YubiKey enrolled — type the PIN (if any), then Ctrl+Y to unlock by touch.",
            Style::default().fg(CYAN),
        )));
    }
    if let Some(err) = &form.error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  {err}"),
            Style::default().fg(Color::Red),
        )));
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Unlock ")
        .border_style(Style::default().fg(DIM));
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

// ── Login gate ───────────────────────────────────────────────────────────────

fn draw_login(frame: &mut Frame, area: Rect, form: &LoginForm) {
    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Sign in to Svault",
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "  Enter your master passphrase to continue.",
            Style::default().fg(DIM),
        )),
        Line::from(""),
        Line::from(vec![
            Span::raw("  Master passphrase  > "),
            Span::styled(
                mask(&form.passphrase),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(" ", Style::default().add_modifier(Modifier::REVERSED)),
        ]),
    ];
    if form.yubikey {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  YubiKey enrolled — type the PIN (if any), then Ctrl+Y to sign in by touch.",
            Style::default().fg(CYAN),
        )));
    }
    if let Some(err) = &form.error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  {err}"),
            Style::default().fg(Color::Red),
        )));
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Sign in ")
        .border_style(Style::default().fg(CYAN));
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

// ── First-run onboarding ─────────────────────────────────────────────────────

fn draw_onboard(frame: &mut Frame, area: Rect, form: &OnboardForm) {
    let bold = Style::default().add_modifier(Modifier::BOLD);
    let dim = Style::default().fg(DIM);
    let accent = Style::default().fg(CYAN).add_modifier(Modifier::BOLD);

    let (title, mut lines): (&str, Vec<Line>) = match form.step {
        OnboardStep::Disclaimer => (
            " Welcome to Svault — Step 1 of 3 ",
            vec![
                Line::from(""),
                Line::from(Span::styled(
                    "  Svault gives cooperative AI agents structured, policy-gated, audited",
                    Style::default(),
                )),
                Line::from(Span::styled(
                    "  access to your secrets, and encrypts everything at rest.",
                    Style::default(),
                )),
                Line::from(""),
                Line::from(Span::styled("  Be honest about the boundary:", accent)),
                Line::from(Span::styled(
                    "  Svault is NOT a sandbox against a hostile process running as your own",
                    Style::default(),
                )),
                Line::from(Span::styled(
                    "  user — such a process can read an unlocked session directly. It raises",
                    Style::default(),
                )),
                Line::from(Span::styled(
                    "  the bar for agents that mostly play by the rules and gives you an audit",
                    Style::default(),
                )),
                Line::from(Span::styled(
                    "  trail when one doesn't. There are no accounts and no cloud — everything",
                    Style::default(),
                )),
                Line::from(Span::styled(
                    "  stays on this machine, and your master passphrase is the root of trust.",
                    Style::default(),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "  Press Enter to acknowledge this and continue.",
                    dim,
                )),
            ],
        ),
        OnboardStep::Passphrase => {
            let caret = |focused: bool| if focused { "> " } else { "  " };
            (
                " Set your master passphrase — Step 2 of 3 ",
                vec![
                    Line::from(""),
                    Line::from(Span::styled(
                        "  One passphrase unlocks every vault. Choose a strong one — it is the",
                        Style::default(),
                    )),
                    Line::from(Span::styled(
                        "  root of trust and cannot be recovered except via the recovery code.",
                        dim,
                    )),
                    Line::from(""),
                    Line::from(vec![
                        Span::styled(format!("  {}Passphrase  ", caret(form.focus == 0)), dim),
                        Span::styled(mask(&form.passphrase), bold),
                        Span::styled(
                            if form.focus == 0 { " " } else { "" },
                            Style::default().add_modifier(Modifier::REVERSED),
                        ),
                    ]),
                    Line::from(vec![
                        Span::styled(format!("  {}Confirm     ", caret(form.focus == 1)), dim),
                        Span::styled(mask(&form.confirm), bold),
                        Span::styled(
                            if form.focus == 1 { " " } else { "" },
                            Style::default().add_modifier(Modifier::REVERSED),
                        ),
                    ]),
                ],
            )
        }
        OnboardStep::Recovery => {
            let code = form.recovery_code.as_deref().unwrap_or("(unavailable)");
            (
                " Save your recovery code ",
                vec![
                    Line::from(""),
                    Line::from(Span::styled(
                        "  This one-time code is the ONLY way back in if you forget the master",
                        Style::default(),
                    )),
                    Line::from(Span::styled(
                        "  passphrase. It is shown once. Write it down and store it offline.",
                        Style::default(),
                    )),
                    Line::from(""),
                    Line::from(vec![
                        Span::styled("  Master recovery code   ", dim),
                        Span::styled(code.to_string(), accent),
                    ]),
                    Line::from(""),
                    Line::from(Span::styled(
                        "  Press 'y' once you have saved it to continue.",
                        dim,
                    )),
                ],
            )
        }
        OnboardStep::Yubikey => {
            let device = if form.yubikey_present {
                Span::styled("connected", Style::default().fg(CYAN))
            } else {
                Span::styled("not connected", dim)
            };
            (
                " Optional: enroll a YubiKey — Step 3 of 3 ",
                vec![
                    Line::from(""),
                    Line::from(Span::styled(
                        "  Optionally add a YubiKey as an alternative way to unlock (a touch",
                        Style::default(),
                    )),
                    Line::from(Span::styled(
                        "  instead of typing the passphrase). It's passphrase OR touch — never",
                        Style::default(),
                    )),
                    Line::from(Span::styled(
                        "  required, and the passphrase always still works.",
                        dim,
                    )),
                    Line::from(""),
                    Line::from(vec![Span::styled("  Device   ", dim), device]),
                    Line::from(vec![
                        Span::styled("  PIN      ", dim),
                        Span::styled(mask(&form.pin), bold),
                        Span::styled(" ", Style::default().add_modifier(Modifier::REVERSED)),
                        Span::styled("  (leave blank if your key has no PIN)", dim),
                    ]),
                    Line::from(""),
                    Line::from(Span::styled(
                        "  Enter to enroll (you'll touch the key twice), or Esc to skip.",
                        dim,
                    )),
                ],
            )
        }
    };

    if let Some(err) = &form.error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  {err}"),
            Style::default().fg(Color::Red),
        )));
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(Style::default().fg(CYAN));
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

// ── Secrets ────────────────────────────────────────────────────────────────────

fn draw_secrets(frame: &mut Frame, area: Rect, scr: &mut SecretScreen) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" Secrets · {} (unlocked) ", scr.name))
        .border_style(Style::default().fg(DIM));

    if scr.secrets.is_empty() {
        let p = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "  No secrets yet.",
                Style::default()
                    .fg(theme::WARN)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                "  Press 'a' to add one.",
                Style::default().fg(theme::TEXT),
            )),
        ])
        .block(block);
        frame.render_widget(p, area);
    } else {
        // Each row shows the secret's name next to the policy classification
        // (tier/scope/require-reason/description) that gates an agent `get`.
        let header =
            Row::new(["SECRET", "TIER", "SCOPE", "REASON?", "DESCRIPTION"]).style(theme::header());
        let rows: Vec<Row> = scr
            .secrets
            .iter()
            .map(|n| {
                let rule = scr.classifications.get(n);
                let (tier, tier_style) = match rule.map(|r| r.tier) {
                    Some(crate::core::policy::Tier::High) => {
                        ("high", Style::default().fg(theme::ERR))
                    }
                    Some(crate::core::policy::Tier::Medium) => {
                        ("medium", Style::default().fg(theme::WARN))
                    }
                    Some(crate::core::policy::Tier::Low) => ("low", Style::default().fg(theme::OK)),
                    None => ("unset", Style::default().fg(theme::MUTED)),
                };
                let scope = rule
                    .map(|r| r.scope.clone())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "-".to_string());
                let reason = match rule.map(|r| r.require_reason) {
                    Some(true) => "yes",
                    _ => "-",
                };
                let desc = rule
                    .map(|r| r.description.clone())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "-".to_string());
                Row::new(vec![
                    Cell::from(n.clone()).style(Style::default().fg(CYAN)),
                    Cell::from(tier).style(tier_style),
                    Cell::from(scope).style(Style::default().fg(theme::TEXT)),
                    Cell::from(reason).style(Style::default().fg(theme::MUTED)),
                    Cell::from(desc).style(Style::default().fg(theme::MUTED)),
                ])
            })
            .collect();
        let widths = [
            Constraint::Length(22),
            Constraint::Length(8),
            Constraint::Length(12),
            Constraint::Length(8),
            Constraint::Min(10),
        ];
        let table = Table::new(rows, widths)
            .header(header)
            .block(block)
            .column_spacing(2)
            .row_highlight_style(theme::selected_row())
            .highlight_symbol("> ");
        frame.render_stateful_widget(table, area, &mut scr.list_state);
    }

    // Reveal modal.
    if let Some(reveal) = &scr.reveal {
        let value = if reveal.masked {
            mask(&reveal.value)
        } else {
            reveal.value.to_string()
        };
        let lines = vec![
            Line::from(""),
            Line::from(vec![
                Span::raw("  "),
                Span::styled(
                    reveal.name.clone(),
                    Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                format!("  {value}"),
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(Span::styled(
                if reveal.masked {
                    "  (hidden — press space to reveal)"
                } else {
                    "  (press space to hide)"
                },
                Style::default().fg(DIM),
            )),
        ];
        let popup = centered_rect(60, 40, area);
        frame.render_widget(Clear, popup);
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Secret value ")
            .border_style(Style::default().fg(CYAN));
        frame.render_widget(
            Paragraph::new(lines)
                .block(block)
                .wrap(Wrap { trim: false }),
            popup,
        );
    }

    // Delete confirmation modal.
    if let Some(name) = &scr.pending_delete {
        let lines = vec![
            Line::from(""),
            Line::from(vec![
                Span::raw("  Delete secret "),
                Span::styled(
                    name.clone(),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                Span::raw("?"),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "  y = delete    n / esc = cancel",
                Style::default().fg(DIM),
            )),
        ];
        let popup = centered_rect(50, 30, area);
        frame.render_widget(Clear, popup);
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Confirm delete ")
            .border_style(Style::default().fg(Color::Red));
        frame.render_widget(
            Paragraph::new(lines)
                .block(block)
                .alignment(Alignment::Left),
            popup,
        );
    }
}

/// Center a rectangle taking `pct_x`% width and `pct_y`% height of `area`.
fn centered_rect(pct_x: u16, pct_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - pct_y) / 2),
            Constraint::Percentage(pct_y),
            Constraint::Percentage((100 - pct_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - pct_x) / 2),
            Constraint::Percentage(pct_x),
            Constraint::Percentage((100 - pct_x) / 2),
        ])
        .split(vertical[1])[1]
}
