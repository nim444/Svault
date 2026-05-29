//! Rendering for the Svault TUI. Each screen draws into a three-row layout:
//! a header (title + status), a body, and a footer with context key hints.

use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, List, ListItem, Paragraph, Row, Table, Wrap},
    Frame,
};

use super::theme;
use super::{
    App, CreateForm, MsgKind, Screen, SecretAddForm, SecretScreen, SettingsForm, UnlockForm,
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

    draw_header(frame, chunks[0]);

    match &mut app.screen {
        Screen::List => draw_list(frame, chunks[1], &app.vaults, &mut app.list_state),
        Screen::Create(form) => draw_create(frame, chunks[1], form),
        Screen::Settings(form) => draw_settings(frame, chunks[1], form),
        Screen::Unlock(form) => draw_unlock(frame, chunks[1], form),
        Screen::Secrets(scr) => draw_secrets(frame, chunks[1], scr),
        Screen::SecretAdd(form) => draw_secret_add(frame, chunks[1], form),
        Screen::RecoveryCode(code) => draw_recovery_code(frame, chunks[1], code),
        Screen::Import(form) => draw_import(frame, chunks[1], form),
        Screen::Recover(form) => draw_recover(frame, chunks[1], form),
        Screen::Activity(scr) => draw_activity(frame, chunks[1], scr),
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

fn draw_header(frame: &mut Frame, area: Rect) {
    let spans = vec![
        Span::styled(" Svault ", theme::title()),
        Span::styled("— AI-aware secret manager", theme::label_dim()),
    ];
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::border());
    frame.render_widget(Paragraph::new(Line::from(spans)).block(block), area);
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
    let hint = if app.confirm_quit {
        "enter  quit        esc / any key  stay"
    } else if app.show_help {
        "any key / esc  close help"
    } else {
        match &app.screen {
            Screen::List => {
                "↑/↓ move   enter open   c create   u unlock   l lock   s settings   v activity   e export   i import   r recover   ? help   q quit"
            }
            Screen::Activity(_) => "↑/↓ scroll   esc / b back   q quit",
            Screen::Create(_) => {
                "↑/↓ field   ←/→ change   space toggle   enter next/create   esc cancel"
            }
            Screen::Settings(_) => {
                "↑/↓ field   ←/→ change   space toggle   enter next/save   esc cancel"
            }
            Screen::Unlock(_) => "type passphrase   enter unlock   esc cancel",
            Screen::Secrets(scr) => {
                if scr.reveal.is_some() {
                    "space reveal/hide   esc close"
                } else if scr.pending_delete.is_some() {
                    "y confirm delete   n cancel"
                } else {
                    "↑/↓ move   enter view   a add   d delete   l lock   ? help   esc back"
                }
            }
            Screen::SecretAdd(_) => "↑/↓ field   enter next/save   esc cancel",
            Screen::RecoveryCode(_) => "press 'y' to confirm you have saved the code",
            Screen::Import(_) => "type/paste path to bundle   enter import   esc cancel",
            Screen::Recover(_) => "↑/↓ field   enter next/recover   esc cancel",
        }
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
            ("d", "delete the selected secret"),
            ("l", "lock the vault"),
            ("esc or b", "back to vault list"),
        ],
        // Default to the list bindings — the main hub.
        _ => &[
            ("↑/↓ or j/k", "move selection"),
            ("enter", "open a vault's secrets"),
            ("c", "create a new vault"),
            ("u / l", "unlock / lock the selected vault"),
            (
                "s",
                "edit settings (description, agents, rate limit, auto-lock)",
            ),
            ("v", "view the activity timeline (human + agent)"),
            ("e / i", "export / import an encrypted bundle"),
            ("r", "recover a vault with its recovery code"),
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

    let header = Row::new(["WHEN", "ACTOR", "ACTION", "TARGET"]).style(theme::header());
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
            let actor_style = if e.actor == crate::usage::AGENT {
                Style::default().fg(theme::WARN)
            } else {
                Style::default().fg(theme::ACCENT)
            };
            let actor = format!("{} {}", e.actor, e.actor_id);
            let target = e.target.clone().unwrap_or_else(|| "-".to_string());
            Row::new(vec![
                Cell::from(when).style(Style::default().fg(theme::MUTED)),
                Cell::from(actor).style(actor_style),
                Cell::from(e.action.clone()).style(Style::default().fg(theme::TEXT)),
                Cell::from(target).style(Style::default().fg(theme::MUTED)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(14),
        Constraint::Length(18),
        Constraint::Length(16),
        Constraint::Min(10),
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
    // Order must match CreateField::ORDER.
    let fields = [
        ("Name", form.name.clone()),
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
        ("Passphrase", mask(&form.passphrase)),
        ("Confirm passphrase", mask(&form.confirm)),
    ];
    let mut lines = field_lines(&fields, form.focus, form.focus_is_text());
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Storage: local   Login: passphrase   (more options coming soon)",
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
    ];
    let mut lines = field_lines(&fields, form.focus, form.focus_is_text());
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Login: passphrase   (more options coming soon)",
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
    let fields = [("Name", form.name.clone()), ("Value", mask(&form.value))];
    let mut lines = field_lines(&fields, form.focus, true);
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

fn draw_recovery_code(frame: &mut Frame, area: Rect, code: &str) {
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Recovery code",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            format!("    {code}"),
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  This is the ONLY time this code is shown — it is not stored in plaintext.",
            Style::default().fg(Color::Yellow),
        )),
        Line::from(Span::styled(
            "  Save it in a password manager (or on paper, offline). It is the only way",
            Style::default().fg(DIM),
        )),
        Line::from(Span::styled(
            "  back in if you lose your passphrase — then run 'svault recover'.",
            Style::default().fg(DIM),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  Press 'y' to confirm you have saved it.",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
    ];
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Save your recovery code ")
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
            Span::raw("  Passphrase for "),
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
        let items: Vec<ListItem> = scr
            .secrets
            .iter()
            .map(|n| ListItem::new(Span::styled(n.clone(), Style::default().fg(CYAN))))
            .collect();
        let list = List::new(items)
            .block(block)
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol("> ");
        frame.render_stateful_widget(list, area, &mut scr.list_state);
    }

    // Reveal modal.
    if let Some(reveal) = &scr.reveal {
        let value = if reveal.masked {
            mask(&reveal.value)
        } else {
            reveal.value.clone()
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
