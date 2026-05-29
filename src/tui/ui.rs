//! Rendering for the Svault TUI. Each screen draws into a three-row layout:
//! a header (title + status), a body, and a footer with context key hints.

use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
    Frame,
};

use super::{
    App, CreateForm, MsgKind, Screen, SecretAddForm, SecretScreen, SettingsForm, UnlockForm,
};

const CYAN: Color = Color::Cyan;
const DIM: Color = Color::DarkGray;

pub fn draw(frame: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(frame.area());

    draw_header(frame, chunks[0], app);

    match &mut app.screen {
        Screen::List => draw_list(frame, chunks[1], &app.vaults, &mut app.list_state),
        Screen::Create(form) => draw_create(frame, chunks[1], form),
        Screen::Settings(form) => draw_settings(frame, chunks[1], form),
        Screen::Unlock(form) => draw_unlock(frame, chunks[1], form),
        Screen::Secrets(scr) => draw_secrets(frame, chunks[1], scr),
        Screen::SecretAdd(form) => draw_secret_add(frame, chunks[1], form),
    }

    draw_footer(frame, chunks[2], &app.screen);
}

// ── Header ─────────────────────────────────────────────────────────────────────

fn draw_header(frame: &mut Frame, area: Rect, app: &App) {
    let title = Span::styled(
        " Svault ",
        Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
    );
    let mut spans = vec![
        title,
        Span::styled("— AI-aware secret manager", Style::default().fg(DIM)),
    ];

    if let Some(status) = &app.status {
        let color = match status.kind {
            MsgKind::Ok => Color::Green,
            MsgKind::Warn => Color::Yellow,
            MsgKind::Error => Color::Red,
            MsgKind::Info => Color::Cyan,
        };
        let prefix = match status.kind {
            MsgKind::Ok => "ok: ",
            MsgKind::Warn => "warning: ",
            MsgKind::Error => "error: ",
            MsgKind::Info => "note: ",
        };
        spans.push(Span::raw("   "));
        spans.push(Span::styled(
            format!("{prefix}{}", status.text),
            Style::default().fg(color),
        ));
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(DIM));
    let p = Paragraph::new(Line::from(spans)).block(block);
    frame.render_widget(p, area);
}

// ── Footer ─────────────────────────────────────────────────────────────────────

fn draw_footer(frame: &mut Frame, area: Rect, screen: &Screen) {
    let hint = match screen {
        Screen::List => {
            "↑/↓ move   enter open   c create   u unlock   l lock   s settings   q quit"
        }
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
                "↑/↓ move   enter view   a add   d delete   l lock   esc back"
            }
        }
        Screen::SecretAdd(_) => "↑/↓ field   enter next/save   esc cancel",
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(DIM));
    let p = Paragraph::new(Span::styled(hint, Style::default().fg(DIM))).block(block);
    frame.render_widget(p, area);
}

// ── List ───────────────────────────────────────────────────────────────────────

fn draw_list(
    frame: &mut Frame,
    area: Rect,
    vaults: &[super::VaultRow],
    state: &mut ratatui::widgets::ListState,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Vaults ")
        .border_style(Style::default().fg(DIM));

    if vaults.is_empty() {
        let p = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled("  No vaults yet.", Style::default().fg(DIM))),
            Line::from(Span::styled(
                "  Press 'c' to create your first vault.",
                Style::default().fg(DIM),
            )),
        ])
        .block(block);
        frame.render_widget(p, area);
        return;
    }

    let items: Vec<ListItem> = vaults
        .iter()
        .map(|v| {
            let (badge, badge_style) = if v.unlocked {
                ("unlocked", Style::default().fg(Color::Green))
            } else {
                ("locked  ", Style::default().fg(DIM))
            };
            let desc = if v.description.is_empty() {
                "-"
            } else {
                v.description.as_str()
            };
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{:<26}", format!("{}:{}", v.storage, v.name)),
                    Style::default().fg(CYAN),
                ),
                Span::styled(format!("{badge}  "), badge_style),
                Span::styled(desc.to_string(), Style::default().fg(Color::Gray)),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(block)
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("> ");
    frame.render_stateful_widget(list, area, state);
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

fn login_label(method: usize) -> &'static str {
    match method {
        0 => "passphrase",
        1 => "yubikey (coming soon)",
        _ => "google auth (coming soon)",
    }
}

fn storage_label(storage: usize) -> &'static str {
    match storage {
        0 => "local",
        1 => "Soluzy cloud (coming soon)",
        2 => "self-hosted (coming soon)",
        _ => "S3 / MinIO (coming soon)",
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
fn field_lines<'a>(fields: &'a [(&'a str, String)], focus: usize) -> Vec<Line<'a>> {
    let mut lines = vec![Line::from("")];
    for (i, (label, value)) in fields.iter().enumerate() {
        let focused = i == focus;
        let marker = if focused { "> " } else { "  " };
        let label_style = if focused {
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(DIM)
        };
        let value_style = if focused {
            Style::default().add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        lines.push(Line::from(vec![
            Span::raw(marker),
            Span::styled(format!("{label:<18}"), label_style),
            Span::styled(value.clone(), value_style),
        ]));
    }
    lines
}

fn draw_create(frame: &mut Frame, area: Rect, form: &CreateForm) {
    let fields = [
        ("Storage", storage_label(form.storage).to_string()),
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
        ("Login method", login_label(form.login_method).to_string()),
        ("Passphrase", mask(&form.passphrase)),
        ("Confirm", mask(&form.confirm)),
    ];
    let mut lines = field_lines(&fields, form.focus);
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
        ("Login method", login_label(form.login_method).to_string()),
    ];
    let mut lines = field_lines(&fields, form.focus);
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
    let mut lines = field_lines(&fields, form.focus);
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
            Line::from(Span::styled("  No secrets yet.", Style::default().fg(DIM))),
            Line::from(Span::styled(
                "  Press 'a' to add one.",
                Style::default().fg(DIM),
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
