//! Central color + style tokens for the TUI. Every screen pulls its colors from
//! here so the look stays consistent and is themeable from one place.

use ratatui::style::{Color, Modifier, Style};

/// Primary accent — vault names, titles, focused labels.
pub const ACCENT: Color = Color::Cyan;
/// Muted text — hints, borders, unfocused labels.
pub const MUTED: Color = Color::DarkGray;
/// Ordinary body text.
pub const TEXT: Color = Color::Gray;

pub const OK: Color = Color::Green;
pub const WARN: Color = Color::Yellow;
pub const ERR: Color = Color::Red;

/// Background for the selected table row — a muted slate so colored cell text
/// stays readable (unlike a full reverse, which inverts every cell separately).
pub const SELECT_BG: Color = Color::Rgb(45, 51, 64);

pub fn header() -> Style {
    Style::default().fg(MUTED).add_modifier(Modifier::BOLD)
}

pub fn selected_row() -> Style {
    Style::default().bg(SELECT_BG).add_modifier(Modifier::BOLD)
}

pub fn title() -> Style {
    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
}

pub fn border() -> Style {
    Style::default().fg(MUTED)
}

pub fn hint() -> Style {
    Style::default().fg(MUTED)
}

pub fn label_focused() -> Style {
    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
}

pub fn label_dim() -> Style {
    Style::default().fg(MUTED)
}

pub fn value_focused() -> Style {
    Style::default().add_modifier(Modifier::BOLD)
}
