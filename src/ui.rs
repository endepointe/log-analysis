use crate::types::{AppState,InputMode};
use std::string::{String};

use unicode_width::UnicodeWidthStr;

use ratatui::{
    backend::{CrosstermBackend, Backend},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    layout::{Constraint, Direction, Layout},
    text::{Line, Span, Text},
    style::{Color, Modifier, Style},
    Frame,
};

pub fn user_input<B: Backend>(f: &mut Frame<B>, app: &AppState) {
    let chunks = Layout::default()
        .horizontal_margin(30)
        .vertical_margin(20)
        .constraints(
            [
                Constraint::Length(1),
                Constraint::Length(3), 
                Constraint::Min(1),
            ]
            .as_ref(),
        )
        .split(f.size());

    let (msg, style) = match app.input_mode {
        InputMode::Normal => (
            vec![
                Span::raw("Press "),
                Span::styled("q", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(" to exit, "),
                Span::styled("e", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(" to start editing."),
            ],
            Style::default().add_modifier(Modifier::RAPID_BLINK),
        ),
        InputMode::Editing => (
            vec![
                Span::raw("Press "),
                Span::styled("q", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(" to stop editing, "),
                Span::styled("Enter", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(" to record the message."),
            ],
            Style::default(),
        ),
    };

    let mut text = Text::from(Line::from(msg));
    text.patch_style(style);
    let help_message = Paragraph::new(text);
    f.render_widget(help_message, chunks[0]);

    let input = Paragraph::new(app.input.as_str())
        .style(match app.input_mode {
            InputMode::Normal => Style::default(),
            InputMode::Editing => Style::default().fg(Color::Green),
        })
        .block(Block::default().borders(Borders::ALL).title("Input"));
    f.render_widget(input, chunks[1]);

    match app.input_mode {
        InputMode::Normal =>
            // hide the cursor. `Frame` does this by defaul
            {}
        InputMode::Editing => {
            // make the cursor visible and request that tui put it at the coords after render
            f.set_cursor(
                // put cursor past the end of the input text
                chunks[1].x + app.input.width() as u16 + 1,
                chunks[1].y + 1, 
            )
        }
    }

    let messages: Vec<ListItem> = app
        .messages
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let content = Line::from(Span::raw(format!("{i}: {m}")));
            ListItem::new(content)
        })
        .collect();
    let messages = List::new(messages).block(Block::default().borders(Borders::ALL).title("Messages"));
    f.render_widget(messages, chunks[2]);
}

