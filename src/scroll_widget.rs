use ratatui::{
    backend::Backend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    text::{Span, Spans},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame, Terminal,
};
use std::cmp::{max, min};

pub struct ScrollableList<'a> {
    items: Vec<&'a str>,
    scroll_offset: usize,
}

impl<'a> ScrollableList<'a> {
    pub fn new(text: &'a str) -> Self {
        let items: Vec<&str> = text.split(',').map(|item| item.trim()).collect();
        Self {
            items,
            scroll_offset: 0,
        }
    }

    pub fn scroll_to(&mut self, offset: usize) {
        self.scroll_offset = offset;
    }

    pub fn scroll_up(&mut self) {
        if self.scroll_offset > 0 {
            self.scroll_offset -= 1;
        }
    }

    pub fn scroll_down(&mut self) {
        if self.scroll_offset < self.items.len().saturating_sub(1) {
            self.scroll_offset += 1;
        }
    }

    pub fn render<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let visible_items: Vec<Spans> = self
            .items
            .iter()
            .skip(self.scroll_offset)
            .map(|&item| Spans::from(Span::raw(item)))
            .collect();

        let paragraph = Paragraph::new(visible_items)
            .block(Block::default().borders(Borders::ALL).title("Scrollable List"))
            .style(Style::default().fg(Color::White))
            .wrap(Wrap { trim: false }); 

        f.render_widget(paragraph, area);
    }
    pub fn handle_input(&mut self, input: Event) {
        if let Event::Key(key) = input {
            match key.code {
                KeyCode::Up => {
                    self.scroll_offset = self.scroll_offset.saturating_sub(1);
                }
                KeyCode::Down => {
                    self.scroll_offset += 1;
                }
                _ => {}
            }
        }
    }
}
