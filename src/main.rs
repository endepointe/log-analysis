mod types;
mod helper;
use crate::types::{AppState,InputMode,Creds,Cli};
use crate::helper::{run_cmd,create_session,get_user_info,create_tree};



use std::{
    sync::Arc,
    error::Error, 
    io,
    io::prelude::*, 
    thread,
    time,
    env::{var_os},
    net::{TcpStream},
    path::Path,
    string::{String},
};

use clap::Parser;
//use ssh2::Session;

use ratatui::{
    backend::{CrosstermBackend, Backend},
    widgets::{Block, Borders,List,ListItem,Paragraph},
    layout::{Constraint, Direction, Layout},
    text::{Line,Span,Text},
    style::{Color, Modifier, Style},
    Frame,
    Terminal
};

use crossterm::{
    event::{
        self, Event, KeyCode, KeyEventKind,
        DisableMouseCapture, EnableMouseCapture
    },
    execute,
    terminal::{
        disable_raw_mode, enable_raw_mode,
        EnterAlternateScreen, LeaveAlternateScreen
    },
};


use unicode_width::UnicodeWidthStr;

fn main() -> Result<(), Box<dyn Error>> {

    let list = create_tree();
    for item in list {
        println!("{item}");
    }

    // check host and private keyfile
    let mut host = Cli::try_parse(); 
    let mut creds = Creds {
        user: String::from(""),
        hostname: String::from(""),
        path: std::path::PathBuf::from("/")
    };

    match host {
        Ok(host) => {
            creds.user = host.user;
            creds.hostname = host.hostname;
            creds.path = host.path;
        }
        Err(reason) => {
            creds = get_user_info();
        }
    } 

    let mut session = create_session(creds.user,creds.hostname,creds.path.into_os_string().into_string().unwrap())?;

    let _ = run_cmd(&mut session, "tree /opt/zeek/logs/current/".to_string())?;
    //let _ = run_cmd(&mut session, "cat rdb.sh".to_string())?;

    // setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnableMouseCapture, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let app = AppState::default(&mut session);
    let res = run_app(&mut terminal, app);

    // restores the terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{err:?}");
    }

    Ok(())
}

fn run_app<B: Backend>(
    terminal: &mut Terminal<B>, 
    mut app: AppState
) -> io::Result<()> {

    loop {

        terminal.draw(|f| ui(f, &app))?;
        if let Event::Key(key) = event::read()? {
            match app.input_mode {
                InputMode::Normal => match key.code {
                    KeyCode::Char('e') => {
                        app.input_mode = InputMode::Editing;
                    }
                    KeyCode::Char('q') => {
                        return Ok(());
                    }
                    _ => {}
                },
                InputMode::Editing if key.kind == KeyEventKind::Press => 
                    match key.code {
                        KeyCode::Enter => {
                            app.messages.push(app.input.drain(..).collect());
                            let _ = run_cmd(app.session, app.messages[app.messages.len()-1].to_string());
                            //println!("{:?} {}",app.messages, app.messages.len());
                        } 
                        KeyCode::Char(c) => {
                            app.input.push(c);
                        }
                        KeyCode::Backspace => {
                            app.input.pop();
                        }
                        KeyCode::Esc => {
                            app.input_mode = InputMode::Normal;
                        }
                        _ => {}
                },
                _ => {
                    
                }
            }
        }
    }
}

fn ui<B: Backend>(f: &mut Frame<B>, app: &AppState) {
    let chunks = Layout::default()
        .horizontal_margin(30)
        .vertical_margin(20)
        .constraints(
            [
                Constraint::Length(1),
                Constraint::Length(3), Constraint::Min(1),
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

