mod types;
mod helper;
mod ui;
use crate::types::{AppState,InputMode,Creds,Cli};
use crate::helper::{connect_ws_client,get_user_info};
use crate::ui::{user_input};

use std::{
    error::Error, 
    io,
    string::{String},
};

use clap::Parser;

use ratatui::{
    backend::{CrosstermBackend, Backend},
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

fn main() -> Result<(), Box<dyn Error>> {

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

    connect_ws_client(creds.user);

    // setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnableMouseCapture, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let app = AppState::default();
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

        terminal.draw(|f| user_input(f, &app))?;
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

