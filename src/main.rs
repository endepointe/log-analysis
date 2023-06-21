mod types;
mod helper;
mod ui;
use crate::types::{AppState,InputMode,Creds,Cli};
use crate::helper::{run_cmd,create_session,get_user_info,create_tree};
use crate::ui::{ui};

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

