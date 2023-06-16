use std::{
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
use ssh2::Session;

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

enum InputMode {
    Normal,
    Editing,
}

struct AppState<'a> {
    input: String,
    input_mode: InputMode,
    messages: Vec<String>,
    session: &'a mut Session,
}

#[derive(Debug)]
#[derive(Parser)]
struct Cli {
    // User
    #[arg(short = 'u', value_name = "user")]
    user: String,
    // Hostname
    #[arg(short = 'n', value_name = "hostname")]
    hostname: String,
    // Path
    #[arg(short = 'p', value_name = "path/to/private/key")]
    path: std::path::PathBuf,
}

// mirrors Cli values to give the user the option of providing cli options.
// ill find a better way but for now, this is fine.
#[derive(Debug)]
struct Creds {
    user: String,
    hostname: String,
    path: std::path::PathBuf,
}
/*
impl Creds {
    fn new(&self) {
        self.user = String::from("");
        self.hostname = String::from("");
        self.path = std::path::PathBuf::from("/");
    }
}
*/
impl<'a> AppState<'a> {
    fn default(s: & mut Session) -> AppState {
        AppState {
            input: String::new(),
            input_mode: InputMode::Normal,
            messages: Vec::new(),
            session: s,
        }
    }
}
/*
impl Default for AppState {
    fn default(s: &Session) -> AppState {
        AppState {
            input: String::new(),
            input_mode: InputMode::Normal,
            messages: Vec::new(),
            session: &s,
        }
    }
}
*/

fn create_session(user: String, host: String, key: String) 
    -> Result<Session, Box<dyn Error>> {

    let tcp = TcpStream::connect(host + ":22")?;
    let mut sess = Session::new()?;

    sess.set_tcp_stream(tcp);
    sess.handshake()?;
    sess.userauth_pubkey_file(&user,
                              None,
                              Path::new(&key),
                              None)?;
    let interval = sess.keepalive_send()?;
    sess.set_keepalive(true,interval);
    
    Ok(sess) 
}

fn run_cmd(sess: &mut Session, cmd: String) -> Result<(),Box<dyn Error>> {
    let mut channel = sess.channel_session()?;
    channel.exec(&cmd)?;
    let mut s = String::new();
    let _ = channel.read_to_string(&mut s)?;
    let v: Vec<String> = s.lines().map(|s| s.to_string()).collect();
    if v.is_empty() != true {
        println!("{:?}\n",v);
    }
    let _ = channel.wait_close();

    Ok(())
}

fn get_home_dir() -> Result<String, Box<dyn Error>> {
    let key = "HOME";
    let mut home_dir = String::from("");
    match var_os(key) {
        Some(val) => home_dir = val.into_string().unwrap(),
        None => home_dir = "/".to_string() 
    }
    /*
    let mut list_dir = Command::new("ls");
    list_dir.current_dir(home);
    list_dir.status().expect("ls ~ failed");
    */
    Ok(home_dir)
}
fn get_user_info() -> Creds {
    // create a proc_macro to create a fn that iterates over future struct members
    //doc.rust-lang.org/reference/procedural-macros.html/
    //https://stackoverflow.com/questions/54177438/how-to-programmatically-get-the-number-of-fields-of-a-struct
    let cli_member_count = 3;
    let mut i = 0;
    let key = Vec::from(["username","hostname","key file path"]);
    let mut value: Vec<String> = Vec::from([String::new(),String::new(),String::new()]);
    
    loop {
        println!("Enter {}:", key[i]);
        let mut input = String::new();
        let mut err = "Failed to read ".to_owned() + key[i];
        match io::stdin().read_line(&mut input) {
            Ok(val) => {
                value[i] = input.trim_end().to_owned();
            }
            Err(err) => println!("{}",&err), 
        }
        i += 1;
        if i == cli_member_count {
            println!("Logging in...");
            break;
        }
    }
    
    Creds {
        user: String::from(&value[0]),
        hostname: String::from(&value[1]),
        path: std::path::PathBuf::from(&value[2]),
    }
}

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

    let mut session = create_session(creds.user,creds.hostname,creds.path.into_os_string().into_string().unwrap())?;

    let _ = run_cmd(&mut session, "ls /opt/zeek/logs".to_string())?;
    //let _ = run_cmd(&mut session, "cat rdb.sh".to_string())?;

    // setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
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
    match app.session.authenticated() {
        true => println!("app is authenticated"),
        false => println!("app session is not authenticated"),
        _ => ()
    }

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











































