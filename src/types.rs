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

pub enum InputMode {
    Normal,
    Editing,
}

pub struct AppState<'a> {
    pub input: String,
    pub input_mode: InputMode,
    pub messages: Vec<String>,
    pub session: &'a mut Session,
    pub dir_data: Vec<Arc<&'a str>>,
}

#[derive(Debug)]
#[derive(Parser)]
pub struct Cli {
    // User
    #[arg(short = 'u', value_name = "user")]
    pub user: String,
    // Hostname
    #[arg(short = 'n', value_name = "hostname")]
    pub hostname: String,
    // Path
    #[arg(short = 'p', value_name = "path/to/private/key")]
    pub path: std::path::PathBuf,
}

// mirrors Cli values to give the user the option of providing cli options.
// ill find a better way but for now, this is fine.
#[derive(Debug)]
pub struct Creds {
    pub user: String,
    pub hostname: String,
    pub path: std::path::PathBuf,
}

impl<'a> AppState<'a> {
    pub fn default(s: & mut Session) -> AppState {
        AppState {
            input: String::new(),
            input_mode: InputMode::Normal,
            messages: Vec::new(),
            session: s,
            dir_data: Vec::new(),
        }
    }
}



