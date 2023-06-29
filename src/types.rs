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

pub enum InputMode {
    Normal,
    Editing,
}

pub struct AppState {
    pub input: String,
    pub input_mode: InputMode,
    pub messages: Vec<String>,
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

impl AppState {
    pub fn default() -> AppState {
        AppState {
            input: String::new(),
            input_mode: InputMode::Normal,
            messages: Vec::new(),
        }
    }
}
