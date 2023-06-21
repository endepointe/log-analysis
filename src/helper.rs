use crate::types::{Creds};

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

pub fn create_session(user: String, host: String, key: String) 
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

pub fn run_cmd(sess: &mut Session, cmd: String) -> Result<(),Box<dyn Error>> {
    let mut channel = sess.channel_session()?;
    channel.exec(&cmd)?;
    let mut s = String::new();
    let _ = channel.read_to_string(&mut s)?;
    let v: Vec<String> = s.lines().map(|s| s.to_string()).collect();
    println!("{s}");
    let _ = channel.wait_close();

    Ok(())
}

pub fn get_home_dir() -> Result<String, Box<dyn Error>> {
    let key = "HOME";
    let mut home_dir = String::from("");
    match var_os(key) {
        Some(val) => home_dir = val.into_string().unwrap(),
        None => home_dir = "/".to_string() 
    }
    Ok(home_dir)
}

pub fn get_user_info() -> Creds {
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
        let err = "Failed to read ".to_owned() + key[i];
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

pub fn create_tree<'a>() -> Vec<Arc<&'a str>> {
    let mut list: Vec<Arc<&str>> = Vec::new();
    list.push("hello".into());
    list.push("world".into());
    list
}


