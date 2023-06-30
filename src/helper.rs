use crate::types::{Creds};

use std::{
    sync::Arc,
    error::Error, 
    io,
    io::Read,
    io::prelude::*,
    env::{var_os},
    net::{TcpStream},
    path::{Path,PathBuf},
    string::{String},
};

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

use tungstenite::client::connect;
use tungstenite::protocol::Message;
use url::Url;

use unicode_width::UnicodeWidthStr;

pub fn connect_ws_client(s: String) -> Result<(), Box<dyn Error>> {
    let mut url = String::from("ws://localhost:1337/");
    url.push_str(&s);

    let (mut socket, response) = connect(Url::parse(&url).unwrap())
                                    .expect("WS connection err");
    println!("Connected to the server");
    println!("Response HTTP code: {}", response.status());
    println!("Response contains the following headers:");
    for (ref header, _value) in response.headers() {
        println!("*{}", header);
    }

    socket.write_message(Message::Text("hello ws".into())).unwrap();
    loop {
        let msg = socket.read_message().expect("Error reading message");
        println!("Received: {}", msg);
    }
    socket.close(None);
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
        path: PathBuf::from(&value[2]),
    }
}

pub fn create_tree<'a>() -> Vec<Arc<&'a str>> {
    let mut list: Vec<Arc<&str>> = Vec::new();
    list.push("hello".into());
    list.push("world".into());
    list
}


