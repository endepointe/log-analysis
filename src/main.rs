
use log_analysis::{
    zeek::zeek_search_params::ZeekSearchParamsBuilder, 
    zeek::zeek_log::{ZeekLog,Data},
    zeek::zeek_log_proto::ZeekProtocol,
    types::error::Error,
    types::helpers::print_type_of,
};
use std::io::{self, BufRead};
use ratatui::prelude::*;
use ratatui::widgets::*;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    crossterm::event::{self, KeyCode, KeyEventKind},
    style::{Color, Modifier, Style, Stylize},
    widgets::{Borders, Paragraph, Block, List, ListItem, ListState, Wrap},
    DefaultTerminal,
};

use log_analysis::ip2location::{request,IP2LocationResponse};
use std::sync::{Arc,Mutex};
use std::net::IpAddr;
use std::collections::HashMap;
use chrono::{Duration, NaiveDate};

#[derive(Debug)]
struct ParsedInput
{
    ip: Option<IpAddr>,
    start: Option<NaiveDate>,
    end: Option<NaiveDate>,
    base: Option<String>,
}

#[derive(Debug, PartialEq)]
enum Focus
{
    IpInput,
    StartInput,
    EndInput,
    BaseDirInput,
}

enum AppMode 
{
    Normal,
    InputIP, // change the name of this to Menu
}

#[derive(Debug)]
struct AppState
{
    info_data: bool,
    list_state: ListState,
    input_text: String,
    info_text: String,
    ip_list: Vec<String>,
    log_data: HashMap<String, Data>,
    ip2loc_info: String,
    modal_open: bool,
    focus: Focus,
    ip: String,
    start_date: String,
    end_date: String,
    base_dir: String,
    index: usize,
}

impl AppState
{
    fn new() -> Self
    {
        AppState {
            info_data: false,
            list_state: ListState::default(), 
            input_text: String::new(),
            info_text: String::from("Enter IP address."),
            ip_list: Vec::<String>::new(),
            log_data: HashMap::new(),
            ip2loc_info: String::new(),
            modal_open: false,
            focus: Focus::IpInput,
            ip: String::new(),
            start_date: String::new(),
            end_date: String::new(),
            base_dir: String::from("zeek-test-logs"),
            index: 0,
        }
    }
}

fn main() -> io::Result<()>
{
    // thi sshould be a modal menu in the tui 
    let mut terminal = ratatui::init();
    terminal.clear()?;
    let app_result = run(terminal);
    ratatui::restore();
    app_result
}

fn
run(mut terminal: DefaultTerminal) -> io::Result<()>
{
    //let app_state = Arc::new(Mutex::new(AppState::new()));
    let mut state = AppState::new();
    let mut app_mode = AppMode::InputIP;
    let mut ip_input = String::new();
    let mut list_state = ListState::default();

    //let mut index = 0;

    loop 
    {
        terminal.draw(|frame| {
            let layout = Layout::default()
                .direction(Direction::Horizontal)
                .constraints(vec![
                    Constraint::Max(30),
                    Constraint::Percentage(75),
                ])
                .split(frame.area());

            let right = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(60), Constraint::Percentage(40)].as_ref())
                .split(layout[1]);

            let bottom = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(40), Constraint::Percentage(60)].as_ref())
                .split(right[1]);

            //let mut state = app_state.lock().unwrap();
            if state.info_data 
            {                          
                let mut keys = Vec::<ListItem>::new();
                for ip in &state.ip_list
                {
                    keys.push(ListItem::new(ip.to_string()));
                }

                let ip_keys = List::new(keys)
                    .block(Block::default().borders(Borders::ALL).title("IP Addressses"))
                    .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));
                let index = state.index;
                state.list_state.select(Some(index));
                frame.render_stateful_widget(ip_keys, layout[0], &mut state.list_state);

                if let Some(ip) = state.ip_list.get(state.index)
                {
                    if let Some(data) = state.log_data.get(ip) 
                    {                     

                        let main_data = format!(
                            "\nIP Address: {}\nFrequency: {}\nConnection UIDs: {:?}
                            \nProtocols: {:?}\nConnection State: {:?}\nHistory: {:?}
                            \nDports: {:?}\nMalicious: todo \nBytes Transferred: {}
                            \nRelated IPs: todo",
                            data.get_ip_address(),
                            data.get_frequency(),
                            data.get_connection_uids(),
                            data.get_protocols(),
                            data.get_conn_state(),
                            data.get_history(),
                            data.get_dports(),
                            //data.get_malicious(),
                            data.get_bytes_transferred(),
                            //data.get_related_ips()
                        );

                        let main_data_para = Paragraph::new(main_data)
                            .block(Block::default().borders(Borders::ALL).title("General Data"));
                        frame.render_widget(main_data_para, right[0]);
                        if cfg!(feature = "ip2location") 
                        {
                           
                        let ip2location_data = match data.get_ip2location_data()
                        {
                            Some(data) => {
                                let none = String::from("");
                                format!("\nip: {:?}\ncountry_code: {:?}\nregion_name: {:?}
                                    \ncity_name: {:?}\nlatitude: {:?}\nlongitude: {:?}
                                    \nzip_code: {:?}\ntime_zone: {:?}\nauto_system_num: {:?}
                                    \nauto_system_name: {:?}\nis_proxy: {:?}", data.get_ip().as_ref().unwrap_or(&none), 
                                    data.get_country_code().as_ref().unwrap_or(&none),
                                    data.get_region_name().as_ref().unwrap_or(&none),
                                    data.get_city_name().as_ref().unwrap_or(&none), 
                                    data.get_latitude().as_ref().unwrap_or(&none), 
                                    data.get_longitude().as_ref().unwrap_or(&none),
                                    data.get_zip_code().as_ref().unwrap_or(&none),
                                    data.get_time_zone().as_ref().unwrap_or(&none),
                                    data.get_auto_system_num().as_ref().unwrap_or(&none),
                                    data.get_auto_system_name().as_ref().unwrap_or(&none),
                                    data.get_is_proxy().as_ref().unwrap_or(&none))
                            }
                            None => "none".to_string(),
                        };
                        let ip2location_para = Paragraph::new(ip2location_data)
                            .block(Block::default().borders(Borders::ALL).title("IP2Location Data"))
                            .wrap(Wrap {trim: true });
                        frame.render_widget(ip2location_para, bottom[0]);
                        }
                       
                        let mut filehash_formatted_data = Vec::<String>::new();
                        for file in data.get_file_info()
                        {
                            for (key,val) in file.iter()
                            {
                                let s = format!("\n{key}: {val}");
                                filehash_formatted_data.push(s);
                            }                    
                        }
                        if !filehash_formatted_data.is_empty()
                        {
                            filehash_formatted_data.push("\n-------------------------".to_string());
                        }
                        let filehash_data = filehash_formatted_data.join(" ");

                        let filehash_para = Paragraph::new(filehash_data)
                            .block(Block::default().borders(Borders::ALL).title("File Hash Data"));
                        frame.render_widget(filehash_para, bottom[1]);
                    }
                }
            } 
            //else {drop(state);} //give state back} // data layout
              
            if let AppMode::InputIP = app_mode 
            {
                let screen_size = frame.area();
                let modal_width = 120;
                let modal_height = 30;
                //https://doc.rust-lang.org/core/primitive.u16.html#method.saturating_sub
                let modal_x = (screen_size.width.saturating_sub(modal_width)) / 2;
                let modal_y = (screen_size.height.saturating_sub(modal_height)) / 2;

                let modal = Block::default()
                    .title("Enter IP / Start date / End date")
                    .borders(Borders::ALL)
                    .style(Style::default().fg(Color::White).bg(Color::Black).add_modifier(Modifier::BOLD));

                let modal_block = Rect::new(modal_x, modal_y, modal_width, modal_height); 
                frame.render_widget(Clear, modal_block);
                frame.render_widget(modal, modal_block);

                let inner_layout = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
                    .split(modal_block);

                let left_col = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Length(4), Constraint::Length(4), 
                                 Constraint::Length(4), Constraint::Length(4)].as_ref())
                    .split(inner_layout[0]);

                let right_col = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(100)].as_ref())
                    .split(inner_layout[1]);

                let draw_input_box = |title: Option<&str>, text: &str, is_focused: bool| -> Paragraph {
                    let input_style = if is_focused {
                        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::White)
                    };
                    
                    if let Some(title) = title 
                    {
                        Paragraph::new(Span::styled(
                            format!("{}: {}", title, text),
                            input_style,
                        ))
                        .block(Block::default().borders(Borders::ALL))
                        .alignment(Alignment::Left)
                        .wrap(Wrap {trim: true })
                    }
                    else 
                    {
                        Paragraph::new(Span::styled(
                            format!("{}", text),
                            input_style,
                        ))
                        .block(Block::default().borders(Borders::ALL))
                        .alignment(Alignment::Left)
                        .wrap(Wrap {trim: true })
                    }
                };

                //let mut state = app_state.lock().unwrap();
                frame.render_widget(
                    draw_input_box(Some("IP address"), &state.ip, state.focus == Focus::IpInput),
                    left_col[0],
                );
                frame.render_widget(
                    draw_input_box(Some("Start Date"), &state.start_date, state.focus == Focus::StartInput),
                    left_col[1],
                );
                frame.render_widget(
                    draw_input_box(Some("End Date"), &state.end_date, state.focus == Focus::EndInput),
                    left_col[2],
                );
                frame.render_widget(
                    draw_input_box(Some("Base Dir"), &state.base_dir, state.focus == Focus::BaseDirInput),
                    left_col[3],
                );
                frame.render_widget(
                    draw_input_box(None, &state.info_text, false),
                    right_col[0],
                );
                match state.focus
                {
                    Focus::IpInput => {
                        let cursor_x = left_col[0].x + 13 + state.ip.len() as u16;
                        let cursor_y = left_col[0].y + 1;
                        frame.set_cursor(cursor_x,cursor_y);
                    }
                    Focus::StartInput => {
                        let cursor_x = left_col[1].x + 13 + state.start_date.len() as u16;
                        let cursor_y = left_col[1].y + 1;
                        frame.set_cursor(cursor_x,cursor_y);
                    }
                    Focus::EndInput => {
                        let cursor_x = left_col[2].x + 11 + state.end_date.len() as u16;
                        let cursor_y = left_col[2].y + 1;
                        frame.set_cursor(cursor_x,cursor_y);
                    }
                    Focus::BaseDirInput => {
                        let cursor_x = left_col[3].x + 11 + state.base_dir.len() as u16;
                        let cursor_y = left_col[3].y + 1;
                        frame.set_cursor(cursor_x,cursor_y);
                    }
                    _ => {}
                }
            }
        })?; // end terminal draw

        if let event::Event::Key(key) = event::read()? 
        {
            if key.kind == KeyEventKind::Press && key.code == KeyCode::Char('q')
            {
                return Ok(());
            }
            match app_mode 
            {
                AppMode::Normal => match key.code {
                    KeyCode::Char('i') => {
                        //let mut state = app_state.lock().unwrap();
                        state.info_data = false;
                        state.input_text.clear();
                        state.info_text.clear();
                        state.modal_open = true;
                        app_mode = AppMode::InputIP;
                    }
                    KeyCode::Up => 
                    {
                        if state.index > 0 { state.index -= 1;}
                        else { state.index = state.ip_list.len() - 1; }
                    }
                    KeyCode::Down =>
                    {
                        if state.index < state.ip_list.len() - 1
                        {
                            state.index += 1;
                        } else { state.index = 0; }
                    }
                    KeyCode::Esc => {
                        //let mut state = app_state.lock().unwrap();
                        state.info_data = false;
                        app_mode = AppMode::InputIP;
                    },
                    _ => {}
                }
                AppMode::InputIP => match key.code
                {
                    KeyCode::Esc => {
                        //let mut state = app_state.lock().unwrap();
                        state.input_text.clear();
                        state.info_text.clear();
                        state.modal_open = false;
                        app_mode = AppMode::Normal;
                        state.info_data = true;
                    }
                    KeyCode::Enter => {
                        //let mut state = app_state.lock().unwrap();
                        state.info_text.clear();
                        let data = format!("ip={},start={},end={},base={}",&state.ip,&state.start_date,&state.end_date,&state.base_dir);
                        if let Ok(input_args) = parse_input(&data)
                        {
                            if let Some(start_date) = &input_args.start
                            {
                                let date = format!("{:?}", start_date);
                                let params = ZeekSearchParamsBuilder::default()
                                    .path_prefix(&*state.base_dir)
                                    .start_date(&*date)
                                    .build()
                                    .unwrap();
                                let mut log = ZeekLog::new();
                                let res = log.search(&params);
                                if let Err(_err) = res {
                                    // messy for now. clean it up if you want and make a pr.
                                    state.info_text = format!("{}\n{}\n{}\n{}\n{}\n",
                                                              "Check usage.(", 
                                                              " ip: address,", 
                                                              " start: yyyy-mm-dd,",
                                                              " end: yyyy-mm-dd,",
                                                              " base: valid_base_dir_to_logs)");
                                } 
                                else 
                                {
                                    for ip in log.data.keys()
                                    {
                                        state.ip_list.push(ip.to_string());
                                    }
                                    state.log_data = log.data;

                                    if let Some(end) = input_args.end 
                                    {
                                        let date_strings = generate_dates(&input_args.start.unwrap().to_string(),&input_args.end.unwrap().to_string());
                                        state.info_text = format!("{date_strings:?}");
                                    }
                                    //if cfg!(feature = "ip2location") 
                                    //{
                                    //    if let Ok(response) = request(&state.ip.to_string())
                                    //    {
                                    //        let mut data = IP2LocationResponse::new();
                                    //        data.create(&response);
                                    //        let none = String::from("");
                                    //        state.ip2loc_info = format!("\nip: {:?}\ncountry_code: {:?}\nregion_name: {:?}
                                    //            \ncity_name: {:?}\nlatitude: {:?}\nlongitude: {:?}
                                    //            \nzip_code: {:?}\ntime_zone: {:?}\nauto_system_num: {:?}
                                    //            \nauto_system_name: {:?}\nis_proxy: {:?}", data.get_ip().as_ref().unwrap_or(&none), 
                                    //            data.get_country_code().as_ref().unwrap_or(&none),
                                    //            data.get_region_name().as_ref().unwrap_or(&none),
                                    //            data.get_city_name().as_ref().unwrap_or(&none), 
                                    //            data.get_latitude().as_ref().unwrap_or(&none), 
                                    //            data.get_longitude().as_ref().unwrap_or(&none),
                                    //            data.get_zip_code().as_ref().unwrap_or(&none),
                                    //            data.get_time_zone().as_ref().unwrap_or(&none),
                                    //            data.get_auto_system_num().as_ref().unwrap_or(&none),
                                    //            data.get_auto_system_name().as_ref().unwrap_or(&none),
                                    //            data.get_is_proxy().as_ref().unwrap_or(&none));
                                    //    }
                                    //    else 
                                    //    {
                                    //        state.info_text = format!("{}","Usage: ip = address, start = yyyy-mm-dd, end= yyyy-mm-dd, base=valid_directory");
                                    //    }
                                    //}
                                }
                            } 
                        } else {state.modal_open = true;}
                    }
                    KeyCode::Backspace => {
                        //let mut state = app_state.lock().unwrap();
                        match state.focus
                        {
                            Focus::IpInput => {
                                state.ip.pop();
                            }
                            Focus::StartInput => {
                                state.start_date.pop();
                            }
                            Focus::EndInput => {
                                state.end_date.pop();
                            }
                            Focus::BaseDirInput => {
                                state.base_dir.pop();
                            }
                            _ => {}
                        }
                        state.info_text.clear();
                    }
                    KeyCode::Char(c) => {
                        //let mut state = app_state.lock().unwrap();
                        match state.focus
                        {
                            Focus::IpInput => state.ip.push(c),
                            Focus::StartInput => state.start_date.push(c),
                            Focus::EndInput => state.end_date.push(c),
                            Focus::BaseDirInput => state.base_dir.push(c),
                            _ => {}
                        }
                    }
                    KeyCode::Tab => {
                        //let mut state = app_state.lock().unwrap();
                        state.focus = match state.focus {
                            Focus::IpInput => {
                                state.info_text = format!("{}", "Enter start date: yyyy-mm-dd");
                                Focus::StartInput
                            }
                            Focus::StartInput => {
                                state.info_text = format!("{}", "Enter end date: yyyy-mm-dd ");
                                Focus::EndInput
                            }
                            Focus::EndInput => {
                                state.info_text = format!("{}", "Enter the base directory of the logs.
                                                          \n (eg: basedir/yyyy-mm-dd)");
                                Focus::BaseDirInput
                            }
                            Focus::BaseDirInput => {
                                state.info_text = format!("{}", "Enter an IP address.");
                                Focus::IpInput
                            }
                        }
                    }
                    _ => {}
                }
            }
        } // end event check
    } // end loop
}

fn parse_input(input: &str) -> Result<ParsedInput,String> 
{
    let parts: Vec<&str> = input.split(',').map(|s| s.trim()).collect();
    let mut ip: Option<IpAddr> = None;
    let mut start: Option<NaiveDate> = None;
    let mut end: Option<NaiveDate> = None;
    let mut base: Option<String> = None;

    for part in parts {
        let mut key_value = part.split('=').map(|s| s.trim());
        let key = key_value.next();
        let value = key_value.next();

        match (key, value) 
        {
            (Some("ip"), Some(ip_str)) if !ip_str.is_empty() => {
                ip = ip_str.parse().ok();
            }
            (Some("start"), Some(start_str)) if !start_str.is_empty() => {
                start = NaiveDate::parse_from_str(start_str, "%Y-%m-%d").ok();
            }
            (Some("end"), Some(end_str)) if !end_str.is_empty() => {
                end = NaiveDate::parse_from_str(end_str, "%Y-%m-%d").ok();
            }
            (Some("base"), Some(base_str)) if !base_str.is_empty() => {
                base = base_str.parse().ok();
            }
            _ => {}
        }
    }
    Ok(ParsedInput{ip,start,end,base})
}

fn
generate_dates(start: &str, end: &str) -> Vec<String>
{
    let start_date = NaiveDate::parse_from_str(start, "%Y-%m-%d")
        .expect("Invalid start date format: YYYY-MM-DD");

    let end_date = NaiveDate::parse_from_str(end, "%Y-%m-%d")
        .expect("Invalid end date format: YYYY-MM-DD");

    let mut dates = Vec::new();
    let mut current_date = start_date;

    while current_date <= end_date 
    {
        dates.push(current_date.format("%Y-%m-%d").to_string());
        current_date += Duration::days(1);
    }

    dates
}

fn 
centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Percentage((100 - percent_y) / 2),
                Constraint::Percentage(percent_y),
                Constraint::Percentage((100 - percent_y) / 2),
            ]
            .as_ref(),
        )
        .split(r);

    Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Percentage((100 - percent_x) / 2),
                Constraint::Percentage(percent_x),
                Constraint::Percentage((100 - percent_x) / 2),
            ]
            .as_ref(),
        )
        .split(popup_layout[1])[1]
}
