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

#[derive(Debug, PartialEq, Clone)]
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
    Menu, 
}

#[derive(Debug, Clone)]
struct AppState
{
    display_dashboard: bool,
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
            display_dashboard: false,
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
    let mut app_mode = AppMode::Menu;
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
            if state.display_dashboard 
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

                                                // combine existing data
                                                // data:
                                                //epcohs: Vec<String>,
                                                //ip_address: String,
                                                //frequency: usize,
                                                //connection_uids: Vec<UID>,
                                                //protocols: Vec<String>,
                                                //time_ranges: HashMap<String, u32>,
                                                //file_info: Vec<HashMap<String,String>>,
                                                //conn_state: Vec::<String>,
                                                //history: Vec::<String>,
                                                //dports: Vec<u16>,
                                                //ip2location: Option<IP2LocationResponse>,
                                                //malicious: bool, // virustotal?
                                                //bytes_transferred: u64,
                                                //related_ips: Vec<String>,
                        let main_data = format!(
                            "\nIP Address: {}\nFrequency: {}\nConnection UIDs: {:?}
                            \nTime: {:?}\nTime Ranges: {:?}\nProtocols: {:?}
                            \nConnection State: {:?}\nHistory: {:?}
                            \nDports: {:?}\nMalicious: {} 
                            \nBytes Transferred: {}\nRelated IPs: {:?}",
                            data.get_ip_address(),
                            data.get_frequency(),
                            data.get_connection_uids(),
                            data.epochs,
                            data.time_ranges,
                            data.get_protocols(),
                            data.get_conn_state(),
                            data.get_history(),
                            data.get_dports(),
                            data.malicious,
                            data.bytes_transferred,
                            data.related_ips
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
              
            if let AppMode::Menu = app_mode 
            {
                let screen_size = frame.area();
                let modal_width = 90; // give this a dynamic width/height
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
                        state.display_dashboard = false;
                        state.input_text.clear();
                        state.info_text.clear();
                        state.modal_open = true;
                        app_mode = AppMode::Menu;
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
                        state.display_dashboard = false;
                        app_mode = AppMode::Menu;
                    },
                    _ => {}
                }
                AppMode::Menu => match key.code
                {
                    KeyCode::Esc => {
                        //let mut state = app_state.lock().unwrap();
                        state.input_text.clear();
                        state.info_text.clear();
                        state.modal_open = false;
                        app_mode = AppMode::Normal;
                        state.display_dashboard = true;
                    }
                    KeyCode::Enter => {
                        //let mut state = app_state.lock().unwrap();
                        //state.info_text.clear();
                        let start_date = parse_date(&state.start_date);
                        let end_date = parse_date(&state.end_date);
                        let ip_addr = parse_ip(&state.ip);
                        let base_dir = parse_base(&state.base_dir); // should always be Some(base)
                        state.info_text = format!("{:?}{:?}{:?}{:?}",&start_date,&end_date,&ip_addr,&base_dir);
                        match (start_date,end_date,ip_addr,base_dir)
                        {
                            (Some(start),Some(end),Some(ip),Some(_base)) => 
                            {
                                // all fields correct
                                state.info_text = format!("Search for {} between {} and {}", ip, start, end);
                            }
                            (Some(start),None,Some(ip),Some(_base)) => 
                            {
                                // use start  
                                state.info_text = format!("Searching for {} on {}.", ip, start);
                            }
                            (None,Some(end),Some(ip),Some(_base)) => 
                            {
                                // use end
                                state.info_text = format!("Searching for {} on {}.", ip, end);
                            }
                            (None,None,Some(ip),Some(_base)) => 
                            {
                                // use ip 
                                state.info_text = format!("Searching for {} on all dates. This is expensive!", ip);
                            }
                            (Some(start),Some(end),None,Some(base)) => 
                            {
                                // check end > start. swap if not.
                                state.info_text = format!("Searching between {} and {}", start, end);

                                // get the first date to work from
                                // TODO: 
                                //  - Verify with zeek-cut.
                                //  - Issue when more than one start date is invalid. 
                                //      (eg: 2024-07-01 through 2024-07-09 dne. The
                                //      issue is most likely caused by not repeatedly
                                //      checking the supplied start date until a valid
                                //      date is found.
                                let start_date: &str = &start.format("%Y-%m-%d").to_string();
                                let end_date: &str = &end.format("%Y-%m-%d").to_string();

                                let path_prefix = String::from(base);

                                let params = ZeekSearchParamsBuilder::default()
                                    .path_prefix(&*path_prefix)
                                    .selected_date(start_date)
                                    .build()
                                    .unwrap();
                                let mut main_log = ZeekLog::new();
                                let res = main_log.search(&params);

                                let len_a = &main_log.data.len();
                                let mut len_b = 0;

                                let empty_data = Data::new(String::from("de.ad.be.ef"));
                                main_log.data.insert(String::from("de.ad.be.ef"), empty_data);

                                // once the main functionality is done, swap is start > end.
                                assert!(start < end);

                                let mut current = start;
                                let mut information = String::new();

                                while current <= end
                                {
                                    let clone_prefix = path_prefix.clone();
                                    let curr_date: &str = &current.format("%Y-%m-%d").to_string();
                                    let params = ZeekSearchParamsBuilder::default()
                                        .path_prefix(&*clone_prefix)
                                        .selected_date(curr_date)
                                        .build()
                                        .unwrap();
                                    let mut curr_log = ZeekLog::new();
                                    let res = curr_log.search(&params);  

                                    // check IPs against existing list
                                    if res.is_ok() 
                                    {
                                        // There must be a better way to do this to satisfy
                                        // borrowchecker.
                                        let mut from_log_data = curr_log.data.clone();
                                        for ip in curr_log.data.keys()
                                        {
                                            if !main_log.data.contains_key(ip) 
                                            {
                                                len_b += 1;
                                                //if let Some(data) = curr_log.data.get(ip) 
                                                //{
                                                //    main_log.data.insert(ip.to_string(),data.clone());
                                                //}
                                            } 
                                            else 
                                            {
                                                // combine existing data
                                                // data:
                                                //epochs: Vec<String>,
                                                //ip_address: String,
                                                //frequency: usize,
                                                //connection_uids: Vec<UID>,
                                                //protocols: Vec<String>,
                                                //time_ranges: HashMap<String, u32>,
                                                //file_info: Vec<HashMap<String,String>>,
                                                //conn_state: Vec::<String>,
                                                //history: Vec::<String>,
                                                //dports: Vec<u16>,
                                                //ip2location: Option<IP2LocationResponse>,
                                                //malicious: bool, // virustotal?
                                                //bytes_transferred: u64,
                                                //related_ips: Vec<String>,
                                                let to_main = main_log.data.get_mut(ip);
                                                let from_data = from_log_data.get_mut(ip);
                                                if let (Some(to),Some(from)) = (to_main,from_data) 
                                                {
                                                    to.connection_uids.extend(from.connection_uids.clone());
                                                    to.epochs.extend(from.epochs.clone());
                                                    //let freq = from.get_frequency();
                                                    to.set_ip_address(from.get_ip_address().clone());
                                                    //Setting time range increments frequency.
                                                    //to.set_frequency(from.get_frequency());
                                                    to.set_ip2location_data(from.get_ip2location_data().clone());
                                                    let protos: Vec<String> = from.get_protocols().clone();
                                                    for proto in protos {to.set_protocol(proto);}
                                                    let time_ranges: HashMap<String,u32> = from.get_time_range().clone();    
                                                    for (time,_) in time_ranges {to.set_time_range(time);}
                                                    //let file_info = from.file_info.clone();
                                                    to.file_info.extend(from.file_info.clone());  
                                                    to.conn_state.extend(from.conn_state.clone());
                                                }
                                                //data.set_frequency(curr_log.data.get_frequency()); 
                                            }
                                        }
                                        information.push_str(&current.to_string());
                                    } 
                                    current += Duration::days(1);
                                }
                                // probably could do this in the while but MVP needed, not
                                // perfection.
                                for ip in main_log.data.keys()
                                {
                                    state.ip_list.push(ip.to_string());
                                }
                                state.log_data = main_log.data;
                                //let dates = generate_dates(start_date,end_date);
                                state.info_text = format!("len_a: {}, found {} new IPs, 
                                                          info: {:?}", len_a, len_b, information);
                                state.modal_open = false;
                                app_mode = AppMode::Normal;
                                state.display_dashboard = true;
                            }
                            (Some(start),None,None,Some(base)) => // start,_,_,base
                            {
                                // check end > start. swap if not.
                                state.info_text = format!("Searching {}.", &start);
                                let day: &str = &start.format("%Y-%m-%d").to_string();
                                let base: &str = &base.to_string();
                                let params = ZeekSearchParamsBuilder::default()
                                    .path_prefix(base)
                                    .selected_date(day)
                                    .build()
                                    .unwrap();
                                let mut log = ZeekLog::new();
                                let res = log.search(&params);

                                assert!(log.data.len() > 0);
                                if res.is_ok() 
                                {
                                    for ip in log.data.keys()
                                    {
                                        state.ip_list.push(ip.to_string());
                                    }
                                    state.log_data = log.data;
                                    state.modal_open = false;
                                    app_mode = AppMode::Normal;
                                    state.display_dashboard = true;
                                }
                            }
                            (None,Some(end),None,Some(_base)) => 
                            {
                                // check end > start. swap if not.
                                state.info_text = format!("Searching {}.", end);
                            }
                            _ => 
                            {
                                //notify the user that they have done something wrong.
                                state.modal_open = true;
                            }
                        }
                        /*
                        let data = format!("ip={},start={},end={},base={}",&state.ip,&state.start_date,&state.end_date,&state.base_dir);
                        if let Ok(input_args) = parse_input(&data)
                        {
                            if let Some(start_date) = &input_args.start
                            {
                                if let Some(end_date) = input_args.end 
                                {
                                    let date_strings = generate_dates(&input_args.start.unwrap().to_string(),&input_args.end_date.unwrap().to_string());
                                    state.info_text = format!("{date_strings:?}");
                                }

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
                        */
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

fn 
parse_ip(input: &str) -> Option<IpAddr> 
{
    if *&input.len() > 0 
    {
        return input.trim().parse::<IpAddr>().ok()    
    }
    None
}
fn 
parse_date(input: &str) -> Option<NaiveDate>
{
    if *&input.len() > 0 
    {
        return NaiveDate::parse_from_str(input.trim(), "%Y-%m-%d").ok();
    }
    None
}
fn
parse_base(input: &str) -> Option<String>
{
    if !input.len() > 0
    {
        return input.parse().ok();
    }
    None
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
run_the_jewels()
{
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
