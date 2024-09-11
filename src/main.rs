
use log_analysis::{
    zeek::zeek_search_params::ZeekSearchParamsBuilder, 
    zeek::zeek_log::ZeekLog,
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
use chrono::NaiveDate;

#[derive(Debug)]
struct ParsedInput
{
    ip: Option<IpAddr>,
    start: Option<NaiveDate>,
    end: Option<NaiveDate>,
}

#[derive(Debug, PartialEq)]
enum Focus
{
    IpInput,
    StartInput,
    EndInput,
}

enum AppMode 
{
    Normal,
    InputIP,
}

#[derive(Debug)]
struct AppState
{
    display_data: bool,
    list_state: ListState,
    input_text: String,
    display_text: String,
    modal_open: bool,
    focus: Focus,
    ip: String,
    start_date: String,
    end_date: String
}

impl AppState
{
    fn new() -> Self
    {
        AppState {
            display_data: false,
            list_state: ListState::default(), 
            input_text: String::new(),
            display_text: String::new(),
            modal_open: false,
            focus: Focus::IpInput,
            ip: String::new(),
            start_date: String::new(),
            end_date: String::new()
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
    let app_state = Arc::new(Mutex::new(AppState::new()));
    let mut app_mode = AppMode::InputIP;
    let mut ip_input = String::new();
    let mut list_state = ListState::default();

    let mut index = 0;

    loop 
    {
        terminal.draw(|frame| {
            let layout = Layout::default()
                .direction(Direction::Horizontal)
                .constraints(vec![
                    Constraint::Percentage(25),
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

            let mut state = app_state.lock().unwrap();
            if state.display_data 
            {                          
                /*
                let keys: Vec<ListItem> = ip_list
                    .iter()
                    .map(|ip| ListItem::new(ip.to_string()))
                    .collect();

                let ip_keys = List::new(keys)
                    .block(Block::default().borders(Borders::ALL).title("IP Addressses"))
                    .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));

                state.list_state.select(Some(index));
                frame.render_stateful_widget(ip_keys, layout[0], &mut state.list_state);

                if let Some(ip) = ip_list.get(index)
                {
                    if let Some(data) = log.data.get(ip) 
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
            */
            } else {drop(state); //give state back} // data layout
              
            if let AppMode::InputIP = app_mode 
            {
                let area = centered_rect(50,20,frame.area());

                let modal = Block::default()
                    .title("Enter IP / Start date / End date")
                    .borders(Borders::ALL)
                    .style(Style::default().fg(Color::White).bg(Color::Black).add_modifier(Modifier::BOLD));

                let modal_block = Rect{x: area.x, y: area.y + area.height, width: area.width, height: 20};
                frame.render_widget(Clear, modal_block);
                frame.render_widget(modal, modal_block);

                let inner_layout = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Length(4), Constraint::Length(4), Constraint::Length(40)].as_ref())
                    .split(modal_block);

                let top_row = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
                    .split(inner_layout[0]);

                let second_row = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(50),Constraint::Percentage(50)].as_ref())
                    .split(inner_layout[1]);

                let bottom_row = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(100)].as_ref())
                    .split(inner_layout[2]);

                let draw_input_box = |title: &str, text: &str, is_focused: bool| -> Paragraph {
                    let input_style = if is_focused {
                        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::White)
                    };

                    Paragraph::new(Span::styled(
                        format!("{}: {}", title, text),
                        input_style,
                    ))
                    .block(Block::default().borders(Borders::ALL))
                    .alignment(Alignment::Left)
                };

                {
                    let mut state = app_state.lock().unwrap();
                    frame.render_widget(
                        draw_input_box("IP Address", &state.ip, state.focus == Focus::IpInput),
                        top_row[0],
                    );
                    frame.render_widget(
                        draw_input_box("Start Date", &state.start_date, state.focus == Focus::StartInput),
                        top_row[1],
                    );
                    frame.render_widget(
                        draw_input_box("End Date", &state.end_date, state.focus == Focus::EndInput),
                        second_row[0],
                    );
                    frame.render_widget(
                        draw_input_box("Addl info", &state.display_text, false),
                        bottom_row[0],
                    );
                    match state.focus
                    {
                        Focus::IpInput => {
                            let cursor_x = top_row[0].x + 13 + state.ip.len() as u16;
                            let cursor_y = top_row[0].y + 1;
                            frame.set_cursor(cursor_x,cursor_y);
                        }
                        Focus::StartInput => {
                            let cursor_x = top_row[1].x + 13 + state.start_date.len() as u16;
                            let cursor_y = top_row[1].y + 1;
                            frame.set_cursor(cursor_x,cursor_y);
                        }
                        Focus::EndInput => {
                            let cursor_x = second_row[0].x + 11 + state.end_date.len() as u16;
                            let cursor_y = second_row[0].y + 1;
                            frame.set_cursor(cursor_x,cursor_y);
                        }
                        _ => {}
                    }
                }
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
                        let mut state = app_state.lock().unwrap();
                        state.display_data = false;
                        state.input_text.clear();
                        state.display_text.clear();
                        state.modal_open = true;
                        app_mode = AppMode::InputIP;
                    }
                    KeyCode::Up => 
                    {
                        //if index > 0 { index -= 1;}
                        //else { index = ip_list.len() - 1; }
                    }
                    KeyCode::Down =>
                    {
                        //if index < ip_list.len() - 1
                        //{
                        //    index += 1;
                        //} else { index = 0; }
                    }
                    KeyCode::Esc => {
                        let mut state = app_state.lock().unwrap();
                        state.display_data = false;
                        app_mode = AppMode::InputIP;
                    },
                    _ => {}
                }
                AppMode::InputIP => match key.code
                {
                    KeyCode::Esc => {
                        let mut state = app_state.lock().unwrap();
                        state.input_text.clear();
                        state.display_text.clear();
                        state.modal_open = false;
                        app_mode = AppMode::Normal;
                        state.display_data = true;
                    }
                    KeyCode::Enter => {
                        let mut state = app_state.lock().unwrap();
                        state.display_text.clear();
                        state.display_text = format!("getting deeta...");
                        //state.display_data = true;
                        let data = format!("ip={},start={},end={}",&state.ip,&state.start_date,&state.end_date);
                        if let Ok(input_args) = parse_input(&data)
                        {
                            state.display_text = format!("{:?}",&input_args);
                            if let Some(start_date) = input_args.start
                            {
                                let date = format!("{:?}", start_date);
                                let params = ZeekSearchParamsBuilder::default()
                                    .path_prefix("zeek-test-logs")
                                    .start_date(&*date)
                                    .build()
                                    .unwrap();
                                let mut log = ZeekLog::new();
                                let res = log.search(&params);
                                assert!(res.is_ok());
                                assert_eq!(false, log.data.len() == 0);

                                let mut ip_list = Vec::<String>::new();

                                for ip in log.data.keys()
                                {
                                    ip_list.push(ip.to_string());
                                }
                                state.display_text = format!("{:?}",ip_list);
                        //        if let Ok(response) = request(&entered_ip.to_string())
                        //        {
                        //            let mut data = IP2LocationResponse::new();
                        //            data.create(&response);
                        //            let none = String::from("");
                        //            state.display_text = format!("\nip: {:?}\ncountry_code: {:?}\nregion_name: {:?}
                        //                \ncity_name: {:?}\nlatitude: {:?}\nlongitude: {:?}
                        //                \nzip_code: {:?}\ntime_zone: {:?}\nauto_system_num: {:?}
                        //                \nauto_system_name: {:?}\nis_proxy: {:?}", data.get_ip().as_ref().unwrap_or(&none), 
                        //                data.get_country_code().as_ref().unwrap_or(&none),
                        //                data.get_region_name().as_ref().unwrap_or(&none),
                        //                data.get_city_name().as_ref().unwrap_or(&none), 
                        //                data.get_latitude().as_ref().unwrap_or(&none), 
                        //                data.get_longitude().as_ref().unwrap_or(&none),
                        //                data.get_zip_code().as_ref().unwrap_or(&none),
                        //                data.get_time_zone().as_ref().unwrap_or(&none),
                        //                data.get_auto_system_num().as_ref().unwrap_or(&none),
                        //                data.get_auto_system_name().as_ref().unwrap_or(&none),
                        //                data.get_is_proxy().as_ref().unwrap_or(&none));
                        //        }
                        //        else {
                        //            state.input_text = format!("{}","Usage: ip = address, start = yyyy-mm-dd, end= yyyy-mm-dd");
                        //        }
                        //    }
                        //    else {
                        //        state.input_text = format!("{}","Usage: ip = address, start = yyyy-mm-dd, end= yyyy-mm-dd");
                        //    }
                            } 
                        } else {state.modal_open = true;}
                    }
                    KeyCode::Backspace => {
                        let mut state = app_state.lock().unwrap();
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
                            _ => {}
                        }
                        state.display_text.clear();
                    }
                    KeyCode::Char(c) => {
                        let mut state = app_state.lock().unwrap();
                        match state.focus
                        {
                            Focus::IpInput => state.ip.push(c),
                            Focus::StartInput => state.start_date.push(c),
                            Focus::EndInput => state.end_date.push(c),
                            _ => {}
                        }
                    }
                    KeyCode::Tab => {
                        let mut state = app_state.lock().unwrap();
                        state.focus = match state.focus {
                            Focus::IpInput => Focus::StartInput,
                            Focus::StartInput => Focus::EndInput,
                            Focus::EndInput => Focus::IpInput,
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
            _ => {}
        }
    }
    Ok(ParsedInput{ip,start,end})
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Percentage((100 - percent_y) / 4),
                Constraint::Percentage(percent_y),
                Constraint::Percentage((100 - percent_y) / 2),
            ]
            .as_ref(),
        )
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
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
