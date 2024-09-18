use log_analysis::{
    zeek::zeek_search_params::ZeekSearchParamsBuilder, 
    zeek::zeek_log::{ZeekLog,SummaryData},
    zeek::zeek_log_proto::ZeekProtocol,
    types::error::Error,
    types::helpers::print_type_of,
};
use log_analysis::ip2location::{request,IP2LocationResponse};

use ratatui::prelude::*;
use ratatui::widgets::*;
use ratatui::{prelude::*, widgets::canvas::*};
use ratatui::symbols::Marker;
use ratatui::symbols::scrollbar;
use ratatui::text::Line;

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    crossterm::event::{self, KeyCode, KeyEvent, KeyEventKind},
    style::{Color, Modifier, Style, Stylize},
    widgets::{Borders, BorderType, Paragraph, Block, List, ListItem, ListState, Wrap},
    DefaultTerminal,
};
use std::sync::{Arc,Mutex};
use std::net::IpAddr;
use std::collections::HashMap;
use std::io::{self, BufRead};

use chrono::{Duration, NaiveDate};


#[derive(Debug, PartialEq, Clone)]
enum MenuFocus
{
    IpInput,
    StartInput,
    EndInput,
    BaseDirInput,
}

#[derive(Debug, PartialEq, Clone)]
enum Tab_0_Focus
{
    IpListArea,
    ContentArea,
}

enum AppMode 
{
    Normal,
    Menu, 
}

#[derive(Default, Debug, Clone)]
struct Tab_0_InfoState 
{
    vertical_scroll_state: ScrollbarState,
    vertical_scroll: usize,
}
#[derive(Debug, Clone)]
struct AppState<'a>
{
    tab_titles: Vec<&'a str>,
    tab_index: usize,
    list_state: ListState,
    input_text: String,
    info_text: String,
    ip_list: Vec<String>,
    ip_index: usize,
    log_data: HashMap<String, SummaryData>,
    ip2loc_info: String,
    ip: String,
    start_date: String,
    end_date: String,
    base_dir: String,
    show_info_box: bool,
    menu_focus: MenuFocus,
    tab_0_state: Tab_0_InfoState,
    tab_0_focus: Tab_0_Focus,
}

impl<'a> AppState<'a>
{
    fn new() -> AppState<'a> 
    {
        AppState {
            tab_titles: vec!["World Map","Zeek Dashboard", "todo dash"],
            tab_index: 0,
            list_state: ListState::default(), 
            input_text: String::new(),
            info_text: String::from("Enter IP address."),
            ip_list: Vec::<String>::new(),
            ip_index: 0,
            log_data: HashMap::new(),
            ip2loc_info: String::new(),
            ip: String::new(),
            start_date: String::new(),
            end_date: String::new(),
            base_dir: String::from("zeek-test-logs"),
            show_info_box: false,
            menu_focus: MenuFocus::IpInput,
            tab_0_state: Tab_0_InfoState::default(),
            tab_0_focus: Tab_0_Focus::IpListArea,
        }
    }
    fn next_tab(&mut self) 
    {
        self.tab_index = (self.tab_index + 1) % self.tab_titles.len();
    }
    fn prev_tab(&mut self) 
    {
        if self.tab_index > 0 { self.tab_index -= 1; }
        else { self.tab_index = self.tab_titles.len() - 1; }
    }
}

fn main() -> io::Result<()>
{
    let mut terminal = ratatui::init();
    terminal.clear()?;
    let app_result = run(terminal);
    ratatui::restore();
    app_result
}

fn
run(mut terminal: DefaultTerminal) -> io::Result<()>
{
    let mut state = AppState::new();
    let mut app_mode = AppMode::Menu;
    let mut ip_input = String::new();
    let mut list_state = ListState::default();

    loop 
    {
        terminal.draw(|frame| run_the_jewels(frame, &mut state, &app_mode, &list_state))?;

        if let event::Event::Key(key) = event::read()? 
        {
            if key.kind == KeyEventKind::Press && key.code == KeyCode::Char('q')
            {
                return Ok(());
            }
            match app_mode 
            {
                AppMode::Normal => match key.code {
                    KeyCode::Char('m') => {
                        app_mode = AppMode::Menu;
                    }
                    KeyCode::Up => 
                    {
                        match state.tab_index { 
                            0 => {
                                match state.tab_0_focus {
                                    Tab_0_Focus::IpListArea => {
                                        if state.ip_index > 0 { state.ip_index -= 1;}
                                        else { state.ip_index = state.ip_list.len() - 1; }
                                    }
                                    Tab_0_Focus::ContentArea => {
                                        state.tab_0_state.vertical_scroll = 
                                            state.tab_0_state.vertical_scroll.saturating_add(1);
                                        state.tab_0_state.vertical_scroll_state =
                                            state.tab_0_state.vertical_scroll_state
                                                .position(state.tab_0_state.vertical_scroll);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    KeyCode::Down =>
                    {
                        match state.tab_index { 
                            0 => {
                                match state.tab_0_focus {
                                    Tab_0_Focus::IpListArea => {
                                        if state.ip_index < state.ip_list.len() - 1
                                        {
                                            state.ip_index += 1;
                                        } else { state.ip_index = 0; }
                                    }
                                    Tab_0_Focus::ContentArea => {
                                        state.tab_0_state.vertical_scroll = 
                                            state.tab_0_state.vertical_scroll.saturating_sub(1);
                                        state.tab_0_state.vertical_scroll_state =
                                            state.tab_0_state.vertical_scroll_state
                                                .position(state.tab_0_state.vertical_scroll);
                                    }
                                }
                            }
                            _ => {}
                        }

                    }
                    KeyCode::Left => state.prev_tab(),
                    KeyCode::Right => state.next_tab(),
                    KeyCode::Esc => { app_mode = AppMode::Menu; },
                    KeyCode::Char('i') => 
                    { 
                        if state.show_info_box == true { state.show_info_box = false; }
                        else { state.show_info_box = true; }
                    }, 
                    KeyCode::Tab => {
                        match state.tab_index { 
                            0 => {
                                state.tab_0_focus = match state.tab_0_focus {
                                    Tab_0_Focus::IpListArea => {
                                        Tab_0_Focus::ContentArea
                                    }
                                    Tab_0_Focus::ContentArea => {
                                        Tab_0_Focus::IpListArea
                                    }
                                }
                            }
                            _ => {}
                        }
                    }, 
                    _ => {}
                }
                AppMode::Menu => match key.code
                {
                    KeyCode::Esc => {
                        app_mode = AppMode::Normal;
                    }
                    KeyCode::Enter => {
                        let start_date = parse_date(&state.start_date);
                        let end_date = parse_date(&state.end_date);
                        let ip_addr = parse_ip(&state.ip);
                        let base_dir = parse_base(&state.base_dir); // should always be Some(base)
                        state.info_text = format!("{:?}{:?}{:?}{:?}",&start_date,&end_date,&ip_addr,&base_dir);
                        match (start_date,end_date,ip_addr,base_dir)
                        {
                            (Some(start),Some(end),Some(ip),Some(_base)) => 
                            {
                                state.info_text = format!("Search for {} between {} and {}", 
                                                          ip, start, end);
                            }
                            (Some(start),None,Some(ip),Some(_base)) => 
                            {
                                state.info_text = format!("Searching for {} on {}.", ip, start);
                            }
                            (None,Some(end),Some(ip),Some(_base)) => 
                            {
                                state.info_text = format!("Searching for {} on {}.", ip, end);
                                
                            }
                            (None,None,Some(ip),Some(_base)) => 
                            {
                                state.info_text = format!("Searching for {} on all 
                                                          available zeek log dates. 
                                                          This is expensive.", ip);
                            }
                            (None,None,Some(ip),None) => 
                            {
                                let ip: String = ip.to_string(); 
                                let res = request(&ip);

                                if res.is_ok() {
                                    state.ip_list.push(ip.to_string());
                                    let mut summary_data = SummaryData::new(String::from(&ip));
                                    let mut loc = IP2LocationResponse::new();
                                    let res = res.unwrap();
                                    loc.create(res.as_str());
                                    summary_data.ip2location = Some(loc.clone());
                                    let mut main_log = ZeekLog::new();
                                    main_log.summary.insert(ip, summary_data);
                                    state.log_data = main_log.summary;
                                    app_mode = AppMode::Normal;
                                }

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

                                let empty_data = SummaryData::new(String::from("de.ad.be.ef"));
                                main_log.summary.insert(String::from("de.ad.be.ef"), empty_data);

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
                                        let mut from_log_data = curr_log.summary.clone();
                                        for ip in curr_log.summary.keys()
                                        {
                                            if !main_log.summary.contains_key(ip) 
                                            {
                                                if let Some(data) = curr_log.summary.get(ip) 
                                                {
                                                    main_log.summary.insert(ip.to_string(),data.clone());
                                                }
                                            } 
                                        }
                                        information.push_str(&current.to_string());
                                    } 
                                    current += Duration::days(1);
                                }
                                // probably could do this in the while but MVP needed, not
                                // perfection.
                                for ip in main_log.summary.keys()
                                {
                                    state.ip_list.push(ip.to_string());
                                }
                                state.log_data = main_log.summary;
                                app_mode = AppMode::Normal;
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

                                assert!(log.summary.len() > 0);
                                if res.is_ok() 
                                {
                                    for ip in log.summary.keys()
                                    {
                                        state.ip_list.push(ip.to_string());
                                    }
                                    state.log_data = log.summary;
                                    app_mode = AppMode::Normal;
                                }
                            }
                            (None,Some(end),None,Some(_base)) => 
                            {
                                // check end > start. swap if not.
                                state.info_text = format!("Searching {}.", end);
                            }
                            _ => 
                            {
                                //notify the user that they have done something horribly wrong.
                            }
                        }
                    }
                    KeyCode::Backspace => {
                        match state.menu_focus
                        {
                            MenuFocus::IpInput => {
                                state.ip.pop();
                            }
                            MenuFocus::StartInput => {
                                state.start_date.pop();
                            }
                            MenuFocus::EndInput => {
                                state.end_date.pop();
                            }
                            MenuFocus::BaseDirInput => {
                                state.base_dir.pop();
                            }
                            _ => {}
                        }
                        state.info_text.clear();
                    }
                    KeyCode::Char(c) => {
                        match state.menu_focus
                        {
                            MenuFocus::IpInput => state.ip.push(c),
                            MenuFocus::StartInput => state.start_date.push(c),
                            MenuFocus::EndInput => state.end_date.push(c),
                            MenuFocus::BaseDirInput => state.base_dir.push(c),
                            _ => {}
                        }
                    }
                    KeyCode::Tab => {
                        state.menu_focus = match state.menu_focus {
                            MenuFocus::IpInput => {
                                state.info_text = format!("{}", "Enter start date: yyyy-mm-dd");
                                MenuFocus::StartInput
                            }
                            MenuFocus::StartInput => {
                                state.info_text = format!("{}", "Enter end date: yyyy-mm-dd ");
                                MenuFocus::EndInput
                            }
                            MenuFocus::EndInput => {
                                state.info_text = format!("{}", "Enter the base directory of the logs.
                                                          \n (eg: basedir/yyyy-mm-dd)");
                                MenuFocus::BaseDirInput
                            }
                            MenuFocus::BaseDirInput => {
                                state.info_text = format!("{}", "Enter an IP address.");
                                MenuFocus::IpInput
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
run_the_jewels(frame: &mut Frame, state: &mut AppState, 
               app_mode: &AppMode, list_state: &ListState)
{
    if let AppMode::Menu = app_mode { draw_input_menu(frame,state); }
    else { draw_dashboard(frame,state); }
}

fn
draw_dashboard(frame: &mut Frame, state: &mut AppState)
{
    let tab_window = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Percentage(90)])
        .split(frame.area());

    let tab_titles: Vec<_> = state
        .tab_titles
        .iter()
        .map(|tab| {
            let (first, rest) = tab.split_at(1);
            Line::from(vec![first.yellow(), rest.green()])
        })
        .collect();

    let tabs = Tabs::new(tab_titles)
        .block(Block::default().borders(Borders::ALL).title("Tabs"))
        .select(state.tab_index)
        .style(Style::default().cyan().black())
        .highlight_style(Style::default().bold().on_black());

    frame.render_widget(tabs, tab_window[0]);

    match state.tab_index {
        0 => draw_tab_0(frame, state, tab_window[1]),
        _ => {},
    };
}

fn
draw_tab_0(frame: &mut Frame, state: &mut AppState, area: Rect)
{
    let layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(vec![
            Constraint::Percentage(100),
        ])
        .split(area);

    let bordered = match state.tab_0_focus {
        Tab_0_Focus::IpListArea => 0,
        Tab_0_Focus::ContentArea => 1,
    };

    let create_block = |title| {
        Block::default()
            .borders(Borders::ALL)
            .border_type(if bordered == 1 { BorderType::Double } else {BorderType::Plain })
            .style(Style::default().fg(Color::White).bg(Color::Black).add_modifier(Modifier::BOLD))
            .title(Span::styled(
                title,
                Style::default().bg(Color::Black).add_modifier(Modifier::BOLD),
            ))
    };

    if let Some(ip) = state.ip_list.get(state.ip_index)
    {
        if let Some(data) = state.log_data.get(ip) 
        {                     


            let mut text_list: Vec<Line> = Vec::new();
            let mut lat = 0.0;
            let mut lon = 0.0;

            let ip2location_data = match data.get_ip2location_data()
            {
                Some(data) => {
                    let none = String::from("");
                    lat = data.get_latitude().as_ref()
                        .unwrap_or(&"0.0".to_string()).parse::<f32>().unwrap();
                    lon = data.get_longitude().as_ref()
                        .unwrap_or(&"0.0".to_string()).parse::<f32>().unwrap();
                    text_list.push(Line::from(format!("Lat: {}",lat)));
                    text_list.push(Line::from(format!("Lon: {}",lon)));
                    text_list.push(Line::from(format!("IP: {}",
                        data.get_ip().as_ref().unwrap_or(&none))));
                    text_list.push(Line::from(format!("Country Code: {}",
                        data.get_country_code().as_ref().unwrap_or(&none))));
                    text_list.push(Line::from(format!("Region: {}",
                        data.get_region_name().as_ref().unwrap_or(&none))));
                    text_list.push(Line::from(format!("City Name: {}",
                        data.get_city_name().as_ref().unwrap_or(&none))));
                    text_list.push(Line::from(format!("Zipcode: {}",
                        data.get_zip_code().as_ref().unwrap_or(&none))));
                    text_list.push(Line::from(format!("Timezone: {}",
                        data.get_time_zone().as_ref().unwrap_or(&none))));
                    text_list.push(Line::from(format!("Auto System Number: {}",
                        data.get_auto_system_num().as_ref().unwrap_or(&none))));
                    text_list.push(Line::from(format!("Auto System Name: {}",
                        data.get_auto_system_name().as_ref().unwrap_or(&none))));
                    text_list.push(Line::from(format!("Is a proxy: {}",
                        data.get_is_proxy().as_ref().unwrap_or(&none))));
                }
                None => {}
            };

            let some_para = Paragraph::new(String::from("placeholder"))
                .block(Block::default().borders(Borders::ALL).title("SummaryData"));

            let canvas = Canvas::default()
                .block(Block::bordered().title("World"))
                .marker(Marker::Dot)
                .paint(|ctx| {
                    ctx.draw(&Map {
                        color: Color::Green,
                        resolution: MapResolution::High,
                    });
                    ctx.print(lon.into(), lat.into(), data.get_ip_address().clone().yellow());
                })
                .x_bounds([-180.0, 180.0])
                .y_bounds([-90.0, 90.0]);

            frame.render_widget(canvas, layout[0]);

            let ip_overlay_area = Rect {
                x: layout[0].x + (layout[0].width * 1 / 100),
                y: layout[0].y + (layout[0].height * 65 / 100),
                width: layout[0].width * 16 / 100,
                height: layout[0].height * 35 / 100,
            };


            let ip_list_block = Block::default()
                .title("IP List")
                .borders(Borders::ALL)
                .border_type(if bordered == 0 { BorderType::Double } else {BorderType::Plain })
                .style(Style::default().fg(Color::White).bg(Color::Black).add_modifier(Modifier::BOLD));

            frame.render_widget(Clear, ip_overlay_area);
            frame.render_widget(ip_list_block, ip_overlay_area);

            let mut keys = Vec::<ListItem>::new();
            for ip in &state.ip_list
            {
                keys.push(ListItem::new(ip.to_string()));
            }

            let ip_keys = List::new(keys)
                .block(Block::default().borders(Borders::ALL).title("IP Addressses"))
                .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));

            state.list_state.select(Some(state.ip_index));
            frame.render_stateful_widget(ip_keys, ip_overlay_area, &mut state.list_state);

            //https://doc.rust-lang.org/core/primitive.u16.html#method.saturating_sub
            let screen_size = frame.area();
            let width = layout[0].width * 30 / 100;
            let height = layout[0].height * 50 / 100;

            let info_overlay_area = Rect {
                x: (screen_size.width.saturating_sub(width)) / 2,
                y: (screen_size.height.saturating_sub(height)) / 2,
                width: width,
                height: height,
            };

            let info_layout = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Percentage(100),
                ])
                .split(info_overlay_area);

            // TODO:
            // - the tab focus changes value but does not double the iplist border.

            let mut text = vec![
                Line::from(""),
                Line::from(""),
                Line::from(""),
                Line::from(""),
                Line::from("Press tab to control this menu"),
                Line::from(""),
                Line::from(""),
                Line::from(""),
                Line::from(""),
                Line::from("Scroll up/down"),
                Line::from(""),
                Line::from(""),
                Line::from(""),
                Line::from(""),
                Line::from("This is a line "),
                Line::from("This is a line   ".red()),
                Line::from("This is a line".on_dark_gray()),
                Line::from("This is a longer line".crossed_out()),
                Line::from("This is a line".reset()),
                Line::from(vec![
                    Span::raw("Masked text: "),
                    Span::styled(
                        Masked::new("password", '*'),
                        Style::default().fg(Color::Red),
                    ),
                ]),
                Line::from("This is a line "),
                Line::from("This is a line   ".red()),
                Line::from("This is a line".on_dark_gray()),
                Line::from("This is a longer line".crossed_out()),
                Line::from("Press q to quit".dark_gray())
                        .alignment(Alignment::Center),
                    Line::from("Each line has 2 constraints, plus Min(0) to fill the remaining space."),
                    Line::from("E.g. the second line of the Len/Min box is [Length(2), Min(2), Min(0)]"),
                    Line::from("Note: constraint labels that don't fit are truncated"),

                Line::from("This is a line".reset()),
                Line::from(vec![
                    Span::raw("Masked text: "),
                    Span::styled(
                        Masked::new("password", '*'),
                        Style::default().fg(Color::Red),
                    ),
                ]),
            ];
            text_list.append(&mut text);

            if state.show_info_box
            {
                frame.render_widget(Clear, info_layout[0]);
                let info_para = Paragraph::new(text_list)
                    .block(create_block(format!("Additional info for: {}",
                                                data.get_ip_address().as_str())))
                    .scroll((state.tab_0_state.vertical_scroll as u16, 0));

                frame.render_widget(Clear, info_layout[0]);
                frame.render_widget(info_para, info_layout[0]);
            }
        }
    }
}

fn
draw_input_menu(frame: &mut Frame, state: &mut AppState)
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

    frame.render_widget(
        draw_input_box(Some("IP address"), &state.ip, state.menu_focus == MenuFocus::IpInput),
        left_col[0],
    );
    frame.render_widget(
        draw_input_box(Some("Start Date"), &state.start_date, state.menu_focus == MenuFocus::StartInput),
        left_col[1],
    );
    frame.render_widget(
        draw_input_box(Some("End Date"), &state.end_date, state.menu_focus == MenuFocus::EndInput),
        left_col[2],
    );
    frame.render_widget(
        draw_input_box(Some("Base Dir"), &state.base_dir, state.menu_focus == MenuFocus::BaseDirInput),
        left_col[3],
    );
    frame.render_widget(
        draw_input_box(None, &state.info_text, false),
        right_col[0],
    );
    match state.menu_focus
    {
        MenuFocus::IpInput => {
            let cursor_x = left_col[0].x + 13 + state.ip.len() as u16;
            let cursor_y = left_col[0].y + 1;
            frame.set_cursor(cursor_x,cursor_y);
        }
        MenuFocus::StartInput => {
            let cursor_x = left_col[1].x + 13 + state.start_date.len() as u16;
            let cursor_y = left_col[1].y + 1;
            frame.set_cursor(cursor_x,cursor_y);
        }
        MenuFocus::EndInput => {
            let cursor_x = left_col[2].x + 11 + state.end_date.len() as u16;
            let cursor_y = left_col[2].y + 1;
            frame.set_cursor(cursor_x,cursor_y);
        }
        MenuFocus::BaseDirInput => {
            let cursor_x = left_col[3].x + 11 + state.base_dir.len() as u16;
            let cursor_y = left_col[3].y + 1;
            frame.set_cursor(cursor_x,cursor_y);
        }
        _ => {}
    }
}
// helpers
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
    if input.len() > 0
    {
        return input.parse().ok();
    }
    None
}

// unused
fn
_generate_dates(start: &str, end: &str) -> Vec<String>
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
_centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
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
