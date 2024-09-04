
use log_analysis::{
    zeek::zeek_search_params::ZeekSearchParamsBuilder, 
    zeek::zeek_log::ZeekLog,
    zeek::zeek_log_proto::ZeekProtocol,
    types::error::Error,
    types::helpers::print_type_of,
};
use std::io;
use ratatui::prelude::*;
use ratatui::widgets::*;
use ratatui::{
    layout::{Constraint, Direction, Layout},
    crossterm::event::{self, KeyCode, KeyEventKind},
    style::Stylize,
    widgets::{Borders, Paragraph, Block, List, ListItem, ListState},
    DefaultTerminal,
};

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
    let params = ZeekSearchParamsBuilder::default()
        .path_prefix("zeek-test-logs")
        .start_date("2024-07-02")
        .build()
        .unwrap();

    let mut log = ZeekLog::new();
    let res = log.search(&params);
    assert!(res.is_ok());
    assert_eq!(false, log.data.len() == 0);

    let mut app_state = ListState::default();
    let rows = [Row::new(vec!["cell1", "cell2", "cell3"])];
    let widths = [Constraint::Length(5),Constraint::Length(5),Constraint::Length(10)];

    let mut index = 0;
    let mut ip_list = Vec::<String>::new();

    for ip in log.data.keys()
    {
        ip_list.push(ip.to_string());
    }

    loop 
    {
        app_state.select(Some(index));

        terminal.draw(|frame| {
            let layout = Layout::default()
                .direction(Direction::Horizontal)
                .constraints(vec![
                    Constraint::Percentage(25),
                    Constraint::Percentage(75),
                ])
                .split(frame.size());

            let keys: Vec<ListItem> = ip_list
                .iter()
                .map(|ip| ListItem::new(ip.to_string()))
                .collect();

            let ip_keys = List::new(keys)
                .block(Block::default().borders(Borders::ALL).title("IP Addressses"))
                .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));

            frame.render_stateful_widget(ip_keys, layout[0], &mut app_state);

            let right = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(60), Constraint::Percentage(40)].as_ref())
                .split(layout[1]);

            let bottom = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(40), Constraint::Percentage(60)].as_ref())
                .split(right[1]);
                       
            if let Some(ip) = ip_list.get(index)
            {
                if let Some(data) = log.data.get(ip) 
                {                     

                    let main_data = format!(
                        "IP Address: {}\nFrequency: {}\nConnection UIDs: {:?}\nProtocols: {:?}\nConnection State: {:?}\nHistory: {:?}\nDports: {:?}\nMalicious: todo \nBytes Transferred: {}\nRelated IPs: todo",
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
                        Some(data) => format!("ip: {:?}\ncountry_code: {:?}\nregion_name: {:?}\ncity_name: {:?}\nlatitude: {:?}\nlongitude: {:?}\nzip_code: {:?}\ntime_zone: {:?}\nauto_system_num: {:?}\nauto_system_name: {:?}\nis_proxy: {:?}", data.get_ip(), data.get_country_code(),data.get_region_name(),data.get_city_name(), data.get_latitude(), data.get_longitude(),data.get_zip_code(),data.get_time_zone(),data.get_auto_system_num(),data.get_auto_system_name(),data.get_is_proxy()),
                        None => "none".to_string(),
                    };
                    let ip2location_para = Paragraph::new(ip2location_data)
                        .block(Block::default().borders(Borders::ALL).title("IP2Location Data"));
                    frame.render_widget(ip2location_para, bottom[0]);
                    
                    let filehash_data = data.get_file_info().iter()
                        .map(|file| format!("{:?}", file))
                        .collect::<Vec<String>>()
                        .join("\n");
                    // this needs to be formatted. boring, work but needs to be done
                    let filehash_para = Paragraph::new(filehash_data)
                        .block(Block::default().borders(Borders::ALL).title("File Hash Data"));
                    frame.render_widget(filehash_para, bottom[1]);
                }
            }
        })?;

        if let event::Event::Key(key) = event::read()? 
        {
            if key.kind == KeyEventKind::Press && key.code == KeyCode::Char('q')
            {
                return Ok(());
            }
            match key.code 
            {
                KeyCode::Up => 
                {
                    if index > 0 { index -= 1;}
                }
                KeyCode::Down =>
                {
                    if index < ip_list.len() - 1
                    {
                        index += 1;
                    }
                }
                _ => {}
            }
        }
    }
}