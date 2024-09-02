
use log_analysis::{
    zeek::zeek_search_params::ZeekSearchParamsBuilder, 
    zeek::zeek_log::ZeekLog,
    zeek::zeek_log_proto::ZeekProtocol,
    types::error::Error,
    types::helpers::print_type_of,
};
use std::io;
use ratatui::prelude::*;
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

            if let Some(ip) = ip_list.get(index)
            {
                if let Some(data) = log.data.get(ip) 
                {
                    let data_displayed = Paragraph::new(format!("{:#?}", data))
                        .block(Block::default().borders(Borders::ALL).title("Data Response"));
                    frame.render_widget(data_displayed, layout[1]);
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
