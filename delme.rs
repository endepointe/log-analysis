use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Terminal,
};
use crossterm::event::{self, Event, KeyCode};
use std::collections::HashMap;
use std::io;

#[derive(Debug)]
struct Data {
    ip_address: String,
    frequency: usize,
    connection_uids: Vec<String>,
    protocols: Vec<String>,
    time_ranges: HashMap<String, u32>,
    file_info: Vec<HashMap<String, String>>,
    conn_state: Vec<String>,
    history: Vec<String>,
    dports: Vec<u16>,
    ip2location: Option<String>, // Replace with actual IP2LocationResponse type
    malicious: bool,
    bytes_transferred: u64,
    related_ips: Vec<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    let mut data_map: HashMap<String, Data> = HashMap::new();
    // Populate your data_map with Data instances...

    let mut selected_index = 0;
    let ip_addresses: Vec<&String> = data_map.keys().collect();
    let mut list_state = ListState::default();

    loop {
        // Set the selected index in the list state for highlighting
        list_state.select(Some(selected_index));

        terminal.draw(|f| {
            let main_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(30), Constraint::Percentage(70)].as_ref())
                .split(f.size());

            // Left column: IP addresses list
            let items: Vec<ListItem> = ip_addresses
                .iter()
                .map(|ip| ListItem::new(ip.to_string()))
                .collect();
            let ip_list = List::new(items)
                .block(Block::default().borders(Borders::ALL).title("IP Addresses"))
                .highlight_style(
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                );

            f.render_stateful_widget(ip_list, main_chunks[0], &mut list_state);

            // Right column layout: Split into top and bottom sections
            let right_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(60), Constraint::Percentage(40)].as_ref())
                .split(main_chunks[1]);

            // Bottom section split into two columns for ip2location and file_info
            let bottom_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
                .split(right_chunks[1]);

            // Right column: Data display
            if let Some(selected_ip) = ip_addresses.get(selected_index) {
                if let Some(data) = data_map.get(*selected_ip) {
                    // Top section: Main data display
                    let main_data = format!(
                        "IP Address: {}\nFrequency: {}\nConnection UIDs: {:?}\nProtocols: {:?}\nConnection State: {:?}\nHistory: {:?}\nDports: {:?}\nMalicious: {}\nBytes Transferred: {}\nRelated IPs: {:?}",
                        data.ip_address,
                        data.frequency,
                        data.connection_uids,
                        data.protocols,
                        data.conn_state,
                        data.history,
                        data.dports,
                        data.malicious,
                        data.bytes_transferred,
                        data.related_ips,
                    );
                    let main_data_paragraph = Paragraph::new(main_data)
                        .block(Block::default().borders(Borders::ALL).title("Main Data"));
                    f.render_widget(main_data_paragraph, right_chunks[0]);

                    // Bottom left: IP2Location display
                    let ip2location_info = match &data.ip2location {
                        Some(info) => format!("IP2Location: {}", info),
                        None => "IP2Location: None".to_string(),
                    };
                    let ip2location_paragraph = Paragraph::new(ip2location_info)
                        .block(Block::default().borders(Borders::ALL).title("IP2Location"));
                    f.render_widget(ip2location_paragraph, bottom_chunks[0]);

                    // Bottom right: File information display
                    let file_info_data = data
                        .file_info
                        .iter()
                        .map(|file| format!("{:?}", file))
                        .collect::<Vec<String>>()
                        .join("\n");
                    let file_info_paragraph = Paragraph::new(file_info_data)
                        .block(Block::default().borders(Borders::ALL).title("File Info"));
                    f.render_widget(file_info_paragraph, bottom_chunks[1]);
                }
            }
        })?;

        // Handle input
        if let Event::Key(key) = event::read()? {
            match key.code {
                KeyCode::Char('q') => break, // Quit on 'q'
                KeyCode::Up => {
                    if selected_index > 0 {
                        selected_index -= 1;
                    }
                }
                KeyCode::Down => {
                    if selected_index < ip_addresses.len() - 1 {
                        selected_index += 1;
                    }
                }
                _ => {}
            }
        }
    }

    Ok(())
}

