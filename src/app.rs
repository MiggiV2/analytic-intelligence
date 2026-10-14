use std::collections::HashMap;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, Gauge, Paragraph, Row, Table, TableState};
use ratatui::Frame;

use crate::scanner::{Phase, ScanEvent, Source};

const LOG_LINES: usize = 2;

#[derive(PartialEq)]
enum EntryState {
    Pending,
    Online,
    Offline,
    Skipped(String),
}

impl EntryState {
    fn label(&self) -> String {
        match self {
            EntryState::Pending => "WAIT".to_string(),
            EntryState::Online => "UP".to_string(),
            EntryState::Offline => "DOWN".to_string(),
            EntryState::Skipped(_) => "SKIP".to_string(),
        }
    }

    fn color(&self) -> Color {
        match self {
            EntryState::Pending => Color::Yellow,
            EntryState::Online => Color::Green,
            EntryState::Offline => Color::Red,
            EntryState::Skipped(_) => Color::DarkGray,
        }
    }
}

struct HostEntry {
    domain: String,
    ip: String,
    location: String,
    state: EntryState,
    title: Option<String>,
}

impl HostEntry {
    fn new(domain: String, ip: String, location: String) -> Self {
        Self {
            domain,
            ip,
            location,
            state: EntryState::Pending,
            title: None,
        }
    }
}

pub struct App {
    domain: String,
    phase: Phase,
    source: Option<Source>,
    mail_server: Option<String>,
    discovered: usize,
    done: usize,
    online: usize,
    offline: usize,
    skipped: usize,
    rows: Vec<HostEntry>,
    row_index: HashMap<String, usize>,
    ip_locations: HashMap<String, String>,
    logs: Vec<String>,
    table_state: TableState,
    follow: bool,
    pub should_quit: bool,
}

impl App {
    pub fn new(domain: String) -> Self {
        Self {
            domain,
            phase: Phase::MailServer,
            source: None,
            mail_server: None,
            discovered: 0,
            done: 0,
            online: 0,
            offline: 0,
            skipped: 0,
            rows: Vec::new(),
            row_index: HashMap::new(),
            ip_locations: HashMap::new(),
            logs: Vec::new(),
            table_state: TableState::default(),
            follow: true,
            should_quit: false,
        }
    }

    pub fn handle_scan_event(&mut self, event: ScanEvent) {
        match event {
            ScanEvent::Phase(phase) => self.phase = phase,
            ScanEvent::Log(message) => self.push_log(message),
            ScanEvent::MailServer(mail) => self.mail_server = Some(mail),
            ScanEvent::Discovery { count, source } => {
                self.discovered = count;
                if count > 0 {
                    self.source = Some(source);
                }
            }
            ScanEvent::SourceError { source, error } => {
                self.push_log(format!("{source} failed: {error}"));
            }
            ScanEvent::HostResolved { domain, ip } => {
                let location = self
                    .ip_locations
                    .get(&ip)
                    .cloned()
                    .unwrap_or_default();
                self.row_index.insert(domain.clone(), self.rows.len());
                self.rows.push(HostEntry::new(domain, ip, location));
            }
            ScanEvent::IpInfo { ip, info } => {
                let location = format!("{}, {}, {}", info.org, info.country, info.city);
                self.ip_locations.insert(ip.clone(), location.clone());
                for row in &mut self.rows {
                    if row.ip == ip {
                        row.location = location.clone();
                    }
                }
            }
            ScanEvent::HostChecked { domain, status } => {
                if let Some(index) = self.row_index.get(&domain) {
                    let row = &mut self.rows[*index];
                    match status.online {
                        true => self.online += 1,
                        false => self.offline += 1,
                    }
                    row.title = status.title;
                    row.state = match status.online {
                        true => EntryState::Online,
                        false => EntryState::Offline,
                    };
                }
                self.done += 1;
            }
            ScanEvent::HostSkipped { domain, reason } => {
                let mut entry = HostEntry::new(domain.clone(), String::new(), String::new());
                entry.state = EntryState::Skipped(reason);
                self.row_index.insert(domain, self.rows.len());
                self.rows.push(entry);
                self.skipped += 1;
                self.done += 1;
            }
            ScanEvent::Finished => {}
        }
        self.update_selection();
    }

    pub fn handle_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.should_quit = true;
            }
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
            KeyCode::Down | KeyCode::Char('j') => {
                self.follow = false;
                self.table_state.select_next();
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.follow = false;
                self.table_state.select_previous();
            }
            KeyCode::Char('g') | KeyCode::Home => {
                self.follow = false;
                self.table_state.select_first();
            }
            KeyCode::Char('G') | KeyCode::End | KeyCode::Char('f') => {
                self.follow = true;
            }
            _ => {}
        }
    }

    fn update_selection(&mut self) {
        if self.follow && !self.rows.is_empty() {
            self.table_state.select(Some(self.rows.len() - 1));
        }
    }

    fn push_log(&mut self, message: String) {
        self.logs.push(message);
        if self.logs.len() > LOG_LINES {
            self.logs.remove(0);
        }
    }

    pub fn render(&mut self, frame: &mut Frame) {
        let area = frame.area();
        let layout = Layout::vertical([
            Constraint::Length(5),
            Constraint::Length(1),
            Constraint::Fill(1),
            Constraint::Length(LOG_LINES as u16),
            Constraint::Length(1),
        ])
        .split(area);

        self.render_header(frame, layout[0]);
        self.render_progress(frame, layout[1]);
        self.render_table(frame, layout[2]);
        self.render_logs(frame, layout[3]);
        self.render_footer(frame, layout[4]);
    }

    fn render_header(&self, frame: &mut Frame, area: Rect) {
        let mut source_info = String::new();
        if let Some(source) = self.source {
            source_info = format!(" via {source}");
        }

        let first = Line::from(vec![
            Span::styled(
                "Analytic Intelligence",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(self.domain.clone(), Style::default().fg(Color::Cyan)),
        ]);
        let second = Line::from(vec![
            Span::styled("Phase: ", Style::default().fg(Color::DarkGray)),
            Span::styled(self.phase.to_string(), Style::default().fg(Color::Yellow)),
            Span::raw(format!(
                "  -  {} subdomains{source_info}",
                self.discovered
            )),
        ]);
        let third = match &self.mail_server {
            Some(mail) => Line::from(vec![
                Span::styled("Mail server: ", Style::default().fg(Color::DarkGray)),
                Span::raw(mail.clone()),
            ]),
            None => Line::from(Span::styled(
                "Mail server: none found",
                Style::default().fg(Color::DarkGray),
            )),
        };

        let paragraph = Paragraph::new(vec![first, second, third]).block(
            Block::bordered().title(" Scan "),
        );
        frame.render_widget(paragraph, area);
    }

    fn render_progress(&self, frame: &mut Frame, area: Rect) {
        let ratio = if self.discovered == 0 {
            0.0
        } else {
            self.done as f64 / self.discovered as f64
        };
        let label = format!(" checked {} / {}", self.done, self.discovered);
        let color = if self.phase == Phase::Done {
            Color::Green
        } else {
            Color::Cyan
        };
        let gauge = Gauge::default()
            .ratio(ratio.min(1.0))
            .label(label)
            .gauge_style(Style::default().fg(color));
        frame.render_widget(gauge, area);
    }

    fn render_table(&mut self, frame: &mut Frame, area: Rect) {
        let title = format!(
            " Results (up {} - down {} - skipped {}) ",
            self.online, self.offline, self.skipped
        );
        let header = Row::new(["State", "Domain", "IP", "Organization / Location", "Title"])
            .style(Style::default().add_modifier(Modifier::BOLD));

        let rows = self.rows.iter().map(|entry| {
            let state = Span::styled(
                entry.state.label(),
                Style::default().fg(entry.state.color()),
            );
            let domain = if let EntryState::Skipped(reason) = &entry.state {
                format!("{} ({reason})", entry.domain)
            } else {
                entry.domain.clone()
            };
            let title = match (&entry.state, &entry.title) {
                (EntryState::Online, Some(title)) => title.clone(),
                (EntryState::Offline, Some(title)) => title.clone(),
                _ => String::new(),
            };
            Row::new(vec![
                Cell::from(state),
                Cell::from(domain),
                Cell::from(entry.ip.clone()),
                Cell::from(entry.location.clone()),
                Cell::from(Span::styled(title, Style::default().fg(Color::DarkGray))),
            ])
        });

        let widths = [
            Constraint::Length(6),
            Constraint::Percentage(28),
            Constraint::Length(15),
            Constraint::Percentage(26),
            Constraint::Percentage(30),
        ];
        let table = Table::new(rows, widths)
            .header(header)
            .block(Block::bordered().title(title))
            .row_highlight_style(Style::default().add_modifier(Modifier::BOLD))
            .highlight_symbol("> ");

        frame.render_stateful_widget(table, area, &mut self.table_state);
    }

    fn render_logs(&self, frame: &mut Frame, area: Rect) {
        let logs = if self.logs.is_empty() {
            vec![Line::from(Span::styled(
                "No messages",
                Style::default().fg(Color::DarkGray),
            ))]
        } else {
            self.logs
                .iter()
                .map(|log| Line::from(log.clone()))
                .collect()
        };
        let paragraph = Paragraph::new(logs);
        frame.render_widget(paragraph, area);
    }

    fn render_footer(&self, frame: &mut Frame, area: Rect) {
        let hint = " q: quit  -  j/k or up/down: scroll  -  f: follow";
        let line = Line::from(Span::styled(hint, Style::default().fg(Color::DarkGray)));
        frame.render_widget(Paragraph::new(line), area);
    }
}
