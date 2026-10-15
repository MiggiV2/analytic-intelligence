use std::collections::HashMap;
use std::path::PathBuf;

use chrono::{DateTime, FixedOffset, Local};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, Gauge, Paragraph, Row, Table, TableState};

use crate::report::{self, HostReport, HostState, ScanReport, SecurityHeaders, TlsReport};
use crate::scanner::{Phase, ScanEvent, ScanOptions, SharedOptions, Source};
use crate::status::SecurityReport;
use crate::tls::TlsInfo;

const LOG_LINES: usize = 2;
const TLS_COLUMN_WIDTH: u16 = 9;
const SEC_COLUMN_WIDTH: u16 = 5;

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
    tech: Vec<String>,
    security: Option<SecurityReport>,
    tls_info: Option<TlsInfo>,
}

impl HostEntry {
    fn new(domain: String, ip: String, location: String) -> Self {
        Self {
            domain,
            ip,
            location,
            state: EntryState::Pending,
            title: None,
            tech: Vec::new(),
            security: None,
            tls_info: None,
        }
    }
}

enum Feature {
    SecurityHeaders,
    TlsCert,
    Tech,
    ReverseDns,
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
    ip_ptr: HashMap<String, Option<String>>,
    logs: Vec<String>,
    table_state: TableState,
    follow: bool,
    options: ScanOptions,
    shared: SharedOptions,
    export_dir: PathBuf,
    loaded_scanned_at: Option<DateTime<FixedOffset>>,
    pub should_quit: bool,
}

impl App {
    pub fn new(domain: String, shared: SharedOptions) -> Self {
        let options = *shared.read().unwrap_or_else(|e| e.into_inner());
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
            ip_ptr: HashMap::new(),
            logs: Vec::new(),
            table_state: TableState::default(),
            follow: true,
            options,
            shared,
            export_dir: PathBuf::from("."),
            loaded_scanned_at: None,
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
                let location = self.ip_locations.get(&ip).cloned().unwrap_or_default();
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
                    row.tech = status.tech;
                    row.security = status.security;
                    row.state = match status.online {
                        true => EntryState::Online,
                        false => EntryState::Offline,
                    };
                }
                self.done += 1;
            }
            ScanEvent::TlsChecked { domain, info } => {
                if let Some(index) = self.row_index.get(&domain) {
                    self.rows[*index].tls_info = info;
                }
            }
            ScanEvent::PtrRecord { ip, ptr } => {
                self.ip_ptr.insert(ip, ptr);
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
            KeyCode::Char('1') => self.toggle_feature(Feature::SecurityHeaders),
            KeyCode::Char('2') => self.toggle_feature(Feature::TlsCert),
            KeyCode::Char('3') => self.toggle_feature(Feature::Tech),
            KeyCode::Char('4') => self.toggle_feature(Feature::ReverseDns),
            KeyCode::Char('e') => self.export(),
            _ => {}
        }
    }

    pub fn from_report(report: ScanReport, shared: SharedOptions) -> Self {
        let mut app = Self::new(report.domain, shared);
        app.phase = if report.complete {
            Phase::Done
        } else {
            Phase::Checking
        };
        app.source = report.source.as_deref().and_then(Source::from_name);
        app.mail_server = report.mail_server;
        app.discovered = report.hosts.len();
        app.loaded_scanned_at = Some(report.scanned_at);
        for host in report.hosts {
            app.push_loaded_host(host);
        }
        app.update_selection();
        app
    }

    fn push_loaded_host(&mut self, host: HostReport) {
        let ip = host.ip.unwrap_or_default();
        if let Some(ptr) = host.ptr {
            self.ip_ptr.insert(ip.clone(), Some(ptr));
        }
        let mut entry = HostEntry::new(host.domain, ip, host.location.unwrap_or_default());
        entry.state = match host.state {
            HostState::Up => EntryState::Online,
            HostState::Down => EntryState::Offline,
            HostState::Skipped => EntryState::Skipped(host.skip_reason.unwrap_or_default()),
            HostState::Pending => EntryState::Pending,
        };
        match entry.state {
            EntryState::Online => self.online += 1,
            EntryState::Offline => self.offline += 1,
            EntryState::Skipped(_) => self.skipped += 1,
            EntryState::Pending => {}
        }
        if entry.state != EntryState::Pending {
            self.done += 1;
        }
        entry.title = host.title;
        entry.tech = host.tech;
        entry.security = host.security_headers.map(|sec| SecurityReport {
            present: sec.present,
            total: sec.total,
        });
        entry.tls_info = host.tls.map(|tls| TlsInfo {
            issuer: tls.issuer,
            days_left: tls.days_left,
            self_signed: tls.self_signed,
        });
        self.row_index.insert(entry.domain.clone(), self.rows.len());
        self.rows.push(entry);
    }

    pub fn report(&self, scanned_at: DateTime<FixedOffset>) -> ScanReport {
        ScanReport {
            domain: self.domain.clone(),
            scanned_at,
            complete: self.phase == Phase::Done,
            source: self.source.map(|source| source.to_string()),
            mail_server: self.mail_server.clone(),
            hosts: self
                .rows
                .iter()
                .map(|entry| self.host_report(entry))
                .collect(),
        }
    }

    fn host_report(&self, entry: &HostEntry) -> HostReport {
        let (state, skip_reason) = match &entry.state {
            EntryState::Pending => (HostState::Pending, None),
            EntryState::Online => (HostState::Up, None),
            EntryState::Offline => (HostState::Down, None),
            EntryState::Skipped(reason) => (HostState::Skipped, Some(reason.clone())),
        };
        HostReport {
            domain: entry.domain.clone(),
            state,
            skip_reason,
            ip: non_empty(&entry.ip),
            ptr: self.ip_ptr.get(&entry.ip).cloned().flatten(),
            location: non_empty(&entry.location),
            title: entry.title.clone(),
            tech: entry.tech.clone(),
            security_headers: entry.security.as_ref().map(|sec| SecurityHeaders {
                present: sec.present,
                total: sec.total,
            }),
            tls: entry.tls_info.as_ref().map(|tls| TlsReport {
                issuer: tls.issuer.clone(),
                days_left: tls.days_left,
                self_signed: tls.self_signed,
            }),
        }
    }

    fn export(&mut self) {
        let scanned_at = self
            .loaded_scanned_at
            .unwrap_or_else(|| Local::now().fixed_offset());
        let report = self.report(scanned_at);
        match report::write(&report, &self.export_dir) {
            Ok((json, md)) => self.push_log(format!(
                "Exported to {} and {}",
                json.display(),
                md.display()
            )),
            Err(error) => self.push_log(format!("Export failed: {error}")),
        }
    }

    fn toggle_feature(&mut self, feature: Feature) {
        let options = &mut self.options;
        match feature {
            Feature::SecurityHeaders => options.security_headers = !options.security_headers,
            Feature::TlsCert => options.tls_cert = !options.tls_cert,
            Feature::Tech => options.tech = !options.tech,
            Feature::ReverseDns => options.reverse_dns = !options.reverse_dns,
        }
        let mut shared = self.shared.write().unwrap_or_else(|e| e.into_inner());
        *shared = self.options;
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
        let status = match self.loaded_scanned_at {
            Some(scanned_at) => vec![
                Span::styled("Loaded report: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!(
                        "scanned {}{}",
                        scanned_at.format("%Y-%m-%d %H:%M"),
                        if self.phase == Phase::Done {
                            ""
                        } else {
                            " (incomplete)"
                        }
                    ),
                    Style::default().fg(Color::Yellow),
                ),
            ],
            None => vec![
                Span::styled("Phase: ", Style::default().fg(Color::DarkGray)),
                Span::styled(self.phase.to_string(), Style::default().fg(Color::Yellow)),
            ],
        };
        let mut second = status;
        second.push(Span::raw(format!(
            "  -  {} subdomains{source_info}",
            self.discovered
        )));
        let second = Line::from(second);
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

        let paragraph =
            Paragraph::new(vec![first, second, third]).block(Block::bordered().title(" Scan "));
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

        let mut headers = vec!["State", "Domain", "IP"];
        let mut widths = vec![
            Constraint::Length(6),
            Constraint::Percentage(20),
            Constraint::Length(16),
        ];
        if self.options.reverse_dns {
            headers.push("PTR");
            widths.push(Constraint::Percentage(13));
        }
        headers.push("Org / Location");
        widths.push(Constraint::Percentage(15));
        if self.options.tls_cert {
            headers.push("TLS");
            widths.push(Constraint::Length(TLS_COLUMN_WIDTH));
        }
        if self.options.tech {
            headers.push("Tech");
            widths.push(Constraint::Percentage(11));
        }
        if self.options.security_headers {
            headers.push("Sec");
            widths.push(Constraint::Length(SEC_COLUMN_WIDTH));
        }
        headers.push("Title");
        widths.push(Constraint::Fill(1));

        let header = Row::new(headers).style(Style::default().add_modifier(Modifier::BOLD));

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
                (EntryState::Online, Some(title)) | (EntryState::Offline, Some(title)) => {
                    title.clone()
                }
                _ => String::new(),
            };

            let mut cells = vec![
                Cell::from(state),
                Cell::from(domain),
                Cell::from(entry.ip.clone()),
            ];
            if self.options.reverse_dns {
                cells.push(Cell::from(ptr_cell(&self.ip_ptr, &entry.ip)));
            }
            cells.push(Cell::from(entry.location.clone()));
            if self.options.tls_cert {
                cells.push(Cell::from(Span::styled(
                    tls_label(entry),
                    Style::default().fg(tls_color(entry)),
                )));
            }
            if self.options.tech {
                cells.push(Cell::from(Span::styled(
                    entry.tech.join(", "),
                    Style::default().fg(Color::DarkGray),
                )));
            }
            if self.options.security_headers {
                cells.push(security_cell(entry));
            }
            cells.push(Cell::from(Span::styled(
                title,
                Style::default().fg(Color::DarkGray),
            )));

            Row::new(cells)
        });

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
        let gray = Style::default().fg(Color::DarkGray);
        let mut spans = vec![
            Span::styled(" q: quit  -  j/k: scroll  -  f: follow  -  e: export", gray),
            Span::raw("    toggle: "),
        ];
        for (label, on) in [
            ("1:sec-hdrs", self.options.security_headers),
            ("2:tls", self.options.tls_cert),
            ("3:tech", self.options.tech),
            ("4:ptr", self.options.reverse_dns),
        ] {
            spans.push(Span::styled(
                label,
                if on {
                    Style::default().fg(Color::Green)
                } else {
                    gray
                },
            ));
            spans.push(Span::styled(" ", gray));
        }
        frame.render_widget(Paragraph::new(Line::from(spans)), area);
    }
}

fn non_empty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_string())
}

fn ptr_cell(ip_ptr: &HashMap<String, Option<String>>, ip: &str) -> String {
    match ip_ptr.get(ip) {
        Some(Some(ptr)) => ptr.clone(),
        Some(None) => String::from("-"),
        None => String::new(),
    }
}

/// Compact TLS summary: issuer abbreviation plus days until expiry,
/// e.g. "LE 66d", "SS 12d" (self-signed), "expired"
fn tls_label(entry: &HostEntry) -> String {
    let Some(info) = &entry.tls_info else {
        return match entry.state {
            EntryState::Online | EntryState::Offline => String::from("-"),
            _ => String::new(),
        };
    };
    if info.days_left < 0 {
        return String::from("expired");
    }
    let issuer = if info.self_signed {
        "SS"
    } else {
        issuer_abbreviation(&info.issuer)
    };
    if issuer.is_empty() {
        format!("{}d", info.days_left)
    } else {
        format!("{issuer} {}d", info.days_left)
    }
}

fn issuer_abbreviation(issuer: &str) -> &'static str {
    let issuer = issuer.to_lowercase();
    if issuer.contains("let's encrypt") || issuer.contains("letsencrypt") {
        "LE"
    } else if issuer.contains("digicert") {
        "DC"
    } else if issuer.contains("sectigo") || issuer.contains("comodo") {
        "SC"
    } else if issuer.contains("globalsign") {
        "GS"
    } else if issuer.contains("godaddy") {
        "GD"
    } else if issuer.contains("amazon") {
        "AMZ"
    } else if issuer.contains("google") {
        "GTS"
    } else if issuer.contains("zerossl") {
        "ZS"
    } else if issuer.contains("microsoft") {
        "MS"
    } else {
        ""
    }
}

fn tls_color(entry: &HostEntry) -> Color {
    match &entry.tls_info {
        Some(info) if info.self_signed || info.days_left < 0 => Color::Red,
        Some(info) if info.days_left <= 30 => Color::Yellow,
        Some(_) => Color::Green,
        None => Color::DarkGray,
    }
}

/// Security header score as "present/total", colored by how many are set
fn security_cell(entry: &HostEntry) -> Cell<'_> {
    match &entry.security {
        Some(report) => {
            let color = if report.present == report.total {
                Color::Green
            } else if report.present >= 2 {
                Color::Yellow
            } else {
                Color::Red
            };
            Cell::from(Span::styled(
                format!("{}/{}", report.present, report.total),
                Style::default().fg(color),
            ))
        }
        None => Cell::from(""),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, RwLock};

    use crossterm::event::KeyEventKind;

    use super::*;
    use crate::ipinfo::IpInfo;
    use crate::status::Status;

    fn scanned_at() -> DateTime<FixedOffset> {
        DateTime::parse_from_rfc3339("2026-10-15T14:03:27+02:00").unwrap()
    }

    fn scanned_app() -> App {
        let mut app = App::new(
            "example.com".to_string(),
            Arc::new(RwLock::new(ScanOptions::default())),
        );
        for event in [
            ScanEvent::MailServer("mx.example.com".to_string()),
            ScanEvent::Discovery {
                count: 3,
                source: Source::CrtSh,
            },
            ScanEvent::IpInfo {
                ip: "93.184.215.14".to_string(),
                info: IpInfo {
                    org: "Edgecast".to_string(),
                    country: "US".to_string(),
                    city: "Los Angeles".to_string(),
                },
            },
            ScanEvent::HostResolved {
                domain: "www.example.com".to_string(),
                ip: "93.184.215.14".to_string(),
            },
            ScanEvent::HostResolved {
                domain: "old.example.com".to_string(),
                ip: "unknown".to_string(),
            },
            ScanEvent::HostSkipped {
                domain: "intranet.example.com".to_string(),
                reason: "local address".to_string(),
            },
            ScanEvent::PtrRecord {
                ip: "93.184.215.14".to_string(),
                ptr: Some("edge.example.net".to_string()),
            },
            ScanEvent::HostChecked {
                domain: "www.example.com".to_string(),
                status: Status {
                    online: true,
                    title: Some("Example".to_string()),
                    tech: vec!["nginx".to_string()],
                    security: Some(SecurityReport {
                        present: 3,
                        total: 5,
                    }),
                },
            },
            ScanEvent::TlsChecked {
                domain: "www.example.com".to_string(),
                info: Some(TlsInfo {
                    issuer: "CN=R11".to_string(),
                    days_left: 66,
                    self_signed: false,
                }),
            },
            ScanEvent::HostChecked {
                domain: "old.example.com".to_string(),
                status: Status {
                    online: false,
                    title: Some("connection refused".to_string()),
                    tech: Vec::new(),
                    security: None,
                },
            },
            ScanEvent::Phase(Phase::Done),
        ] {
            app.handle_scan_event(event);
        }
        app
    }

    #[test]
    fn report_reflects_the_scan_results() {
        // given
        let app = scanned_app();

        // when
        let report = app.report(scanned_at());

        // then
        assert_eq!(report.domain, "example.com");
        assert_eq!(report.scanned_at, scanned_at());
        assert!(report.complete);
        assert_eq!(report.source.as_deref(), Some("crt.sh"));
        assert_eq!(report.mail_server.as_deref(), Some("mx.example.com"));
        assert_eq!(
            report.hosts,
            vec![
                HostReport {
                    domain: "www.example.com".to_string(),
                    state: HostState::Up,
                    skip_reason: None,
                    ip: Some("93.184.215.14".to_string()),
                    ptr: Some("edge.example.net".to_string()),
                    location: Some("Edgecast, US, Los Angeles".to_string()),
                    title: Some("Example".to_string()),
                    tech: vec!["nginx".to_string()],
                    security_headers: Some(SecurityHeaders {
                        present: 3,
                        total: 5
                    }),
                    tls: Some(TlsReport {
                        issuer: "CN=R11".to_string(),
                        days_left: 66,
                        self_signed: false,
                    }),
                },
                HostReport {
                    domain: "old.example.com".to_string(),
                    state: HostState::Down,
                    skip_reason: None,
                    ip: Some("unknown".to_string()),
                    ptr: None,
                    location: None,
                    title: Some("connection refused".to_string()),
                    tech: Vec::new(),
                    security_headers: None,
                    tls: None,
                },
                HostReport {
                    domain: "intranet.example.com".to_string(),
                    state: HostState::Skipped,
                    skip_reason: Some("local address".to_string()),
                    ip: None,
                    ptr: None,
                    location: None,
                    title: None,
                    tech: Vec::new(),
                    security_headers: None,
                    tls: None,
                },
            ]
        );
    }

    #[test]
    fn loaded_report_round_trips_through_the_app() {
        // given
        let original = scanned_app().report(scanned_at());

        // when
        let app = App::from_report(
            original.clone(),
            Arc::new(RwLock::new(ScanOptions::default())),
        );

        // then
        assert_eq!(app.report(scanned_at()), original);
        assert_eq!(app.online, 1);
        assert_eq!(app.offline, 1);
        assert_eq!(app.skipped, 1);
        assert_eq!(app.done, 3);
        assert_eq!(app.discovered, 3);
    }

    #[test]
    fn loaded_incomplete_report_stays_incomplete() {
        // given
        let mut original = scanned_app().report(scanned_at());
        original.complete = false;

        // when
        let app = App::from_report(
            original.clone(),
            Arc::new(RwLock::new(ScanOptions::default())),
        );

        // then
        assert_eq!(app.report(scanned_at()), original);
    }

    #[test]
    fn exporting_a_loaded_report_keeps_its_original_timestamp() {
        // given
        let dir = tempfile::tempdir().unwrap();
        let original = scanned_app().report(scanned_at());
        let mut app = App::from_report(original, Arc::new(RwLock::new(ScanOptions::default())));
        app.export_dir = dir.path().to_path_buf();

        // when
        app.handle_key(KeyEvent::new_with_kind(
            KeyCode::Char('e'),
            KeyModifiers::NONE,
            KeyEventKind::Press,
        ));

        // then
        assert!(dir.path().join("example.com-20261015-1403.json").exists());
        assert!(dir.path().join("example.com-20261015-1403.md").exists());
    }

    #[test]
    fn report_is_incomplete_while_scanning() {
        // given
        let mut app = scanned_app();
        app.handle_scan_event(ScanEvent::Phase(Phase::Checking));

        // when
        let report = app.report(scanned_at());

        // then
        assert!(!report.complete);
    }

    #[test]
    fn pressing_e_exports_json_and_markdown() {
        // given
        let dir = tempfile::tempdir().unwrap();
        let mut app = scanned_app();
        app.export_dir = dir.path().to_path_buf();

        // when
        app.handle_key(KeyEvent::new_with_kind(
            KeyCode::Char('e'),
            KeyModifiers::NONE,
            KeyEventKind::Press,
        ));

        // then
        let mut extensions: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                assert!(
                    path.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with("example.com-")
                );
                path.extension().unwrap().to_string_lossy().to_string()
            })
            .collect();
        extensions.sort();
        assert_eq!(extensions, vec!["json", "md"]);
        assert!(app.logs.last().unwrap().starts_with("Exported to "));
    }
}
