use std::env;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crossterm::event::{self, Event as CrosstermEvent, KeyEvent, KeyEventKind};
use ratatui::{Terminal, backend::CrosstermBackend};
use tokio::sync::mpsc;

mod app;
mod certspotter;
mod crt;
mod ip_helper;
mod ipinfo;
mod ptr;
mod report;
mod scanner;
mod status;
mod tls;

use crate::app::App;
use crate::scanner::{ScanEvent, ScanOptions, SharedOptions};

#[derive(Debug, PartialEq)]
enum Mode {
    Scan(String),
    Open(PathBuf),
}

enum UiEvent {
    Scan(ScanEvent),
    Key(KeyEvent),
}

const REDRAW_INTERVAL: Duration = Duration::from_millis(100);
const KEY_POLL_INTERVAL: Duration = Duration::from_millis(250);

#[tokio::main]
async fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let mode = parse_mode(&args).unwrap_or_else(|error| exit_with_error(&error));
    let (ui_tx, mut ui_rx) = mpsc::unbounded_channel::<UiEvent>();

    // The options are shared so feature toggles (keys 1-4) take effect while scanning.
    let options: SharedOptions = Arc::new(std::sync::RwLock::new(ScanOptions::default()));
    let mut app = match mode {
        Mode::Scan(domain) => {
            start_scan(domain.clone(), Arc::clone(&options), ui_tx.clone());
            App::new(domain, options)
        }
        Mode::Open(path) => {
            let report = report::read(&path).unwrap_or_else(|error| exit_with_error(&error));
            App::from_report(report, options)
        }
    };

    // Keyboard input: crossterm's blocking event loop on a dedicated thread.
    // The flag lets the loop exit shortly after the UI is done, otherwise the
    // runtime shutdown would block forever waiting for this thread.
    let quit_flag = Arc::new(AtomicBool::new(false));
    let key_tx = ui_tx.clone();
    let key_flag = Arc::clone(&quit_flag);
    let key_task = tokio::task::spawn_blocking(move || {
        loop {
            if key_flag.load(Ordering::Relaxed) {
                break;
            }
            if !event::poll(KEY_POLL_INTERVAL).unwrap_or(false) {
                continue;
            }
            if let Ok(CrosstermEvent::Key(key)) = event::read()
                && key.kind == KeyEventKind::Press
                && key_tx.send(UiEvent::Key(key)).is_err()
            {
                break;
            }
        }
    });

    let mut terminal = ratatui::init();
    let result = run(&mut terminal, &mut app, &mut ui_rx).await;
    ratatui::restore();
    quit_flag.store(true, Ordering::SeqCst);
    key_task.abort();
    result
}

async fn run(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    ui_rx: &mut mpsc::UnboundedReceiver<UiEvent>,
) -> io::Result<()> {
    loop {
        terminal.draw(|frame| app.render(frame))?;

        match tokio::time::timeout(REDRAW_INTERVAL, ui_rx.recv()).await {
            Ok(Some(UiEvent::Scan(event))) => app.handle_scan_event(event),
            Ok(Some(UiEvent::Key(key))) => app.handle_key(key),
            Ok(None) => break,
            Err(_) => {} // redraw interval elapsed, no new events
        }

        if app.should_quit {
            break;
        }
    }
    Ok(())
}

fn start_scan(domain: String, options: SharedOptions, ui_tx: mpsc::UnboundedSender<UiEvent>) {
    let (scan_tx, mut scan_rx) = mpsc::unbounded_channel::<ScanEvent>();
    tokio::spawn(scanner::run_scan(domain, options, scan_tx));
    tokio::spawn(async move {
        while let Some(event) = scan_rx.recv().await {
            let _ = ui_tx.send(UiEvent::Scan(event));
        }
    });
}

fn parse_mode(args: &[String]) -> Result<Mode, String> {
    match args {
        [_, flag, path] if flag == "--open" => Ok(Mode::Open(PathBuf::from(path))),
        [_, flag] if flag == "--open" => Err(String::from("--open requires a JSON report file")),
        [_, domain] if !domain.is_empty() => Ok(Mode::Scan(domain.clone())),
        [_, _] => Err(String::from("The domain name must not be empty")),
        _ => Err(String::from(
            "Please provide a domain name or --open <report.json>",
        )),
    }
}

fn exit_with_error(error: &str) -> ! {
    eprintln!("Error: {error}");
    eprintln!("Usage: analytic-intelligence <domain>");
    eprintln!("       analytic-intelligence --open <report.json>");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn a_domain_starts_a_scan() {
        // given
        let args = args(&["analytic-intelligence", "example.com"]);

        // when
        let mode = parse_mode(&args);

        // then
        assert_eq!(mode, Ok(Mode::Scan("example.com".to_string())));
    }

    #[test]
    fn open_flag_loads_a_report() {
        // given
        let args = args(&["analytic-intelligence", "--open", "scan.json"]);

        // when
        let mode = parse_mode(&args);

        // then
        assert_eq!(mode, Ok(Mode::Open(PathBuf::from("scan.json"))));
    }

    #[test]
    fn open_flag_without_file_is_rejected() {
        // given
        let args = args(&["analytic-intelligence", "--open"]);

        // when
        let mode = parse_mode(&args);

        // then
        assert!(mode.unwrap_err().contains("--open"));
    }

    #[test]
    fn missing_or_empty_domain_is_rejected() {
        // given
        let no_args = args(&["analytic-intelligence"]);
        let empty = args(&["analytic-intelligence", ""]);

        // when / then
        assert!(parse_mode(&no_args).is_err());
        assert!(parse_mode(&empty).is_err());
    }
}
