use std::env;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crossterm::event::{self, Event as CrosstermEvent, KeyEvent, KeyEventKind};
use ratatui::{backend::CrosstermBackend, Terminal};
use tokio::sync::mpsc;

mod app;
mod certspotter;
mod crt;
mod ip_helper;
mod ipinfo;
mod ptr;
mod scanner;
mod status;
mod tls;

use crate::app::App;
use crate::scanner::{ScanEvent, ScanOptions, SharedOptions};

enum UiEvent {
    Scan(ScanEvent),
    Key(KeyEvent),
}

const REDRAW_INTERVAL: Duration = Duration::from_millis(100);
const KEY_POLL_INTERVAL: Duration = Duration::from_millis(250);

#[tokio::main]
async fn main() -> io::Result<()> {
    let domain = parse_arguments()?;
    let (ui_tx, mut ui_rx) = mpsc::unbounded_channel::<UiEvent>();

    // Scanner: sends events into a ScanEvent channel which gets forwarded to the UI channel.
    // The options are shared so feature toggles (keys 1-4) take effect while scanning.
    let options: SharedOptions = Arc::new(std::sync::RwLock::new(ScanOptions::default()));
    let (scan_tx, mut scan_rx) = mpsc::unbounded_channel::<ScanEvent>();
    tokio::spawn(scanner::run_scan(domain.clone(), Arc::clone(&options), scan_tx));
    let forward_tx = ui_tx.clone();
    tokio::spawn(async move {
        while let Some(event) = scan_rx.recv().await {
            let _ = forward_tx.send(UiEvent::Scan(event));
        }
    });

    // Keyboard input: crossterm's blocking event loop on a dedicated thread.
    // The flag lets the loop exit shortly after the UI is done, otherwise the
    // runtime shutdown would block forever waiting for this thread.
    let quit_flag = Arc::new(AtomicBool::new(false));
    let key_tx = ui_tx.clone();
    let key_flag = Arc::clone(&quit_flag);
    let key_task = tokio::task::spawn_blocking(move || loop {
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
    });

    let mut terminal = ratatui::init();
    let mut app = App::new(domain, options);
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

fn parse_arguments() -> io::Result<String> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Error: Please provide a domain name as argument");
        eprintln!("Usage: {} <domain>", args[0]);
        std::process::exit(1);
    }
    let domain = args[1].clone();
    if domain.is_empty() {
        eprintln!("Error: The domain name must not be empty");
        std::process::exit(1);
    }
    Ok(domain)
}
