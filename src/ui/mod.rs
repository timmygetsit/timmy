pub mod app;
pub mod event;
pub mod theme;
pub mod views;

pub use app::App;
pub use event::{Event, EventHandler};

use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io::{stdout, Result as IoResult};
use std::panic;
use std::time::Duration;

/// Custom panic hook to ensure terminal is restored to normal state even if a panic occurs.
pub fn install_panic_hook() {
    let original_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        let _ = disable_raw_mode();
        let _ = execute!(stdout(), LeaveAlternateScreen);
        original_hook(panic_info);
    }));
}

/// Runs the interactive terminal user interface.
pub fn run_tui(mut app: App, refresh_interval_ms: u64) -> IoResult<()> {
    install_panic_hook();

    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let tick_rate = Duration::from_millis(refresh_interval_ms);
    let events = EventHandler::new(tick_rate);

    loop {
        terminal.draw(|f| app.draw(f))?;

        if app.should_quit {
            break;
        }

        match events.next() {
            Ok(Event::Key(key)) => {
                app.handle_key(key);
                if app.should_quit {
                    break;
                }
            }
            Ok(Event::Tick) => {
                // Periodic refresh on tick if no modal is active
                if matches!(app.modal, app::ActiveModal::None) {
                    app.refresh();
                }
            }
            Ok(Event::Resize(_, _)) => {}
            Err(_) => {
                break;
            }
        }
    }

    // Restore terminal state safely
    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();

    Ok(())
}

/// Evaluates whether all whitespace-separated tokens in `query` match at least
/// one field in `target_fields` (case-insensitive multi-token AND matching).
pub fn matches_filter_tokens(target_fields: &[&str], query: &str) -> bool {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return true;
    }
    let tokens: Vec<&str> = q.split_whitespace().collect();
    if tokens.is_empty() {
        return true;
    }

    // Every token must appear in at least one of the target fields
    tokens.iter().all(|token| {
        target_fields
            .iter()
            .any(|field| field.to_lowercase().contains(token))
    })
}
