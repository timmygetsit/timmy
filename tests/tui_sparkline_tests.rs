use ratatui::backend::TestBackend;
use ratatui::Terminal;
use timmy::config::TimmyConfig;
use timmy::engine::EngineOrchestrator;
use timmy::ui::app::App;

#[test]
fn test_sparkline_history_sampling_and_bound() {
    let config = TimmyConfig::default();
    let orchestrator = EngineOrchestrator::new(config, None);
    let mut app = App::new(orchestrator);

    // Initial state after new() has at least 1 sample from initial refresh
    assert!(!app.cpu_history.is_empty());
    assert!(!app.mem_history.is_empty());

    // Simulate 50 refreshes
    for _ in 0..50 {
        app.refresh();
    }

    // Queue length must stay bounded at <= 35
    assert_eq!(app.cpu_history.len(), 35);
    assert_eq!(app.mem_history.len(), 35);
}

#[test]
fn test_sparkline_rendering_wide_and_narrow_terminals() {
    let config = TimmyConfig::default();
    let orchestrator = EngineOrchestrator::new(config, None);
    let mut app = App::new(orchestrator);

    // Populate history with synthetic points
    for i in 0..20 {
        app.cpu_history.push_back((i * 4).min(100));
        app.mem_history.push_back(100 + i * 10);
    }

    // 1. Wide terminal test (width >= 90) -> Renders sparklines
    let backend_wide = TestBackend::new(120, 30);
    let mut terminal_wide = Terminal::new(backend_wide).unwrap();
    terminal_wide.draw(|f| app.draw(f)).unwrap();

    let buffer_wide = terminal_wide.backend().buffer();
    let wide_content: String = (0..buffer_wide.area.height)
        .map(|y| {
            let row_chars: String = (0..buffer_wide.area.width)
                .map(|x| buffer_wide[(x, y)].symbol().to_string())
                .collect();
            format!("{}\n", row_chars)
        })
        .collect();

    assert!(
        wide_content.contains("CPU:"),
        "Wide dashboard should render CPU sparkline header"
    );
    assert!(
        wide_content.contains("RAM:"),
        "Wide dashboard should render RAM sparkline header"
    );

    // 2. Narrow terminal test (width < 90) -> Renders compact fallback
    let backend_narrow = TestBackend::new(75, 25);
    let mut terminal_narrow = Terminal::new(backend_narrow).unwrap();
    terminal_narrow.draw(|f| app.draw(f)).unwrap();

    let buffer_narrow = terminal_narrow.backend().buffer();
    let narrow_content: String = (0..buffer_narrow.area.height)
        .map(|y| {
            let row_chars: String = (0..buffer_narrow.area.width)
                .map(|x| buffer_narrow[(x, y)].symbol().to_string())
                .collect();
            format!("{}\n", row_chars)
        })
        .collect();

    assert!(
        narrow_content.contains("Agent Processes:"),
        "Narrow dashboard should render compact metrics text"
    );
}
