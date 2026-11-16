use chrono::Utc;
use ratatui::backend::TestBackend;
use ratatui::Terminal;
use timmy::model::agent::{AgentKind, Confidence};
use timmy::model::session::{SessionInfo, SessionStatus, TrackedResource};
use timmy::ui::theme::Theme;
use timmy::ui::views::render_session_view;

fn make_test_session() -> SessionInfo {
    SessionInfo {
        id: "sess_view_test_01".to_string(),
        agent_kind: AgentKind::ClaudeCode,
        status: SessionStatus::Active,
        start_time: Utc::now(),
        end_time: None,
        root_pid: Some(2000),
        root_process_name: Some("claude".to_string()),
        confidence: Confidence::Confirmed,
        evidence: vec!["root process binary matched claude".to_string()],
        tracked_pids: vec![2000, 2001],
        total_memory_bytes: 1024 * 1024 * 80,
        total_cpu_usage: 1.5,
        open_ports: vec![8080],
        resource_count: 2,
        root_binding: None,
    }
}

#[test]
fn test_session_view_toggle_tree_and_table() {
    let backend = TestBackend::new(120, 40);
    let mut terminal = Terminal::new(backend).unwrap();

    let session = make_test_session();
    let sessions = vec![session];
    let resources = vec![TrackedResource {
        session_id: "sess_view_test_01".to_string(),
        pid: Some(2001),
        name: "webpack".to_string(),
        exe_path: Some("/bin/webpack".to_string()),
        memory_bytes: Some(1024 * 1024 * 40),
        cpu_usage: Some(0.5),
        listening_ports: vec![8080],
        confidence: Confidence::Confirmed,
        evidence: vec!["Child process".to_string()],
        is_detached: false,
        is_protected: false,
        safe_to_terminate: true,
        first_seen: Utc::now(),
        last_seen: Utc::now(),
        process_start_time: Some(2001),
        provenance: None,
    }];

    let tree_text = "├── [ACTIVE] PID 2000 (claude) [ROOT]\n└── [ACTIVE] PID 2001 (webpack)\n    └── Ports: [8080]";
    let mut table_state = ratatui::widgets::TableState::default();
    table_state.select(Some(0));

    let theme = Theme::default_dark();

    // 1. Render with show_tree = false (Table mode)
    terminal
        .draw(|f| {
            render_session_view(
                f,
                f.area(),
                &sessions,
                &resources,
                Some(tree_text),
                false, // show_tree = false
                &mut table_state,
                &theme,
                "",
            );
        })
        .unwrap();

    let buffer = terminal.backend().buffer();
    let content = (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        content.contains("Tracked Resources"),
        "Bottom pane should show Tracked Resources"
    );
    assert!(content.contains("webpack"), "Should show webpack in table");

    // 2. Render with show_tree = true (Lineage Tree mode)
    terminal
        .draw(|f| {
            render_session_view(
                f,
                f.area(),
                &sessions,
                &resources,
                Some(tree_text),
                true, // show_tree = true
                &mut table_state,
                &theme,
                "",
            );
        })
        .unwrap();

    let buffer2 = terminal.backend().buffer();
    let content2 = (0..buffer2.area.height)
        .map(|y| {
            (0..buffer2.area.width)
                .map(|x| buffer2[(x, y)].symbol())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        content2.contains("Lineage Tree"),
        "Bottom pane should show Lineage Tree title"
    );
    assert!(
        content2.contains("PID 2000 (claude) [ROOT]"),
        "Should render tree node for claude"
    );
    assert!(
        content2.contains("PID 2001 (webpack)"),
        "Should render tree node for webpack"
    );
}

#[test]
fn test_session_view_key_t_toggles_tree() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use timmy::config::TimmyConfig;
    use timmy::engine::EngineOrchestrator;
    use timmy::ui::app::{ActiveTab, App};

    let config = TimmyConfig::default();
    let orchestrator = EngineOrchestrator::new(config, None);
    let mut app = App::new(orchestrator);

    app.current_tab = ActiveTab::Sessions;
    assert!(!app.session_view_show_tree);

    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    assert!(app.session_view_show_tree);

    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    assert!(!app.session_view_show_tree);
}
