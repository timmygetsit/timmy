use chrono::Utc;
use ratatui::backend::TestBackend;
use ratatui::Terminal;
use timmy::engine::lineage::{format_lineage_tree_unicode, LineageTreeNode};
use timmy::model::agent::{AgentKind, Confidence};
use timmy::model::lineage::LineageStatus;
use timmy::model::process::ProcessStartTime;
use timmy::model::session::{CleanupRecommendation, SessionInfo, SessionStatus, TrackedResource};
use timmy::safety::masker::SecretMasker;
use timmy::ui::theme::Theme;
use timmy::ui::views::render_session_modal;

fn make_test_session() -> SessionInfo {
    SessionInfo {
        id: "sess_modal_test_01".to_string(),
        agent_kind: AgentKind::ClaudeCode,
        status: SessionStatus::Active,
        start_time: Utc::now(),
        end_time: None,
        root_pid: Some(1000),
        root_process_name: Some("claude".to_string()),
        confidence: Confidence::Confirmed,
        evidence: vec!["Direct agent binary claude".to_string()],
        tracked_pids: vec![1000, 1001],
        total_memory_bytes: 1024 * 1024 * 100,
        total_cpu_usage: 2.5,
        open_ports: vec![3000],
        resource_count: 2,
        root_binding: None,
    }
}

fn make_test_tree() -> Vec<LineageTreeNode> {
    vec![LineageTreeNode {
        pid: 1000,
        start_time: ProcessStartTime::new(1000, 0),
        name: "claude".to_string(),
        exe: None,
        status: LineageStatus::BothActive,
        confidence: Confidence::Confirmed,
        is_root: true,
        is_detached: false,
        ports: vec![],
        evidence: vec!["Root agent".to_string()],
        is_active: true,
        children: vec![LineageTreeNode {
            pid: 1001,
            start_time: ProcessStartTime::new(1001, 0),
            name: "node-server".to_string(),
            exe: None,
            status: LineageStatus::BothActive,
            confidence: Confidence::Confirmed,
            is_root: false,
            is_detached: false,
            ports: vec![3000],
            evidence: vec!["Direct child".to_string()],
            is_active: true,
            children: vec![],
        }],
    }]
}

#[test]
fn test_render_session_modal_all_tabs() {
    let backend = TestBackend::new(120, 40);
    let mut terminal = Terminal::new(backend).unwrap();

    let session = make_test_session();
    let tree = make_test_tree();
    let masker = SecretMasker::new();
    let tree_text = format_lineage_tree_unicode(&tree, &masker);

    let resources = vec![TrackedResource {
        session_id: session.id.clone(),
        pid: Some(1000),
        name: "claude".to_string(),
        exe_path: Some("/bin/claude".to_string()),
        memory_bytes: Some(1024 * 1024 * 50),
        cpu_usage: Some(1.0),
        listening_ports: vec![],
        confidence: Confidence::Confirmed,
        evidence: vec!["Root agent".to_string()],
        is_detached: false,
        is_protected: false,
        safe_to_terminate: true,
        first_seen: Utc::now(),
        last_seen: Utc::now(),
        process_start_time: Some(1000),
        provenance: None,
    }];

    let recs = vec![CleanupRecommendation {
        resource_name: "node-server".to_string(),
        pid_or_id: "1001".to_string(),
        memory_formatted: "50.0 MB".to_string(),
        associated_ports: vec![3000],
        ownership_confidence: Confidence::Confirmed,
        ownership_evidence: "Direct child".to_string(),
        is_protected: false,
        termination_eligible: true,
        eligibility_reason: "Eligible for termination".to_string(),
        user_authorized: false,
        is_detached: false,
        confidence: Confidence::Confirmed,
        safe_to_terminate: true,
        evidence: "Direct child".to_string(),
    }];

    let theme = Theme::default_dark();

    // 1. Render Tab 0: Lineage Tree
    terminal
        .draw(|f| {
            render_session_modal(
                f,
                f.area(),
                &session,
                &resources,
                &recs,
                &tree_text,
                0, // active_tab 0: Lineage Tree
                0, // scroll 0
                &theme,
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
        content.contains("Lineage Tree"),
        "Modal header should contain Lineage Tree tab"
    );
    assert!(
        content.contains("claude"),
        "Should render root process claude"
    );
    assert!(
        content.contains("node-server"),
        "Should render child node-server"
    );
    assert!(
        content.contains("3000"),
        "Should render listening port 3000"
    );

    // 2. Render Tab 1: Cleanup Plan
    terminal
        .draw(|f| {
            render_session_modal(
                f,
                f.area(),
                &session,
                &resources,
                &recs,
                &tree_text,
                1, // active_tab 1: Cleanup Plan
                0, // scroll 0
                &theme,
            );
        })
        .unwrap();

    let buffer1 = terminal.backend().buffer();
    let content1 = (0..buffer1.area.height)
        .map(|y| {
            (0..buffer1.area.width)
                .map(|x| buffer1[(x, y)].symbol())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n");

    assert!(content1.contains("Cleanup Plan") || content1.contains("Recommendations"));
    assert!(content1.contains("ELIGIBLE"));

    // 3. Render Tab 2: Tracked Resources
    terminal
        .draw(|f| {
            render_session_modal(
                f,
                f.area(),
                &session,
                &resources,
                &recs,
                &tree_text,
                2, // active_tab 2: Tracked Resources
                0, // scroll 0
                &theme,
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

    assert!(content2.contains("Tracked Resources") || content2.contains("RESOURCE / PROCESS"));
}

#[test]
fn test_session_modal_key_navigation() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use timmy::config::TimmyConfig;
    use timmy::engine::EngineOrchestrator;
    use timmy::ui::app::{ActiveModal, App};

    let config = TimmyConfig::default();
    let orchestrator = EngineOrchestrator::new(config, None);
    let mut app = App::new(orchestrator);

    let session = make_test_session();
    let tree = make_test_tree();
    let masker = SecretMasker::new();
    let tree_text = format_lineage_tree_unicode(&tree, &masker);

    app.modal = ActiveModal::SessionInspect {
        session: Box::new(session),
        resources: vec![],
        recommendations: vec![],
        lineage_tree: tree,
        tree_text,
        active_tab: 0,
        scroll: 0,
    };

    // Press '2' -> switches to tab 1
    app.handle_key(KeyEvent::new(KeyCode::Char('2'), KeyModifiers::NONE));
    if let ActiveModal::SessionInspect { active_tab, .. } = &app.modal {
        assert_eq!(*active_tab, 1);
    } else {
        panic!("Modal should be SessionInspect");
    }

    // Press '3' -> switches to tab 2
    app.handle_key(KeyEvent::new(KeyCode::Char('3'), KeyModifiers::NONE));
    if let ActiveModal::SessionInspect { active_tab, .. } = &app.modal {
        assert_eq!(*active_tab, 2);
    }

    // Press Tab -> wraps to tab 0
    app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    if let ActiveModal::SessionInspect { active_tab, .. } = &app.modal {
        assert_eq!(*active_tab, 0);
    }

    // Press 'j' -> scroll increases to 1
    app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
    if let ActiveModal::SessionInspect { scroll, .. } = &app.modal {
        assert_eq!(*scroll, 1);
    }

    // Press 'k' -> scroll decreases to 0
    app.handle_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE));
    if let ActiveModal::SessionInspect { scroll, .. } = &app.modal {
        assert_eq!(*scroll, 0);
    }

    // Press Esc -> modal closes
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(matches!(app.modal, ActiveModal::None));
}
