use chrono::Utc;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use timmy::config::TimmyConfig;
use timmy::engine::EngineOrchestrator;
use timmy::model::agent::{AgentAttribution, AgentKind, Confidence};
use timmy::model::session::{SessionInfo, SessionStatus};
use timmy::model::ProcessInfo;
use timmy::ui::app::{ActiveModal, ActiveTab, App};

#[test]
fn test_process_view_jump_to_lineage_tree() {
    let config = TimmyConfig::default();
    let orchestrator = EngineOrchestrator::new(config, None);
    let mut app = App::new(orchestrator);

    let proc = ProcessInfo {
        pid: 3001,
        name: "node".to_string(),
        exe: Some(std::path::PathBuf::from("/usr/local/bin/node")),
        attribution: AgentAttribution {
            kind: AgentKind::ClaudeCode,
            confidence: Confidence::Confirmed,
            reason: "Direct child of claude".to_string(),
            evidence: "PPID matches claude".to_string(),
            is_confirmed: true,
            safe_to_terminate: true,
            root_agent_pid: Some(3000),
            root_agent_name: Some("claude".to_string()),
            parent_pid: Some(3000),
            parent_name: Some("claude".to_string()),
        },
        ..Default::default()
    };

    let session = SessionInfo {
        id: "sess_jump_01".to_string(),
        agent_kind: AgentKind::ClaudeCode,
        status: SessionStatus::Active,
        start_time: Utc::now(),
        end_time: None,
        root_pid: Some(3000),
        root_process_name: Some("claude".to_string()),
        confidence: Confidence::Confirmed,
        evidence: vec!["claude binary".to_string()],
        tracked_pids: vec![3000, 3001],
        total_memory_bytes: 1024 * 1024 * 60,
        total_cpu_usage: 1.0,
        open_ports: vec![],
        resource_count: 2,
        root_binding: None,
    };

    app.snapshot.processes = vec![proc];
    app.snapshot.sessions = vec![session];
    app.current_tab = ActiveTab::Processes;
    app.process_table_state.select(Some(0));

    // Press 't' on the selected process
    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));

    // Modal should now be SessionInspect with active_tab = 0 (Lineage Tree)
    if let ActiveModal::SessionInspect {
        session,
        active_tab,
        ..
    } = &app.modal
    {
        assert_eq!(session.id, "sess_jump_01");
        assert_eq!(*active_tab, 0, "Should open directly to Lineage Tree tab");
    } else {
        panic!("Modal should have opened to SessionInspect");
    }
}

#[test]
fn test_process_view_jump_no_session_shows_status_message() {
    let config = TimmyConfig::default();
    let orchestrator = EngineOrchestrator::new(config, None);
    let mut app = App::new(orchestrator);

    let proc = ProcessInfo {
        pid: 9999,
        name: "unrelated-tool".to_string(),
        ..Default::default()
    };

    app.snapshot.processes = vec![proc];
    app.snapshot.sessions = vec![];
    app.current_tab = ActiveTab::Processes;
    app.process_table_state.select(Some(0));

    // Press 't' on the selected process with no session
    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));

    // Modal should remain None, and status_message should inform user
    assert!(matches!(app.modal, ActiveModal::None));
    let (msg, is_error) = app.status_message.unwrap();
    assert!(!is_error);
    assert!(msg.contains("No active or recorded session found for PID 9999"));
}
