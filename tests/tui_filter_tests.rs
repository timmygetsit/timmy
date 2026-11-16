use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use timmy::config::TimmyConfig;
use timmy::engine::EngineOrchestrator;
use timmy::model::agent::{AgentAttribution, AgentKind, Confidence};
use timmy::model::session::{SessionInfo, SessionStatus};
use timmy::model::{ListeningPort, ProcessInfo};
use timmy::ui::app::{ActiveTab, App};
use timmy::ui::matches_filter_tokens;

#[test]
fn test_matches_filter_tokens_logic() {
    let fields = [
        "claude-code",
        "4001",
        "node server.js",
        "/Users/dev/project",
    ];

    // Empty or whitespace queries match everything
    assert!(matches_filter_tokens(&fields, ""));
    assert!(matches_filter_tokens(&fields, "   "));

    // Single token matching (case-insensitive)
    assert!(matches_filter_tokens(&fields, "claude"));
    assert!(matches_filter_tokens(&fields, "CLAUDE"));
    assert!(matches_filter_tokens(&fields, "4001"));
    assert!(matches_filter_tokens(&fields, "server"));

    // Multi-token matching where each token appears in some field
    assert!(matches_filter_tokens(&fields, "claude node"));
    assert!(matches_filter_tokens(&fields, "4001 server dev"));

    // Multi-token failing when any token is absent
    assert!(!matches_filter_tokens(&fields, "claude python"));
    assert!(!matches_filter_tokens(&fields, "4001 missing"));
}

#[test]
fn test_app_multi_token_process_filtering() {
    let config = TimmyConfig::default();
    let orchestrator = EngineOrchestrator::new(config, None);
    let mut app = App::new(orchestrator);

    let p1 = ProcessInfo {
        pid: 3001,
        name: "node".to_string(),
        attribution: AgentAttribution {
            kind: AgentKind::ClaudeCode,
            confidence: Confidence::Confirmed,
            reason: "Child of claude CLI".to_string(),
            evidence: "Direct process lineage".to_string(),
            is_confirmed: true,
            safe_to_terminate: true,
            root_agent_pid: Some(3000),
            root_agent_name: Some("claude".to_string()),
            parent_pid: Some(3000),
            parent_name: Some("claude".to_string()),
        },
        ..Default::default()
    };

    let p2 = ProcessInfo {
        pid: 3002,
        name: "python3".to_string(),
        attribution: AgentAttribution {
            kind: AgentKind::Cursor,
            confidence: Confidence::Confirmed,
            reason: "Child of cursor".to_string(),
            evidence: "Direct child".to_string(),
            is_confirmed: true,
            safe_to_terminate: true,
            root_agent_pid: Some(2000),
            root_agent_name: Some("cursor".to_string()),
            parent_pid: Some(2000),
            parent_name: Some("cursor".to_string()),
        },
        ..Default::default()
    };

    app.snapshot.processes = vec![p1, p2];
    app.current_tab = ActiveTab::Processes;

    // 1. Initially both processes are visible
    assert_eq!(app.filtered_processes().len(), 2);

    // 2. Set multi-token filter "claude node" -> should match only p1
    app.filter_query = "claude node".to_string();
    let filtered = app.filtered_processes();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].pid, 3001);

    // 3. Multi-token filter "python cursor" -> should match only p2
    app.filter_query = "python cursor".to_string();
    let filtered = app.filtered_processes();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].pid, 3002);

    // 4. Multi-token filter "claude python" -> matches neither
    app.filter_query = "claude python".to_string();
    assert_eq!(app.filtered_processes().len(), 0);

    // 5. Esc clears filter
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(app.filter_query, "");
    assert_eq!(app.filtered_processes().len(), 2);
}

#[test]
fn test_app_multi_token_ports_and_sessions_filtering() {
    let config = TimmyConfig::default();
    let orchestrator = EngineOrchestrator::new(config, None);
    let mut app = App::new(orchestrator);

    let port1 = ListeningPort {
        port: 5432,
        protocol: timmy::model::Protocol::Tcp,
        ip: "127.0.0.1".to_string(),
        pid: Some(101),
        process_name: Some("postgres".to_string()),
        state: timmy::model::SocketState::Listen,
    };
    let port2 = ListeningPort {
        port: 8080,
        protocol: timmy::model::Protocol::Tcp,
        ip: "0.0.0.0".to_string(),
        pid: Some(102),
        process_name: Some("node".to_string()),
        state: timmy::model::SocketState::Listen,
    };
    app.snapshot.ports = vec![port1, port2];

    let sess1 = SessionInfo {
        id: "sess-abc".to_string(),
        agent_kind: AgentKind::ClaudeCode,
        status: SessionStatus::Active,
        start_time: chrono::Utc::now(),
        end_time: None,
        root_pid: Some(500),
        root_process_name: Some("claude".to_string()),
        confidence: Confidence::Confirmed,
        evidence: vec!["Direct tracking".to_string()],
        tracked_pids: vec![500, 501],
        total_memory_bytes: 2048,
        total_cpu_usage: 0.5,
        open_ports: vec![8080],
        resource_count: 2,
        root_binding: None,
    };
    app.snapshot.sessions = vec![sess1];

    // Filter ports with multi-token "5432 postgres"
    app.filter_query = "5432 postgres".to_string();
    let filtered_ports = app.filtered_ports();
    assert_eq!(filtered_ports.len(), 1);
    assert_eq!(filtered_ports[0].port, 5432);

    // Filter sessions with multi-token "abc claude"
    app.filter_query = "abc claude".to_string();
    let filtered_sessions = app.filtered_sessions();
    assert_eq!(filtered_sessions.len(), 1);
    assert_eq!(filtered_sessions[0].id, "sess-abc");
}
