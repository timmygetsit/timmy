use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use timmy::config::TimmyConfig;
use timmy::engine::EngineOrchestrator;
use timmy::model::agent::{AgentAttribution, AgentKind, Confidence};
use timmy::model::ProcessInfo;
use timmy::ui::app::{ActiveModal, ActiveTab, App};

#[test]
fn test_batch_tagging_and_confirmation_modal() {
    let config = TimmyConfig::default();
    let orchestrator = EngineOrchestrator::new(config, None);
    let mut app = App::new(orchestrator);

    let p1 = ProcessInfo {
        pid: 4001,
        name: "safe-worker".to_string(),
        attribution: AgentAttribution {
            kind: AgentKind::ClaudeCode,
            confidence: Confidence::Confirmed,
            reason: "Child of claude".to_string(),
            evidence: "Direct child".to_string(),
            is_confirmed: true,
            safe_to_terminate: true,
            root_agent_pid: Some(4000),
            root_agent_name: Some("claude".to_string()),
            parent_pid: Some(4000),
            parent_name: Some("claude".to_string()),
        },
        ..Default::default()
    };

    let p2 = ProcessInfo {
        pid: 1, // launchd -> system essential, blocked by SafetyShield!
        name: "launchd".to_string(),
        ..Default::default()
    };

    app.snapshot.processes = vec![p1, p2];
    app.current_tab = ActiveTab::Processes;

    // 1. Tag process 4001 using Space
    app.process_table_state.select(Some(0));
    app.handle_key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
    assert!(app.tagged_pids.contains(&4001), "PID 4001 should be tagged");

    // 2. Tag process 1 using Space
    app.process_table_state.select(Some(1));
    app.handle_key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
    assert!(app.tagged_pids.contains(&1), "PID 1 should be tagged");
    assert_eq!(app.tagged_pids.len(), 2);

    // 3. Press 'x' to trigger batch termination modal
    app.handle_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE));

    // 4. Modal should be ConfirmBatchKill
    if let ActiveModal::ConfirmBatchKill {
        eligible,
        blocked,
        force,
    } = &app.modal
    {
        assert!(!force);
        assert_eq!(eligible.len(), 1, "Only PID 4001 should be eligible");
        assert_eq!(eligible[0].pid, 4001);
        assert_eq!(blocked.len(), 1, "PID 1 should be blocked by safety shield");
        assert_eq!(blocked[0].0.pid, 1);
    } else {
        panic!("Modal should be ConfirmBatchKill");
    }

    // 5. Cancel with 'n'
    app.handle_key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));
    assert!(matches!(app.modal, ActiveModal::None));
}

#[test]
fn test_batch_tag_all_toggle() {
    let config = TimmyConfig::default();
    let orchestrator = EngineOrchestrator::new(config, None);
    let mut app = App::new(orchestrator);

    let p1 = ProcessInfo {
        pid: 5001,
        ..Default::default()
    };
    let p2 = ProcessInfo {
        pid: 5002,
        ..Default::default()
    };

    app.snapshot.processes = vec![p1, p2];
    app.current_tab = ActiveTab::Processes;

    // Press 'a' -> tags all filtered processes
    app.handle_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE));
    assert_eq!(app.tagged_pids.len(), 2);
    assert!(app.tagged_pids.contains(&5001));
    assert!(app.tagged_pids.contains(&5002));

    // Press 'a' again -> clears all
    app.handle_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE));
    assert_eq!(app.tagged_pids.len(), 0);
}

#[test]
fn test_batch_termination_execution_and_status() {
    let config = TimmyConfig::default();
    let orchestrator = EngineOrchestrator::new(config, None);
    let mut app = App::new(orchestrator);

    let p1 = ProcessInfo {
        pid: 999991,
        name: "safe-worker-1".to_string(),
        ..Default::default()
    };
    let p2 = ProcessInfo {
        pid: 0, // Kernel scheduler -> blocked
        name: "kernel_task".to_string(),
        ..Default::default()
    };

    app.snapshot.processes = vec![p1, p2];
    app.current_tab = ActiveTab::Processes;

    // Tag all
    app.handle_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE));
    assert_eq!(app.tagged_pids.len(), 2);

    // Prompt batch termination
    app.handle_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE));
    assert!(matches!(app.modal, ActiveModal::ConfirmBatchKill { .. }));

    // Confirm with 'y'
    app.handle_key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE));

    // Modal should close
    assert!(matches!(app.modal, ActiveModal::None));
    // Tagged pids should be cleared
    assert!(app.tagged_pids.is_empty());
    // Status message should indicate batch execution results and blocked count
    assert!(app.status_message.is_some());
    let (msg, _) = app.status_message.unwrap();
    assert!(msg.contains("Batch terminated") || msg.contains("blocked by shield"));
}
