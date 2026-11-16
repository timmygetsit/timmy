use std::path::PathBuf;
use std::sync::Arc;
use timmy::config::TimmyConfig;
use timmy::engine::{
    AttributionEngine, EngineOrchestrator, ProcessTerminator, ResourceMonitor, TerminationError,
};
use timmy::model::{AgentAttribution, AgentKind, Confidence, ProcessInfo};
use timmy::platform::macos::ports::parse_lsof_field_output;
use timmy::safety::masker::SecretMasker;
use timmy::safety::{SafetyShield, SafetyViolation};
use timmy::storage::{AuditRecord, StorageManager};

#[test]
fn test_agent_attribution_engine() {
    let engine = AttributionEngine::default();

    let mut procs = vec![
        ProcessInfo {
            pid: 101,
            ppid: Some(1),
            name: "claude".to_string(),
            exe: Some(PathBuf::from("/usr/local/bin/claude")),
            cpu_usage: Some(1.2),
            memory_bytes: Some(50 * 1024 * 1024),
            run_time_secs: 120,
            start_time: Some(1000),
            user: Some("developer".to_string()),
            attribution: AgentAttribution::default(),
            listening_ports: Vec::new(),
            cmdline: Vec::new(),
            command_outcome: None,
            provenance: None,
            ..Default::default()
        },
        ProcessInfo {
            pid: 102,
            ppid: Some(101),
            name: "node".to_string(),
            exe: Some(PathBuf::from("/usr/local/bin/node")),
            cpu_usage: Some(8.5),
            memory_bytes: Some(120 * 1024 * 1024),
            run_time_secs: 60,
            start_time: Some(1010),
            user: Some("developer".to_string()),
            attribution: AgentAttribution::default(),
            listening_ports: vec![3000, 5173],
            cmdline: Vec::new(),
            command_outcome: None,
            provenance: None,
            ..Default::default()
        },
        ProcessInfo {
            pid: 103,
            ppid: Some(102),
            name: "esbuild".to_string(),
            exe: None,
            cpu_usage: Some(0.1),
            memory_bytes: Some(20 * 1024 * 1024),
            run_time_secs: 30,
            start_time: Some(1020),
            user: Some("developer".to_string()),
            attribution: AgentAttribution::default(),
            listening_ports: Vec::new(),
            cmdline: Vec::new(),
            command_outcome: None,
            provenance: None,
            ..Default::default()
        },
        ProcessInfo {
            pid: 999,
            ppid: Some(1),
            name: "calculator".to_string(),
            exe: None,
            cpu_usage: Some(0.0),
            memory_bytes: Some(10 * 1024 * 1024),
            run_time_secs: 500,
            start_time: Some(500),
            user: Some("developer".to_string()),
            attribution: AgentAttribution::default(),
            listening_ports: Vec::new(),
            cmdline: Vec::new(),
            command_outcome: None,
            provenance: None,
            ..Default::default()
        },
    ];

    engine.propagate_tree_attribution(&mut procs);

    // 101 is Confirmed Claude Code
    assert_eq!(procs[0].attribution.kind, AgentKind::ClaudeCode);
    assert_eq!(procs[0].attribution.confidence, Confidence::Confirmed);
    assert!(procs[0].attribution.is_confirmed);
    assert!(procs[0].attribution.safe_to_terminate);

    // 102 is child of Claude -> HighConfidence Claude Code, safe to stop
    assert_eq!(procs[1].attribution.kind, AgentKind::ClaudeCode);
    assert_eq!(procs[1].attribution.confidence, Confidence::HighConfidence);
    assert!(!procs[1].attribution.is_confirmed);
    assert!(procs[1].attribution.safe_to_terminate);

    // 103 is grandchild -> HighConfidence Claude Code, safe to stop
    assert_eq!(procs[2].attribution.kind, AgentKind::ClaudeCode);
    assert_eq!(procs[2].attribution.confidence, Confidence::HighConfidence);
    assert!(procs[2].attribution.safe_to_terminate);

    // 999 is unrelated calculator -> Unknown, safe_to_terminate = false
    assert_eq!(procs[3].attribution.confidence, Confidence::Unknown);
    assert!(!procs[3].attribution.safe_to_terminate);
}

#[test]
fn test_attribution_distinguishes_interactive_shells_and_timmy() {
    let engine = AttributionEngine::default();
    let current_pid = std::process::id();

    let mut procs = vec![
        ProcessInfo {
            pid: 500,
            ppid: Some(1),
            name: "Cursor".to_string(),
            exe: None,
            cpu_usage: Some(2.0),
            memory_bytes: Some(500 * 1024 * 1024),
            run_time_secs: 600,
            start_time: Some(100),
            user: None,
            attribution: AgentAttribution::default(),
            listening_ports: Vec::new(),
            cmdline: Vec::new(),
            command_outcome: None,
            provenance: None,
            ..Default::default()
        },
        ProcessInfo {
            pid: 501,
            ppid: Some(500),
            name: "zsh".to_string(),
            exe: None,
            cpu_usage: Some(0.1),
            memory_bytes: Some(10 * 1024 * 1024),
            run_time_secs: 300,
            start_time: Some(200),
            user: None,
            attribution: AgentAttribution::default(),
            listening_ports: Vec::new(),
            cmdline: Vec::new(),
            command_outcome: None,
            provenance: None,
            ..Default::default()
        },
        ProcessInfo {
            pid: current_pid,
            ppid: Some(501),
            name: "timmy".to_string(),
            exe: None,
            cpu_usage: Some(0.5),
            memory_bytes: Some(15 * 1024 * 1024),
            run_time_secs: 10,
            start_time: Some(300),
            user: None,
            attribution: AgentAttribution::default(),
            listening_ports: Vec::new(),
            cmdline: Vec::new(),
            command_outcome: None,
            provenance: None,
            ..Default::default()
        },
    ];

    engine.propagate_tree_attribution(&mut procs);

    // Cursor is confirmed
    assert_eq!(procs[0].attribution.kind, AgentKind::Cursor);
    assert_eq!(procs[0].attribution.confidence, Confidence::Confirmed);

    // zsh under Cursor is attributed to Cursor tree, but explicitly marked NOT safe to terminate!
    assert_eq!(procs[1].attribution.kind, AgentKind::Cursor);
    assert!(!procs[1].attribution.safe_to_terminate);

    // timmy itself must NEVER be attributed to an AI agent!
    assert_eq!(procs[2].attribution.kind, AgentKind::Unknown);
    assert_eq!(procs[2].attribution.confidence, Confidence::Unknown);
    assert!(!procs[2].attribution.safe_to_terminate);
}

#[test]
fn test_safety_shield_system_protection() {
    let shield = SafetyShield::new();

    // Must block PID 0 & 1
    assert!(matches!(
        shield.validate_termination(0, "kernel"),
        Err(SafetyViolation::ProtectedPid(0))
    ));
    assert!(matches!(
        shield.validate_termination(1, "launchd"),
        Err(SafetyViolation::ProtectedPid(1))
    ));

    // Must block macOS system processes
    assert!(matches!(
        shield.validate_termination(500, "WindowServer"),
        Err(SafetyViolation::CriticalSystemProcess(..))
    ));
    assert!(matches!(
        shield.validate_termination(501, "loginwindow"),
        Err(SafetyViolation::CriticalSystemProcess(..))
    ));
    assert!(matches!(
        shield.validate_termination(502, "Dock"),
        Err(SafetyViolation::CriticalSystemProcess(..))
    ));
    assert!(matches!(
        shield.validate_termination(503, "Finder"),
        Err(SafetyViolation::CriticalSystemProcess(..))
    ));
    assert!(matches!(
        shield.validate_termination(504, "securityd"),
        Err(SafetyViolation::CriticalSystemProcess(..))
    ));

    // Must block terminal applications
    assert!(matches!(
        shield.validate_termination(600, "Terminal"),
        Err(SafetyViolation::TerminalHost(..))
    ));
    assert!(matches!(
        shield.validate_termination(601, "iTerm2"),
        Err(SafetyViolation::TerminalHost(..))
    ));

    // Must allow safe developer processes
    assert!(shield.validate_termination(12345, "vite").is_ok());
    assert!(shield.validate_termination(12346, "python3").is_ok());
}

#[test]
fn test_toctou_pid_reuse_protection() {
    let terminator = ProcessTerminator::new();

    // If we expect PID 1 (launchd) to be named "vite", safety shield blocks PID 1
    assert!(matches!(
        terminator.verify_target_identity(1, "vite", None),
        Err(TerminationError::Safety(SafetyViolation::ProtectedPid(1)))
    ));

    // If we look for a non-existent PID, it catches it as gone
    let non_existent_pid = 9999999;
    assert!(matches!(
        terminator.verify_target_identity(non_existent_pid, "node", None),
        Err(TerminationError::ProcessGone(9999999))
    ));
}

#[test]
fn test_lsof_field_parser_space_safety() {
    let raw_lsof = r#"
p4500
cVisual Studio Code
f12
n127.0.0.1:3000
TST=LISTEN
p4501
cAntigravity Helper
f14
n*:8080
TST=LISTEN
p4502
cnode
f20
n[::1]:5432
TST=LISTEN
"#;

    let ports = parse_lsof_field_output(raw_lsof);
    assert_eq!(ports.len(), 3);

    let p3000 = ports.iter().find(|p| p.port == 3000).unwrap();
    assert_eq!(p3000.process_name.as_deref(), Some("Visual Studio Code"));
    assert_eq!(p3000.pid, Some(4500));

    let p8080 = ports.iter().find(|p| p.port == 8080).unwrap();
    assert_eq!(p8080.process_name.as_deref(), Some("Antigravity Helper"));
    assert_eq!(p8080.pid, Some(4501));

    let p5432 = ports.iter().find(|p| p.port == 5432).unwrap();
    assert_eq!(p5432.process_name.as_deref(), Some("node"));
    assert_eq!(p5432.ip, "::1");
}

#[test]
fn test_secret_masker_redaction() {
    assert_eq!(
        SecretMasker::mask_env_var("OPENAI_API_KEY", "sk-proj-1234567890abcdef"),
        "sk-...[REDACTED]...def"
    );
    assert_eq!(
        SecretMasker::mask_env_var(
            "AWS_SECRET_ACCESS_KEY",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        ),
        "wJa...[REDACTED]...KEY"
    );
    assert_eq!(
        SecretMasker::mask_env_var("PUBLIC_PATH", "/usr/local/bin"),
        "/usr/local/bin"
    );

    // Command line flags and URL credentials
    let cmd = vec![
        "python".to_string(),
        "app.py".to_string(),
        "--api-key".to_string(),
        "sk-ant-mysecretkey".to_string(),
        "--db-uri".to_string(),
        "postgres://admin:topsecret@localhost:5432/app".to_string(),
    ];
    let masked = SecretMasker::mask_cmdline(&cmd);
    assert_eq!(masked[2], "--api-key");
    assert_eq!(masked[3], "sk-...[REDACTED]...key");
    assert_eq!(masked[5], "postgres://admin:[REDACTED]@localhost:5432/app");
}

#[test]
fn test_storage_audit_log_persists() {
    let storage = StorageManager::open_in_memory().expect("Must open in-memory db");
    let record = AuditRecord {
        timestamp: "2026-11-11T13:00:00Z".to_string(),
        pid: 7777,
        process_name: "vite".to_string(),
        agent_attribution: "Claude Code".to_string(),
        signal_sent: "SIGTERM".to_string(),
        success: true,
        note: Some("Terminated safely".to_string()),
    };

    storage
        .log_termination(&record)
        .expect("Must log termination");
    let recents = storage
        .get_recent_audits(5)
        .expect("Must get recent audits");
    assert_eq!(recents.len(), 1);
    assert_eq!(recents[0].pid, 7777);
    assert_eq!(recents[0].signal_sent, "SIGTERM");
}

#[test]
fn test_resource_monitoring_calculation() {
    let procs = vec![
        ProcessInfo {
            pid: 1,
            ppid: None,
            name: "test-agent".to_string(),
            exe: None,
            cpu_usage: Some(12.5),
            memory_bytes: Some(256 * 1024 * 1024),
            run_time_secs: 100,
            start_time: Some(100),
            user: None,
            attribution: AgentAttribution {
                kind: AgentKind::ClaudeCode,
                confidence: Confidence::Confirmed,
                reason: "Direct match".to_string(),
                evidence: "Binary match".to_string(),
                parent_pid: None,
                parent_name: None,
                root_agent_pid: Some(1),
                root_agent_name: Some("test-agent".to_string()),
                is_confirmed: true,
                safe_to_terminate: true,
            },
            listening_ports: vec![3000, 8080],
            cmdline: Vec::new(),
            command_outcome: None,
            provenance: None,
            ..Default::default()
        },
        ProcessInfo {
            pid: 2,
            ppid: None,
            name: "sys-daemon".to_string(),
            exe: None,
            cpu_usage: Some(2.0),
            memory_bytes: Some(50 * 1024 * 1024),
            run_time_secs: 200,
            start_time: Some(50),
            user: None,
            attribution: AgentAttribution::default(),
            listening_ports: vec![22],
            cmdline: Vec::new(),
            command_outcome: None,
            provenance: None,
            ..Default::default()
        },
    ];

    let summary = ResourceMonitor::calculate_summary(&procs);
    assert_eq!(summary.total_agent_processes, 1);
    assert_eq!(summary.total_agent_cpu_usage, 12.5);
    assert_eq!(summary.total_listening_ports, 2);
}

#[test]
fn test_engine_orchestrator_initialization() {
    let config = TimmyConfig::default();
    let storage = StorageManager::open_in_memory().ok().map(Arc::new);
    let orchestrator = EngineOrchestrator::new(config, storage);

    let snapshot = orchestrator
        .refresh_snapshot()
        .expect("Snapshot refresh must succeed");
    assert!(
        !snapshot.processes.is_empty(),
        "Processes should be discovered on system"
    );
}
