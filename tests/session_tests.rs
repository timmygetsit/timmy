use std::path::PathBuf;
use std::sync::Arc;
use timmy::config::TimmyConfig;
use timmy::engine::{SessionCoordinator, SessionError};
use timmy::model::agent::{AgentAttribution, AgentKind, Confidence};
use timmy::model::process::{ProcessAncestor, ProcessDetail, ProcessInfo};
use timmy::model::session::SessionStatus;
use timmy::model::{
    ContainerDetail, ContainerInfo, ContainerStats, DockerStatus, ListeningPort, Protocol,
    ServiceInfo, SocketState,
};
use timmy::platform::traits::{
    DockerCollector, PlatformError, PortCollector, ProcessCollector, ServiceCollector,
};
use timmy::storage::StorageManager;

/// Mock system collector for hermetic unit testing without relying on host system state.
struct MockSystemCollector {
    processes: Vec<ProcessInfo>,
    ports: Vec<ListeningPort>,
}

impl MockSystemCollector {
    fn new(processes: Vec<ProcessInfo>, ports: Vec<ListeningPort>) -> Self {
        Self { processes, ports }
    }
}

impl ProcessCollector for MockSystemCollector {
    fn collect_processes(&self) -> Result<Vec<ProcessInfo>, PlatformError> {
        Ok(self.processes.clone())
    }

    fn inspect_process(&self, pid: u32) -> Result<ProcessDetail, PlatformError> {
        let proc = self
            .processes
            .iter()
            .find(|p| p.pid == pid)
            .cloned()
            .ok_or(PlatformError::ProcessNotFound(pid))?;

        Ok(ProcessDetail {
            info: proc,
            cmdline: vec!["mock".to_string()],
            cwd: Some(PathBuf::from("/workspace")),
            environment: vec![],
            open_files: vec![],
            parent_chain: vec![ProcessAncestor {
                pid: 1,
                name: "launchd".to_string(),
                cmdline_summary: None,
            }],
        })
    }
}

impl PortCollector for MockSystemCollector {
    fn collect_listening_ports(&self) -> Result<Vec<ListeningPort>, PlatformError> {
        Ok(self.ports.clone())
    }
}

impl ServiceCollector for MockSystemCollector {
    fn collect_services(&self) -> Result<Vec<ServiceInfo>, PlatformError> {
        Ok(vec![])
    }
}

impl DockerCollector for MockSystemCollector {
    fn docker_status(&self) -> Result<DockerStatus, PlatformError> {
        Ok(DockerStatus {
            installed: false,
            running: false,
            socket_path: "/var/run/docker.sock".to_string(),
            api_version: None,
            engine_version: None,
            os: None,
            arch: None,
            active_context: None,
            error_message: Some("Mock collector has no Docker daemon".to_string()),
            error_category: Some(timmy::model::DockerErrorCategory::NotInstalled),
        })
    }

    fn is_available(&self) -> bool {
        false
    }

    fn collect_containers(&self) -> Result<Vec<ContainerInfo>, PlatformError> {
        Ok(vec![])
    }

    fn inspect_container(&self, id: &str) -> Result<ContainerDetail, PlatformError> {
        Err(PlatformError::ContainerNotFound(id.to_string()))
    }

    fn collect_container_stats(&self, id: &str) -> Result<ContainerStats, PlatformError> {
        Err(PlatformError::ContainerNotFound(id.to_string()))
    }
}

fn create_mock_proc(
    pid: u32,
    ppid: Option<u32>,
    name: &str,
    start_time: Option<u64>,
    ports: Vec<u16>,
    memory_bytes: u64,
) -> ProcessInfo {
    ProcessInfo {
        pid,
        ppid,
        name: name.to_string(),
        exe: Some(PathBuf::from(format!("/usr/local/bin/{}", name))),
        cpu_usage: Some(1.5),
        memory_bytes: Some(memory_bytes),
        run_time_secs: 60,
        start_time,
        user: Some("developer".to_string()),
        attribution: AgentAttribution::default(),
        listening_ports: ports,
        cmdline: Vec::new(),
        command_outcome: None,
        provenance: None,
        ..Default::default()
    }
}

#[test]
fn test_session_id_format() {
    let id1 = SessionCoordinator::generate_session_id();
    let id2 = SessionCoordinator::generate_session_id();

    assert!(id1.starts_with("sess-"));
    assert!(id2.starts_with("sess-"));
    assert_ne!(id1, id2);
}

#[test]
fn test_session_start_with_explicit_agent() {
    let storage = Arc::new(StorageManager::open_in_memory().expect("in-memory db"));
    let coord = SessionCoordinator::new(storage.clone(), TimmyConfig::default());

    let procs = vec![
        create_mock_proc(
            1001,
            Some(1),
            "claude",
            Some(1000),
            vec![],
            50 * 1024 * 1024,
        ),
        create_mock_proc(
            1002,
            Some(1001),
            "node",
            Some(1010),
            vec![3000],
            100 * 1024 * 1024,
        ),
    ];
    let ports = vec![ListeningPort {
        port: 3000,
        protocol: Protocol::Tcp,
        ip: "127.0.0.1".to_string(),
        pid: Some(1002),
        process_name: Some("node".to_string()),
        state: SocketState::Listen,
    }];
    let mock = MockSystemCollector::new(procs, ports);

    let session = coord
        .start_session(Some("claude".to_string()), false, &mock)
        .expect("must start session");

    assert_eq!(session.agent_kind, AgentKind::ClaudeCode);
    assert_eq!(session.confidence, Confidence::Confirmed);
    assert_eq!(session.status, SessionStatus::Active);
    assert_eq!(session.root_pid, Some(1001));
    assert_eq!(session.open_ports, vec![3000]);
    assert!(session.tracked_pids.contains(&1001));
    assert!(session.tracked_pids.contains(&1002));

    // Verify storage persistence
    let fetched = storage
        .get_session(&session.id)
        .expect("query session")
        .expect("session must exist");
    assert_eq!(fetched.id, session.id);
    assert_eq!(fetched.agent_kind, AgentKind::ClaudeCode);
}

#[test]
fn test_session_start_auto_detect_agent() {
    let storage = Arc::new(StorageManager::open_in_memory().expect("in-memory db"));
    let coord = SessionCoordinator::new(storage.clone(), TimmyConfig::default());

    let procs = vec![create_mock_proc(
        2001,
        Some(1),
        "cursor-server",
        Some(1000),
        vec![],
        80 * 1024 * 1024,
    )];
    let mock = MockSystemCollector::new(procs, vec![]);

    let session = coord
        .start_session(None, false, &mock)
        .expect("must auto-detect agent");

    assert_eq!(session.agent_kind, AgentKind::Cursor);
    assert_eq!(session.confidence, Confidence::HighConfidence);
    assert_eq!(session.root_pid, Some(2001));
}

#[test]
fn test_session_start_uncertain_when_no_agent_running() {
    let storage = Arc::new(StorageManager::open_in_memory().expect("in-memory db"));
    let coord = SessionCoordinator::new(storage.clone(), TimmyConfig::default());

    let procs = vec![create_mock_proc(
        3001,
        Some(1),
        "calculator",
        Some(1000),
        vec![],
        20 * 1024 * 1024,
    )];
    let mock = MockSystemCollector::new(procs, vec![]);

    let session = coord
        .start_session(None, false, &mock)
        .expect("must fallback to uncertain");

    assert_eq!(session.agent_kind, AgentKind::Unknown);
    assert_eq!(session.confidence, Confidence::Unknown);
    assert_eq!(session.root_pid, None);
    assert!(session.evidence[0].contains("Uncertain: No active AI agent detected"));
}

#[test]
fn test_active_session_already_exists_requires_replace_flag() {
    let storage = Arc::new(StorageManager::open_in_memory().expect("in-memory db"));
    let coord = SessionCoordinator::new(storage.clone(), TimmyConfig::default());

    let procs = vec![create_mock_proc(
        100,
        Some(1),
        "claude",
        Some(1000),
        vec![],
        50 * 1024 * 1024,
    )];
    let mock = MockSystemCollector::new(procs, vec![]);

    // 1. Start initial active session
    let s1 = coord
        .start_session(Some("claude".to_string()), false, &mock)
        .expect("start 1");
    assert_eq!(s1.status, SessionStatus::Active);

    // 2. Attempt starting second session without replace flag -> must fail safely!
    let err = coord
        .start_session(Some("cursor".to_string()), false, &mock)
        .unwrap_err();
    match err {
        SessionError::ActiveSessionAlreadyExists { id, .. } => {
            assert_eq!(id, s1.id);
        }
        other => panic!(
            "Expected ActiveSessionAlreadyExists error, got: {:?}",
            other
        ),
    }

    // 3. Start second session WITH replace flag -> succeeds and stops previous session!
    let s2 = coord
        .start_session(Some("cursor".to_string()), true, &mock)
        .expect("start with replace");
    assert_eq!(s2.status, SessionStatus::Active);

    let old_s1 = storage
        .get_session(&s1.id)
        .expect("query")
        .expect("s1 exists");
    assert_eq!(old_s1.status, SessionStatus::Stopped);
    assert!(old_s1.end_time.is_some());
}

#[test]
fn test_session_stop_preserves_processes_and_rejects_repeat_stop() {
    let storage = Arc::new(StorageManager::open_in_memory().expect("in-memory db"));
    let coord = SessionCoordinator::new(storage.clone(), TimmyConfig::default());

    let procs = vec![create_mock_proc(
        4001,
        Some(1),
        "claude",
        Some(1000),
        vec![],
        50 * 1024 * 1024,
    )];
    let mock = MockSystemCollector::new(procs, vec![]);

    let started = coord
        .start_session(Some("claude".to_string()), false, &mock)
        .expect("start");
    assert_eq!(started.status, SessionStatus::Active);

    let stopped = coord.stop_session(Some(&started.id)).expect("stop");
    assert_eq!(stopped.status, SessionStatus::Stopped);
    assert!(stopped.end_time.is_some());

    // Verify repeat stop on stopped session returns clean error
    let repeat_err = coord.stop_session(Some(&started.id)).unwrap_err();
    match repeat_err {
        SessionError::SessionAlreadyStopped(id) => assert_eq!(id, started.id),
        other => panic!("Expected SessionAlreadyStopped error, got: {:?}", other),
    }

    // Verify observation on stopped session is blocked
    let obs_err = coord.observe_and_update(&stopped, &mock).unwrap_err();
    match obs_err {
        SessionError::CannotObserveInactiveSession(id) => assert_eq!(id, started.id),
        other => panic!(
            "Expected CannotObserveInactiveSession error, got: {:?}",
            other
        ),
    }
}

#[test]
fn test_detached_process_previously_observed_vs_unobserved_orphan() {
    let storage = Arc::new(StorageManager::open_in_memory().expect("in-memory db"));
    let coord = SessionCoordinator::new(storage.clone(), TimmyConfig::default());

    let now_ts = chrono::Utc::now().timestamp() as u64;

    // Round 1: Claude (PID 500) has observed child Vite (PID 501, PPID 500)
    let procs_round1 = vec![
        create_mock_proc(
            500,
            Some(1),
            "claude",
            Some(now_ts.saturating_sub(10)),
            vec![],
            50 * 1024 * 1024,
        ),
        create_mock_proc(
            501,
            Some(500),
            "vite",
            Some(now_ts.saturating_sub(5)),
            vec![5173],
            60 * 1024 * 1024,
        ),
    ];
    let ports = vec![
        ListeningPort {
            port: 5173,
            protocol: Protocol::Tcp,
            ip: "127.0.0.1".to_string(),
            pid: Some(501),
            process_name: Some("vite".to_string()),
            state: SocketState::Listen,
        },
        ListeningPort {
            port: 8080,
            protocol: Protocol::Tcp,
            ip: "127.0.0.1".to_string(),
            pid: Some(502),
            process_name: Some("python3".to_string()),
            state: SocketState::Listen,
        },
    ];
    let mock_round1 = MockSystemCollector::new(procs_round1, ports.clone());

    let session = coord
        .start_session(Some("claude".to_string()), false, &mock_round1)
        .expect("start");
    assert_eq!(session.resource_count, 2);

    // Round 2: Claude (PID 500) exited!
    // PID 501 (Vite) was previously observed under Claude -> now under PID 1 (Detached, HighConfidence)
    // PID 502 (python3) was NEVER previously observed when Claude was running -> orphan under PID 1 (Inferred ONLY!)
    let procs_round2 = vec![
        create_mock_proc(
            501,
            Some(1),
            "vite",
            Some(now_ts.saturating_sub(5)),
            vec![5173],
            62 * 1024 * 1024,
        ),
        create_mock_proc(
            502,
            Some(1),
            "python3",
            Some(now_ts + 2),
            vec![8080],
            40 * 1024 * 1024,
        ),
    ];
    let mock_round2 = MockSystemCollector::new(procs_round2, ports);

    let (updated, resources) = coord
        .observe_and_update(&session, &mock_round2)
        .expect("observe round 2");

    assert_eq!(updated.resource_count, 2);

    let vite = resources
        .iter()
        .find(|r| r.pid == Some(501))
        .expect("vite resource");
    assert!(
        vite.is_detached,
        "Previously observed child must be flagged as DETACHED"
    );
    assert_eq!(
        vite.confidence,
        Confidence::HighConfidence,
        "Preserves high confidence from observed lineage"
    );
    assert!(
        vite.safe_to_terminate,
        "Verified detached dev worker is safe to terminate"
    );

    let orphan_python = resources
        .iter()
        .find(|r| r.pid == Some(502))
        .expect("orphan python");
    assert!(orphan_python.is_detached);
    assert_eq!(
        orphan_python.confidence,
        Confidence::Inferred,
        "Unobserved orphan under PID 1 must be strictly INFERRED"
    );
    assert!(
        !orphan_python.safe_to_terminate,
        "Inferred processes must default to safe_to_terminate = FALSE (fail-safe)"
    );
}

#[test]
fn test_pid_reuse_rejection() {
    let storage = Arc::new(StorageManager::open_in_memory().expect("in-memory db"));
    let coord = SessionCoordinator::new(storage.clone(), TimmyConfig::default());

    // Round 1: Claude has child worker (PID 600) started at timestamp 1000
    let procs_round1 = vec![
        create_mock_proc(599, Some(1), "claude", Some(990), vec![], 40 * 1024 * 1024),
        create_mock_proc(
            600,
            Some(599),
            "worker",
            Some(1000),
            vec![],
            20 * 1024 * 1024,
        ),
    ];
    let mock_round1 = MockSystemCollector::new(procs_round1, vec![]);

    let session = coord
        .start_session(Some("claude".to_string()), false, &mock_round1)
        .expect("start");

    // Round 2: Original PID 600 exited, and the OS recycled PID 600 for an unrelated process 'backup_tool' started at 2000
    let procs_round2 = vec![create_mock_proc(
        600,
        Some(1),
        "backup_tool",
        Some(2000),
        vec![],
        30 * 1024 * 1024,
    )];
    let mock_round2 = MockSystemCollector::new(procs_round2, vec![]);

    let (_, resources) = coord
        .observe_and_update(&session, &mock_round2)
        .expect("observe round 2");

    // PID 600 must NOT be attributed to the session because start time and binary changed
    assert!(
        resources.is_empty(),
        "Recycled PID with different start time must be rejected"
    );
}

#[test]
fn test_fail_safe_termination_defaults() {
    let storage = Arc::new(StorageManager::open_in_memory().expect("in-memory db"));
    let coord = SessionCoordinator::new(storage.clone(), TimmyConfig::default());

    // Agent root (PID 700), shell (PID 701), dev worker (PID 702)
    let procs = vec![
        create_mock_proc(700, Some(1), "claude", Some(1000), vec![], 50 * 1024 * 1024),
        create_mock_proc(701, Some(700), "zsh", Some(1001), vec![], 10 * 1024 * 1024),
        create_mock_proc(
            702,
            Some(701),
            "python3",
            Some(1005),
            vec![8000],
            45 * 1024 * 1024,
        ),
    ];
    let ports = vec![ListeningPort {
        port: 8000,
        protocol: Protocol::Tcp,
        ip: "0.0.0.0".to_string(),
        pid: Some(702),
        process_name: Some("python3".to_string()),
        state: SocketState::Listen,
    }];
    let mock = MockSystemCollector::new(procs, ports);

    let session = coord
        .start_session(Some("claude".to_string()), false, &mock)
        .expect("start");
    let (_, _, recs) = coord
        .inspect_session(Some(&session.id), &mock)
        .expect("inspect");

    // 1. Root agent process must NOT be safe to terminate
    let root_rec = recs
        .iter()
        .find(|r| r.resource_name == "claude")
        .expect("root rec");
    assert!(
        !root_rec.safe_to_terminate,
        "Root agent IDE must NOT be safe to terminate"
    );

    // 2. Interactive shell must NOT be safe to terminate
    let zsh_rec = recs
        .iter()
        .find(|r| r.resource_name == "zsh")
        .expect("zsh rec");
    assert!(
        !zsh_rec.safe_to_terminate,
        "Interactive shell must NOT be safe to terminate"
    );

    // 3. Worker process is safe to terminate
    let python_rec = recs
        .iter()
        .find(|r| r.resource_name == "python3")
        .expect("python rec");
    assert!(
        python_rec.safe_to_terminate,
        "High confidence dev worker must be safe to terminate"
    );
}

#[test]
fn test_resource_retention_and_pruning() {
    let storage = Arc::new(StorageManager::open_in_memory().expect("in-memory db"));

    // Record an active session
    let start_now = chrono::Utc::now();
    let sess1 = timmy::model::SessionInfo {
        id: "sess-active".to_string(),
        agent_kind: AgentKind::ClaudeCode,
        status: SessionStatus::Active,
        start_time: start_now,
        end_time: None,
        root_pid: Some(100),
        root_process_name: Some("claude".to_string()),
        confidence: Confidence::Confirmed,
        evidence: vec!["Active".to_string()],
        tracked_pids: vec![100],
        total_memory_bytes: 1024 * 1024,
        total_cpu_usage: 1.0,
        open_ports: vec![],
        resource_count: 1,
        root_binding: None,
    };
    storage.save_session(&sess1).expect("save sess1");

    // Record an old stopped session (30 days old)
    let start_old = start_now - chrono::Duration::days(30);
    let sess2 = timmy::model::SessionInfo {
        id: "sess-old".to_string(),
        agent_kind: AgentKind::Cursor,
        status: SessionStatus::Stopped,
        start_time: start_old,
        end_time: Some(start_old + chrono::Duration::hours(2)),
        root_pid: Some(200),
        root_process_name: Some("cursor".to_string()),
        confidence: Confidence::HighConfidence,
        evidence: vec!["Old".to_string()],
        tracked_pids: vec![200],
        total_memory_bytes: 1024 * 1024,
        total_cpu_usage: 1.0,
        open_ports: vec![],
        resource_count: 1,
        root_binding: None,
    };
    storage.save_session(&sess2).expect("save sess2");

    // Add snapshots
    for _ in 0..10 {
        storage
            .record_session_snapshot("sess-active", 1, 1024, 1.0, 0)
            .expect("snapshot");
    }

    // Prune with retention of 14 days and max snapshots of 5
    let deleted_count = storage.prune_history(14, 5).expect("prune");
    assert_eq!(deleted_count, 1, "Must delete 1 old stopped session");

    // Active session remains
    let active = storage.get_session("sess-active").expect("get sess1");
    assert!(active.is_some());

    // Old session was purged
    let old = storage.get_session("sess-old").expect("get sess2");
    assert!(old.is_none());
}

#[test]
fn test_session_listing_and_inspection() {
    let storage = Arc::new(StorageManager::open_in_memory().expect("in-memory db"));
    let coord = SessionCoordinator::new(storage.clone(), TimmyConfig::default());

    let procs1 = vec![create_mock_proc(
        101,
        Some(1),
        "claude",
        Some(1000),
        vec![],
        50 * 1024 * 1024,
    )];
    let mock1 = MockSystemCollector::new(procs1, vec![]);
    let sess1 = coord
        .start_session(Some("claude".to_string()), false, &mock1)
        .expect("start 1");

    let procs2 = vec![create_mock_proc(
        201,
        Some(1),
        "cursor",
        Some(2000),
        vec![],
        80 * 1024 * 1024,
    )];
    let mock2 = MockSystemCollector::new(procs2, vec![]);
    let sess2 = coord
        .start_session(Some("cursor".to_string()), true, &mock2)
        .expect("start 2 (replace)");

    let list = coord.list_sessions().expect("list");
    assert_eq!(list.len(), 2);
    // Ordered descending by start_time, so sess2 is first
    assert_eq!(list[0].id, sess2.id);
    assert_eq!(list[1].id, sess1.id);

    // Inspect sess1
    let (info1, resources1, _recs1) = coord
        .inspect_session(Some(&sess1.id), &mock1)
        .expect("inspect 1");
    assert_eq!(info1.id, sess1.id);
    assert_eq!(info1.agent_kind, AgentKind::ClaudeCode);
    assert_eq!(resources1.len(), 1);
    assert_eq!(resources1[0].name, "claude");
}

#[test]
fn test_database_migration_v1_to_v2_to_v3() {
    use rusqlite::Connection;
    let conn = Connection::open_in_memory().expect("sqlite memory");

    // Manually execute only MIGRATION_V1
    conn.execute_batch(timmy::storage::MIGRATION_V1)
        .expect("v1 execute");
    conn.execute_batch("PRAGMA user_version = 1;")
        .expect("set v1");

    // Insert an audit log record into V1 schema
    conn.execute(
        "INSERT INTO audit_log (timestamp, pid, process_name, agent_attribution, signal_sent, success, note)
         VALUES ('2026-11-11T10:00:00Z', 1234, 'node', 'Claude', 'SIGTERM', 1, 'OK')",
        [],
    ).expect("insert v1 audit");

    // Now execute MIGRATION_V2
    conn.execute_batch(timmy::storage::MIGRATION_V2)
        .expect("v2 execute");
    conn.execute_batch("PRAGMA user_version = 2;")
        .expect("set v2");

    // Insert a resource with confidence = 0 (Unknown) and safe_to_terminate = 1
    conn.execute(
        "INSERT INTO sessions (id, agent_kind, status, start_time, end_time, root_pid, root_process_name, confidence, evidence, created_at)
         VALUES ('sess-test', 'None', 'ACTIVE', '2026-11-11T12:00:00Z', NULL, NULL, NULL, 0, 'test', '2026-11-11T12:00:00Z')",
        [],
    ).expect("insert v2 session");

    conn.execute(
        "INSERT INTO session_resources (session_id, pid, name, confidence, evidence, is_detached, is_protected, safe_to_terminate, first_seen, last_seen)
         VALUES ('sess-test', 9999, 'unrelated', 0, 'none', 0, 0, 1, '2026-11-11T12:00:00Z', '2026-11-11T12:00:00Z')",
        [],
    ).expect("insert resource with unsafe default");

    // Now execute MIGRATION_V3 (Sanitizes unsafe defaults)
    conn.execute_batch(timmy::storage::MIGRATION_V3)
        .expect("v3 execute");
    conn.execute_batch("PRAGMA user_version = 3;")
        .expect("set v3");

    // Verify safe_to_terminate was flipped to 0 (fail-safe)
    let safe_val: i32 = conn
        .query_row(
            "SELECT safe_to_terminate FROM session_resources WHERE pid = 9999",
            [],
            |r| r.get(0),
        )
        .expect("query safe_to_terminate");
    assert_eq!(
        safe_val, 0,
        "MIGRATION_V3 must sanitize safe_to_terminate to 0"
    );
}

#[test]
fn test_real_child_process_tracking_and_safe_stop() {
    use std::process::Command;

    // Spawn a real benign OS process: sleep 30
    let mut child = Command::new("/bin/sleep")
        .arg("30")
        .spawn()
        .expect("Failed to spawn test child process");

    let child_pid = child.id();
    assert!(child_pid > 0);

    let storage = Arc::new(StorageManager::open_in_memory().expect("in-memory db"));
    let coord = SessionCoordinator::new(storage.clone(), TimmyConfig::default());

    // Create a mock platform that contains this real process
    let real_proc = ProcessInfo {
        pid: child_pid,
        ppid: Some(std::process::id()),
        name: "sleep".to_string(),
        exe: Some(PathBuf::from("/bin/sleep")),
        cpu_usage: Some(0.0),
        memory_bytes: Some(1024 * 512),
        run_time_secs: 1,
        start_time: Some(1000),
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: vec![],
        cmdline: Vec::new(),
        command_outcome: None,
        provenance: None,
        ..Default::default()
    };
    let mock = MockSystemCollector::new(vec![real_proc], vec![]);

    // Start tracking
    let session = coord
        .start_session(Some("claude".to_string()), false, &mock)
        .expect("start session");
    assert_eq!(session.status, SessionStatus::Active);

    // Stop tracking
    let stopped = coord.stop_session(Some(&session.id)).expect("stop session");
    assert_eq!(stopped.status, SessionStatus::Stopped);

    // CRUCIAL VERIFICATION: Process must STILL be alive after stopping session!
    // try_wait() returns Ok(None) if the child is still running
    let wait_res = child.try_wait().expect("try_wait on child");
    assert!(
        wait_res.is_none(),
        "Stopping session tracking must NEVER terminate processes!"
    );

    // Clean up test child process
    let _ = child.kill();
    let _ = child.wait();
}

/// Dynamic mock system collector allowing runtime mutation of process lists during tests.
struct DynamicSystemCollector {
    processes: Arc<std::sync::Mutex<Vec<ProcessInfo>>>,
    ports: Arc<std::sync::Mutex<Vec<ListeningPort>>>,
}

impl DynamicSystemCollector {
    fn new(processes: Vec<ProcessInfo>, ports: Vec<ListeningPort>) -> Self {
        Self {
            processes: Arc::new(std::sync::Mutex::new(processes)),
            ports: Arc::new(std::sync::Mutex::new(ports)),
        }
    }

    fn set_processes(&self, procs: Vec<ProcessInfo>) {
        *self.processes.lock().unwrap() = procs;
    }

    #[allow(dead_code)]
    fn set_ports(&self, ports: Vec<ListeningPort>) {
        *self.ports.lock().unwrap() = ports;
    }
}

impl ProcessCollector for DynamicSystemCollector {
    fn collect_processes(&self) -> Result<Vec<ProcessInfo>, PlatformError> {
        Ok(self.processes.lock().unwrap().clone())
    }

    fn inspect_process(&self, pid: u32) -> Result<ProcessDetail, PlatformError> {
        let procs = self.processes.lock().unwrap();
        let proc = procs
            .iter()
            .find(|p| p.pid == pid)
            .cloned()
            .ok_or(PlatformError::ProcessNotFound(pid))?;

        Ok(ProcessDetail {
            info: proc,
            cmdline: vec!["mock".to_string()],
            cwd: Some(PathBuf::from("/workspace")),
            environment: vec![],
            open_files: vec![],
            parent_chain: vec![],
        })
    }
}

impl PortCollector for DynamicSystemCollector {
    fn collect_listening_ports(&self) -> Result<Vec<ListeningPort>, PlatformError> {
        Ok(self.ports.lock().unwrap().clone())
    }
}

impl ServiceCollector for DynamicSystemCollector {
    fn collect_services(&self) -> Result<Vec<ServiceInfo>, PlatformError> {
        Ok(vec![])
    }
}

impl DockerCollector for DynamicSystemCollector {
    fn docker_status(&self) -> Result<DockerStatus, PlatformError> {
        Ok(DockerStatus {
            installed: false,
            running: false,
            socket_path: "/var/run/docker.sock".to_string(),
            api_version: None,
            engine_version: None,
            os: None,
            arch: None,
            active_context: None,
            error_message: Some("Dynamic collector has no Docker daemon".to_string()),
            error_category: Some(timmy::model::DockerErrorCategory::NotInstalled),
        })
    }

    fn is_available(&self) -> bool {
        false
    }

    fn collect_containers(&self) -> Result<Vec<ContainerInfo>, PlatformError> {
        Ok(vec![])
    }

    fn inspect_container(&self, id: &str) -> Result<ContainerDetail, PlatformError> {
        Err(PlatformError::ContainerNotFound(id.to_string()))
    }

    fn collect_container_stats(&self, id: &str) -> Result<ContainerStats, PlatformError> {
        Err(PlatformError::ContainerNotFound(id.to_string()))
    }
}

#[test]
fn test_session_identity_separated_from_process_ownership() {
    let storage = Arc::new(StorageManager::open_in_memory().expect("in-memory db"));
    let coord = SessionCoordinator::new(storage.clone(), TimmyConfig::default());

    // Scenario A: User declares --agent claude, but only unrelated processes exist on host
    let procs_a = vec![
        create_mock_proc(
            901,
            Some(1),
            "postgres",
            Some(100),
            vec![5432],
            100 * 1024 * 1024,
        ),
        create_mock_proc(902, Some(1), "zsh", Some(200), vec![], 20 * 1024 * 1024),
    ];
    let mock_a = MockSystemCollector::new(procs_a, vec![]);

    let session_a = coord
        .start_session(Some("claude".to_string()), false, &mock_a)
        .expect("start session");

    // 1. Declared session identity is confirmed as ClaudeCode
    assert_eq!(session_a.agent_kind, AgentKind::ClaudeCode);
    assert_eq!(session_a.confidence, Confidence::Confirmed);
    // 2. But root_pid is None because no process independently verifies Claude!
    assert_eq!(session_a.root_pid, None);
    // 3. Unrelated processes (postgres, zsh) are NOT promoted to Confirmed or attributed
    assert_eq!(session_a.resource_count, 0);
    assert_eq!(session_a.tracked_pids.len(), 0);

    // Scenario B: User declares --agent claude, and authentic Claude process IS running
    let procs_b = vec![
        create_mock_proc(950, Some(1), "claude", Some(1000), vec![], 80 * 1024 * 1024),
        create_mock_proc(
            951,
            Some(1),
            "redis-server",
            Some(500),
            vec![6379],
            30 * 1024 * 1024,
        ),
    ];
    let mock_b = MockSystemCollector::new(procs_b, vec![]);

    let session_b = coord
        .start_session(Some("claude".to_string()), true, &mock_b)
        .expect("start session replace");

    // Authentic Claude process was independently verified by AttributionEngine
    assert_eq!(session_b.root_pid, Some(950));
    assert_eq!(session_b.root_process_name.as_deref(), Some("claude"));
    // Claude process itself has Confirmed ownership
    let (_sess_info, resources) = coord
        .get_session_resources(Some(&session_b.id), &mock_b)
        .expect("res");
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0].pid, Some(950));
    assert_eq!(resources[0].confidence, Confidence::Confirmed);
    // Redis-server (unrelated, started before session) is NOT tracked or promoted!
    assert!(!resources.iter().any(|r| r.pid == Some(951)));
}

#[test]
fn test_attribution_vs_termination_eligibility_vs_user_authorization() {
    let storage = Arc::new(StorageManager::open_in_memory().expect("in-memory db"));
    let coord = SessionCoordinator::new(storage.clone(), TimmyConfig::default());
    let now_ts = chrono::Utc::now().timestamp() as u64;

    // Session with root Claude (PID 1000), child Vite (PID 1001), child interactive shell zsh (PID 1002),
    // and unobserved orphan under PID 1 (PID 1003)
    let procs = vec![
        create_mock_proc(
            1000,
            Some(1),
            "claude",
            Some(now_ts),
            vec![],
            50 * 1024 * 1024,
        ),
        create_mock_proc(
            1001,
            Some(1000),
            "vite",
            Some(now_ts + 1),
            vec![5173],
            60 * 1024 * 1024,
        ),
        create_mock_proc(
            1002,
            Some(1000),
            "zsh",
            Some(now_ts + 2),
            vec![],
            15 * 1024 * 1024,
        ),
        create_mock_proc(
            1003,
            Some(1),
            "python3",
            Some(now_ts + 3),
            vec![8000],
            40 * 1024 * 1024,
        ),
    ];
    let ports = vec![
        ListeningPort {
            port: 5173,
            protocol: Protocol::Tcp,
            ip: "127.0.0.1".to_string(),
            pid: Some(1001),
            process_name: Some("vite".to_string()),
            state: SocketState::Listen,
        },
        ListeningPort {
            port: 8000,
            protocol: Protocol::Tcp,
            ip: "127.0.0.1".to_string(),
            pid: Some(1003),
            process_name: Some("python3".to_string()),
            state: SocketState::Listen,
        },
    ];
    let mock = MockSystemCollector::new(procs, ports);

    let session = coord
        .start_session(Some("claude".to_string()), false, &mock)
        .expect("start");

    let (_, _resources, recs) = coord
        .inspect_session(Some(&session.id), &mock)
        .expect("inspect");

    // Case 1: Vite dev server
    let vite = recs.iter().find(|r| r.pid_or_id == "1001").expect("vite");
    assert_eq!(
        vite.ownership_confidence,
        Confidence::HighConfidence,
        "Vite is HighConfidence child"
    );
    assert!(
        vite.termination_eligible,
        "Vite dev worker is termination eligible"
    );
    assert!(
        !vite.user_authorized,
        "User authorization MUST be false (never inferred)"
    );
    assert!(vite.eligibility_reason.contains("Eligible"));

    // Case 2: Interactive shell child (zsh)
    let shell = recs.iter().find(|r| r.pid_or_id == "1002").expect("zsh");
    assert_eq!(
        shell.ownership_confidence,
        Confidence::HighConfidence,
        "Shell is HighConfidence child"
    );
    assert!(
        !shell.termination_eligible,
        "Interactive shell is NOT eligible for termination"
    );
    assert!(shell.is_protected, "Interactive shell must be protected");
    assert!(!shell.user_authorized, "User authorization MUST be false");
    assert!(shell
        .eligibility_reason
        .contains("Interactive developer shell"));

    // Case 3: Unobserved orphan (python3 under PID 1)
    let orphan = recs
        .iter()
        .find(|r| r.pid_or_id == "1003")
        .expect("python3");
    assert_eq!(
        orphan.ownership_confidence,
        Confidence::Inferred,
        "Unobserved orphan is Inferred"
    );
    assert!(
        !orphan.termination_eligible,
        "Inferred process fails closed: NOT eligible"
    );
    assert!(!orphan.user_authorized, "User authorization MUST be false");
    assert!(orphan.eligibility_reason.contains("Fail-Closed"));
}

#[test]
fn test_watcher_concurrency_and_session_replacement() {
    let storage = Arc::new(StorageManager::open_in_memory().expect("in-memory db"));
    let coord = Arc::new(SessionCoordinator::new(
        storage.clone(),
        TimmyConfig::default(),
    ));

    // 1. Start Session A
    let procs_a = vec![create_mock_proc(
        100,
        Some(1),
        "claude",
        Some(1000),
        vec![],
        50 * 1024 * 1024,
    )];
    let collector = Arc::new(DynamicSystemCollector::new(procs_a, vec![]));
    let sess_a = coord
        .start_session(Some("claude".to_string()), false, collector.as_ref())
        .expect("start session A");
    assert_eq!(sess_a.status, SessionStatus::Active);

    // 2. Start foreground watcher for Session A in a background thread
    let stop_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let coord_clone = coord.clone();
    let sess_a_id = sess_a.id.clone();
    let collector_clone = collector.clone();
    let stop_flag_clone = stop_flag.clone();

    let watcher_handle = std::thread::spawn(move || {
        coord_clone.watch_session(
            &sess_a_id,
            std::time::Duration::from_millis(50),
            stop_flag_clone,
            collector_clone.as_ref(),
            |_sess, _res| {},
        )
    });

    // Give watcher time to perform at least 1 observation cycle
    std::thread::sleep(std::time::Duration::from_millis(150));

    // Record Session A snapshot count before replacement
    let initial_snaps_a = storage.get_session_snapshots(&sess_a.id).expect("snaps a");
    assert!(!initial_snaps_a.is_empty());

    // 3. Start Session B using --replace!
    let procs_b = vec![create_mock_proc(
        200,
        Some(1),
        "cursor",
        Some(2000),
        vec![],
        60 * 1024 * 1024,
    )];
    collector.set_processes(procs_b);

    let sess_b = coord
        .start_session(Some("cursor".to_string()), true, collector.as_ref())
        .expect("start session B with replace");
    assert_eq!(sess_b.status, SessionStatus::Active);

    // 4. Observe that Session A's watcher detects status change and cleanly exits!
    let watcher_res = watcher_handle.join().expect("watcher thread join");
    assert!(
        watcher_res.is_ok(),
        "Watcher must exit cleanly when session is replaced"
    );
    let final_sess_a = watcher_res.unwrap();
    assert_eq!(final_sess_a.status, SessionStatus::Stopped);

    // 5. Verify that Session A is no longer modified
    let snaps_a_after = storage
        .get_session_snapshots(&sess_a.id)
        .expect("snaps a after");
    assert_eq!(
        initial_snaps_a.len(),
        snaps_a_after.len(),
        "Session A must NOT receive additional snapshots after being stopped!"
    );

    // 6. Verify that Session B receives only its own observations
    let (sess_b_info, res_b) = coord
        .get_session_resources(Some(&sess_b.id), collector.as_ref())
        .expect("sess b resources");
    assert_eq!(sess_b_info.agent_kind, AgentKind::Cursor);
    assert_eq!(res_b.len(), 1);
    assert_eq!(res_b[0].pid, Some(200));

    // 7. Verify that Session A's historical records remain intact
    let hist_a = storage
        .get_session(&sess_a.id)
        .expect("query")
        .expect("exists");
    assert_eq!(hist_a.status, SessionStatus::Stopped);
    assert_eq!(hist_a.agent_kind, AgentKind::ClaudeCode);
    assert!(hist_a.end_time.is_some());

    stop_flag.store(true, std::sync::atomic::Ordering::SeqCst);
}

#[test]
fn test_e2e_foreground_watch_with_controlled_child_processes() {
    use std::process::Command;

    // 1. Create a session using a controlled test root agent process fixture
    let mut root_proc = Command::new("/bin/sleep")
        .arg("60")
        .spawn()
        .expect("spawn root test process");
    let root_pid = root_proc.id();

    // Also spawn child 1, child 2, and unrelated process
    let mut child1 = Command::new("/bin/sleep")
        .arg("60")
        .spawn()
        .expect("spawn child1");
    let child1_pid = child1.id();

    let mut child2 = Command::new("/bin/sleep")
        .arg("60")
        .spawn()
        .expect("spawn child2");
    let child2_pid = child2.id();

    let mut unrelated = Command::new("/bin/sleep")
        .arg("60")
        .spawn()
        .expect("spawn unrelated");
    let unrelated_pid = unrelated.id();

    let storage = Arc::new(StorageManager::open_in_memory().expect("in-memory db"));
    let coord = Arc::new(SessionCoordinator::new(
        storage.clone(),
        TimmyConfig::default(),
    ));

    let now_ts = chrono::Utc::now().timestamp() as u64;

    // Start with root agent process
    let initial_procs = vec![
        create_mock_proc(
            root_pid,
            Some(1),
            "claude",
            Some(now_ts),
            vec![],
            50 * 1024 * 1024,
        ),
        create_mock_proc(
            unrelated_pid,
            Some(1),
            "sleep",
            Some(now_ts - 10),
            vec![],
            10 * 1024 * 1024,
        ),
    ];
    let collector = Arc::new(DynamicSystemCollector::new(initial_procs, vec![]));

    let session = coord
        .start_session(Some("claude".to_string()), false, collector.as_ref())
        .expect("start session");
    assert_eq!(session.root_pid, Some(root_pid));

    // 2. Start foreground monitoring loop in a background thread
    let stop_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let coord_clone = coord.clone();
    let sess_id = session.id.clone();
    let collector_clone = collector.clone();
    let stop_flag_clone = stop_flag.clone();

    let watch_handle = std::thread::spawn(move || {
        coord_clone.watch_session(
            &sess_id,
            std::time::Duration::from_millis(50),
            stop_flag_clone,
            collector_clone.as_ref(),
            |_s, _r| {},
        )
    });

    // 3. Spawn known child process under root
    // 4. Allow TIMMY to observe it
    std::thread::sleep(std::time::Duration::from_millis(100));
    collector.set_processes(vec![
        create_mock_proc(
            root_pid,
            Some(1),
            "claude",
            Some(now_ts),
            vec![],
            50 * 1024 * 1024,
        ),
        create_mock_proc(
            child1_pid,
            Some(root_pid),
            "node",
            Some(now_ts + 1),
            vec![3000],
            60 * 1024 * 1024,
        ),
        create_mock_proc(
            unrelated_pid,
            Some(1),
            "sleep",
            Some(now_ts - 10),
            vec![],
            10 * 1024 * 1024,
        ),
    ]);
    std::thread::sleep(std::time::Duration::from_millis(150));

    // 5. Spawn second process from that child
    // 6. Allow TIMMY to observe the second process
    collector.set_processes(vec![
        create_mock_proc(
            root_pid,
            Some(1),
            "claude",
            Some(now_ts),
            vec![],
            50 * 1024 * 1024,
        ),
        create_mock_proc(
            child1_pid,
            Some(root_pid),
            "node",
            Some(now_ts + 1),
            vec![3000],
            60 * 1024 * 1024,
        ),
        create_mock_proc(
            child2_pid,
            Some(child1_pid),
            "vite",
            Some(now_ts + 2),
            vec![5173],
            40 * 1024 * 1024,
        ),
        create_mock_proc(
            unrelated_pid,
            Some(1),
            "sleep",
            Some(now_ts - 10),
            vec![],
            10 * 1024 * 1024,
        ),
    ]);
    std::thread::sleep(std::time::Duration::from_millis(150));

    // 7. Terminate original parent process
    let _ = root_proc.kill();
    let _ = root_proc.wait();

    // 8. Surviving child processes re-parent to PID 1
    // Watcher observes that surviving children retain previously recorded attribution evidence (detached!)
    collector.set_processes(vec![
        create_mock_proc(
            child1_pid,
            Some(1),
            "node",
            Some(now_ts + 1),
            vec![3000],
            60 * 1024 * 1024,
        ),
        create_mock_proc(
            child2_pid,
            Some(child1_pid),
            "vite",
            Some(now_ts + 2),
            vec![5173],
            40 * 1024 * 1024,
        ),
        create_mock_proc(
            unrelated_pid,
            Some(1),
            "sleep",
            Some(now_ts - 10),
            vec![],
            10 * 1024 * 1024,
        ),
    ]);
    std::thread::sleep(std::time::Duration::from_millis(200));

    // 10. Stop monitoring loop cleanly
    stop_flag.store(true, std::sync::atomic::Ordering::SeqCst);
    let watch_res = watch_handle.join().expect("join watch handle");
    assert!(watch_res.is_ok(), "Watch loop must exit cleanly");

    // 11. Inspect the session from a separate TIMMY invocation
    let separate_coord = SessionCoordinator::new(storage.clone(), TimmyConfig::default());
    let (_inspected_sess, inspected_res, _recs) = separate_coord
        .inspect_session(Some(&session.id), collector.as_ref())
        .expect("inspect session");

    // 8 & 9. Verify surviving children retained with attribution evidence, unrelated NOT attributed
    assert!(inspected_res
        .iter()
        .any(|r| r.pid == Some(child1_pid) && r.is_detached));
    assert!(inspected_res.iter().any(|r| r.pid == Some(child2_pid)));
    assert!(
        !inspected_res.iter().any(|r| r.pid == Some(unrelated_pid)),
        "Unrelated process must NOT be attributed!"
    );

    // 12. Verify persisted resource records and final timestamps
    let snapshots = storage
        .get_session_snapshots(&session.id)
        .expect("snapshots");
    assert!(
        snapshots.len() >= 2,
        "Must have recorded multiple snapshots during watch"
    );

    // 13. Verify that NO tracked process was terminated by the monitoring workflow
    assert!(
        child1.try_wait().expect("try_wait child1").is_none(),
        "child1 must still be running!"
    );
    assert!(
        child2.try_wait().expect("try_wait child2").is_none(),
        "child2 must still be running!"
    );
    assert!(
        unrelated.try_wait().expect("try_wait unrelated").is_none(),
        "unrelated must still be running!"
    );

    // Cleanup all test child processes
    let _ = child1.kill();
    let _ = child1.wait();
    let _ = child2.kill();
    let _ = child2.wait();
    let _ = unrelated.kill();
    let _ = unrelated.wait();
}
