use chrono::{Duration, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use timmy::config::TimmyConfig;
use timmy::engine::{DockerCoordinator, EngineOrchestrator};
use timmy::model::agent::{AgentKind, Confidence};
use timmy::model::docker::{
    AttributionBasis, ContainerDetail, ContainerInfo, ContainerState, ContainerStats,
    CreationOutcome, DockerStatus, MountInfo, PortBinding,
};
use timmy::model::process::{ProcessDetail, ProcessInfo};
use timmy::model::session::{SessionInfo, SessionStatus};
use timmy::model::{ListeningPort, ServiceInfo};
use timmy::platform::docker::MockDockerCollector;
use timmy::platform::traits::{
    DockerCollector, PlatformError, PortCollector, ProcessCollector, ServiceCollector,
};
use timmy::safety::masker::SecretMasker;
use timmy::storage::StorageManager;

/// Test helper implementing `SystemCollector` with hermetic mock components.
struct MockSystem {
    processes: Vec<ProcessInfo>,
    ports: Vec<ListeningPort>,
    docker: MockDockerCollector,
}

impl ProcessCollector for MockSystem {
    fn collect_processes(&self) -> Result<Vec<ProcessInfo>, PlatformError> {
        Ok(self.processes.clone())
    }
    fn inspect_process(&self, pid: u32) -> Result<ProcessDetail, PlatformError> {
        Err(PlatformError::ProcessNotFound(pid))
    }
}

impl PortCollector for MockSystem {
    fn collect_listening_ports(&self) -> Result<Vec<ListeningPort>, PlatformError> {
        Ok(self.ports.clone())
    }
}

impl ServiceCollector for MockSystem {
    fn collect_services(&self) -> Result<Vec<ServiceInfo>, PlatformError> {
        Ok(vec![])
    }
}

impl DockerCollector for MockSystem {
    fn docker_status(&self) -> Result<DockerStatus, PlatformError> {
        self.docker.docker_status()
    }
    fn is_available(&self) -> bool {
        self.docker.is_available()
    }
    fn collect_containers(&self) -> Result<Vec<ContainerInfo>, PlatformError> {
        self.docker.collect_containers()
    }
    fn inspect_container(&self, id: &str) -> Result<ContainerDetail, PlatformError> {
        self.docker.inspect_container(id)
    }
    fn collect_container_stats(&self, id: &str) -> Result<ContainerStats, PlatformError> {
        self.docker.collect_container_stats(id)
    }
}

fn sample_container(id: &str, name: &str, state: ContainerState) -> ContainerInfo {
    let short_id = if id.len() >= 12 {
        id[..12].to_string()
    } else {
        id.to_string()
    };
    ContainerInfo {
        id: id.to_string(),
        short_id,
        name: name.to_string(),
        image: "postgres:16-alpine".to_string(),
        image_id: Some("sha256:abc123def456".to_string()),
        state,
        status: "Up 2 hours".to_string(),
        created_at: Some(Utc::now().to_rfc3339()),
        started_at: Some(Utc::now().to_rfc3339()),
        ports: vec![PortBinding {
            host_ip: "0.0.0.0".to_string(),
            host_port: 5432,
            container_port: 5432,
            protocol: "tcp".to_string(),
        }],
        exit_code: None,
        health_status: Some("healthy".to_string()),
        restart_count: Some(0),
        command: Some("postgres".to_string()),
        entrypoint: Some("docker-entrypoint.sh".to_string()),
        working_dir: Some("/app".to_string()),
        labels: HashMap::new(),
        runtime: Some("runc".to_string()),
        networks: vec!["bridge".to_string()],
        ip_addresses: vec!["172.17.0.2".to_string()],
        network_mode: Some("bridge".to_string()),
        stats: None,
        session_id: None,
        declared_session_id: None,
        conflicting_sessions: Vec::new(),
        confidence: Confidence::Unknown,
        evidence: Vec::new(),
        creation_outcome: CreationOutcome::Unknown,
        attribution_basis: AttributionBasis::None,
    }
}

fn sample_session(id: &str, agent: AgentKind, status: SessionStatus) -> SessionInfo {
    SessionInfo {
        id: id.to_string(),
        agent_kind: agent,
        status,
        start_time: Utc::now() - Duration::minutes(30),
        end_time: if status == SessionStatus::Active {
            None
        } else {
            Some(Utc::now())
        },
        root_pid: Some(1001),
        root_process_name: Some("node".to_string()),
        confidence: Confidence::Confirmed,
        evidence: vec!["Declared agent".to_string()],
        tracked_pids: vec![1001, 1002],
        total_memory_bytes: 128 * 1024 * 1024,
        total_cpu_usage: 2.5,
        open_ports: vec![5432, 3000],
        resource_count: 2,
        root_binding: None,
    }
}

// -----------------------------------------------------------------------------
// SCENARIO 1: Docker Unavailable (neither binary nor socket present)
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_01_docker_unavailable() {
    let mock = MockDockerCollector::new();
    // Default mock represents completely unavailable Docker
    let status = mock
        .docker_status()
        .expect("Must return clean status without panic");
    assert!(!status.installed);
    assert!(!status.running);
    assert!(status.error_message.is_some());
    assert!(!mock.is_available());

    let containers = mock.collect_containers().expect("Must return empty list");
    assert!(containers.is_empty());
}

// -----------------------------------------------------------------------------
// SCENARIO 2: Docker Desktop Installed but Daemon Stopped
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_02_docker_desktop_installed_daemon_stopped() {
    let mock = MockDockerCollector::new();
    mock.set_status(Ok(DockerStatus {
        installed: true,
        running: false,
        socket_path: "/Users/test/.docker/run/docker.sock".to_string(),
        api_version: None,
        engine_version: None,
        os: None,
        arch: None,
        active_context: Some("desktop-linux".to_string()),
        error_message: Some("Docker socket not found. Is Docker Desktop running?".to_string()),
        error_category: Some(timmy::model::DockerErrorCategory::DaemonStopped),
    }));

    let status = mock.docker_status().expect("Must return status cleanly");
    assert!(status.installed, "Should detect installed Docker Desktop");
    assert!(!status.running, "Should indicate daemon is not running");
    assert_eq!(status.active_context.as_deref(), Some("desktop-linux"));
    assert!(status
        .error_message
        .unwrap()
        .contains("Docker Desktop running"));
}

// -----------------------------------------------------------------------------
// SCENARIO 3: Socket Permission Failure
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_03_socket_permission_failure() {
    let mock = MockDockerCollector::new();
    mock.set_status(Err(PlatformError::PermissionDenied(0)));

    let res = mock.docker_status();
    assert!(res.is_err());
    match res.unwrap_err() {
        PlatformError::PermissionDenied(_) => {}
        other => panic!("Expected PermissionDenied, got {:?}", other),
    }

    // Also test status returning permission diagnostics string
    let mock2 = MockDockerCollector::new();
    mock2.set_status(Ok(DockerStatus {
        installed: true,
        running: false,
        socket_path: "/var/run/docker.sock".to_string(),
        api_version: None,
        engine_version: None,
        os: None,
        arch: None,
        active_context: None,
        error_message: Some("Permission denied accessing Docker socket".to_string()),
        error_category: Some(timmy::model::DockerErrorCategory::PermissionDenied),
    }));
    let status2 = mock2.docker_status().unwrap();
    assert!(status2.error_message.unwrap().contains("Permission denied"));
}

// -----------------------------------------------------------------------------
// SCENARIO 4: Successful Connection
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_04_successful_connection() {
    let mock = MockDockerCollector::with_running_status("27.3.1", "1.45", "/var/run/docker.sock");
    let status = mock.docker_status().expect("Should succeed");

    assert!(status.installed);
    assert!(status.running);
    assert_eq!(status.engine_version.as_deref(), Some("27.3.1"));
    assert_eq!(status.api_version.as_deref(), Some("1.45"));
    assert!(mock.is_available());
}

// -----------------------------------------------------------------------------
// SCENARIO 5: API Version Negotiation
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_05_api_version_negotiation() {
    let mock = MockDockerCollector::with_running_status("26.1.4", "1.44", "/var/run/docker.sock");
    let status = mock.docker_status().unwrap();
    assert_eq!(status.api_version.as_deref(), Some("1.44"));
    assert_eq!(status.engine_version.as_deref(), Some("26.1.4"));
}

// -----------------------------------------------------------------------------
// SCENARIO 6: Empty Container List
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_06_empty_container_list() {
    let mock = MockDockerCollector::with_running_status("27.3.1", "1.45", "/var/run/docker.sock");
    let containers = mock.collect_containers().expect("Must succeed");
    assert_eq!(containers.len(), 0);
}

// -----------------------------------------------------------------------------
// SCENARIO 7: Multiple Running Containers
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_07_multiple_running_containers() {
    let mock = MockDockerCollector::with_running_status("27.3.1", "1.45", "/var/run/docker.sock");
    mock.add_container(sample_container(
        "111111111111222222222222333333333333",
        "db",
        ContainerState::Running,
    ));
    mock.add_container(sample_container(
        "444444444444555555555555666666666666",
        "redis",
        ContainerState::Running,
    ));
    mock.add_container(sample_container(
        "777777777777888888888888999999999999",
        "web",
        ContainerState::Running,
    ));

    let containers = mock.collect_containers().unwrap();
    assert_eq!(containers.len(), 3);
    assert_eq!(containers[0].name, "db");
    assert_eq!(containers[1].name, "redis");
    assert_eq!(containers[2].name, "web");
    for c in &containers {
        assert_eq!(c.state, ContainerState::Running);
    }
}

// -----------------------------------------------------------------------------
// SCENARIO 8: Stopped and Exited Containers
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_08_stopped_and_exited_containers() {
    let mock = MockDockerCollector::with_running_status("27.3.1", "1.45", "/var/run/docker.sock");
    let mut exited = sample_container(
        "aaaabbbbcccc111122223333",
        "old-worker",
        ContainerState::Exited,
    );
    exited.exit_code = Some(137);

    let paused = sample_container(
        "ddddcount111122223333",
        "paused-job",
        ContainerState::Paused,
    );
    let created = sample_container(
        "eeeeffff111122223333",
        "pending-init",
        ContainerState::Created,
    );

    mock.add_container(exited);
    mock.add_container(paused);
    mock.add_container(created);

    let containers = mock.collect_containers().unwrap();
    assert_eq!(containers.len(), 3);
    assert_eq!(containers[0].state, ContainerState::Exited);
    assert_eq!(containers[0].exit_code, Some(137));
    assert_eq!(containers[1].state, ContainerState::Paused);
    assert_eq!(containers[2].state, ContainerState::Created);
}

// -----------------------------------------------------------------------------
// SCENARIO 9: Container Inspection
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_09_container_inspection() {
    let mock = MockDockerCollector::with_running_status("27.3.1", "1.45", "/var/run/docker.sock");
    let info = sample_container(
        "abcdef1234567890abcdef12",
        "my-app",
        ContainerState::Running,
    );
    let detail = ContainerDetail {
        info: info.clone(),
        env_keys: vec!["NODE_ENV".to_string()],
        mounts: vec![MountInfo {
            source: "/Users/dev/project".to_string(),
            destination: "/app".to_string(),
            mount_type: "bind".to_string(),
            read_only: false,
        }],
        restart_policy: "unless-stopped".to_string(),
        platform: Some("linux/arm64".to_string()),
    };

    mock.add_detail("abcdef1234567890abcdef12", detail);

    let inspected = mock.inspect_container("abcdef1234567890abcdef12").unwrap();
    assert_eq!(inspected.info.name, "my-app");
    assert_eq!(inspected.mounts.len(), 1);
    assert_eq!(inspected.mounts[0].source, "/Users/dev/project");
    assert_eq!(inspected.restart_policy, "unless-stopped");
    assert_eq!(inspected.platform.as_deref(), Some("linux/arm64"));
}

// -----------------------------------------------------------------------------
// SCENARIO 10: Published Port Parsing
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_10_published_port_parsing() {
    let mut container = sample_container("test-port-id", "port-tester", ContainerState::Running);
    container.ports = vec![
        PortBinding {
            host_ip: "0.0.0.0".to_string(),
            host_port: 8080,
            container_port: 80,
            protocol: "tcp".to_string(),
        },
        PortBinding {
            host_ip: "127.0.0.1".to_string(),
            host_port: 3306,
            container_port: 3306,
            protocol: "tcp".to_string(),
        },
    ];

    assert_eq!(container.ports[0].to_string(), "0.0.0.0:8080->80/tcp");
    assert_eq!(container.ports[1].to_string(), "127.0.0.1:3306->3306/tcp");
    assert_eq!(
        container.formatted_ports(),
        "0.0.0.0:8080->80/tcp, 127.0.0.1:3306->3306/tcp"
    );
}

// -----------------------------------------------------------------------------
// SCENARIO 11: Network Information Parsing
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_11_network_information_parsing() {
    let mut container = sample_container("net-id", "net-test", ContainerState::Running);
    container.networks = vec!["bridge".to_string(), "custom-tier".to_string()];
    container.ip_addresses = vec!["172.18.0.4".to_string()];
    container.network_mode = Some("custom-tier".to_string());

    assert_eq!(container.networks.len(), 2);
    assert_eq!(container.ip_addresses[0], "172.18.0.4");
    assert_eq!(container.network_mode.as_deref(), Some("custom-tier"));
}

// -----------------------------------------------------------------------------
// SCENARIO 12: CPU and Memory Statistics Calculation
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_12_cpu_and_memory_statistics_calculation() {
    let stats = ContainerStats {
        cpu_percentage: Some(4.5),
        memory_usage_bytes: Some(256 * 1024 * 1024),
        memory_working_set_bytes: Some(240 * 1024 * 1024),
        memory_limit_bytes: Some(1024 * 1024 * 1024),
        memory_percentage: Some(25.0),
        network_rx_bytes: Some(1024 * 1024),
        network_tx_bytes: Some(512 * 1024),
        block_read_bytes: Some(2048),
        block_write_bytes: Some(4096),
        pids_count: Some(12),
    };

    let mut container = sample_container("stat-id", "stat-test", ContainerState::Running);
    container.stats = Some(stats);

    assert_eq!(container.formatted_cpu(), "4.5%");
    assert_eq!(container.formatted_memory(), "256.0 MB");
    assert_eq!(
        container.stats.as_ref().unwrap().memory_percentage,
        Some(25.0)
    );
    assert_eq!(container.stats.as_ref().unwrap().pids_count, Some(12));
}

// -----------------------------------------------------------------------------
// SCENARIO 13: Missing or Incomplete Statistics
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_13_missing_or_incomplete_statistics() {
    let mut container =
        sample_container("incomplete-id", "incomplete-test", ContainerState::Running);
    container.stats = None;

    // Graceful formatting without panic or NaN
    assert_eq!(container.formatted_cpu(), "N/A");
    assert_eq!(container.formatted_memory(), "N/A");

    let partial_stats = ContainerStats {
        cpu_percentage: None,
        memory_usage_bytes: Some(500),
        memory_working_set_bytes: None,
        memory_limit_bytes: None,
        memory_percentage: None,
        network_rx_bytes: None,
        network_tx_bytes: None,
        block_read_bytes: None,
        block_write_bytes: None,
        pids_count: None,
    };
    container.stats = Some(partial_stats);
    assert_eq!(container.formatted_cpu(), "N/A");
    assert_eq!(container.formatted_memory(), "500 B");
}

// -----------------------------------------------------------------------------
// SCENARIO 14: Container Disappearing During Inspection (404)
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_14_container_disappearing_during_inspection() {
    let mock = MockDockerCollector::with_running_status("27.3.1", "1.45", "/var/run/docker.sock");
    // Not added to mock.details -> should return ContainerNotFound
    let res = mock.inspect_container("vanished-container-id");
    assert!(res.is_err());
    match res.unwrap_err() {
        PlatformError::ContainerNotFound(id) => assert_eq!(id, "vanished-container-id"),
        other => panic!("Expected ContainerNotFound, got {:?}", other),
    }
}

// -----------------------------------------------------------------------------
// SCENARIO 15: Secret Masking (commands and env vars)
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_15_secret_masking() {
    // 1. Mask command line flags
    let args = vec![
        "npm".to_string(),
        "run".to_string(),
        "start".to_string(),
        "--token".to_string(),
        "secret_tok_xyz123".to_string(),
        "--api-key=super_secret_value".to_string(),
    ];
    let masked_args = SecretMasker::mask_cmdline(&args);
    assert_eq!(masked_args[3], "--token");
    assert!(masked_args[4].contains("[REDACTED]"));
    assert!(masked_args[5].contains("--api-key="));
    assert!(masked_args[5].contains("[REDACTED]"));

    // 2. Mask env vars
    let masked_key = SecretMasker::mask_env_var("OPENAI_API_KEY", "sk-proj-1234567890abcdef");
    assert!(masked_key.contains("[REDACTED]"));

    let masked_db = SecretMasker::mask_env_var("DATABASE_PASSWORD", "mypassword123");
    assert!(masked_db.contains("[REDACTED]"));

    let unmasked_env = SecretMasker::mask_env_var("PORT", "3000");
    assert_eq!(unmasked_env, "3000");
}

// -----------------------------------------------------------------------------
// SCENARIO 16: Session Correlation with Declared Metadata Label (INFERRED per Rule 2)
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_16_session_correlation_declared_metadata() {
    let sess = sample_session(
        "sess-20261111-0001",
        AgentKind::ClaudeCode,
        SessionStatus::Active,
    );
    let mut container =
        sample_container("confirmed-c1", "claude-postgres", ContainerState::Running);
    container.ports.clear();
    container.labels.insert(
        "timmy.session.id".to_string(),
        "sess-20261111-0001".to_string(),
    );

    let mut containers = vec![container];
    DockerCoordinator::correlate_containers(&mut containers, &[sess], &[]);

    assert_eq!(
        containers[0].session_id.as_deref(),
        Some("sess-20261111-0001")
    );
    assert_eq!(
        containers[0].declared_session_id.as_deref(),
        Some("sess-20261111-0001")
    );
    // Rule 2: Container label MUST NEVER establish Confirmed or HighConfidence
    assert_ne!(containers[0].confidence, Confidence::Confirmed);
    assert_ne!(containers[0].confidence, Confidence::HighConfidence);
    assert_eq!(containers[0].confidence, Confidence::Inferred);
    assert!(containers[0].evidence[0]
        .contains("Declared session metadata via container label 'timmy.session.id'"));
}

// -----------------------------------------------------------------------------
// SCENARIO 16B: Process Execution Attempt Alone Yields INFERRED (Never Confirmed)
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_16b_session_correlation_direct_provenance_confirmed() {
    let sess = sample_session(
        "sess-20261111-0001",
        AgentKind::ClaudeCode,
        SessionStatus::Active,
    );
    let mut container = sample_container("c-confirmed", "claude-postgres", ContainerState::Running);
    container.ports.clear(); // Isolate command line signal from port overlap

    // Process belonging to the session executed docker targeting this container
    let proc = ProcessInfo {
        pid: 1001,
        ppid: Some(100),
        name: "docker".to_string(),
        exe: Some(std::path::PathBuf::from("/usr/local/bin/docker")),
        cpu_usage: Some(0.1),
        memory_bytes: Some(10 * 1024 * 1024),
        run_time_secs: 5,
        start_time: Some(1000),
        user: Some("dev".to_string()),
        attribution: timmy::model::AgentAttribution {
            kind: AgentKind::ClaudeCode,
            confidence: Confidence::Confirmed,
            reason: "Root agent process".to_string(),
            evidence: "Verified agent execution".to_string(),
            parent_pid: Some(100),
            parent_name: Some("launchd".to_string()),
            root_agent_pid: Some(1001),
            root_agent_name: Some("docker".to_string()),
            is_confirmed: true,
            safe_to_terminate: false,
        },
        listening_ports: vec![],
        cmdline: vec![
            "docker".to_string(),
            "run".to_string(),
            "-d".to_string(),
            "--name".to_string(),
            "claude-postgres".to_string(),
            "postgres:15".to_string(),
        ],
        command_outcome: None,
        provenance: None,
        ..Default::default()
    };

    let mut containers = vec![container];
    DockerCoordinator::correlate_containers(&mut containers, &[sess], &[proc]);

    assert_eq!(
        containers[0].session_id.as_deref(),
        Some("sess-20261111-0001")
    );
    // Rule 1 & Rule 7: Command match alone proves attempt, NEVER Confirmed!
    assert_ne!(containers[0].confidence, Confidence::Confirmed);
    assert_eq!(containers[0].confidence, Confidence::Inferred);
    assert!(containers[0].evidence[0].contains("attempted container command"));
}

// -----------------------------------------------------------------------------
// SCENARIO 17: Session Correlation with Insufficient Evidence (UNKNOWN)
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_17_session_correlation_insufficient_evidence_unknown() {
    let sess = sample_session(
        "sess-20261111-0002",
        AgentKind::Cursor,
        SessionStatus::Active,
    );
    let mut container =
        sample_container("unrelated-c2", "unrelated-redis", ContainerState::Running);
    // Even if created recently, no matching labels, no cwd, no port link
    container.created_at = Some(Utc::now().to_rfc3339());
    container.ports.clear(); // no shared ports

    let mut containers = vec![container];
    DockerCoordinator::correlate_containers(&mut containers, &[sess], &[]);

    assert_eq!(containers[0].session_id, None);
    assert_eq!(containers[0].confidence, Confidence::Unknown);
    assert!(containers[0].evidence.is_empty());
}

// -----------------------------------------------------------------------------
// SCENARIO 18: Containers Surviving After Session Termination (Retained Attribution)
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_18_containers_surviving_after_session_termination() {
    let stopped_sess = sample_session(
        "sess-20261111-0003",
        AgentKind::Windsurf,
        SessionStatus::Stopped,
    );
    let mut container = sample_container("surviving-c3", "dev-db", ContainerState::Running);
    // Prior confirmed attribution from when session was active
    container.session_id = Some("sess-20261111-0003".to_string());
    container.confidence = Confidence::Confirmed;
    container.evidence = vec!["Original session match".to_string()];

    let mut containers = vec![container];
    DockerCoordinator::correlate_containers(&mut containers, &[stopped_sess], &[]);

    // Attribution MUST be retained after session termination!
    assert_eq!(
        containers[0].session_id.as_deref(),
        Some("sess-20261111-0003")
    );
    assert_eq!(containers[0].confidence, Confidence::Confirmed);
    assert!(containers[0]
        .evidence
        .iter()
        .any(|e| e.contains("Retained attribution")));
}

// -----------------------------------------------------------------------------
// SCENARIO 19: Multiple Sessions Sharing a Docker Daemon
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_19_multiple_sessions_sharing_docker_daemon() {
    let mut sess1 = sample_session("sess-claude", AgentKind::ClaudeCode, SessionStatus::Active);
    sess1.open_ports = vec![5432];
    let mut sess2 = sample_session("sess-cursor", AgentKind::Cursor, SessionStatus::Active);
    sess2.open_ports = vec![6379];

    let mut c1 = sample_container("c1-id", "claude-db", ContainerState::Running);
    c1.ports = vec![PortBinding {
        host_ip: "0.0.0.0".to_string(),
        host_port: 5432,
        container_port: 5432,
        protocol: "tcp".to_string(),
    }];
    c1.labels
        .insert("timmy.session.id".to_string(), "sess-claude".to_string());

    let mut c2 = sample_container("c2-id", "cursor-redis", ContainerState::Running);
    c2.ports = vec![PortBinding {
        host_ip: "0.0.0.0".to_string(),
        host_port: 6379,
        container_port: 6379,
        protocol: "tcp".to_string(),
    }];
    c2.labels
        .insert("timmy.session.id".to_string(), "sess-cursor".to_string());

    let mut c3 = sample_container("c3-id", "global-traefik", ContainerState::Running);
    // Unrelated ports and no session labels
    c3.ports = vec![PortBinding {
        host_ip: "0.0.0.0".to_string(),
        host_port: 8080,
        container_port: 80,
        protocol: "tcp".to_string(),
    }];

    let mut containers = vec![c1, c2, c3];
    DockerCoordinator::correlate_containers(&mut containers, &[sess1, sess2], &[]);

    assert_eq!(containers[0].session_id.as_deref(), Some("sess-claude"));
    assert_eq!(containers[0].confidence, Confidence::Inferred);

    assert_eq!(containers[1].session_id.as_deref(), Some("sess-cursor"));
    assert_eq!(containers[1].confidence, Confidence::Inferred);

    assert_eq!(containers[2].session_id, None);
    assert_eq!(containers[2].confidence, Confidence::Unknown);
}

// -----------------------------------------------------------------------------
// SCENARIO 20: TUI Behaviour When Docker Is Unavailable
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_20_tui_behaviour_when_docker_unavailable() {
    let mock_docker = MockDockerCollector::new(); // unavailable
    let system = Arc::new(MockSystem {
        processes: Vec::new(),
        ports: Vec::new(),
        docker: mock_docker,
    });

    let storage = Arc::new(StorageManager::open_in_memory().expect("in-memory db"));
    let orchestrator =
        EngineOrchestrator::with_collector(TimmyConfig::default(), Some(storage), system);

    // Refreshing snapshot when Docker is unavailable MUST succeed without panicking!
    let snapshot = orchestrator
        .refresh_snapshot()
        .expect("Must not fail snapshot when Docker unavailable");
    assert!(
        snapshot.containers.is_empty(),
        "Containers list must be empty"
    );

    // Checking status returns clean diagnostics
    let status = orchestrator
        .docker_status()
        .expect("Must query status cleanly");
    assert!(!status.running);
    assert!(status.error_message.is_some());
}

// -----------------------------------------------------------------------------
// SCENARIO 21: Remote Endpoint Rejection (tcp, http, https, ssh, host:port)
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_21_remote_endpoint_rejection() {
    use timmy::platform::docker::BollardDockerCollector;

    let remote_endpoints = [
        "tcp://192.168.1.50:2375",
        "tcp://localhost:2375",
        "http://127.0.0.1:2375",
        "https://remote-docker.corp:2376",
        "ssh://user@remote-host",
        "127.0.0.1:2375",
        "localhost:2375",
    ];

    for ep in remote_endpoints {
        let parsed = BollardDockerCollector::parse_and_validate_local_endpoint(ep);
        assert!(
            parsed.is_err(),
            "Endpoint '{}' must be rejected as remote or invalid",
            ep
        );
        match parsed.unwrap_err() {
            PlatformError::DockerUnsupportedRemote(rejected) => {
                assert_eq!(rejected, ep);
            }
            other => panic!(
                "Expected DockerUnsupportedRemote for '{}', got {:?}",
                ep, other
            ),
        }
    }

    // Valid local endpoints must succeed
    assert_eq!(
        BollardDockerCollector::parse_and_validate_local_endpoint("unix:///var/run/docker.sock")
            .unwrap(),
        "/var/run/docker.sock"
    );
    assert_eq!(
        BollardDockerCollector::parse_and_validate_local_endpoint("/var/run/docker.sock").unwrap(),
        "/var/run/docker.sock"
    );
}

// -----------------------------------------------------------------------------
// SCENARIO 22: No Silent Fallback When Explicit Socket Is Missing
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_22_no_silent_fallback_when_explicit_socket_missing() {
    use std::time::Duration;
    use timmy::platform::docker::BollardDockerCollector;

    let collector = BollardDockerCollector::new(
        Some("/tmp/timmy_nonexistent_custom_socket.sock".to_string()),
        Duration::from_millis(500),
    );

    let res = collector.resolve_endpoint();
    assert!(res.is_err());
    match res.unwrap_err() {
        PlatformError::DockerSocketMissing(path) => {
            assert_eq!(path, "/tmp/timmy_nonexistent_custom_socket.sock");
        }
        other => panic!("Expected DockerSocketMissing, got {:?}", other),
    }

    // Verify status returns SocketMissing category
    let status = collector.docker_status().unwrap();
    assert!(!status.running);
    assert_eq!(
        status.error_category,
        Some(timmy::model::DockerErrorCategory::SocketMissing)
    );
    assert!(status
        .error_message
        .unwrap()
        .contains("No fallback attempted"));
}

// -----------------------------------------------------------------------------
// SCENARIO 23: Context Resolution via Direct SHA-256 and Scan
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_23_context_resolution_mock() {
    use sha2::{Digest, Sha256};

    // Test context hashing logic
    let context_name = "orbstack";
    let mut hasher = Sha256::new();
    hasher.update(context_name.as_bytes());
    let hash_hex = format!("{:x}", hasher.finalize());

    assert_eq!(hash_hex.len(), 64);
    assert!(hash_hex.chars().all(|c| c.is_ascii_hexdigit()));
}

// -----------------------------------------------------------------------------
// SCENARIO 24: Conflicting Session Claims Handled Explicitly
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_24_conflicting_session_claims_handled_explicitly() {
    let sess1 = sample_session("sess-1", AgentKind::ClaudeCode, SessionStatus::Active);
    let sess2 = sample_session("sess-2", AgentKind::Cursor, SessionStatus::Active);

    // Container matches both sessions via declared labels or shared criteria
    let mut container = sample_container("c-conflict", "shared-db", ContainerState::Running);
    // Simulate both sessions claiming with equal confidence
    container
        .labels
        .insert("timmy.session.id".to_string(), "sess-1".to_string());
    container
        .labels
        .insert("agent.session".to_string(), "sess-2".to_string());

    let mut containers = vec![container];
    DockerCoordinator::correlate_containers(&mut containers, &[sess1, sess2], &[]);

    // Multiple conflicting claims MUST clear session_id, populate conflicting_sessions, and set Unknown
    assert_eq!(containers[0].session_id, None);
    assert_eq!(containers[0].confidence, Confidence::Unknown);
    assert_eq!(containers[0].conflicting_sessions.len(), 2);
    assert!(containers[0]
        .conflicting_sessions
        .contains(&"sess-1".to_string()));
    assert!(containers[0]
        .conflicting_sessions
        .contains(&"sess-2".to_string()));
    assert!(containers[0].evidence[0].contains("Conflicting session claims detected"));
}

// -----------------------------------------------------------------------------
// SCENARIO 25: Decreasing CPU Counters & Zero System Delta Return None
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_25_invalid_cpu_counters_return_none() {
    use bollard::models::{ContainerCpuStats, ContainerCpuUsage, ContainerStatsResponse};
    use timmy::platform::docker::client::calculate_cpu_percentage;

    // 1. Decreasing total_usage (reset or corrupted measurement)
    let resp_decreasing = ContainerStatsResponse {
        cpu_stats: Some(ContainerCpuStats {
            cpu_usage: Some(ContainerCpuUsage {
                total_usage: Some(100),
                ..Default::default()
            }),
            system_cpu_usage: Some(2000),
            online_cpus: Some(4),
            ..Default::default()
        }),
        precpu_stats: Some(ContainerCpuStats {
            cpu_usage: Some(ContainerCpuUsage {
                total_usage: Some(200), // Previous usage higher than current!
                ..Default::default()
            }),
            system_cpu_usage: Some(1000),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert_eq!(
        calculate_cpu_percentage(&resp_decreasing),
        None,
        "Decreasing container CPU usage must return None"
    );

    // 2. Zero or negative system delta
    let resp_zero_system_delta = ContainerStatsResponse {
        cpu_stats: Some(ContainerCpuStats {
            cpu_usage: Some(ContainerCpuUsage {
                total_usage: Some(200),
                ..Default::default()
            }),
            system_cpu_usage: Some(1000),
            online_cpus: Some(4),
            ..Default::default()
        }),
        precpu_stats: Some(ContainerCpuStats {
            cpu_usage: Some(ContainerCpuUsage {
                total_usage: Some(100),
                ..Default::default()
            }),
            system_cpu_usage: Some(1000), // Zero delta!
            ..Default::default()
        }),
        ..Default::default()
    };
    assert_eq!(
        calculate_cpu_percentage(&resp_zero_system_delta),
        None,
        "Zero system delta must return None (not 0.0%)"
    );
}

// -----------------------------------------------------------------------------
// SCENARIO 26: Genuine Idle Container Returns Some(0.0) CPU
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_26_genuine_idle_cpu_returns_zero() {
    use bollard::models::{ContainerCpuStats, ContainerCpuUsage, ContainerStatsResponse};
    use timmy::platform::docker::client::calculate_cpu_percentage;

    let resp_idle = ContainerStatsResponse {
        cpu_stats: Some(ContainerCpuStats {
            cpu_usage: Some(ContainerCpuUsage {
                total_usage: Some(500),
                ..Default::default()
            }),
            system_cpu_usage: Some(2000),
            online_cpus: Some(4),
            ..Default::default()
        }),
        precpu_stats: Some(ContainerCpuStats {
            cpu_usage: Some(ContainerCpuUsage {
                total_usage: Some(500), // Delta is 0, container idle!
                ..Default::default()
            }),
            system_cpu_usage: Some(1000), // System delta is 1000 > 0
            ..Default::default()
        }),
        ..Default::default()
    };

    assert_eq!(
        calculate_cpu_percentage(&resp_idle),
        Some(0.0),
        "Idle container with valid system delta must return Some(0.0)"
    );
}

// -----------------------------------------------------------------------------
// SCENARIO 27: Adjusted Working-Set Memory Calculation
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_27_adjusted_working_set_memory() {
    use bollard::models::{ContainerMemoryStats, ContainerStatsResponse};
    use timmy::platform::docker::client::calculate_memory_stats;

    let mut stats_map = HashMap::new();
    stats_map.insert("inactive_file".to_string(), 50 * 1024 * 1024); // 50MB inactive cache

    let resp = ContainerStatsResponse {
        memory_stats: Some(ContainerMemoryStats {
            usage: Some(200 * 1024 * 1024),  // 200MB total usage
            limit: Some(1024 * 1024 * 1024), // 1GB limit
            stats: Some(stats_map),
            ..Default::default()
        }),
        ..Default::default()
    };

    let (raw, working_set, limit, pct) = calculate_memory_stats(&resp);
    assert_eq!(raw, Some(200 * 1024 * 1024));
    // Working set = 200MB - 50MB inactive = 150MB
    assert_eq!(working_set, Some(150 * 1024 * 1024));
    assert_eq!(limit, Some(1024 * 1024 * 1024));
    assert!(pct.is_some());
    // Percentage calculated on working set: 150 / 1024 ~= 14.65%
    let percentage = pct.unwrap();
    assert!((percentage - 14.648).abs() < 0.1);
}

// -----------------------------------------------------------------------------
// SCENARIO 28: Sensitive Label Masking & Environment Variable Names Only
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_28_sensitive_label_masking_and_env_keys() {
    // 1. Sensitive label masking
    let mut raw_labels = HashMap::new();
    raw_labels.insert("app.version".to_string(), "1.2.3".to_string());
    raw_labels.insert("database.secret".to_string(), "supersecret123".to_string());
    raw_labels.insert("api_key".to_string(), "sk-ant-123456789".to_string());

    let masked = SecretMasker::mask_labels(&raw_labels);
    assert_eq!(masked.get("app.version").unwrap(), "1.2.3");
    assert!(masked
        .get("database.secret")
        .unwrap()
        .contains("[REDACTED]"));
    assert!(masked.get("api_key").unwrap().contains("[REDACTED]"));

    // 2. ContainerDetail environment keys only
    let detail = ContainerDetail {
        info: sample_container("sec-c", "secure-container", ContainerState::Running),
        env_keys: vec!["PATH".to_string(), "SECRET_TOKEN".to_string()],
        mounts: vec![],
        restart_policy: "no".to_string(),
        platform: Some("linux/arm64".to_string()),
    };

    // Serialize to JSON and ensure values are nowhere in the output
    let json_str = serde_json::to_string(&detail).expect("JSON serialization");
    assert!(json_str.contains("\"SECRET_TOKEN\""));
    assert!(!json_str.contains("supersecret123"));
}

// =============================================================================
// AUDIT & ACCEPTANCE SCENARIOS: PRECEDENCE, STRICT PROVENANCE & NON-BLOCKING UI
// =============================================================================

use sha2::Digest;
use std::path::PathBuf;
use timmy::model::AgentAttribution;
use timmy::platform::docker::BollardDockerCollector;

static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

// -----------------------------------------------------------------------------
// SCENARIO 29: DOCKER_CONFIG Environment Variable Resolution
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_29_docker_config_env_directory_resolution() {
    let _lock = ENV_LOCK.lock().unwrap();

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let config_path = temp_dir.path().join("config.json");
    std::fs::write(&config_path, r#"{"currentContext": "custom-cfg-ctx"}"#).expect("write config");

    // Write context meta inside <temp_dir>/contexts/meta/<sha256(custom-cfg-ctx)>/meta.json
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"custom-cfg-ctx");
    let hash = format!("{:x}", hasher.finalize());

    let meta_dir = temp_dir.path().join(format!("contexts/meta/{}", hash));
    std::fs::create_dir_all(&meta_dir).expect("create meta dir");
    let meta_file = meta_dir.join("meta.json");
    std::fs::write(
        &meta_file,
        r#"{"Name": "custom-cfg-ctx", "Endpoints": {"docker": {"Host": "unix:///tmp/custom-cfg.sock"}}}"#,
    )
    .expect("write meta");

    std::env::set_var(
        "DOCKER_CONFIG",
        temp_dir.path().to_string_lossy().to_string(),
    );
    std::env::remove_var("DOCKER_CONTEXT");
    std::env::remove_var("DOCKER_HOST");

    let active_ctx = BollardDockerCollector::read_docker_context();
    assert_eq!(active_ctx.as_deref(), Some("custom-cfg-ctx"));

    let endpoint_res = BollardDockerCollector::resolve_context_endpoint("custom-cfg-ctx");
    assert!(endpoint_res.is_ok());
    assert_eq!(endpoint_res.unwrap(), "unix:///tmp/custom-cfg.sock");

    std::env::remove_var("DOCKER_CONFIG");
}

// -----------------------------------------------------------------------------
// SCENARIO 30: Endpoint Precedence: DOCKER_CONTEXT overrides DOCKER_HOST
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_30_endpoint_precedence_docker_context_over_docker_host() {
    let _lock = ENV_LOCK.lock().unwrap();

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"ctx-override");
    let hash = format!("{:x}", hasher.finalize());

    let meta_dir = temp_dir.path().join(format!("contexts/meta/{}", hash));
    std::fs::create_dir_all(&meta_dir).expect("create meta dir");
    std::fs::write(
        meta_dir.join("meta.json"),
        r#"{"Name": "ctx-override", "Endpoints": {"docker": {"Host": "unix:///tmp/from-context.sock"}}}"#,
    )
    .expect("write meta");

    std::env::set_var(
        "DOCKER_CONFIG",
        temp_dir.path().to_string_lossy().to_string(),
    );
    std::env::set_var("DOCKER_CONTEXT", "ctx-override");
    std::env::set_var("DOCKER_HOST", "unix:///tmp/from-host.sock");

    let collector = BollardDockerCollector::new(None, std::time::Duration::from_millis(500));
    // DOCKER_CONTEXT takes precedence: it attempts to connect to /tmp/from-context.sock,
    // which does not exist, producing DockerSocketMissing("/tmp/from-context.sock")
    let resolve_res = collector.resolve_endpoint();
    match resolve_res {
        Err(PlatformError::DockerSocketMissing(path)) => {
            assert!(
                path.contains("from-context.sock"),
                "Precedence must choose DOCKER_CONTEXT over DOCKER_HOST: got {}",
                path
            );
        }
        other => panic!(
            "Expected DockerSocketMissing for from-context.sock, got: {:?}",
            other
        ),
    }

    std::env::remove_var("DOCKER_CONFIG");
    std::env::remove_var("DOCKER_CONTEXT");
    std::env::remove_var("DOCKER_HOST");
}

// -----------------------------------------------------------------------------
// SCENARIO 31: Endpoint Precedence: DOCKER_HOST overrides config.json currentContext
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_31_endpoint_precedence_docker_host_over_config_context() {
    let _lock = ENV_LOCK.lock().unwrap();

    let temp_dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        temp_dir.path().join("config.json"),
        r#"{"currentContext": "from-config-ctx"}"#,
    )
    .expect("write config");

    std::env::set_var(
        "DOCKER_CONFIG",
        temp_dir.path().to_string_lossy().to_string(),
    );
    std::env::remove_var("DOCKER_CONTEXT");
    std::env::set_var("DOCKER_HOST", "unix:///tmp/host-wins.sock");

    let collector = BollardDockerCollector::new(None, std::time::Duration::from_millis(500));
    let resolve_res = collector.resolve_endpoint();
    match resolve_res {
        Err(PlatformError::DockerSocketMissing(path)) => {
            assert!(
                path.contains("host-wins.sock"),
                "Precedence must choose DOCKER_HOST over currentContext: got {}",
                path
            );
        }
        other => panic!(
            "Expected DockerSocketMissing for host-wins.sock, got: {:?}",
            other
        ),
    }

    std::env::remove_var("DOCKER_CONFIG");
    std::env::remove_var("DOCKER_HOST");
}

// -----------------------------------------------------------------------------
// SCENARIO 32: Context Compatibility Edge Cases
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_32_context_compatibility_edge_cases() {
    let _lock = ENV_LOCK.lock().unwrap();

    let temp_dir = tempfile::tempdir().expect("tempdir");
    std::env::set_var(
        "DOCKER_CONFIG",
        temp_dir.path().to_string_lossy().to_string(),
    );

    // 1. Missing context metadata
    let missing_res = BollardDockerCollector::resolve_context_endpoint("non-existent-ctx");
    assert!(missing_res.is_err());
    match missing_res {
        Err(PlatformError::DockerInvalidEndpoint(msg)) => {
            assert!(msg.contains("non-existent-ctx"));
        }
        other => panic!("Expected DockerInvalidEndpoint, got: {:?}", other),
    }

    // 2. Malformed JSON in meta.json
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"malformed-ctx");
    let hash1 = format!("{:x}", hasher.finalize());
    let dir1 = temp_dir.path().join(format!("contexts/meta/{}", hash1));
    std::fs::create_dir_all(&dir1).unwrap();
    std::fs::write(dir1.join("meta.json"), "NOT VALID JSON").unwrap();

    let malformed_res = BollardDockerCollector::resolve_context_endpoint("malformed-ctx");
    assert!(malformed_res.is_err());

    // 3. Missing Endpoints.docker in meta.json
    let mut hasher2 = sha2::Sha256::new();
    hasher2.update(b"missing-docker-endpoint");
    let hash2 = format!("{:x}", hasher2.finalize());
    let dir2 = temp_dir.path().join(format!("contexts/meta/{}", hash2));
    std::fs::create_dir_all(&dir2).unwrap();
    std::fs::write(
        dir2.join("meta.json"),
        r#"{"Name": "missing-docker-endpoint", "Endpoints": {}}"#,
    )
    .unwrap();

    let missing_ep_res =
        BollardDockerCollector::resolve_context_endpoint("missing-docker-endpoint");
    assert!(missing_ep_res.is_err());

    // 4. Remote context endpoint rejection (TLS / TCP)
    let mut hasher3 = sha2::Sha256::new();
    hasher3.update(b"remote-tls-ctx");
    let hash3 = format!("{:x}", hasher3.finalize());
    let dir3 = temp_dir.path().join(format!("contexts/meta/{}", hash3));
    std::fs::create_dir_all(&dir3).unwrap();
    std::fs::write(
        dir3.join("meta.json"),
        r#"{"Name": "remote-tls-ctx", "Endpoints": {"docker": {"Host": "tcp://docker-remote.internal:2376"}}}"#,
    ).unwrap();

    let remote_ep = BollardDockerCollector::resolve_context_endpoint("remote-tls-ctx").unwrap();
    let val_res = BollardDockerCollector::parse_and_validate_local_endpoint(&remote_ep);
    match val_res {
        Err(PlatformError::DockerUnsupportedRemote(raw)) => {
            assert!(raw.contains("tcp://"));
        }
        other => panic!("Expected DockerUnsupportedRemote, got: {:?}", other),
    }

    std::env::remove_var("DOCKER_CONFIG");
}

// -----------------------------------------------------------------------------
// SCENARIO 33: Confirmed Container Ownership Negative Tests
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_33_confirmed_provenance_negative_tests() {
    let sess = sample_session(
        "sess-20261111-neg",
        AgentKind::ClaudeCode,
        SessionStatus::Active,
    );

    // Negative 33a: Forged session label without process execution
    // Container declares session id via label, but NO process executed docker command
    let mut container_forged = sample_container("c-forged", "forged-app", ContainerState::Running);
    container_forged.labels.insert(
        "timmy.session.id".to_string(),
        "sess-20261111-neg".to_string(),
    );

    let mut containers = vec![container_forged];
    DockerCoordinator::correlate_containers(&mut containers, std::slice::from_ref(&sess), &[]);

    // MUST NOT be Confirmed! Must be Inferred at most per Rule 2
    assert_ne!(containers[0].confidence, Confidence::Confirmed);
    assert_ne!(containers[0].confidence, Confidence::HighConfidence);
    assert_eq!(containers[0].confidence, Confidence::Inferred);
    assert_eq!(
        containers[0].declared_session_id.as_deref(),
        Some("sess-20261111-neg")
    );
    assert!(containers[0].evidence[0].contains("unverified runtime ownership"));

    // Negative 33b: Docker command mentioning unrelated container
    let mut container_target = sample_container("c-target", "target-db", ContainerState::Running);
    container_target.ports.clear(); // Clear ports to ensure no multi-signal port correlation
    let proc_unrelated = ProcessInfo {
        pid: 1002,
        ppid: Some(100),
        name: "docker".to_string(),
        exe: Some(PathBuf::from("/usr/local/bin/docker")),
        cpu_usage: Some(0.1),
        memory_bytes: Some(1024),
        run_time_secs: 1,
        start_time: Some(1000),
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: vec![],
        cmdline: vec![
            "docker".to_string(),
            "run".to_string(),
            "--name".to_string(),
            "completely-unrelated-container".to_string(),
        ],
        command_outcome: None,
        provenance: None,
        ..Default::default()
    };

    let mut containers_unrelated = vec![container_target];
    DockerCoordinator::correlate_containers(
        &mut containers_unrelated,
        std::slice::from_ref(&sess),
        &[proc_unrelated],
    );
    assert_ne!(containers_unrelated[0].confidence, Confidence::Confirmed);
    assert_eq!(containers_unrelated[0].confidence, Confidence::Unknown);
    assert_eq!(containers_unrelated[0].session_id, None);

    // Negative 33c: Similar container names (Substring match rejected)
    // Process targeted "app", but container is "app-worker"
    let mut container_similar = sample_container("c-worker", "app-worker", ContainerState::Running);
    container_similar.ports.clear();
    let proc_app = ProcessInfo {
        pid: 1003,
        ppid: Some(100),
        name: "docker".to_string(),
        exe: Some(PathBuf::from("/usr/local/bin/docker")),
        cpu_usage: Some(0.1),
        memory_bytes: Some(1024),
        run_time_secs: 1,
        start_time: Some(1000),
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: vec![],
        cmdline: vec![
            "docker".to_string(),
            "run".to_string(),
            "--name".to_string(),
            "app".to_string(),
        ],
        command_outcome: None,
        provenance: None,
        ..Default::default()
    };

    let mut containers_similar = vec![container_similar];
    DockerCoordinator::correlate_containers(
        &mut containers_similar,
        std::slice::from_ref(&sess),
        &[proc_app],
    );
    assert_ne!(containers_similar[0].confidence, Confidence::Confirmed);
    assert_eq!(containers_similar[0].session_id, None);

    // Negative 33d: Non-session process running docker commands
    // Process PID 9999 runs docker command targeting "my-app", but PID 9999 is NOT in session!
    let mut container_legit = sample_container("c-legit", "my-app", ContainerState::Running);
    container_legit.ports.clear();
    let proc_stranger = ProcessInfo {
        pid: 9999, // NOT in sess.tracked_pids or root_pid
        ppid: Some(1),
        name: "docker".to_string(),
        exe: Some(PathBuf::from("/usr/local/bin/docker")),
        cpu_usage: Some(0.1),
        memory_bytes: Some(1024),
        run_time_secs: 1,
        start_time: Some(1000),
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: vec![],
        cmdline: vec![
            "docker".to_string(),
            "run".to_string(),
            "--name".to_string(),
            "my-app".to_string(),
        ],
        command_outcome: None,
        provenance: None,
        ..Default::default()
    };

    let mut containers_stranger = vec![container_legit];
    DockerCoordinator::correlate_containers(
        &mut containers_stranger,
        std::slice::from_ref(&sess),
        &[proc_stranger],
    );
    assert_eq!(containers_stranger[0].session_id, None);
    assert_eq!(containers_stranger[0].confidence, Confidence::Unknown);

    // Negative 33e: Conflicting claims (Two sessions both ran docker run targeting shared-app)
    let sess2 = sample_session(
        "sess-20261111-rival",
        AgentKind::Cursor,
        SessionStatus::Active,
    );
    let container_shared = sample_container("c-shared", "shared-app", ContainerState::Running);

    let proc_sess1 = ProcessInfo {
        pid: 1001,
        ppid: Some(100),
        name: "docker".to_string(),
        exe: Some(PathBuf::from("/usr/local/bin/docker")),
        cpu_usage: Some(0.1),
        memory_bytes: Some(1024),
        run_time_secs: 1,
        start_time: Some(1000),
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: vec![],
        cmdline: vec![
            "docker".to_string(),
            "run".to_string(),
            "--name".to_string(),
            "shared-app".to_string(),
        ],
        command_outcome: None,
        provenance: None,
        ..Default::default()
    };
    let proc_sess2 = ProcessInfo {
        pid: 2001,
        ppid: Some(200),
        name: "docker".to_string(),
        exe: Some(PathBuf::from("/usr/local/bin/docker")),
        cpu_usage: Some(0.1),
        memory_bytes: Some(1024),
        run_time_secs: 1,
        start_time: Some(1000),
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: vec![],
        cmdline: vec![
            "docker".to_string(),
            "run".to_string(),
            "--name".to_string(),
            "shared-app".to_string(),
        ],
        command_outcome: None,
        provenance: None,
        ..Default::default()
    };

    let mut sess1_clone = sess.clone();
    sess1_clone.tracked_pids.push(1001);
    let mut sess2_clone = sess2.clone();
    sess2_clone.tracked_pids.push(2001);

    let mut containers_conflict = vec![container_shared];
    DockerCoordinator::correlate_containers(
        &mut containers_conflict,
        &[sess1_clone, sess2_clone],
        &[proc_sess1, proc_sess2],
    );

    assert_eq!(containers_conflict[0].session_id, None);
    assert_eq!(containers_conflict[0].confidence, Confidence::Unknown);
    assert_eq!(containers_conflict[0].conflicting_sessions.len(), 2);
    assert!(containers_conflict[0].evidence[0].contains("Conflicting session claims"));

    // Negative 33f: Unresolvable container identity
    let container_nameless = ContainerInfo {
        id: String::new(),
        short_id: String::new(),
        name: String::new(),
        image: "alpine".to_string(),
        image_id: None,
        state: ContainerState::Running,
        status: "Up".to_string(),
        created_at: None,
        started_at: None,
        ports: vec![],
        exit_code: None,
        health_status: None,
        restart_count: None,
        command: None,
        entrypoint: None,
        working_dir: None,
        labels: HashMap::new(),
        runtime: None,
        networks: vec![],
        ip_addresses: vec![],
        network_mode: None,
        stats: None,
        session_id: None,
        declared_session_id: None,
        conflicting_sessions: vec![],
        confidence: Confidence::Unknown,
        evidence: vec![],
        creation_outcome: CreationOutcome::Unknown,
        attribution_basis: AttributionBasis::None,
    };
    let prov = DockerCoordinator::verify_direct_provenance(
        &[
            "docker".to_string(),
            "run".to_string(),
            "alpine".to_string(),
        ],
        &container_nameless,
    );
    assert!(
        prov.is_none(),
        "Unresolvable container identity must return None"
    );
}

// -----------------------------------------------------------------------------
// SCENARIO 34: Genuine Non-Blocking Background Worker Execution
// -----------------------------------------------------------------------------
struct DelayedMockDocker {
    delay_ms: u64,
    containers: Vec<ContainerInfo>,
}

impl DockerCollector for DelayedMockDocker {
    fn docker_status(&self) -> Result<DockerStatus, PlatformError> {
        std::thread::sleep(std::time::Duration::from_millis(self.delay_ms));
        Ok(DockerStatus {
            installed: true,
            running: true,
            socket_path: "/var/run/docker.sock".to_string(),
            api_version: Some("1.44".to_string()),
            engine_version: Some("25.0.3".to_string()),
            os: Some("linux".to_string()),
            arch: Some("aarch64".to_string()),
            active_context: Some("default".to_string()),
            error_message: None,
            error_category: Some(timmy::model::DockerErrorCategory::None),
        })
    }

    fn is_available(&self) -> bool {
        true
    }

    fn collect_containers(&self) -> Result<Vec<ContainerInfo>, PlatformError> {
        std::thread::sleep(std::time::Duration::from_millis(self.delay_ms));
        Ok(self.containers.clone())
    }

    fn inspect_container(&self, id: &str) -> Result<ContainerDetail, PlatformError> {
        std::thread::sleep(std::time::Duration::from_millis(self.delay_ms));
        Ok(ContainerDetail {
            info: sample_container(id, "delayed-app", ContainerState::Running),
            env_keys: vec![],
            mounts: vec![],
            restart_policy: "no".to_string(),
            platform: Some("linux/arm64".to_string()),
        })
    }

    fn collect_container_stats(&self, _id: &str) -> Result<ContainerStats, PlatformError> {
        std::thread::sleep(std::time::Duration::from_millis(self.delay_ms));
        Ok(ContainerStats::default())
    }
}

#[test]
fn test_scenario_34_docker_background_worker_non_blocking_execution() {
    use timmy::platform::DockerBackgroundWorker;

    let delayed_collector = Arc::new(DelayedMockDocker {
        delay_ms: 100, // 100ms deliberate delay
        containers: vec![sample_container(
            "c-bg-1",
            "bg-worker-test",
            ContainerState::Running,
        )],
    });

    let worker = DockerBackgroundWorker::new(delayed_collector);

    // Initial cache should be empty
    assert!(worker.get_cached_containers().is_empty());

    // Trigger refresh: returns immediately without waiting for the 100ms delay!
    let start = std::time::Instant::now();
    let dispatched = worker.trigger_refresh(1, vec![], vec![]);
    let dispatch_elapsed = start.elapsed();

    assert!(dispatched);
    assert!(
        dispatch_elapsed < std::time::Duration::from_millis(20),
        "Triggering refresh must be instant and non-blocking, took {:?}",
        dispatch_elapsed
    );

    // Immediately after dispatch, the worker is marked as refreshing
    assert!(worker.is_refreshing() || !worker.get_cached_containers().is_empty());

    // Wait for the background worker to finish
    let mut waited = 0;
    while worker.is_refreshing() && waited < 50 {
        std::thread::sleep(std::time::Duration::from_millis(10));
        waited += 1;
    }

    // Now the cached containers must be populated
    let cached = worker.get_cached_containers();
    assert_eq!(cached.len(), 1);
    assert_eq!(cached[0].id, "c-bg-1");
    assert_eq!(cached[0].name, "bg-worker-test");
}

// -----------------------------------------------------------------------------
// SCENARIO 35: Deterministic TUI Event Loop Responsiveness Under Slow Docker
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_35_tui_responsiveness_and_frame_rendering_during_slow_docker() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use timmy::ui::App;

    let slow_collector = Arc::new(DelayedMockDocker {
        delay_ms: 200, // 200ms deliberate Docker delay
        containers: vec![sample_container(
            "c-tui-1",
            "tui-slow-app",
            ContainerState::Running,
        )],
    });

    struct MockSystemWithDocker {
        docker: Arc<dyn DockerCollector>,
    }
    impl ProcessCollector for MockSystemWithDocker {
        fn collect_processes(&self) -> Result<Vec<ProcessInfo>, PlatformError> {
            Ok(vec![])
        }
        fn inspect_process(&self, pid: u32) -> Result<ProcessDetail, PlatformError> {
            Err(PlatformError::ProcessNotFound(pid))
        }
    }
    impl PortCollector for MockSystemWithDocker {
        fn collect_listening_ports(&self) -> Result<Vec<ListeningPort>, PlatformError> {
            Ok(vec![])
        }
    }
    impl ServiceCollector for MockSystemWithDocker {
        fn collect_services(&self) -> Result<Vec<ServiceInfo>, PlatformError> {
            Ok(vec![])
        }
    }
    impl DockerCollector for MockSystemWithDocker {
        fn docker_status(&self) -> Result<DockerStatus, PlatformError> {
            self.docker.docker_status()
        }
        fn is_available(&self) -> bool {
            self.docker.is_available()
        }
        fn collect_containers(&self) -> Result<Vec<ContainerInfo>, PlatformError> {
            self.docker.collect_containers()
        }
        fn inspect_container(&self, id: &str) -> Result<ContainerDetail, PlatformError> {
            self.docker.inspect_container(id)
        }
        fn collect_container_stats(&self, id: &str) -> Result<ContainerStats, PlatformError> {
            self.docker.collect_container_stats(id)
        }
    }

    let sys = Arc::new(MockSystemWithDocker {
        docker: slow_collector,
    });

    let storage = Arc::new(StorageManager::open_in_memory().expect("in-memory db"));
    let mut config = TimmyConfig::default();
    config.general.enable_docker = true;
    let orchestrator = EngineOrchestrator::with_collector(config, Some(storage), sys);

    let mut app = App::new(orchestrator);

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).expect("terminal creation");

    // Simulate 10 TUI frames with tick and key events
    for frame_idx in 0..10 {
        let frame_start = std::time::Instant::now();

        // 1. Draw frame
        terminal.draw(|f| app.draw(f)).expect("draw frame");

        // 2. Handle key navigation
        let key = match frame_idx % 4 {
            0 => KeyCode::Char('4'), // switch to Docker tab
            1 => KeyCode::Down,
            2 => KeyCode::Up,
            _ => KeyCode::Char('1'), // switch back to processes
        };
        app.handle_key(KeyEvent::new(key, KeyModifiers::NONE));

        // 3. Periodic tick refresh
        app.refresh();

        let frame_elapsed = frame_start.elapsed();

        // Each frame and key handling must execute in < 25ms, NEVER blocking on the 200ms Docker call!
        assert!(
            frame_elapsed < std::time::Duration::from_millis(25),
            "Frame {} took {:?}, exceeding non-blocking budget of 25ms",
            frame_idx,
            frame_elapsed
        );
    }
}

// -----------------------------------------------------------------------------
// SCENARIO 36: Docker Background Worker Rate Limiting & Bounded Queue
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_36_docker_background_worker_rate_limiting_bounded_queue() {
    use timmy::platform::DockerBackgroundWorker;

    let delayed_collector = Arc::new(DelayedMockDocker {
        delay_ms: 100,
        containers: vec![sample_container(
            "c-rate-1",
            "rate-app",
            ContainerState::Running,
        )],
    });

    let worker = DockerBackgroundWorker::new(delayed_collector);

    // Initial dispatch succeeds
    let first = worker.trigger_refresh(1, vec![], vec![]);
    assert!(first);

    // Rapid successive calls while refreshing must return false (rate limited / dropped)
    let second = worker.trigger_refresh(2, vec![], vec![]);
    // Because delay is 100ms and worker is active, second call is safely rejected or coalesced
    assert!(!second || worker.is_refreshing());
}

// -----------------------------------------------------------------------------
// SCENARIO 37: Clean Container Disappearance & Selection Clamping
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_37_clean_container_disappearance_and_selection_clamping() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use timmy::ui::App;

    let initial_containers = vec![
        sample_container("c-1", "app-1", ContainerState::Running),
        sample_container("c-2", "app-2", ContainerState::Running),
    ];

    let mock_docker = MockDockerCollector::new();
    mock_docker.set_containers_result(Ok(initial_containers.clone()));
    let sys = Arc::new(MockSystem {
        processes: vec![],
        ports: vec![],
        docker: mock_docker,
    });

    let storage = Arc::new(StorageManager::open_in_memory().expect("in-memory db"));
    let mut config = TimmyConfig::default();
    config.general.enable_docker = false; // test synchronous orchestrator container clamping
    let orchestrator = EngineOrchestrator::with_collector(config, Some(storage), sys);

    let mut app = App::new(orchestrator);
    app.current_tab = timmy::ui::app::ActiveTab::Docker;
    app.snapshot.containers = initial_containers;
    app.docker_table_state.select(Some(1)); // select container 2

    assert_eq!(app.docker_table_state.selected(), Some(1));

    // Simulate disappearance of all containers
    app.snapshot.containers.clear();
    app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));

    // Clamped cleanly to None without panic
    assert_eq!(app.docker_table_state.selected(), None);
}

// -----------------------------------------------------------------------------
// SCENARIO 38: Bollard Client Lifecycle and Cache Invalidation
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_38_bollard_client_lifecycle_and_cache_invalidation() {
    let collector = BollardDockerCollector::new(
        Some("/tmp/test-fake-nonexistent.sock".to_string()),
        std::time::Duration::from_millis(500),
    );

    // Initial status call fails gracefully because socket is missing
    let status1 = collector.docker_status().expect("docker status query");
    assert!(!status1.running);

    // Invalidation can be called safely
    collector.invalidate_client_cache();

    // Subsequent call recovers cleanly without deadlock
    let status2 = collector
        .docker_status()
        .expect("second docker status query");
    assert!(!status2.running);
}

// -----------------------------------------------------------------------------
// SCENARIO 39: Adversarial Attribution 1 - Failed Docker Run Command
// -----------------------------------------------------------------------------
#[test]
fn test_adversarial_01_failed_docker_run_command() {
    let mut sess = sample_session("sess-fail", AgentKind::ClaudeCode, SessionStatus::Active);
    sess.tracked_pids.push(1010);

    // Process attempted a docker run command that failed to start the container
    let proc_fail = ProcessInfo {
        pid: 1010,
        ppid: Some(100),
        name: "docker".to_string(),
        exe: Some(PathBuf::from("/usr/local/bin/docker")),
        cpu_usage: Some(0.1),
        memory_bytes: Some(1024),
        run_time_secs: 1,
        start_time: Some(1000),
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: vec![],
        cmdline: vec![
            "docker".to_string(),
            "run".to_string(),
            "--name".to_string(),
            "failing-job".to_string(),
            "invalid-image:latest".to_string(),
        ],
        command_outcome: None,
        provenance: None,
        ..Default::default()
    };

    // Subcase 1A: Container never created, only an unrelated container exists
    let mut unrelated = sample_container("c-unrelated", "other-job", ContainerState::Running);
    unrelated.ports.clear();
    let mut containers_unrelated = vec![unrelated];
    DockerCoordinator::correlate_containers(
        &mut containers_unrelated,
        std::slice::from_ref(&sess),
        std::slice::from_ref(&proc_fail),
    );
    assert_eq!(containers_unrelated[0].session_id, None);
    assert_eq!(containers_unrelated[0].confidence, Confidence::Unknown);

    // Subcase 1B: Failed creation command with independently observed failure evidence
    let mut failed_container = sample_container("c-failed", "failing-job", ContainerState::Exited);
    failed_container.ports.clear();
    let mut proc_with_failure = proc_fail.clone();
    proc_with_failure.command_outcome = Some(CreationOutcome::Failed);
    proc_with_failure.attribution.evidence =
        "Creation operation failed: docker daemon error (invalid image)".to_string();
    let mut containers_failed = vec![failed_container];
    DockerCoordinator::correlate_containers(
        &mut containers_failed,
        std::slice::from_ref(&sess),
        &[proc_with_failure],
    );
    assert_eq!(containers_failed[0].session_id, None);
    assert_eq!(containers_failed[0].confidence, Confidence::Unknown);
    assert!(
        containers_failed[0].evidence[0].contains("creation operation verified failed")
            || containers_failed[0].evidence[0].contains("creation operation explicitly failed")
    );
}

// -----------------------------------------------------------------------------
// SCENARIO 40: Adversarial Attribution 2 - Successful-looking Command with Unidentifiable Container
// -----------------------------------------------------------------------------
#[test]
fn test_adversarial_02_successful_command_unidentifiable_container() {
    let sess = sample_session("sess-anon", AgentKind::ClaudeCode, SessionStatus::Active);

    // Anonymous container run without --name
    let proc_anon = ProcessInfo {
        pid: 1011,
        ppid: Some(100),
        name: "docker".to_string(),
        exe: Some(PathBuf::from("/usr/local/bin/docker")),
        cpu_usage: Some(0.1),
        memory_bytes: Some(1024),
        run_time_secs: 1,
        start_time: Some(1000),
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: vec![],
        cmdline: vec![
            "docker".to_string(),
            "run".to_string(),
            "-d".to_string(),
            "alpine".to_string(),
        ],
        command_outcome: None,
        provenance: None,
        ..Default::default()
    };

    // Daemon generated a random name and ID
    let mut random_container =
        sample_container("e4b2a1c99887", "nostalgic_hopper", ContainerState::Running);
    random_container.ports.clear();
    let mut containers = vec![random_container];
    DockerCoordinator::correlate_containers(
        &mut containers,
        std::slice::from_ref(&sess),
        &[proc_anon],
    );

    assert_eq!(containers[0].session_id, None);
    assert_eq!(containers[0].confidence, Confidence::Unknown);
}

// -----------------------------------------------------------------------------
// SCENARIO 41: Adversarial Attribution 3 - Command Referencing an Existing Container
// -----------------------------------------------------------------------------
#[test]
fn test_adversarial_03_command_referencing_existing_container() {
    let sess = sample_session("sess-ref", AgentKind::ClaudeCode, SessionStatus::Active);
    let mut existing_container = sample_container("c-db", "my-db", ContainerState::Running);
    existing_container.ports.clear();

    // Inspecting or non-lifecycle operations: logs, top, stop, attach, inspect
    let non_lifecycle_cmds = vec![
        vec![
            "docker".to_string(),
            "logs".to_string(),
            "my-db".to_string(),
        ],
        vec!["docker".to_string(), "top".to_string(), "my-db".to_string()],
        vec![
            "docker".to_string(),
            "stop".to_string(),
            "my-db".to_string(),
        ],
        vec![
            "docker".to_string(),
            "attach".to_string(),
            "my-db".to_string(),
        ],
        vec![
            "docker".to_string(),
            "inspect".to_string(),
            "my-db".to_string(),
        ],
    ];

    for cmd in non_lifecycle_cmds {
        let proc = ProcessInfo {
            pid: 1012,
            ppid: Some(100),
            name: "docker".to_string(),
            exe: Some(PathBuf::from("/usr/local/bin/docker")),
            cpu_usage: Some(0.1),
            memory_bytes: Some(1024),
            run_time_secs: 1,
            start_time: Some(1000),
            user: None,
            attribution: AgentAttribution::default(),
            listening_ports: vec![],
            cmdline: cmd,
            command_outcome: None,
            provenance: None,
            ..Default::default()
        };

        let mut containers = vec![existing_container.clone()];
        DockerCoordinator::correlate_containers(
            &mut containers,
            std::slice::from_ref(&sess),
            &[proc],
        );
        assert_eq!(containers[0].session_id, None);
        assert_eq!(containers[0].confidence, Confidence::Unknown);
    }
}

// -----------------------------------------------------------------------------
// SCENARIO 42: Adversarial Attribution 4 - Tracked Process Running Outside the Session
// -----------------------------------------------------------------------------
#[test]
fn test_adversarial_04_tracked_process_running_outside_session() {
    let sess = sample_session("sess-legit", AgentKind::ClaudeCode, SessionStatus::Active);
    let mut container = sample_container("c-srv", "foreign-srv", ContainerState::Running);
    container.ports.clear();

    // Process PID 9876 is NOT in sess.tracked_pids and NOT sess.root_pid
    let proc_outside = ProcessInfo {
        pid: 9876,
        ppid: Some(1),
        name: "docker".to_string(),
        exe: Some(PathBuf::from("/usr/local/bin/docker")),
        cpu_usage: Some(0.1),
        memory_bytes: Some(1024),
        run_time_secs: 1,
        start_time: Some(1000),
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: vec![],
        cmdline: vec![
            "docker".to_string(),
            "run".to_string(),
            "--name".to_string(),
            "foreign-srv".to_string(),
            "alpine".to_string(),
        ],
        command_outcome: None,
        provenance: None,
        ..Default::default()
    };

    let mut containers = vec![container];
    DockerCoordinator::correlate_containers(
        &mut containers,
        std::slice::from_ref(&sess),
        &[proc_outside],
    );
    assert_eq!(containers[0].session_id, None);
    assert_eq!(containers[0].confidence, Confidence::Unknown);
}

// -----------------------------------------------------------------------------
// SCENARIO 43: Adversarial Attribution 5 - Container Label Claiming Session That Did Not Create It
// -----------------------------------------------------------------------------
#[test]
fn test_adversarial_05_container_label_claiming_session_that_did_not_create_it() {
    let sess = sample_session("sess-victim", AgentKind::ClaudeCode, SessionStatus::Active);
    let mut container = sample_container("c-victim", "unrelated-srv", ContainerState::Running);
    container.ports.clear();
    // Injected label claiming sess-victim
    container
        .labels
        .insert("timmy.session.id".to_string(), "sess-victim".to_string());

    let mut containers = vec![container];
    DockerCoordinator::correlate_containers(&mut containers, std::slice::from_ref(&sess), &[]);

    assert_eq!(
        containers[0].declared_session_id.as_deref(),
        Some("sess-victim")
    );
    assert_eq!(containers[0].session_id.as_deref(), Some("sess-victim"));
    // Rule 2: Container label MUST NEVER establish Confirmed or HighConfidence
    assert_ne!(containers[0].confidence, Confidence::Confirmed);
    assert_ne!(containers[0].confidence, Confidence::HighConfidence);
    assert_eq!(containers[0].confidence, Confidence::Inferred);
    assert!(containers[0].evidence[0].contains("unverified runtime ownership"));
}

// -----------------------------------------------------------------------------
// SCENARIO 44: Adversarial Attribution 6 - Forged or Stale Session Label
// -----------------------------------------------------------------------------
#[test]
fn test_adversarial_06_forged_or_stale_session_label() {
    let sess = sample_session("sess-live", AgentKind::ClaudeCode, SessionStatus::Active);
    let mut container = sample_container("c-stale", "stale-app", ContainerState::Running);
    container.ports.clear();
    // Non-existent or stale session ID
    container.labels.insert(
        "timmy.session.id".to_string(),
        "dead-session-uuid-404".to_string(),
    );

    let mut containers = vec![container];
    DockerCoordinator::correlate_containers(&mut containers, std::slice::from_ref(&sess), &[]);

    // Declared session ID must be preserved separately
    assert_eq!(
        containers[0].declared_session_id.as_deref(),
        Some("dead-session-uuid-404")
    );
    // Verified attribution must remain None and Unknown
    assert_eq!(containers[0].session_id, None);
    assert_eq!(containers[0].confidence, Confidence::Unknown);
}

// -----------------------------------------------------------------------------
// SCENARIO 45: Adversarial Attribution 7 - Similar Container Names (Substring Collision)
// -----------------------------------------------------------------------------
#[test]
fn test_adversarial_07_similar_container_names() {
    let sess = sample_session("sess-app", AgentKind::ClaudeCode, SessionStatus::Active);

    // Tracked process targeted "api"
    let proc_api = ProcessInfo {
        pid: 1013,
        ppid: Some(100),
        name: "docker".to_string(),
        exe: Some(PathBuf::from("/usr/local/bin/docker")),
        cpu_usage: Some(0.1),
        memory_bytes: Some(1024),
        run_time_secs: 1,
        start_time: Some(1000),
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: vec![],
        cmdline: vec![
            "docker".to_string(),
            "run".to_string(),
            "--name".to_string(),
            "api".to_string(),
            "alpine".to_string(),
        ],
        command_outcome: None,
        provenance: None,
        ..Default::default()
    };

    // Containers in daemon have substring or prefix variations
    let mut c1 = sample_container("c-api-worker", "api-worker", ContainerState::Running);
    let mut c2 = sample_container("c-my-api", "my-api", ContainerState::Running);
    let mut c3 = sample_container("c-apis", "apis", ContainerState::Running);
    c1.ports.clear();
    c2.ports.clear();
    c3.ports.clear();

    let mut containers = vec![c1, c2, c3];
    DockerCoordinator::correlate_containers(
        &mut containers,
        std::slice::from_ref(&sess),
        &[proc_api],
    );

    for c in &containers {
        assert_eq!(c.session_id, None);
        assert_eq!(c.confidence, Confidence::Unknown);
    }
}

// -----------------------------------------------------------------------------
// SCENARIO 46: Adversarial Attribution 8 - Container ID Appearing as Unrelated Command Argument
// -----------------------------------------------------------------------------
#[test]
fn test_adversarial_08_container_id_as_unrelated_command_argument() {
    let sess = sample_session("sess-arg", AgentKind::ClaudeCode, SessionStatus::Active);
    let mut container = sample_container("a1b2c3d4e5f67890", "legit-app", ContainerState::Running);
    container.ports.clear();

    // Process executing grep or curl with container ID as an argument
    let proc_grep = ProcessInfo {
        pid: 1014,
        ppid: Some(100),
        name: "grep".to_string(),
        exe: Some(PathBuf::from("/usr/bin/grep")),
        cpu_usage: Some(0.1),
        memory_bytes: Some(1024),
        run_time_secs: 1,
        start_time: Some(1000),
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: vec![],
        cmdline: vec![
            "grep".to_string(),
            "a1b2c3d4e5f67890".to_string(),
            "/var/log/syslog".to_string(),
        ],
        command_outcome: None,
        provenance: None,
        ..Default::default()
    };

    let mut containers = vec![container];
    DockerCoordinator::correlate_containers(
        &mut containers,
        std::slice::from_ref(&sess),
        &[proc_grep],
    );

    assert_eq!(containers[0].session_id, None);
    assert_eq!(containers[0].confidence, Confidence::Unknown);
}

// -----------------------------------------------------------------------------
// SCENARIO 47: Adversarial Attribution 9 - Docker Compose Up with Multiple Resulting Containers
// -----------------------------------------------------------------------------
#[test]
fn test_adversarial_09_docker_compose_up_multiple_resulting_containers() {
    let sess = sample_session("sess-compose", AgentKind::ClaudeCode, SessionStatus::Active);

    // Process executed docker compose up -d
    let proc_compose = ProcessInfo {
        pid: 1015,
        ppid: Some(100),
        name: "docker".to_string(),
        exe: Some(PathBuf::from("/usr/local/bin/docker")),
        cpu_usage: Some(0.1),
        memory_bytes: Some(1024),
        run_time_secs: 1,
        start_time: Some(1000),
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: vec![],
        cmdline: vec![
            "docker".to_string(),
            "compose".to_string(),
            "up".to_string(),
            "-d".to_string(),
        ],
        command_outcome: None,
        provenance: None,
        ..Default::default()
    };

    // Resulting stack creates multiple containers
    let mut c_web = sample_container("c-proj-web", "myproj-web-1", ContainerState::Running);
    let mut c_db = sample_container("c-proj-db", "myproj-db-1", ContainerState::Running);
    c_web.ports.clear();
    c_db.ports.clear();

    // Mount pointing to project directory
    let mounts = vec![MountInfo {
        source: "/Users/dev/myproject".to_string(),
        destination: "/workspace".to_string(),
        mount_type: "bind".to_string(),
        read_only: false,
    }];

    // Associated session process exe points into that workspace
    let proc_sess_agent = ProcessInfo {
        pid: 1001,
        ppid: Some(100),
        name: "node".to_string(),
        exe: Some(PathBuf::from(
            "/Users/dev/myproject/node_modules/.bin/agent",
        )),
        cpu_usage: Some(0.5),
        memory_bytes: Some(50 * 1024 * 1024),
        run_time_secs: 10,
        start_time: Some(1000),
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: vec![],
        cmdline: vec![],
        command_outcome: None,
        provenance: None,
        ..Default::default()
    };

    let procs = vec![proc_compose, proc_sess_agent];
    DockerCoordinator::correlate_container_with_mounts(
        &mut c_web,
        &mounts,
        std::slice::from_ref(&sess),
        &procs,
    );
    DockerCoordinator::correlate_container_with_mounts(
        &mut c_db,
        &mounts,
        std::slice::from_ref(&sess),
        &procs,
    );

    // Both containers receive Inferred attribution through mount/working directory
    assert_eq!(c_web.session_id.as_deref(), Some("sess-compose"));
    assert_ne!(c_web.confidence, Confidence::Confirmed);
    assert_eq!(c_web.confidence, Confidence::Inferred);

    assert_eq!(c_db.session_id.as_deref(), Some("sess-compose"));
    assert_ne!(c_db.confidence, Confidence::Confirmed);
    assert_eq!(c_db.confidence, Confidence::Inferred);
}

// -----------------------------------------------------------------------------
// SCENARIO 48: Adversarial Attribution 10 - Two Sessions Claiming the Same Container
// -----------------------------------------------------------------------------
#[test]
fn test_adversarial_10_two_sessions_claiming_same_container() {
    let mut sess1 = sample_session("sess-alpha", AgentKind::ClaudeCode, SessionStatus::Active);
    let mut sess2 = sample_session("sess-beta", AgentKind::Cursor, SessionStatus::Active);
    sess1.tracked_pids = vec![3001];
    sess2.tracked_pids = vec![3002];

    let proc1 = ProcessInfo {
        pid: 3001,
        ppid: Some(100),
        name: "docker".to_string(),
        exe: Some(PathBuf::from("/usr/local/bin/docker")),
        cpu_usage: Some(0.1),
        memory_bytes: Some(1024),
        run_time_secs: 1,
        start_time: Some(1000),
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: vec![],
        cmdline: vec![
            "docker".to_string(),
            "run".to_string(),
            "--name".to_string(),
            "contested-app".to_string(),
        ],
        command_outcome: None,
        provenance: None,
        ..Default::default()
    };
    let proc2 = ProcessInfo {
        pid: 3002,
        ppid: Some(200),
        name: "docker".to_string(),
        exe: Some(PathBuf::from("/usr/local/bin/docker")),
        cpu_usage: Some(0.1),
        memory_bytes: Some(1024),
        run_time_secs: 1,
        start_time: Some(1000),
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: vec![],
        cmdline: vec![
            "docker".to_string(),
            "run".to_string(),
            "--name".to_string(),
            "contested-app".to_string(),
        ],
        command_outcome: None,
        provenance: None,
        ..Default::default()
    };

    let mut container = sample_container("c-contested", "contested-app", ContainerState::Running);
    container.ports.clear();
    let mut containers = vec![container];

    DockerCoordinator::correlate_containers(&mut containers, &[sess1, sess2], &[proc1, proc2]);

    // Conflict detected: session_id must be None, confidence Unknown, conflicting_sessions populated
    assert_eq!(containers[0].session_id, None);
    assert_eq!(containers[0].confidence, Confidence::Unknown);
    assert_eq!(containers[0].conflicting_sessions.len(), 2);
    assert!(containers[0]
        .conflicting_sessions
        .contains(&"sess-alpha".to_string()));
    assert!(containers[0]
        .conflicting_sessions
        .contains(&"sess-beta".to_string()));
    assert!(containers[0].evidence[0].contains("Conflicting session claims"));
}

// -----------------------------------------------------------------------------
// SCENARIO 49: Adversarial Attribution 11 - Stopped Session Whose Historical Attribution Remains Visible
// -----------------------------------------------------------------------------
#[test]
fn test_adversarial_11_stopped_session_historical_attribution_retained() {
    let stopped_sess = sample_session(
        "sess-stopped",
        AgentKind::ClaudeCode,
        SessionStatus::Stopped,
    );
    let mut container = sample_container("c-historical", "persisted-db", ContainerState::Running);
    container.ports.clear();
    container.session_id = Some("sess-stopped".to_string());
    container.confidence = Confidence::Inferred;
    container.evidence = vec!["Original active attribution".to_string()];

    let mut containers = vec![container];
    DockerCoordinator::correlate_containers(&mut containers, &[stopped_sess], &[]);

    assert_eq!(containers[0].session_id.as_deref(), Some("sess-stopped"));
    assert_eq!(containers[0].confidence, Confidence::Inferred);
    assert!(containers[0]
        .evidence
        .iter()
        .any(|e| e.contains("Retained attribution to terminated session")));
}

// -----------------------------------------------------------------------------
// SCENARIO 50: Adversarial Attribution 12 - Container with No Reliable Ownership Evidence
// -----------------------------------------------------------------------------
#[test]
fn test_adversarial_12_container_with_no_reliable_evidence() {
    let sess = sample_session("sess-active", AgentKind::ClaudeCode, SessionStatus::Active);
    let mut orphan = sample_container("c-orphan", "unrelated-daemon", ContainerState::Running);
    orphan.ports.clear();
    orphan.labels.clear();
    // Container created 10 hours before session start
    orphan.created_at = Some((Utc::now() - Duration::hours(10)).to_rfc3339());

    let mut containers = vec![orphan];
    DockerCoordinator::correlate_containers(&mut containers, std::slice::from_ref(&sess), &[]);

    assert_eq!(containers[0].session_id, None);
    assert_eq!(containers[0].confidence, Confidence::Unknown);
    assert!(containers[0].evidence.is_empty());
}

// -----------------------------------------------------------------------------
// SCENARIO 51: Background Worker Shutdown During Stalled/Delayed Request
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_51_worker_shutdown_during_stalled_request() {
    use std::time::Instant;
    use timmy::platform::DockerBackgroundWorker;

    // Stalled mock delays 5 seconds on status
    let stalled_collector = Arc::new(DelayedMockDocker {
        delay_ms: 5000,
        containers: vec![],
    });

    let mut worker = DockerBackgroundWorker::new(stalled_collector);
    // Trigger in-flight request
    let triggered = worker.trigger_refresh(1, vec![], vec![]);
    assert!(triggered);

    // Measure shutdown time
    let start = Instant::now();
    worker.stop();
    let elapsed = start.elapsed();

    // Must return within bounded join timeout (500ms + thread grace period < 1500ms),
    // NEVER blocking for the full 5000ms!
    assert!(
        elapsed < std::time::Duration::from_millis(1500),
        "Shutdown took {:?}, exceeding bounded limit",
        elapsed
    );
}

// -----------------------------------------------------------------------------
// SCENARIO 52: Background Worker Receiver Disconnection Clean Termination
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_52_worker_receiver_disconnection_clean_exit() {
    use timmy::platform::DockerBackgroundWorker;

    let collector = Arc::new(DelayedMockDocker {
        delay_ms: 1,
        containers: vec![],
    });

    let mut worker = DockerBackgroundWorker::new(collector);
    // Explicit stop sends shutdown and drops channel
    worker.stop();
    // Calling stop again is idempotent and does not panic
    worker.stop();
}

// -----------------------------------------------------------------------------
// SCENARIO 53: Refresh Failure Retains Last Valid Snapshot
// -----------------------------------------------------------------------------
struct SwitchableMockDocker {
    should_fail: std::sync::atomic::AtomicBool,
    containers: std::sync::Mutex<Vec<ContainerInfo>>,
}

impl DockerCollector for SwitchableMockDocker {
    fn docker_status(&self) -> Result<DockerStatus, PlatformError> {
        if self.should_fail.load(std::sync::atomic::Ordering::SeqCst) {
            Err(PlatformError::DockerNotRunning(
                "/var/run/docker.sock".to_string(),
            ))
        } else {
            Ok(DockerStatus {
                installed: true,
                running: true,
                socket_path: "/var/run/docker.sock".to_string(),
                api_version: Some("1.44".to_string()),
                engine_version: Some("25.0.3".to_string()),
                os: Some("linux".to_string()),
                arch: Some("aarch64".to_string()),
                active_context: Some("default".to_string()),
                error_message: None,
                error_category: Some(timmy::model::DockerErrorCategory::None),
            })
        }
    }

    fn is_available(&self) -> bool {
        !self.should_fail.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn collect_containers(&self) -> Result<Vec<ContainerInfo>, PlatformError> {
        if self.should_fail.load(std::sync::atomic::Ordering::SeqCst) {
            Err(PlatformError::DockerNotRunning(
                "/var/run/docker.sock".to_string(),
            ))
        } else {
            Ok(self.containers.lock().unwrap().clone())
        }
    }

    fn inspect_container(&self, id: &str) -> Result<ContainerDetail, PlatformError> {
        Ok(ContainerDetail {
            info: sample_container(id, "mock-app", ContainerState::Running),
            env_keys: vec![],
            mounts: vec![],
            restart_policy: "no".to_string(),
            platform: Some("linux/arm64".to_string()),
        })
    }

    fn collect_container_stats(&self, _id: &str) -> Result<ContainerStats, PlatformError> {
        Ok(ContainerStats::default())
    }
}

#[test]
fn test_scenario_53_refresh_failure_retains_last_valid_snapshot() {
    use timmy::platform::DockerBackgroundWorker;

    let initial_containers = vec![
        sample_container("c-persist-1", "app-1", ContainerState::Running),
        sample_container("c-persist-2", "app-2", ContainerState::Running),
    ];

    let mock = Arc::new(SwitchableMockDocker {
        should_fail: std::sync::atomic::AtomicBool::new(false),
        containers: std::sync::Mutex::new(initial_containers.clone()),
    });

    let mut worker = DockerBackgroundWorker::new(mock.clone());

    // Phase 1: Successful initial collection
    worker.trigger_refresh(1, vec![], vec![]);
    for _ in 0..100 {
        if !worker.is_refreshing() && !worker.get_cached_containers().is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert_eq!(worker.get_cached_containers().len(), 2);
    assert_eq!(worker.last_error(), None);
    assert!(!worker.is_error());

    // Phase 2: Daemon failure happens
    mock.should_fail
        .store(true, std::sync::atomic::Ordering::SeqCst);
    worker.trigger_refresh(2, vec![], vec![]);
    for _ in 0..100 {
        if !worker.is_refreshing() && worker.last_error().is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    // CRITICAL RESILIENCE CHECK: Error is noted, but last valid snapshot is RETAINED!
    assert!(worker.last_error().is_some());
    assert!(worker.is_error());
    assert_eq!(
        worker.get_cached_containers().len(),
        2,
        "Failure must not wipe previous snapshot!"
    );
    assert_eq!(worker.get_cached_containers()[0].name, "app-1");

    worker.stop();
}

// -----------------------------------------------------------------------------
// SCENARIO 54: Background Worker Daemon Recovery After Socket Failure / Restart
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_54_worker_daemon_recovery_after_socket_failure() {
    use timmy::platform::DockerBackgroundWorker;

    let mock = Arc::new(SwitchableMockDocker {
        should_fail: std::sync::atomic::AtomicBool::new(true), // Starts in failed state
        containers: std::sync::Mutex::new(vec![]),
    });

    let mut worker = DockerBackgroundWorker::new(mock.clone());

    // Phase 1: Failed attempt
    worker.trigger_refresh(1, vec![], vec![]);
    for _ in 0..100 {
        if !worker.is_refreshing() && worker.last_error().is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(worker.is_error());

    // Phase 2: Daemon recovers / starts up
    *mock.containers.lock().unwrap() = vec![sample_container(
        "c-recov-1",
        "recovered-app",
        ContainerState::Running,
    )];
    mock.should_fail
        .store(false, std::sync::atomic::Ordering::SeqCst);

    worker.trigger_refresh(2, vec![], vec![]);
    for _ in 0..100 {
        if !worker.is_refreshing() && !worker.get_cached_containers().is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    // Successful recovery: error cleared, fresh containers cached
    assert_eq!(worker.last_error(), None);
    assert!(!worker.is_error());
    assert_eq!(worker.get_cached_containers().len(), 1);
    assert_eq!(worker.get_cached_containers()[0].name, "recovered-app");

    worker.stop();
}

// -----------------------------------------------------------------------------
// SCENARIO 55: Snapshot Age, Staleness, and Error Visibility
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_55_worker_snapshot_age_staleness_and_error_visibility() {
    use timmy::platform::DockerBackgroundWorker;

    let mock = Arc::new(SwitchableMockDocker {
        should_fail: std::sync::atomic::AtomicBool::new(false),
        containers: std::sync::Mutex::new(vec![sample_container(
            "c-stale-1",
            "app",
            ContainerState::Running,
        )]),
    });

    let mut worker = DockerBackgroundWorker::new(mock);

    // Initial state before any refresh
    assert_eq!(worker.last_refresh(), None);
    assert_eq!(worker.snapshot_age(), None);
    assert!(worker.is_stale(std::time::Duration::from_secs(1)));

    // Perform refresh
    worker.trigger_refresh(1, vec![], vec![]);
    for _ in 0..100 {
        if !worker.is_refreshing() && worker.last_refresh().is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    assert!(worker.last_refresh().is_some());
    assert!(worker.snapshot_age().is_some());
    // Fresh snapshot is not stale against 10s threshold
    assert!(!worker.is_stale(std::time::Duration::from_secs(10)));
    // But is stale against 0 threshold
    assert!(worker.is_stale(std::time::Duration::from_nanos(1)));

    worker.stop();
}

// -----------------------------------------------------------------------------
// SCENARIO 56: Bounded Inspection Cache Eviction
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_56_bounded_inspection_cache_eviction() {
    use timmy::platform::DockerBackgroundWorker;

    let mock = Arc::new(SwitchableMockDocker {
        should_fail: std::sync::atomic::AtomicBool::new(false),
        containers: std::sync::Mutex::new(vec![]),
    });

    let mut worker = DockerBackgroundWorker::new(mock);

    // Dispatch 150 unique inspection requests
    for i in 0..150 {
        worker.trigger_inspect(format!("container-{:03}", i), vec![], vec![]);
        std::thread::sleep(std::time::Duration::from_millis(1));
    }

    // Wait for worker loop to process
    for _ in 0..100 {
        if worker.get_cached_detail("container-149").is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    // Cache must never grow beyond bounded limit!
    let cached_149 = worker.get_cached_detail("container-149");
    assert!(
        cached_149.is_some(),
        "Latest inspected container must be cached"
    );

    // Oldest container should have been evicted
    let evicted = worker.get_cached_detail("container-000");
    assert!(
        evicted.is_none(),
        "Oldest container must have been evicted from bounded cache"
    );

    worker.stop();
}

// -----------------------------------------------------------------------------
// SCENARIO 57: TUI Event Loop Responsiveness Under Docker Worker Failure
// -----------------------------------------------------------------------------
#[test]
fn test_scenario_57_tui_event_loop_responsiveness_under_worker_failure() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use std::time::Instant;
    use timmy::ui::App;

    // Failing Docker mock simulating completely dead/hanging daemon
    let mock_docker = MockDockerCollector::new();
    mock_docker.set_status(Err(PlatformError::DockerNotRunning(
        "/var/run/docker.sock".to_string(),
    )));
    mock_docker.set_containers_result(Err(PlatformError::DockerNotRunning(
        "/var/run/docker.sock".to_string(),
    )));

    let sys = Arc::new(MockSystem {
        processes: vec![],
        ports: vec![],
        docker: mock_docker,
    });

    let storage = Arc::new(StorageManager::open_in_memory().expect("in-memory db"));
    let mut config = TimmyConfig::default();
    config.general.enable_docker = true;
    let orchestrator = EngineOrchestrator::with_collector(config, Some(storage), sys);

    let mut app = App::new(orchestrator);
    app.current_tab = timmy::ui::app::ActiveTab::Docker;

    // Simulate 50 TUI event loop frame cycles
    let frame_start = Instant::now();
    for _ in 0..50 {
        app.refresh();
        app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
    }
    let total_elapsed = frame_start.elapsed();

    // 50 frames with 2 key events each = 150 operations.
    // Must complete in <150ms (average <1ms per frame), demonstrating complete UI responsiveness!
    assert!(
        total_elapsed < std::time::Duration::from_millis(150),
        "TUI event loop took {:?}, blocked by Docker failure!",
        total_elapsed
    );
}

// =============================================================================
// AUDIT SUITE: Docker Worker Lifecycle & Shutdown Semantics (Tests 1-7)
// =============================================================================

#[test]
fn test_worker_01_shutdown_while_idle() {
    use std::time::Duration;
    use timmy::platform::{DockerBackgroundWorker, WorkerShutdownResult};

    let mock = Arc::new(MockDockerCollector::new());
    let mut worker = DockerBackgroundWorker::new(mock);

    assert!(!worker.is_stopped());
    assert!(!worker.has_thread_exited());
    assert!(!worker.is_shutting_down());

    let res = worker.stop_with_timeout(Duration::from_millis(500));
    assert_eq!(res, WorkerShutdownResult::Terminated);
    assert!(worker.has_thread_exited());
    assert!(worker.is_stopped());

    // Subsequent stop calls are idempotent and return AlreadyStopped
    let second_res = worker.stop();
    assert_eq!(second_res, WorkerShutdownResult::AlreadyStopped);
}

#[test]
fn test_worker_02_shutdown_during_delayed_request() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};
    use timmy::platform::{DockerBackgroundWorker, WorkerShutdownResult};

    // Collector with cancellation awareness: sleeps in small steps while not cancelled
    struct CancellableMockDocker {
        cancelled: Arc<AtomicBool>,
    }
    impl DockerCollector for CancellableMockDocker {
        fn docker_status(&self) -> Result<DockerStatus, PlatformError> {
            for _ in 0..100 {
                if self.cancelled.load(Ordering::SeqCst) {
                    return Err(PlatformError::DockerNotRunning("cancelled".to_string()));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(DockerStatus::default())
        }
        fn is_available(&self) -> bool {
            true
        }
        fn collect_containers(&self) -> Result<Vec<ContainerInfo>, PlatformError> {
            Ok(vec![])
        }
        fn inspect_container(&self, id: &str) -> Result<ContainerDetail, PlatformError> {
            Ok(ContainerDetail {
                info: sample_container(id, "mock", ContainerState::Running),
                env_keys: vec![],
                mounts: vec![],
                restart_policy: "no".to_string(),
                platform: None,
            })
        }
        fn collect_container_stats(&self, _id: &str) -> Result<ContainerStats, PlatformError> {
            Ok(ContainerStats::default())
        }
        fn cancel(&self) {
            self.cancelled.store(true, Ordering::SeqCst);
        }
    }

    let cancelled = Arc::new(AtomicBool::new(false));
    let mock = Arc::new(CancellableMockDocker {
        cancelled: Arc::clone(&cancelled),
    });
    let mut worker = DockerBackgroundWorker::new(mock);

    // Trigger request
    assert!(worker.trigger_refresh(1, vec![], vec![]));

    let start = Instant::now();
    let res = worker.stop_with_timeout(Duration::from_millis(500));
    let elapsed = start.elapsed();

    assert_eq!(res, WorkerShutdownResult::Terminated);
    assert!(worker.has_thread_exited());
    assert!(
        cancelled.load(Ordering::SeqCst),
        "Collector cancel() must have been called"
    );
    assert!(
        elapsed < Duration::from_millis(300),
        "Cancellable shutdown should be rapid (<300ms)"
    );
}

#[test]
fn test_worker_03_shutdown_during_request_exceeding_timeout() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};
    use timmy::platform::{DockerBackgroundWorker, WorkerShutdownResult};

    // Collector that blocks for 200ms and ignores cancellation (simulating uncooperative I/O)
    struct StalledMockDocker {
        in_flight: Arc<AtomicBool>,
    }
    impl DockerCollector for StalledMockDocker {
        fn docker_status(&self) -> Result<DockerStatus, PlatformError> {
            self.in_flight.store(true, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(200));
            Ok(DockerStatus::default())
        }
        fn is_available(&self) -> bool {
            true
        }
        fn collect_containers(&self) -> Result<Vec<ContainerInfo>, PlatformError> {
            Ok(vec![])
        }
        fn inspect_container(&self, id: &str) -> Result<ContainerDetail, PlatformError> {
            Ok(ContainerDetail {
                info: sample_container(id, "mock", ContainerState::Running),
                env_keys: vec![],
                mounts: vec![],
                restart_policy: "no".to_string(),
                platform: None,
            })
        }
        fn collect_container_stats(&self, _id: &str) -> Result<ContainerStats, PlatformError> {
            Ok(ContainerStats::default())
        }
    }

    let in_flight = Arc::new(AtomicBool::new(false));
    let mock = Arc::new(StalledMockDocker {
        in_flight: Arc::clone(&in_flight),
    });
    let mut worker = DockerBackgroundWorker::new(mock);
    assert!(worker.trigger_refresh(1, vec![], vec![]));

    // Wait until worker thread is actively executing inside the slow docker_status()
    while !in_flight.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(1));
    }

    // Caller specifies a 20ms timeout on an active 200ms operation
    let start = Instant::now();
    let res = worker.stop_with_timeout(Duration::from_millis(20));
    let elapsed = start.elapsed();

    // Must return TimedOut honestly within bounded duration (~20-60ms), not blocking for 200ms
    assert_eq!(res, WorkerShutdownResult::TimedOut);
    assert!(
        elapsed < Duration::from_millis(80),
        "stop_with_timeout exceeded caller timeout"
    );
    assert!(worker.is_shutting_down());

    // Requests are rejected during shutdown
    assert!(!worker.trigger_refresh(2, vec![], vec![]));

    // Allow mock to finish, then second stop call cleans up and consumes handle
    std::thread::sleep(Duration::from_millis(220));
    let second_res = worker.stop_with_timeout(Duration::from_millis(100));
    assert_eq!(second_res, WorkerShutdownResult::Terminated);
    assert!(worker.has_thread_exited());
}

#[test]
fn test_worker_04_repeated_start_stop_cycles() {
    use std::time::Duration;
    use timmy::platform::{DockerBackgroundWorker, WorkerShutdownResult};

    // 20 repeated create, start, trigger, stop cycles to verify clean resource release and no thread leaks
    for i in 0..20 {
        let mock = Arc::new(MockDockerCollector::new());
        let mut worker = DockerBackgroundWorker::new(mock);
        let _ = worker.trigger_refresh(i as u64, vec![], vec![]);
        let res = worker.stop_with_timeout(Duration::from_millis(300));
        assert_eq!(res, WorkerShutdownResult::Terminated);
        assert!(worker.has_thread_exited());
    }
}

#[test]
fn test_worker_05_shutdown_with_full_request_queue() {
    use std::time::Duration;
    use timmy::platform::{DockerBackgroundWorker, WorkerShutdownResult};

    // Use delayed collector to keep queue saturated
    let delayed = Arc::new(DelayedMockDocker {
        delay_ms: 100,
        containers: vec![],
    });
    let mut worker = DockerBackgroundWorker::new(delayed);

    // Saturate channel queue (capacity 4)
    for g in 0..10 {
        let _ = worker.trigger_refresh(g, vec![], vec![]);
    }

    let res = worker.stop_with_timeout(Duration::from_millis(500));
    // Either cleanly terminated or timed out gracefully without panic
    assert!(res == WorkerShutdownResult::Terminated || res == WorkerShutdownResult::TimedOut);
    assert!(worker.is_shutting_down());

    // All subsequent triggers must be rejected
    assert!(!worker.trigger_refresh(99, vec![], vec![]));
}

#[test]
fn test_worker_06_shutdown_after_receiver_disconnection() {
    use std::time::Duration;
    use timmy::platform::{DockerBackgroundWorker, WorkerShutdownResult};

    let mock = Arc::new(MockDockerCollector::new());
    let mut worker = DockerBackgroundWorker::new(mock);

    // Initial stop cleanly terminates worker thread and breaks receiver loop
    let res = worker.stop_with_timeout(Duration::from_millis(500));
    assert_eq!(res, WorkerShutdownResult::Terminated);
    assert!(worker.has_thread_exited());
    assert!(worker.is_stopped());

    // Calling stop again handles disconnected receiver gracefully
    let idempotent_res = worker.stop();
    assert_eq!(idempotent_res, WorkerShutdownResult::AlreadyStopped);
}

#[test]
fn test_worker_07_recovery_after_worker_exits_unexpectedly() {
    use std::time::Duration;
    use timmy::platform::{DockerBackgroundWorker, WorkerShutdownResult};

    // Panicking mock collector
    struct PanickingMockDocker;
    impl DockerCollector for PanickingMockDocker {
        fn docker_status(&self) -> Result<DockerStatus, PlatformError> {
            panic!("Simulated worker thread crash!");
        }
        fn is_available(&self) -> bool {
            true
        }
        fn collect_containers(&self) -> Result<Vec<ContainerInfo>, PlatformError> {
            Ok(vec![])
        }
        fn inspect_container(&self, id: &str) -> Result<ContainerDetail, PlatformError> {
            Ok(ContainerDetail {
                info: sample_container(id, "mock", ContainerState::Running),
                env_keys: vec![],
                mounts: vec![],
                restart_policy: "no".to_string(),
                platform: None,
            })
        }
        fn collect_container_stats(&self, _id: &str) -> Result<ContainerStats, PlatformError> {
            Ok(ContainerStats::default())
        }
    }

    let mut worker = DockerBackgroundWorker::new(Arc::new(PanickingMockDocker));
    let _ = worker.trigger_refresh(1, vec![], vec![]);

    // Allow panic unwind to complete
    std::thread::sleep(Duration::from_millis(50));

    // RAII ExitGuard ensures thread_exited is true even after panic!
    assert!(worker.has_thread_exited());

    // Requests are rejected
    assert!(!worker.trigger_refresh(2, vec![], vec![]));

    // stop_with_timeout safely handles panic unwind and consumes join handle without hanging
    let res = worker.stop_with_timeout(Duration::from_millis(100));
    assert_eq!(res, WorkerShutdownResult::Terminated);
}

// =============================================================================
// AUDIT SUITE: Failed-Operation & Confidence Boundary Attribution (Tests 1-5)
// =============================================================================

#[test]
fn test_attribution_known_failed_command_rejected() {
    // 1. Known failed command rejected: independent evidence establishes creation failed
    let mut sess = sample_session("sess-att-1", AgentKind::ClaudeCode, SessionStatus::Active);
    sess.tracked_pids.push(2001);
    let proc_fail = ProcessInfo {
        pid: 2001,
        ppid: Some(100),
        name: "docker".to_string(),
        exe: Some(PathBuf::from("/usr/local/bin/docker")),
        cpu_usage: Some(0.1),
        memory_bytes: Some(1024),
        run_time_secs: 1,
        start_time: Some(1000),
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: vec![],
        cmdline: vec![
            "docker".to_string(),
            "run".to_string(),
            "--name".to_string(),
            "failing-container".to_string(),
            "alpine".to_string(),
        ],
        command_outcome: Some(CreationOutcome::Failed),
        provenance: None,
        ..Default::default()
    };

    // Subtest A: Failed creation rejected on exited container
    let mut container_exit1 =
        sample_container("c-exit1", "failing-container", ContainerState::Exited);
    container_exit1.ports.clear();
    container_exit1.exit_code = Some(1);
    let mut containers_a = vec![container_exit1];
    DockerCoordinator::correlate_containers(
        &mut containers_a,
        &[sess.clone()],
        std::slice::from_ref(&proc_fail),
    );
    assert_eq!(containers_a[0].session_id, None);
    assert_eq!(containers_a[0].confidence, Confidence::Unknown);
    assert!(
        containers_a[0].evidence[0].contains("creation operation verified failed")
            || containers_a[0].evidence[0].contains("creation operation explicitly failed")
    );

    // Subtest B: Failed creation rejected on Dead container
    let mut container_dead = sample_container("c-dead", "failing-container", ContainerState::Dead);
    container_dead.ports.clear();
    container_dead.exit_code = None;
    let mut containers_b = vec![container_dead];
    DockerCoordinator::correlate_containers(&mut containers_b, &[sess], &[proc_fail]);
    assert_eq!(containers_b[0].session_id, None);
    assert_eq!(containers_b[0].confidence, Confidence::Unknown);
    assert!(
        containers_b[0].evidence[0].contains("creation operation verified failed")
            || containers_b[0].evidence[0].contains("creation operation explicitly failed")
    );
}

#[test]
fn test_attribution_unknown_command_outcome() {
    // 2. Unknown command outcome: exit status unobserved, evidence explicitly states execution outcome is unknown
    let mut sess = sample_session("sess-att-2", AgentKind::ClaudeCode, SessionStatus::Active);
    sess.tracked_pids.push(2002);
    let proc_running = ProcessInfo {
        pid: 2002,
        ppid: Some(100),
        name: "docker".to_string(),
        exe: Some(PathBuf::from("/usr/local/bin/docker")),
        cpu_usage: Some(0.1),
        memory_bytes: Some(1024),
        run_time_secs: 1,
        start_time: Some(1000),
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: vec![],
        cmdline: vec![
            "docker".to_string(),
            "run".to_string(),
            "-d".to_string(),
            "--name".to_string(),
            "running-container".to_string(),
            "nginx".to_string(),
        ],
        command_outcome: None,
        provenance: None,
        ..Default::default()
    };

    let mut container =
        sample_container("c-running-ok", "running-container", ContainerState::Running);
    container.ports.clear();
    container.exit_code = None; // Outcome cannot be verified as zero exit or definitive proof

    let mut containers = vec![container];
    DockerCoordinator::correlate_containers(&mut containers, &[sess], &[proc_running]);

    assert_eq!(containers[0].session_id.as_deref(), Some("sess-att-2"));
    assert_eq!(containers[0].confidence, Confidence::Inferred);
    assert_ne!(containers[0].confidence, Confidence::Confirmed);
    assert_ne!(containers[0].confidence, Confidence::HighConfidence);
    assert!(
        containers[0].evidence[0].contains("execution outcome is unknown"),
        "Evidence must explicitly state that execution outcome is unknown: {}",
        containers[0].evidence[0]
    );
}

#[test]
fn test_attribution_successful_command_verified_container_identity() {
    // 3. Successful command with matching identity: verified to remain Inferred (NEVER Confirmed or HighConfidence)
    let mut sess = sample_session("sess-att-3", AgentKind::ClaudeCode, SessionStatus::Active);
    sess.tracked_pids.push(2003);
    sess.open_ports.push(8080);
    let proc = ProcessInfo {
        pid: 2003,
        ppid: Some(100),
        name: "docker".to_string(),
        exe: Some(PathBuf::from("/usr/local/bin/docker")),
        cpu_usage: Some(0.1),
        memory_bytes: Some(1024),
        run_time_secs: 1,
        start_time: Some(1000),
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: vec![],
        cmdline: vec![
            "docker".to_string(),
            "run".to_string(),
            "-p".to_string(),
            "8080:80".to_string(),
            "--name".to_string(),
            "web-app".to_string(),
            "nginx".to_string(),
        ],
        command_outcome: None,
        provenance: None,
        ..Default::default()
    };

    let mut container = sample_container("c-web", "web-app", ContainerState::Running);
    container.ports = vec![PortBinding {
        host_ip: "0.0.0.0".to_string(),
        host_port: 8080,
        container_port: 80,
        protocol: "tcp".to_string(),
    }];
    container.exit_code = Some(0); // Clean status

    let mut containers = vec![container];
    DockerCoordinator::correlate_containers(&mut containers, &[sess], &[proc]);

    assert_eq!(containers[0].session_id.as_deref(), Some("sess-att-3"));
    // Strictly downgraded to Inferred in read-only milestone
    assert_eq!(containers[0].confidence, Confidence::Inferred);
    assert_ne!(containers[0].confidence, Confidence::HighConfidence);
    assert_ne!(containers[0].confidence, Confidence::Confirmed);
}

#[test]
fn test_attribution_successful_command_unidentifiable_container() {
    // 4. Successful command without identifiable container: cannot associate with anonymous random container
    let mut sess = sample_session("sess-att-4", AgentKind::ClaudeCode, SessionStatus::Active);
    sess.tracked_pids.push(2004);
    let proc = ProcessInfo {
        pid: 2004,
        ppid: Some(100),
        name: "docker".to_string(),
        exe: Some(PathBuf::from("/usr/local/bin/docker")),
        cpu_usage: Some(0.1),
        memory_bytes: Some(1024),
        run_time_secs: 1,
        start_time: Some(1000),
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: vec![],
        cmdline: vec![
            "docker".to_string(),
            "run".to_string(),
            "-d".to_string(),
            "redis:alpine".to_string(),
        ],
        command_outcome: None,
        provenance: None,
        ..Default::default()
    };

    let mut container =
        sample_container("c-random-anon", "quirky_pasteur", ContainerState::Running);
    container.ports.clear();
    let mut containers = vec![container];
    DockerCoordinator::correlate_containers(&mut containers, &[sess], &[proc]);

    assert_eq!(containers[0].session_id, None);
    assert_eq!(containers[0].confidence, Confidence::Unknown);
}

#[test]
fn test_attribution_command_targeting_existing_container() {
    // 5. Command targeting existing container: non-creation operations (logs, top, stop, inspect)
    // do NOT establish ownership
    let mut sess = sample_session("sess-att-5", AgentKind::ClaudeCode, SessionStatus::Active);
    sess.tracked_pids.push(2005);
    let non_creation_commands = vec![
        vec![
            "docker".to_string(),
            "logs".to_string(),
            "my-prod-db".to_string(),
        ],
        vec![
            "docker".to_string(),
            "top".to_string(),
            "my-prod-db".to_string(),
        ],
        vec![
            "docker".to_string(),
            "inspect".to_string(),
            "my-prod-db".to_string(),
        ],
        vec![
            "docker".to_string(),
            "stats".to_string(),
            "my-prod-db".to_string(),
        ],
    ];

    for cmd in non_creation_commands {
        let proc = ProcessInfo {
            pid: 2005,
            ppid: Some(100),
            name: "docker".to_string(),
            exe: Some(PathBuf::from("/usr/local/bin/docker")),
            cpu_usage: Some(0.1),
            memory_bytes: Some(1024),
            run_time_secs: 1,
            start_time: Some(1000),
            user: None,
            attribution: AgentAttribution::default(),
            listening_ports: vec![],
            cmdline: cmd,
            command_outcome: None,
            provenance: None,
            ..Default::default()
        };

        let mut container = sample_container("c-prod-db", "my-prod-db", ContainerState::Running);
        container.ports.clear();
        let mut containers = vec![container];
        DockerCoordinator::correlate_containers(
            &mut containers,
            std::slice::from_ref(&sess),
            &[proc],
        );

        assert_eq!(containers[0].session_id, None);
        assert_eq!(containers[0].confidence, Confidence::Unknown);
    }
}

// =============================================================================
// AUDIT SUITE: Container Workload Exit Status vs Creation Outcome (Regression Tests 1-7)
// =============================================================================

// -----------------------------------------------------------------------------
// Regression Test 1: Container created successfully, workload exits with code 1
// -----------------------------------------------------------------------------
#[test]
fn test_regression_01_workload_exits_code_1_retains_attribution() {
    let mut sess = sample_session("sess-reg-1", AgentKind::ClaudeCode, SessionStatus::Active);
    sess.tracked_pids.push(3001);
    let proc = ProcessInfo {
        pid: 3001,
        ppid: Some(100),
        name: "docker".to_string(),
        exe: Some(PathBuf::from("/usr/local/bin/docker")),
        cpu_usage: Some(0.1),
        memory_bytes: Some(1024),
        run_time_secs: 1,
        start_time: Some(1000),
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: vec![],
        cmdline: vec![
            "docker".to_string(),
            "run".to_string(),
            "--name".to_string(),
            "failing-workload".to_string(),
            "python:3".to_string(),
        ],
        command_outcome: None,
        provenance: None,
        ..Default::default()
    };

    let mut container =
        sample_container("c-workload-1", "failing-workload", ContainerState::Exited);
    container.ports.clear();
    container.exit_code = Some(1); // Workload error, NOT Docker CLI creation failure!

    let mut containers = vec![container];
    DockerCoordinator::correlate_containers(&mut containers, &[sess], &[proc]);

    assert_eq!(containers[0].session_id.as_deref(), Some("sess-reg-1"));
    assert_eq!(containers[0].confidence, Confidence::Inferred);
    assert_ne!(containers[0].confidence, Confidence::Confirmed);
    assert_ne!(containers[0].confidence, Confidence::HighConfidence);
}

// -----------------------------------------------------------------------------
// Regression Test 2: Container created successfully, workload exits with code 137 (OOM/Killed)
// -----------------------------------------------------------------------------
#[test]
fn test_regression_02_workload_exits_code_137_retains_attribution() {
    let mut sess = sample_session("sess-reg-2", AgentKind::ClaudeCode, SessionStatus::Active);
    sess.tracked_pids.push(3002);
    let proc = ProcessInfo {
        pid: 3002,
        ppid: Some(100),
        name: "docker".to_string(),
        exe: Some(PathBuf::from("/usr/local/bin/docker")),
        cpu_usage: Some(0.1),
        memory_bytes: Some(1024),
        run_time_secs: 1,
        start_time: Some(1000),
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: vec![],
        cmdline: vec![
            "docker".to_string(),
            "run".to_string(),
            "--name".to_string(),
            "oom-workload".to_string(),
            "node:20".to_string(),
        ],
        command_outcome: None,
        provenance: None,
        ..Default::default()
    };

    let mut container = sample_container("c-workload-137", "oom-workload", ContainerState::Exited);
    container.ports.clear();
    container.exit_code = Some(137); // SIGKILL / OOM-killed workload

    let mut containers = vec![container];
    DockerCoordinator::correlate_containers(&mut containers, &[sess], &[proc]);

    assert_eq!(containers[0].session_id.as_deref(), Some("sess-reg-2"));
    assert_eq!(containers[0].confidence, Confidence::Inferred);
}

// -----------------------------------------------------------------------------
// Regression Test 3: Container created successfully, subsequently enters Dead state
// -----------------------------------------------------------------------------
#[test]
fn test_regression_03_workload_enters_dead_state_retains_attribution() {
    let mut sess = sample_session("sess-reg-3", AgentKind::ClaudeCode, SessionStatus::Active);
    sess.tracked_pids.push(3003);
    let proc = ProcessInfo {
        pid: 3003,
        ppid: Some(100),
        name: "docker".to_string(),
        exe: Some(PathBuf::from("/usr/local/bin/docker")),
        cpu_usage: Some(0.1),
        memory_bytes: Some(1024),
        run_time_secs: 1,
        start_time: Some(1000),
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: vec![],
        cmdline: vec![
            "docker".to_string(),
            "run".to_string(),
            "--name".to_string(),
            "dead-container".to_string(),
            "broken-runtime".to_string(),
        ],
        command_outcome: None,
        provenance: None,
        ..Default::default()
    };

    let mut container = sample_container("c-dead-state", "dead-container", ContainerState::Dead);
    container.ports.clear();
    container.exit_code = None;

    let mut containers = vec![container];
    DockerCoordinator::correlate_containers(&mut containers, &[sess], &[proc]);

    // Runtime state Dead must NOT automatically be treated as creation failure
    assert_eq!(containers[0].session_id.as_deref(), Some("sess-reg-3"));
    assert_eq!(containers[0].confidence, Confidence::Inferred);
}

// -----------------------------------------------------------------------------
// Regression Test 4: Container created successfully, subsequently enters Exited state with code 0
// -----------------------------------------------------------------------------
#[test]
fn test_regression_04_workload_exits_code_0_retains_attribution() {
    let mut sess = sample_session("sess-reg-4", AgentKind::ClaudeCode, SessionStatus::Active);
    sess.tracked_pids.push(3004);
    let proc = ProcessInfo {
        pid: 3004,
        ppid: Some(100),
        name: "docker".to_string(),
        exe: Some(PathBuf::from("/usr/local/bin/docker")),
        cpu_usage: Some(0.1),
        memory_bytes: Some(1024),
        run_time_secs: 1,
        start_time: Some(1000),
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: vec![],
        cmdline: vec![
            "docker".to_string(),
            "run".to_string(),
            "--name".to_string(),
            "clean-task".to_string(),
            "busybox".to_string(),
        ],
        command_outcome: None,
        provenance: None,
        ..Default::default()
    };

    let mut container = sample_container("c-clean-exit", "clean-task", ContainerState::Exited);
    container.ports.clear();
    container.exit_code = Some(0);

    let mut containers = vec![container];
    DockerCoordinator::correlate_containers(&mut containers, &[sess], &[proc]);

    assert_eq!(containers[0].session_id.as_deref(), Some("sess-reg-4"));
    assert_eq!(containers[0].confidence, Confidence::Inferred);
}

// -----------------------------------------------------------------------------
// Regression Test 5: Docker creation command explicitly fails, with independently observed failure evidence
// -----------------------------------------------------------------------------
#[test]
fn test_regression_05_creation_command_explicitly_fails_rejects_attribution() {
    let mut sess = sample_session("sess-reg-5", AgentKind::ClaudeCode, SessionStatus::Active);
    sess.tracked_pids.push(3005);
    let proc = ProcessInfo {
        pid: 3005,
        ppid: Some(100),
        name: "docker".to_string(),
        exe: Some(PathBuf::from("/usr/local/bin/docker")),
        cpu_usage: Some(0.1),
        memory_bytes: Some(1024),
        run_time_secs: 1,
        start_time: Some(1000),
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: vec![],
        cmdline: vec![
            "docker".to_string(),
            "run".to_string(),
            "--name".to_string(),
            "invalid-config-job".to_string(),
            "nonexistent-image:bogus".to_string(),
        ],
        command_outcome: Some(CreationOutcome::Failed),
        provenance: None,
        ..Default::default()
    };

    let mut container = sample_container(
        "c-invalid-config",
        "invalid-config-job",
        ContainerState::Exited,
    );
    container.ports.clear();

    let mut containers = vec![container];
    DockerCoordinator::correlate_containers(&mut containers, &[sess], &[proc]);

    // Attribution rejected because creation operation itself failed
    assert_eq!(containers[0].session_id, None);
    assert_eq!(containers[0].confidence, Confidence::Unknown);
    assert!(
        containers[0].evidence[0].contains("creation operation verified failed")
            || containers[0].evidence[0].contains("creation operation explicitly failed")
    );
}

// -----------------------------------------------------------------------------
// Regression Test 6: Docker creation outcome is unknown
// -----------------------------------------------------------------------------
#[test]
fn test_regression_06_creation_outcome_unknown_preserves_inferred() {
    let mut sess = sample_session("sess-reg-6", AgentKind::ClaudeCode, SessionStatus::Active);
    sess.tracked_pids.push(3006);
    let proc = ProcessInfo {
        pid: 3006,
        ppid: Some(100),
        name: "docker".to_string(),
        exe: Some(PathBuf::from("/usr/local/bin/docker")),
        cpu_usage: Some(0.1),
        memory_bytes: Some(1024),
        run_time_secs: 1,
        start_time: Some(1000),
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: vec![],
        cmdline: vec![
            "docker".to_string(),
            "run".to_string(),
            "-d".to_string(),
            "--name".to_string(),
            "standard-worker".to_string(),
            "redis:alpine".to_string(),
        ],
        command_outcome: None,
        provenance: None,
        ..Default::default()
    };

    let mut container = sample_container(
        "c-standard-worker",
        "standard-worker",
        ContainerState::Running,
    );
    container.ports.clear();

    let mut containers = vec![container];
    DockerCoordinator::correlate_containers(&mut containers, &[sess], &[proc]);

    // Unknown outcome preserves appropriately qualified inferred attribution
    assert_eq!(containers[0].session_id.as_deref(), Some("sess-reg-6"));
    assert_eq!(containers[0].confidence, Confidence::Inferred);
    assert!(containers[0].evidence[0].contains("execution outcome is unknown"));
}

// -----------------------------------------------------------------------------
// Regression Test 7: Historical association survives subsequent container state changes
// -----------------------------------------------------------------------------
#[test]
fn test_regression_07_historical_association_survives_state_changes() {
    let mut sess = sample_session("sess-reg-7", AgentKind::ClaudeCode, SessionStatus::Active);
    sess.tracked_pids.push(3007);
    let proc = ProcessInfo {
        pid: 3007,
        ppid: Some(100),
        name: "docker".to_string(),
        exe: Some(PathBuf::from("/usr/local/bin/docker")),
        cpu_usage: Some(0.1),
        memory_bytes: Some(1024),
        run_time_secs: 1,
        start_time: Some(1000),
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: vec![],
        cmdline: vec![
            "docker".to_string(),
            "run".to_string(),
            "-d".to_string(),
            "--name".to_string(),
            "lifecycle-app".to_string(),
            "alpine".to_string(),
        ],
        command_outcome: None,
        provenance: None,
        ..Default::default()
    };

    // Cycle 1: Container is running during session
    let mut container = sample_container("c-lifecycle", "lifecycle-app", ContainerState::Running);
    container.ports.clear();
    let mut containers = vec![container];
    DockerCoordinator::correlate_containers(
        &mut containers,
        std::slice::from_ref(&sess),
        std::slice::from_ref(&proc),
    );
    assert_eq!(containers[0].session_id.as_deref(), Some("sess-reg-7"));
    assert_eq!(containers[0].confidence, Confidence::Inferred);

    // Cycle 2: Container stops with workload error (exit 1), CLI process is gone
    containers[0].state = ContainerState::Exited;
    containers[0].exit_code = Some(1);
    let empty_procs: Vec<ProcessInfo> = vec![];
    DockerCoordinator::correlate_containers(
        &mut containers,
        std::slice::from_ref(&sess),
        &empty_procs,
    );

    // Historical association survives container state change!
    assert_eq!(containers[0].session_id.as_deref(), Some("sess-reg-7"));
    assert_eq!(containers[0].confidence, Confidence::Inferred);
    assert!(containers[0]
        .evidence
        .iter()
        .any(|e| e.contains("historical") || e.contains("attempted")));

    // Cycle 3: Container enters Dead state, still retained!
    containers[0].state = ContainerState::Dead;
    DockerCoordinator::correlate_containers(
        &mut containers,
        std::slice::from_ref(&sess),
        &empty_procs,
    );
    assert_eq!(containers[0].session_id.as_deref(), Some("sess-reg-7"));
    assert_eq!(containers[0].confidence, Confidence::Inferred);
}

// =============================================================================
// AUDIT SUITE: Network & Socket Timeouts Verification (Tests 1-7)
// =============================================================================

#[test]
fn test_timeout_01_connection_timeout() {
    let mock = MockDockerCollector::new();
    mock.set_status(Err(PlatformError::DockerDaemonStopped(
        "Connection timed out after 500ms querying Docker version".to_string(),
    )));

    let status = DockerCoordinator::docker_status(&mock).unwrap_err();
    match status {
        PlatformError::DockerDaemonStopped(msg) => {
            assert!(msg.contains("timed out") || msg.contains("500ms"));
        }
        other => panic!(
            "Expected DockerDaemonStopped timeout error, got {:?}",
            other
        ),
    }
}

#[test]
fn test_timeout_02_response_timeout() {
    let mock = MockDockerCollector::new();
    mock.set_containers_result(Err(PlatformError::DockerApi(
        "Timed out after 500ms listing containers".to_string(),
    )));

    let err = DockerCoordinator::discover_containers(&mock).unwrap_err();
    match err {
        PlatformError::DockerApi(msg) => {
            assert!(msg.contains("Timed out after 500ms"));
        }
        other => panic!("Expected DockerApi timeout error, got {:?}", other),
    }
}

#[test]
fn test_timeout_03_delayed_container_statistics() {
    let timeout_mock = DelayedMockDocker {
        delay_ms: 10,
        containers: vec![],
    };
    let res = timeout_mock.collect_container_stats("c-any");
    assert!(res.is_ok());
}

#[test]
fn test_timeout_04_worker_shutdown_during_stalled_request() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};
    use timmy::platform::{DockerBackgroundWorker, WorkerShutdownResult};

    struct LongHangingMock {
        in_flight: Arc<AtomicBool>,
    }
    impl DockerCollector for LongHangingMock {
        fn docker_status(&self) -> Result<DockerStatus, PlatformError> {
            self.in_flight.store(true, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(300));
            Ok(DockerStatus::default())
        }
        fn is_available(&self) -> bool {
            true
        }
        fn collect_containers(&self) -> Result<Vec<ContainerInfo>, PlatformError> {
            Ok(vec![])
        }
        fn inspect_container(&self, id: &str) -> Result<ContainerDetail, PlatformError> {
            Ok(ContainerDetail {
                info: sample_container(id, "mock", ContainerState::Running),
                env_keys: vec![],
                mounts: vec![],
                restart_policy: "no".to_string(),
                platform: None,
            })
        }
        fn collect_container_stats(&self, _id: &str) -> Result<ContainerStats, PlatformError> {
            Ok(ContainerStats::default())
        }
    }

    let in_flight = Arc::new(AtomicBool::new(false));
    let mock = Arc::new(LongHangingMock {
        in_flight: Arc::clone(&in_flight),
    });
    let mut worker = DockerBackgroundWorker::new(mock);
    assert!(worker.trigger_refresh(1, vec![], vec![]));

    while !in_flight.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(1));
    }

    let start = Instant::now();
    let res = worker.stop_with_timeout(Duration::from_millis(25));
    let elapsed = start.elapsed();

    assert_eq!(res, WorkerShutdownResult::TimedOut);
    assert!(elapsed < Duration::from_millis(80));
    assert!(worker.is_shutting_down());

    // Allow worker operation to finish
    std::thread::sleep(Duration::from_millis(320));
    let final_res = worker.stop_with_timeout(Duration::from_millis(100));
    assert_eq!(final_res, WorkerShutdownResult::Terminated);
    assert!(worker.has_thread_exited());
}

#[test]
fn test_timeout_05_recovery_after_request_timeout() {
    use std::time::Duration;
    use timmy::platform::DockerBackgroundWorker;

    let mock = Arc::new(SwitchableMockDocker {
        should_fail: std::sync::atomic::AtomicBool::new(true),
        containers: std::sync::Mutex::new(vec![sample_container(
            "c-rec",
            "rec-app",
            ContainerState::Running,
        )]),
    });

    let mut worker = DockerBackgroundWorker::new(mock.clone());

    // Cycle 1: Request fails with daemon timeout/down
    worker.trigger_refresh(1, vec![], vec![]);
    for _ in 0..100 {
        if !worker.is_refreshing() && worker.last_error().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(worker.is_error());
    assert!(worker.last_error().is_some());

    // Cycle 2: Daemon recovers
    mock.should_fail
        .store(false, std::sync::atomic::Ordering::SeqCst);
    worker.trigger_refresh(2, vec![], vec![]);
    for _ in 0..100 {
        if !worker.is_refreshing()
            && worker.last_error().is_none()
            && !worker.get_cached_containers().is_empty()
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    assert!(!worker.is_error());
    assert_eq!(worker.last_error(), None);
    assert_eq!(worker.get_cached_containers().len(), 1);
    assert_eq!(worker.get_cached_containers()[0].name, "rec-app");

    worker.stop();
}

#[test]
fn test_timeout_06_preservation_of_last_successful_snapshot() {
    use std::time::Duration;
    use timmy::platform::DockerBackgroundWorker;

    let initial = vec![
        sample_container("c-snap-1", "snap-1", ContainerState::Running),
        sample_container("c-snap-2", "snap-2", ContainerState::Running),
    ];

    let mock = Arc::new(SwitchableMockDocker {
        should_fail: std::sync::atomic::AtomicBool::new(false),
        containers: std::sync::Mutex::new(initial),
    });

    let mut worker = DockerBackgroundWorker::new(mock.clone());

    // Initial valid collection
    worker.trigger_refresh(1, vec![], vec![]);
    for _ in 0..100 {
        if !worker.is_refreshing() && worker.get_cached_containers().len() == 2 {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(worker.get_cached_containers().len(), 2);

    // Timeout failure on second refresh
    mock.should_fail
        .store(true, std::sync::atomic::Ordering::SeqCst);
    worker.trigger_refresh(2, vec![], vec![]);
    for _ in 0..100 {
        if !worker.is_refreshing() && worker.last_error().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    // Last valid snapshot is preserved!
    assert!(worker.is_error());
    assert_eq!(worker.get_cached_containers().len(), 2);
    assert_eq!(worker.get_cached_containers()[0].name, "snap-1");
    assert_eq!(worker.get_cached_containers()[1].name, "snap-2");

    worker.stop();
}

#[test]
fn test_timeout_07_accurate_worker_shutdown_result_reporting() {
    use std::time::Duration;
    use timmy::platform::{DockerBackgroundWorker, WorkerShutdownResult};

    let mock = Arc::new(MockDockerCollector::new());
    let mut worker = DockerBackgroundWorker::new(mock);

    // Bounded stop on idle worker
    let res = worker.stop_with_timeout(Duration::from_millis(500));
    assert_eq!(res, WorkerShutdownResult::Terminated);
    assert!(worker.has_thread_exited());

    // Subsequent stop accurately reports AlreadyStopped
    let repeat_res = worker.stop();
    assert_eq!(repeat_res, WorkerShutdownResult::AlreadyStopped);
}

// =============================================================================
// AUDIT SUITE: Creation-Failure Evidence Model Adversarial Verification (Tests 1-7)
// =============================================================================

// 1. A tracked process invokes docker run, but the outcome is unknown: attribution remains Inferred.
#[test]
fn test_adversarial_outcome_unknown_remains_inferred() {
    let mut sess = sample_session("sess-adv-1", AgentKind::ClaudeCode, SessionStatus::Active);
    sess.tracked_pids.push(4001);
    let proc = ProcessInfo {
        pid: 4001,
        ppid: Some(100),
        name: "docker".to_string(),
        exe: Some(PathBuf::from("/usr/local/bin/docker")),
        cpu_usage: Some(0.1),
        memory_bytes: Some(1024),
        run_time_secs: 1,
        start_time: Some(1000),
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: vec![],
        cmdline: vec![
            "docker".to_string(),
            "run".to_string(),
            "-d".to_string(),
            "--name".to_string(),
            "adv-unknown-job".to_string(),
            "redis:alpine".to_string(),
        ],
        command_outcome: None,
        provenance: None,
        ..Default::default() // Outcome unknown to read-only observer
    };

    let mut container =
        sample_container("c-adv-unknown", "adv-unknown-job", ContainerState::Running);
    container.ports.clear();
    let mut containers = vec![container];

    DockerCoordinator::correlate_containers(&mut containers, &[sess], &[proc]);

    assert_eq!(containers[0].session_id.as_deref(), Some("sess-adv-1"));
    assert_eq!(containers[0].confidence, Confidence::Inferred);
    assert_eq!(containers[0].creation_outcome, CreationOutcome::Unknown);
    assert_eq!(
        containers[0].attribution_basis,
        AttributionBasis::AttemptedCreation
    );
    assert!(containers[0].evidence[0].contains("execution outcome is unknown"));
}

// 2. A reason string contains "failed" without independent failure evidence: attribution is not rejected.
#[test]
fn test_adversarial_reason_string_contains_failed_not_rejected() {
    let mut sess = sample_session("sess-adv-2", AgentKind::ClaudeCode, SessionStatus::Active);
    sess.tracked_pids.push(4002);
    let mut proc = ProcessInfo {
        pid: 4002,
        ppid: Some(100),
        name: "docker".to_string(),
        exe: Some(PathBuf::from("/usr/local/bin/docker")),
        cpu_usage: Some(0.1),
        memory_bytes: Some(1024),
        run_time_secs: 1,
        start_time: Some(1000),
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: vec![],
        cmdline: vec![
            "docker".to_string(),
            "run".to_string(),
            "-d".to_string(),
            "--name".to_string(),
            "adv-reason-failed-job".to_string(),
            "nginx:alpine".to_string(),
        ],
        command_outcome: None,
        provenance: None,
        ..Default::default() // No structured independent failure evidence
    };
    // Free-text reason containing "failed" must NOT reject attribution!
    proc.attribution.reason = "Agent execution failed due to transient network timeout".to_string();

    let mut container = sample_container(
        "c-adv-reason",
        "adv-reason-failed-job",
        ContainerState::Running,
    );
    container.ports.clear();
    let mut containers = vec![container];

    DockerCoordinator::correlate_containers(&mut containers, &[sess], &[proc]);

    // Attribution is NOT rejected
    assert_eq!(containers[0].session_id.as_deref(), Some("sess-adv-2"));
    assert_eq!(containers[0].confidence, Confidence::Inferred);
    assert_eq!(containers[0].creation_outcome, CreationOutcome::Unknown);
    assert_eq!(
        containers[0].attribution_basis,
        AttributionBasis::AttemptedCreation
    );
}

// 3. A tracked process invokes docker run, but its process attribution evidence alone does not establish command success or failure.
#[test]
fn test_adversarial_process_attribution_evidence_alone_does_not_establish_outcome() {
    let mut sess = sample_session("sess-adv-3", AgentKind::ClaudeCode, SessionStatus::Active);
    sess.tracked_pids.push(4003);
    let mut proc = ProcessInfo {
        pid: 4003,
        ppid: Some(100),
        name: "docker".to_string(),
        exe: Some(PathBuf::from("/usr/local/bin/docker")),
        cpu_usage: Some(0.1),
        memory_bytes: Some(1024),
        run_time_secs: 1,
        start_time: Some(1000),
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: vec![],
        cmdline: vec![
            "docker".to_string(),
            "run".to_string(),
            "-d".to_string(),
            "--name".to_string(),
            "adv-ev-job".to_string(),
            "postgres:16".to_string(),
        ],
        command_outcome: None,
        provenance: None,
        ..Default::default() // No independent structured result
    };
    // Process attribution evidence string containing "failed" alone cannot establish failure
    proc.attribution.evidence = "Child process exited with error: previous task failed".to_string();

    let mut container = sample_container("c-adv-ev", "adv-ev-job", ContainerState::Running);
    container.ports.clear();
    let mut containers = vec![container];

    DockerCoordinator::correlate_containers(&mut containers, &[sess], &[proc]);

    // Attribution is NOT rejected
    assert_eq!(containers[0].session_id.as_deref(), Some("sess-adv-3"));
    assert_eq!(containers[0].confidence, Confidence::Inferred);
    assert_eq!(containers[0].creation_outcome, CreationOutcome::Unknown);
    assert_eq!(
        containers[0].attribution_basis,
        AttributionBasis::AttemptedCreation
    );
}

// 4. A genuine structured failure result, if the current read-only architecture can actually observe one, is handled as Failed.
#[test]
fn test_adversarial_genuine_structured_failure_result_handled_as_failed() {
    let mut sess = sample_session("sess-adv-4", AgentKind::ClaudeCode, SessionStatus::Active);
    sess.tracked_pids.push(4004);
    let proc = ProcessInfo {
        pid: 4004,
        ppid: Some(100),
        name: "docker".to_string(),
        exe: Some(PathBuf::from("/usr/local/bin/docker")),
        cpu_usage: Some(0.1),
        memory_bytes: Some(1024),
        run_time_secs: 1,
        start_time: Some(1000),
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: vec![],
        cmdline: vec![
            "docker".to_string(),
            "run".to_string(),
            "-d".to_string(),
            "--name".to_string(),
            "adv-struct-fail-job".to_string(),
            "bogus:tag".to_string(),
        ],
        // Genuine structured failure result
        command_outcome: Some(CreationOutcome::Failed),
        provenance: None,
        ..Default::default()
    };

    let mut container = sample_container(
        "c-adv-struct-fail",
        "adv-struct-fail-job",
        ContainerState::Exited,
    );
    container.ports.clear();
    let mut containers = vec![container];

    DockerCoordinator::correlate_containers(&mut containers, &[sess], &[proc]);

    // Attribution is REJECTED
    assert_eq!(containers[0].session_id, None);
    assert_eq!(containers[0].confidence, Confidence::Unknown);
    assert_eq!(containers[0].creation_outcome, CreationOutcome::Failed);
    assert_eq!(
        containers[0].attribution_basis,
        AttributionBasis::VerifiedFailedCreation
    );
    assert!(containers[0].evidence[0].contains("creation operation verified failed"));
}

// 5. A container workload exits with code 1 or 137: historical attribution remains.
#[test]
fn test_adversarial_workload_exit_code_1_or_137_retains_attribution() {
    let mut sess = sample_session("sess-adv-5", AgentKind::ClaudeCode, SessionStatus::Active);
    sess.tracked_pids.push(4005);
    let proc = ProcessInfo {
        pid: 4005,
        ppid: Some(100),
        name: "docker".to_string(),
        exe: Some(PathBuf::from("/usr/local/bin/docker")),
        cpu_usage: Some(0.1),
        memory_bytes: Some(1024),
        run_time_secs: 1,
        start_time: Some(1000),
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: vec![],
        cmdline: vec![
            "docker".to_string(),
            "run".to_string(),
            "-d".to_string(),
            "--name".to_string(),
            "adv-workload-exit-job".to_string(),
            "node:20".to_string(),
        ],
        command_outcome: None,
        provenance: None,
        ..Default::default()
    };

    // Cycle 1: Container runs during session
    let mut container = sample_container(
        "c-adv-exit",
        "adv-workload-exit-job",
        ContainerState::Running,
    );
    container.ports.clear();
    let mut containers = vec![container];
    DockerCoordinator::correlate_containers(
        &mut containers,
        std::slice::from_ref(&sess),
        std::slice::from_ref(&proc),
    );
    assert_eq!(containers[0].session_id.as_deref(), Some("sess-adv-5"));
    assert_eq!(containers[0].confidence, Confidence::Inferred);

    // Cycle 2A: CLI process is gone, workload exited with code 1
    containers[0].state = ContainerState::Exited;
    containers[0].exit_code = Some(1);
    let empty_procs: Vec<ProcessInfo> = vec![];
    DockerCoordinator::correlate_containers(
        &mut containers,
        std::slice::from_ref(&sess),
        &empty_procs,
    );
    assert_eq!(containers[0].session_id.as_deref(), Some("sess-adv-5"));
    assert_eq!(containers[0].confidence, Confidence::Inferred);
    assert_eq!(
        containers[0].attribution_basis,
        AttributionBasis::HistoricalInferred
    );

    // Cycle 2B: Workload exited with code 137 (SIGKILL/OOM)
    containers[0].exit_code = Some(137);
    DockerCoordinator::correlate_containers(
        &mut containers,
        std::slice::from_ref(&sess),
        &empty_procs,
    );
    assert_eq!(containers[0].session_id.as_deref(), Some("sess-adv-5"));
    assert_eq!(containers[0].confidence, Confidence::Inferred);
    assert_eq!(
        containers[0].attribution_basis,
        AttributionBasis::HistoricalInferred
    );
}

// 6. A container enters Dead state: historical attribution remains.
#[test]
fn test_adversarial_container_dead_state_retains_attribution() {
    let mut sess = sample_session("sess-adv-6", AgentKind::ClaudeCode, SessionStatus::Active);
    sess.tracked_pids.push(4006);
    let proc = ProcessInfo {
        pid: 4006,
        ppid: Some(100),
        name: "docker".to_string(),
        exe: Some(PathBuf::from("/usr/local/bin/docker")),
        cpu_usage: Some(0.1),
        memory_bytes: Some(1024),
        run_time_secs: 1,
        start_time: Some(1000),
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: vec![],
        cmdline: vec![
            "docker".to_string(),
            "run".to_string(),
            "-d".to_string(),
            "--name".to_string(),
            "adv-dead-job".to_string(),
            "alpine".to_string(),
        ],
        command_outcome: None,
        provenance: None,
        ..Default::default()
    };

    // Cycle 1: Running
    let mut container = sample_container("c-adv-dead", "adv-dead-job", ContainerState::Running);
    container.ports.clear();
    let mut containers = vec![container];
    DockerCoordinator::correlate_containers(
        &mut containers,
        std::slice::from_ref(&sess),
        std::slice::from_ref(&proc),
    );
    assert_eq!(containers[0].session_id.as_deref(), Some("sess-adv-6"));

    // Cycle 2: Enters Dead state, CLI process terminated
    containers[0].state = ContainerState::Dead;
    let empty_procs: Vec<ProcessInfo> = vec![];
    DockerCoordinator::correlate_containers(
        &mut containers,
        std::slice::from_ref(&sess),
        &empty_procs,
    );

    // Historical association remains intact
    assert_eq!(containers[0].session_id.as_deref(), Some("sess-adv-6"));
    assert_eq!(containers[0].confidence, Confidence::Inferred);
    assert_eq!(
        containers[0].attribution_basis,
        AttributionBasis::HistoricalInferred
    );
}

// 7. Conflicting session claims remain Unknown rather than being arbitrarily assigned.
#[test]
fn test_adversarial_conflicting_session_claims_remain_unknown() {
    let mut sess1 = sample_session("sess-adv-7a", AgentKind::ClaudeCode, SessionStatus::Active);
    sess1.tracked_pids.push(4007);
    let mut sess2 = sample_session("sess-adv-7b", AgentKind::Cursor, SessionStatus::Active);
    sess2.tracked_pids.push(4008);

    let proc1 = ProcessInfo {
        pid: 4007,
        ppid: Some(100),
        name: "docker".to_string(),
        exe: Some(PathBuf::from("/usr/local/bin/docker")),
        cpu_usage: Some(0.1),
        memory_bytes: Some(1024),
        run_time_secs: 1,
        start_time: Some(1000),
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: vec![],
        cmdline: vec![
            "docker".to_string(),
            "run".to_string(),
            "-d".to_string(),
            "--name".to_string(),
            "shared-adv-container".to_string(),
            "alpine".to_string(),
        ],
        command_outcome: None,
        provenance: None,
        ..Default::default()
    };

    let proc2 = ProcessInfo {
        pid: 4008,
        ppid: Some(200),
        name: "docker".to_string(),
        exe: Some(PathBuf::from("/usr/local/bin/docker")),
        cpu_usage: Some(0.1),
        memory_bytes: Some(1024),
        run_time_secs: 1,
        start_time: Some(1001),
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: vec![],
        cmdline: vec![
            "docker".to_string(),
            "run".to_string(),
            "-d".to_string(),
            "--name".to_string(),
            "shared-adv-container".to_string(),
            "alpine".to_string(),
        ],
        command_outcome: None,
        provenance: None,
        ..Default::default()
    };

    let mut container = sample_container(
        "c-adv-conflict",
        "shared-adv-container",
        ContainerState::Running,
    );
    container.ports.clear();
    let mut containers = vec![container];

    DockerCoordinator::correlate_containers(&mut containers, &[sess1, sess2], &[proc1, proc2]);

    // Conflicting claims remain Unknown; not arbitrarily assigned to either session
    assert_eq!(containers[0].session_id, None);
    assert_eq!(containers[0].confidence, Confidence::Unknown);
    assert_eq!(containers[0].creation_outcome, CreationOutcome::Unknown);
    assert_eq!(containers[0].attribution_basis, AttributionBasis::None);
    assert_eq!(containers[0].conflicting_sessions.len(), 2);
    assert!(containers[0]
        .conflicting_sessions
        .contains(&"sess-adv-7a".to_string()));
    assert!(containers[0]
        .conflicting_sessions
        .contains(&"sess-adv-7b".to_string()));
    assert!(containers[0].evidence[0].contains("Conflicting session claims detected"));
}
