use chrono::Utc;
use std::path::PathBuf;
use timmy::engine::lineage::{build_session_lineage_tree, format_lineage_tree_unicode};
use timmy::model::agent::{AgentKind, Confidence};
use timmy::model::lineage::{LineageSource, LineageStatus, ProcessLineageEdge};
use timmy::model::process::{ProcessIncarnation, ProcessStartTime};
use timmy::model::provenance::{LaunchProvenance, ProcessIdentity, ProvenanceSource};
use timmy::model::session::{SessionInfo, SessionStatus, TrackedResource};
use timmy::safety::masker::SecretMasker;

fn make_start_time(sec: u64, usec: u64) -> ProcessStartTime {
    ProcessStartTime::new(sec, usec)
}

fn make_incarnation(pid: u32, sec: u64, usec: u64) -> ProcessIncarnation {
    ProcessIncarnation::new(pid, make_start_time(sec, usec))
}

fn make_edge(
    session_id: &str,
    parent: ProcessIncarnation,
    child: ProcessIncarnation,
    parent_name: &str,
    child_name: &str,
    status: LineageStatus,
) -> ProcessLineageEdge {
    let now = Utc::now();
    ProcessLineageEdge {
        id: None,
        session_id: session_id.to_string(),
        parent,
        child,
        parent_name: Some(parent_name.to_string()),
        parent_exe: Some(PathBuf::from(format!("/bin/{}", parent_name))),
        child_name: child_name.to_string(),
        child_exe: Some(PathBuf::from(format!("/bin/{}", child_name))),
        first_observed_at: now,
        last_observed_at: now,
        observation_count: 1,
        source: LineageSource::CompleteSnapshotObservation,
        status,
        snapshot_id: None,
        validation_details: None,
    }
}

fn make_resource(
    session_id: &str,
    pid: u32,
    name: &str,
    start_time: ProcessStartTime,
    ports: Vec<u16>,
    is_detached: bool,
    evidence: Vec<String>,
) -> TrackedResource {
    let now = Utc::now();
    let prov = LaunchProvenance {
        session_id: session_id.to_string(),
        source: ProvenanceSource::DiscoveredDescendant,
        process: ProcessIdentity {
            pid,
            start_time: Some(start_time.tv_sec),
            start_time_precise: Some(start_time),
            name: name.to_string(),
            exe: Some(PathBuf::from(format!("/bin/{}", name))),
        },
        parent: None,
        observed_at: now,
        details: "test resource".to_string(),
    };

    TrackedResource {
        session_id: session_id.to_string(),
        pid: Some(pid),
        name: name.to_string(),
        exe_path: Some(format!("/bin/{}", name)),
        memory_bytes: Some(1024 * 1024 * 50),
        cpu_usage: Some(1.5),
        listening_ports: ports,
        confidence: Confidence::Confirmed,
        evidence,
        is_detached,
        is_protected: false,
        safe_to_terminate: true,
        first_seen: now,
        last_seen: now,
        process_start_time: Some(start_time.tv_sec),
        provenance: Some(prov),
    }
}

#[test]
fn test_lineage_tree_basic_hierarchy() {
    let now = Utc::now();
    let session = SessionInfo {
        id: "sess_tree_01".to_string(),
        agent_kind: AgentKind::ClaudeCode,
        status: SessionStatus::Active,
        start_time: now,
        end_time: None,
        root_pid: Some(100),
        root_process_name: Some("claude".to_string()),
        confidence: Confidence::Confirmed,
        evidence: vec!["root process binary matched claude".to_string()],
        tracked_pids: vec![100, 101, 102],
        total_memory_bytes: 1024 * 1024 * 150,
        total_cpu_usage: 4.5,
        open_ports: vec![3000],
        resource_count: 3,
        root_binding: None,
    };

    let p100 = make_incarnation(100, 1000, 0);
    let p101 = make_incarnation(101, 1001, 0);
    let p102 = make_incarnation(102, 1002, 0);

    let edges = vec![
        make_edge(
            "sess_tree_01",
            p100,
            p101,
            "claude",
            "node-server",
            LineageStatus::BothActive,
        ),
        make_edge(
            "sess_tree_01",
            p101,
            p102,
            "node-server",
            "worker",
            LineageStatus::BothActive,
        ),
    ];

    let r100 = make_resource(
        "sess_tree_01",
        100,
        "claude",
        p100.start_time,
        vec![],
        false,
        vec![],
    );
    let r101 = make_resource(
        "sess_tree_01",
        101,
        "node-server",
        p101.start_time,
        vec![3000],
        false,
        vec![],
    );
    let r102 = make_resource(
        "sess_tree_01",
        102,
        "worker",
        p102.start_time,
        vec![],
        false,
        vec![],
    );

    let resources = vec![r100, r101, r102];

    let tree = build_session_lineage_tree(&session, &resources, &edges, false);
    assert_eq!(tree.len(), 1, "Should have 1 root node (PID 100)");
    assert_eq!(tree[0].pid, 100);
    assert!(tree[0].is_root);
    assert!(tree[0].is_active);
    assert_eq!(
        tree[0].children.len(),
        1,
        "Root should have 1 child (PID 101)"
    );
    assert_eq!(tree[0].children[0].pid, 101);
    assert_eq!(tree[0].children[0].ports, vec![3000]);
    assert_eq!(
        tree[0].children[0].children.len(),
        1,
        "PID 101 should have 1 child (PID 102)"
    );
    assert_eq!(tree[0].children[0].children[0].pid, 102);

    // Format unicode tree
    let masker = SecretMasker::new();
    let formatted = format_lineage_tree_unicode(&tree, &masker);
    assert!(formatted.contains("PID 100 (claude) [ROOT]"));
    assert!(formatted.contains("PID 101 (node-server)"));
    assert!(formatted.contains("Ports: [3000]"));
    assert!(formatted.contains("PID 102 (worker)"));
}

#[test]
fn test_lineage_tree_reparented_child_and_exited_parent() {
    let now = Utc::now();
    let session = SessionInfo {
        id: "sess_tree_02".to_string(),
        agent_kind: AgentKind::ClaudeCode,
        status: SessionStatus::Active,
        start_time: now,
        end_time: None,
        root_pid: Some(200),
        root_process_name: Some("claude".to_string()),
        confidence: Confidence::Confirmed,
        evidence: vec!["root process binary matched claude".to_string()],
        tracked_pids: vec![200, 201],
        total_memory_bytes: 1024 * 1024 * 100,
        total_cpu_usage: 2.0,
        open_ports: vec![8080],
        resource_count: 2,
        root_binding: None,
    };

    let p200 = make_incarnation(200, 2000, 0);
    let p201 = make_incarnation(201, 2001, 0);

    let edges = vec![make_edge(
        "sess_tree_02",
        p200,
        p201,
        "claude",
        "webpack-dev-server",
        LineageStatus::ParentExited,
    )];

    let r201 = make_resource(
        "sess_tree_02",
        201,
        "webpack-dev-server",
        p201.start_time,
        vec![8080],
        true,
        vec![],
    );
    let resources = vec![r201];

    // With show_exited = true: parent node is created as [EXITED]
    let tree_with_exited = build_session_lineage_tree(&session, &resources, &edges, true);
    assert_eq!(tree_with_exited.len(), 1);
    assert_eq!(tree_with_exited[0].pid, 200);
    assert!(
        !tree_with_exited[0].is_active,
        "Parent should be marked exited"
    );
    assert_eq!(tree_with_exited[0].children.len(), 1);
    assert_eq!(tree_with_exited[0].children[0].pid, 201);
    assert!(tree_with_exited[0].children[0].is_active);

    let masker = SecretMasker::new();
    let formatted = format_lineage_tree_unicode(&tree_with_exited, &masker);
    assert!(formatted.contains("[EXITED] PID 200 (claude) [ROOT]"));
    assert!(formatted.contains("[ACTIVE] PID 201 (webpack-dev-server)"));
    assert!(formatted.contains("Ports: [8080]"));

    // With show_exited = false: exited parent is omitted, child reparented to PID 1 becomes top-level detached
    let tree_active_only = build_session_lineage_tree(&session, &resources, &edges, false);
    assert_eq!(tree_active_only.len(), 1);
    assert_eq!(tree_active_only[0].pid, 201);
    assert!(tree_active_only[0].is_detached);
    assert!(tree_active_only[0].is_active);

    let formatted_active = format_lineage_tree_unicode(&tree_active_only, &masker);
    assert!(
        formatted_active.contains("[ACTIVE] PID 201 (webpack-dev-server) [Reparented to PID 1]")
    );
}

#[test]
fn test_lineage_tree_secret_masking() {
    let now = Utc::now();
    let session = SessionInfo {
        id: "sess_tree_03".to_string(),
        agent_kind: AgentKind::ClaudeCode,
        status: SessionStatus::Active,
        start_time: now,
        end_time: None,
        root_pid: Some(300),
        root_process_name: Some("worker_sk-ant-secret1234567".to_string()),
        confidence: Confidence::Confirmed,
        evidence: vec!["token=sk-ant-api03-abcdef123456789".to_string()],
        tracked_pids: vec![300],
        total_memory_bytes: 1024 * 1024 * 50,
        total_cpu_usage: 1.0,
        open_ports: vec![],
        resource_count: 1,
        root_binding: None,
    };

    let p300 = make_incarnation(300, 3000, 0);
    let r300 = make_resource(
        "sess_tree_03",
        300,
        "worker_sk-ant-secret1234567",
        p300.start_time,
        vec![],
        false,
        vec!["token=sk-ant-api03-abcdef123456789".to_string()],
    );

    let tree = build_session_lineage_tree(&session, &[r300], &[], false);
    let masker = SecretMasker::new();
    let formatted = format_lineage_tree_unicode(&tree, &masker);

    // Verify secret tokens were masked and not leaked
    assert!(!formatted.contains("sk-ant-secret1234567"));
    assert!(!formatted.contains("sk-ant-api03-abcdef123456789"));
    assert!(formatted.contains("[REDACTED]"));
}

#[test]
fn test_lineage_tree_pid_reuse_rejection() {
    let now = Utc::now();
    let session = SessionInfo {
        id: "sess_tree_04".to_string(),
        agent_kind: AgentKind::ClaudeCode,
        status: SessionStatus::Active,
        start_time: now,
        end_time: None,
        root_pid: Some(400),
        root_process_name: Some("claude".to_string()),
        confidence: Confidence::Confirmed,
        evidence: vec!["root".to_string()],
        tracked_pids: vec![400, 401],
        total_memory_bytes: 1024 * 1024 * 50,
        total_cpu_usage: 1.0,
        open_ports: vec![],
        resource_count: 2,
        root_binding: None,
    };

    let p400 = make_incarnation(400, 4000, 0);
    // Historical child had start time (4001, 0)
    let p401_orig = make_incarnation(401, 4001, 0);
    // New process that reused PID 401 has start time (5000, 0)
    let p401_reused_st = make_start_time(5000, 0);

    let edges = vec![make_edge(
        "sess_tree_04",
        p400,
        p401_orig,
        "claude",
        "child-worker",
        LineageStatus::BothActive,
    )];

    let r400 = make_resource(
        "sess_tree_04",
        400,
        "claude",
        p400.start_time,
        vec![],
        false,
        vec![],
    );
    // Reused PID 401 process in resources has the newer start time
    let r401_reused = make_resource(
        "sess_tree_04",
        401,
        "unrelated-daemon",
        p401_reused_st,
        vec![],
        false,
        vec![],
    );

    let resources = vec![r400, r401_reused];

    // Tree built with show_exited = false
    let tree = build_session_lineage_tree(&session, &resources, &edges, false);
    // Root should have 0 children because the original child (4001, 0) is no longer active,
    // and the new process (5000, 0) doesn't match the historical incarnation!
    assert_eq!(
        tree[0].children.len(),
        0,
        "Reused PID process must not be attached as child of root"
    );
}

#[test]
fn test_lineage_tree_unobserved_orphan() {
    let now = Utc::now();
    let session = SessionInfo {
        id: "sess_tree_05".to_string(),
        agent_kind: AgentKind::ClaudeCode,
        status: SessionStatus::Active,
        start_time: now,
        end_time: None,
        root_pid: Some(500),
        root_process_name: Some("claude".to_string()),
        confidence: Confidence::Confirmed,
        evidence: vec!["root".to_string()],
        tracked_pids: vec![500, 501],
        total_memory_bytes: 1024 * 1024 * 50,
        total_cpu_usage: 1.0,
        open_ports: vec![9000],
        resource_count: 2,
        root_binding: None,
    };

    let p500 = make_incarnation(500, 5000, 0);
    let p501 = make_incarnation(501, 5001, 0);

    let r500 = make_resource(
        "sess_tree_05",
        500,
        "claude",
        p500.start_time,
        vec![],
        false,
        vec![],
    );
    // Process 501 was discovered heuristically / unobserved orphan under PID 1 (no edge to root 500)
    let r501 = make_resource(
        "sess_tree_05",
        501,
        "orphan-service",
        p501.start_time,
        vec![9000],
        true,
        vec![],
    );

    let resources = vec![r500, r501];

    let tree = build_session_lineage_tree(&session, &resources, &[], false);
    // Both 500 (root) and 501 (detached orphan) appear at the top level
    assert_eq!(tree.len(), 2);
    assert_eq!(tree[0].pid, 500);
    assert!(tree[0].is_root);
    assert_eq!(tree[1].pid, 501);
    assert!(tree[1].is_detached);
}
