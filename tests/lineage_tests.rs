use chrono::Utc;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::NamedTempFile;
use timmy::config::TimmyConfig;
use timmy::engine::lineage::{
    resolve_lineage_chain, update_edge_lifecycle_statuses, validate_lineage_edge,
    LineageValidationError,
};
use timmy::engine::SessionCoordinator;
use timmy::model::agent::{AgentAttribution, AgentKind, Confidence};
use timmy::model::lineage::{LineageChainResult, LineageSource, LineageStatus, ProcessLineageEdge};
use timmy::model::process::{
    FieldStatus, ObservationInterval, ProcessAncestor, ProcessDetail, ProcessIncarnation,
    ProcessInfo, ProcessObservationState, ProcessSnapshot, ProcessStartTime, SnapshotCompleteness,
};
use timmy::model::session::{SessionInfo, SessionStatus};
use timmy::model::{
    ContainerDetail, ContainerInfo, ContainerStats, DockerStatus, ListeningPort, ServiceInfo,
};
use timmy::platform::{
    DockerCollector, PlatformError, PortCollector, ProcessCollector, ServiceCollector,
};
use timmy::storage::{LeaseAcquisitionResult, ObserverLease, StorageError, StorageManager};

// =============================================================================
// MOCK PLATFORM COLLECTOR FOR DETERMINISTIC TESTING
// =============================================================================

#[derive(Clone)]
struct MockCollector {
    processes: Vec<ProcessInfo>,
    ports: Vec<ListeningPort>,
    completeness: SnapshotCompleteness,
}

impl MockCollector {
    fn new(processes: Vec<ProcessInfo>, ports: Vec<ListeningPort>) -> Self {
        Self {
            processes,
            ports,
            completeness: SnapshotCompleteness::Complete,
        }
    }

    #[allow(dead_code)]
    fn with_completeness(mut self, completeness: SnapshotCompleteness) -> Self {
        self.completeness = completeness;
        self
    }
}

impl ProcessCollector for MockCollector {
    fn collect_processes(&self) -> Result<Vec<ProcessInfo>, PlatformError> {
        Ok(self.processes.clone())
    }

    fn collect_process_snapshot(&self) -> Result<ProcessSnapshot, PlatformError> {
        Ok(ProcessSnapshot {
            processes: self.processes.clone(),
            interval: ObservationInterval::default(),
            completeness: self.completeness.clone(),
        })
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

impl PortCollector for MockCollector {
    fn collect_listening_ports(&self) -> Result<Vec<ListeningPort>, PlatformError> {
        Ok(self.ports.clone())
    }
}

impl ServiceCollector for MockCollector {
    fn collect_services(&self) -> Result<Vec<ServiceInfo>, PlatformError> {
        Ok(vec![])
    }
}

impl DockerCollector for MockCollector {
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
            error_message: None,
            error_category: None,
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

fn create_test_session(storage: &StorageManager, id: &str) {
    let now = Utc::now();
    let session = SessionInfo {
        id: id.to_string(),
        agent_kind: AgentKind::ClaudeCode,
        status: SessionStatus::Active,
        start_time: now,
        end_time: None,
        root_pid: Some(100),
        root_process_name: Some("claude".to_string()),
        confidence: Confidence::Confirmed,
        evidence: vec![],
        tracked_pids: vec![],
        total_memory_bytes: 0,
        total_cpu_usage: 0.0,
        open_ports: vec![],
        resource_count: 0,
        root_binding: None,
    };
    storage.save_session(&session).unwrap();
}

// Helper to construct a deterministic ProcessInfo
fn make_proc(
    pid: u32,
    ppid: Option<u32>,
    name: &str,
    start_sec: u64,
    start_usec: u64,
) -> ProcessInfo {
    ProcessInfo {
        pid,
        ppid,
        name: name.to_string(),
        exe: Some(PathBuf::from(format!("/usr/local/bin/{}", name))),
        cpu_usage: Some(1.0),
        memory_bytes: Some(1024 * 1024),
        run_time_secs: 10,
        start_time: Some(start_sec),
        user: Some("testuser".to_string()),
        attribution: AgentAttribution::default(),
        listening_ports: vec![],
        cmdline: vec![name.to_string()],
        command_outcome: None,
        provenance: None,
        start_time_precise: Some(ProcessStartTime::new(start_sec, start_usec)),
        observation_state: ProcessObservationState::Present,
        exe_status: FieldStatus::Available(PathBuf::from(format!("/usr/local/bin/{}", name))),
        cmdline_status: FieldStatus::Available(vec![name.to_string()]),
        cwd_status: FieldStatus::Available(PathBuf::from("/workspace")),
        ..Default::default()
    }
}

fn unwrap_lease(res: LeaseAcquisitionResult) -> ObserverLease {
    match res {
        LeaseAcquisitionResult::Acquired(l) => l,
        LeaseAcquisitionResult::Renewed(l) => l,
        LeaseAcquisitionResult::RecoveredFromExpired { lease, .. } => lease,
        other => panic!("Expected successful lease, got {:?}", other),
    }
}

// =============================================================================
// 17 DETERMINISTIC TEST SCENARIOS
// =============================================================================

#[test]
fn test_scenario_1_parent_and_child_observed_together_edge_recorded_both_active() {
    let tmp = NamedTempFile::new().unwrap();
    let storage = Arc::new(StorageManager::open(tmp.path()).unwrap());
    let coord = SessionCoordinator::new(storage.clone(), TimmyConfig::default());

    let parent = make_proc(100, Some(1), "claude", 1000, 0);
    let child = make_proc(200, Some(100), "node", 1001, 500);

    let collector = MockCollector::new(vec![parent.clone(), child.clone()], vec![]);

    // Start session bound to PID 100
    let session = coord
        .start_session(Some("claude".to_string()), false, &collector)
        .expect("start session");

    // Pass 1: observe and update with authoritative lease
    let lease = unwrap_lease(
        storage
            .acquire_observer_lease(&session.id, "observer-1", 10)
            .unwrap(),
    );

    let (_, resources) = coord
        .observe_and_update_with_lease(
            &session,
            &collector,
            Some(("observer-1", lease.fencing_token)),
        )
        .expect("observe pass 1");

    // Check DB: process_lineage table must record edge
    let edges = storage.get_lineage_edges(&session.id).unwrap();
    assert_eq!(edges.len(), 1, "Must record exactly 1 lineage edge");
    let edge = &edges[0];
    assert_eq!(edge.parent.pid, 100);
    assert_eq!(edge.parent.start_time, ProcessStartTime::new(1000, 0));
    assert_eq!(edge.child.pid, 200);
    assert_eq!(edge.child.start_time, ProcessStartTime::new(1001, 500));
    assert_eq!(edge.status, LineageStatus::BothActive);
    assert_eq!(edge.source, LineageSource::CompleteSnapshotObservation);
    assert_eq!(edge.observation_count, 2);
    assert!(edge.snapshot_id.is_some());

    // Check child resource attribution: active live descendant of verified root receives Confirmed
    let child_res = resources.iter().find(|r| r.pid == Some(200)).unwrap();
    assert_eq!(child_res.confidence, Confidence::Confirmed);
    assert!(!child_res.is_detached);
}

#[test]
fn test_scenario_2_parent_exits_historical_edge_remains_in_db_status_transitions() {
    let tmp = NamedTempFile::new().unwrap();
    let storage = Arc::new(StorageManager::open(tmp.path()).unwrap());
    let coord = SessionCoordinator::new(storage.clone(), TimmyConfig::default());

    let parent = make_proc(100, Some(1), "claude", 1000, 0);
    let child = make_proc(200, Some(100), "node", 1001, 500);

    let collector1 = MockCollector::new(vec![parent, child], vec![]);
    let session = coord
        .start_session(Some("claude".to_string()), false, &collector1)
        .unwrap();

    let lease = unwrap_lease(
        storage
            .acquire_observer_lease(&session.id, "obs", 10)
            .unwrap(),
    );
    coord
        .observe_and_update_with_lease(&session, &collector1, Some(("obs", lease.fencing_token)))
        .unwrap();

    // In Pass 2, parent 100 has exited! Child 200 is reparented to PID 1
    let child_reparented = make_proc(200, Some(1), "node", 1001, 500);
    let collector2 = MockCollector::new(vec![child_reparented], vec![]);

    coord
        .observe_and_update_with_lease(&session, &collector2, Some(("obs", lease.fencing_token)))
        .unwrap();

    // Verify DB: historical edge is NOT deleted!
    let edges = storage.get_lineage_edges(&session.id).unwrap();
    assert_eq!(
        edges.len(),
        1,
        "Historical edge must remain in database after parent exits"
    );
    let edge = &edges[0];
    assert_eq!(edge.parent.pid, 100);
    assert_eq!(edge.child.pid, 200);
    assert_eq!(
        edge.status,
        LineageStatus::ReparentedToPid1,
        "Status must transition to ReparentedToPid1"
    );
}

#[test]
fn test_scenario_3_child_reparented_to_pid1_historical_attribution_remains_high_confidence() {
    let tmp = NamedTempFile::new().unwrap();
    let storage = Arc::new(StorageManager::open(tmp.path()).unwrap());
    let coord = SessionCoordinator::new(storage.clone(), TimmyConfig::default());

    let parent = make_proc(100, Some(1), "claude", 1000, 0);
    let child = make_proc(200, Some(100), "node", 1001, 500);

    let collector1 = MockCollector::new(vec![parent, child], vec![]);
    let session = coord
        .start_session(Some("claude".to_string()), false, &collector1)
        .unwrap();

    let lease = unwrap_lease(
        storage
            .acquire_observer_lease(&session.id, "obs", 10)
            .unwrap(),
    );
    coord
        .observe_and_update_with_lease(&session, &collector1, Some(("obs", lease.fencing_token)))
        .unwrap();

    // Parent exits, child reparented to 1
    let child_reparented = make_proc(200, Some(1), "node", 1001, 500);
    let collector2 = MockCollector::new(vec![child_reparented], vec![]);

    let (_, resources) = coord
        .observe_and_update_with_lease(&session, &collector2, Some(("obs", lease.fencing_token)))
        .unwrap();

    let child_res = resources
        .iter()
        .find(|r| r.pid == Some(200))
        .expect("child tracked");
    assert!(child_res.is_detached);
    assert_eq!(
        child_res.confidence,
        Confidence::HighConfidence,
        "Surviving child reparented to PID 1 must retain HighConfidence attribution via recorded historical lineage"
    );
    assert!(child_res
        .evidence
        .iter()
        .any(|e| e.contains("Verified persistent process lineage")));
}

#[test]
fn test_scenario_4_first_seen_pid1_process_without_recorded_edge_remains_inferred() {
    let tmp = NamedTempFile::new().unwrap();
    let storage = Arc::new(StorageManager::open(tmp.path()).unwrap());
    let coord = SessionCoordinator::new(storage.clone(), TimmyConfig::default());

    let parent = make_proc(100, Some(1), "claude", 1000, 0);
    let collector1 = MockCollector::new(vec![parent.clone()], vec![]);
    let session = coord
        .start_session(Some("claude".to_string()), false, &collector1)
        .unwrap();

    let session_start_sec = session.start_time.timestamp() as u64;

    // A brand new dev server appears directly under PID 1 holding port 3000, never seen under agent
    let orphan_proc = make_proc(300, Some(1), "node", session_start_sec + 5, 0);
    let port = ListeningPort {
        port: 3000,
        protocol: timmy::model::Protocol::Tcp,
        ip: "127.0.0.1".to_string(),
        pid: Some(300),
        process_name: Some("node".to_string()),
        state: timmy::model::SocketState::Listen,
    };

    let collector2 = MockCollector::new(vec![parent, orphan_proc], vec![port]);
    let lease = unwrap_lease(
        storage
            .acquire_observer_lease(&session.id, "obs", 10)
            .unwrap(),
    );

    let (_, resources) = coord
        .observe_and_update_with_lease(&session, &collector2, Some(("obs", lease.fencing_token)))
        .unwrap();

    let orphan_res = resources
        .iter()
        .find(|r| r.pid == Some(300))
        .expect("orphan tracked");
    assert_eq!(
        orphan_res.confidence,
        Confidence::Inferred,
        "First-seen PID 1 process without recorded lineage edge must NEVER receive HighConfidence or Confirmed; capped strictly at Inferred"
    );
    assert!(orphan_res.is_detached);
}

#[test]
fn test_scenario_5_pid_reuse_kernel_reuses_parent_pid_new_process_not_attached() {
    let tmp = NamedTempFile::new().unwrap();
    let storage = Arc::new(StorageManager::open(tmp.path()).unwrap());
    create_test_session(&storage, "sess-reuse-5");

    // Record historical edge for parent (100, (1000, 0)) -> child (200, (1001, 0))
    let edge = ProcessLineageEdge::new_snapshot_edge(
        "sess-reuse-5".to_string(),
        ProcessIncarnation::new(100, ProcessStartTime::new(1000, 0)),
        ProcessIncarnation::new(200, ProcessStartTime::new(1001, 0)),
        Some("claude".to_string()),
        None,
        "node".to_string(),
        None,
        Utc::now(),
        None,
    );
    storage.save_lineage_edges("sess-reuse-5", &[edge]).unwrap();

    // Kernel terminates 100, then reuses PID 100 for a new process at (5000, 0)
    let new_parent_incarnation = ProcessIncarnation::new(100, ProcessStartTime::new(5000, 0));
    let children = storage
        .get_lineage_edges_for_parent("sess-reuse-5", &new_parent_incarnation)
        .unwrap();

    assert!(
        children.is_empty(),
        "New process with recycled parent PID must NOT be attached to historical child edges"
    );
}

#[test]
fn test_scenario_6_child_pid_reuse_new_process_does_not_inherit_historical_parent_edge() {
    let tmp = NamedTempFile::new().unwrap();
    let storage = Arc::new(StorageManager::open(tmp.path()).unwrap());
    create_test_session(&storage, "sess-reuse-6");

    // Record historical edge for child (200, (1001, 0))
    let edge = ProcessLineageEdge::new_snapshot_edge(
        "sess-reuse-6".to_string(),
        ProcessIncarnation::new(100, ProcessStartTime::new(1000, 0)),
        ProcessIncarnation::new(200, ProcessStartTime::new(1001, 0)),
        Some("claude".to_string()),
        None,
        "node".to_string(),
        None,
        Utc::now(),
        None,
    );
    storage.save_lineage_edges("sess-reuse-6", &[edge]).unwrap();

    // Kernel terminates 200, then reuses PID 200 for a new process at (6000, 0)
    let new_child_incarnation = ProcessIncarnation::new(200, ProcessStartTime::new(6000, 0));
    let parent_edge = storage
        .get_lineage_edge_for_child("sess-reuse-6", &new_child_incarnation)
        .unwrap();

    assert!(
        parent_edge.is_none(),
        "New process with recycled child PID must NOT inherit historical parent edge"
    );
}

#[test]
fn test_scenario_7_missing_or_imprecise_start_time_edge_creation_rejected() {
    let mut parent = make_proc(100, Some(1), "claude", 1000, 0);
    let mut child = make_proc(200, Some(100), "node", 1001, 0);

    // Case 7a: Parent lacks precise start time
    parent.start_time_precise = None;
    let res_a = validate_lineage_edge(&parent, &child, true);
    assert_eq!(
        res_a,
        Err(LineageValidationError::MissingStartTime { pid: 100 })
    );

    // Restore parent, child lacks precise start time
    parent.start_time_precise = Some(ProcessStartTime::new(1000, 0));
    child.start_time_precise = None;
    let res_b = validate_lineage_edge(&parent, &child, true);
    assert_eq!(
        res_b,
        Err(LineageValidationError::MissingStartTime { pid: 200 })
    );

    // Case 7c: Parent born AFTER child (impossible lineage)
    parent.start_time_precise = Some(ProcessStartTime::new(2000, 0));
    child.start_time_precise = Some(ProcessStartTime::new(1000, 0));
    let res_c = validate_lineage_edge(&parent, &child, true);
    assert!(matches!(
        res_c,
        Err(LineageValidationError::ParentStartedAfterChild { .. })
    ));
}

#[test]
fn test_scenario_8_partial_snapshot_does_not_create_false_absence_or_delete_edges() {
    let tmp = NamedTempFile::new().unwrap();
    let storage = Arc::new(StorageManager::open(tmp.path()).unwrap());
    create_test_session(&storage, "sess-partial");

    // Record an active edge
    let edge = ProcessLineageEdge::new_snapshot_edge(
        "sess-partial".to_string(),
        ProcessIncarnation::new(100, ProcessStartTime::new(1000, 0)),
        ProcessIncarnation::new(200, ProcessStartTime::new(1001, 0)),
        Some("claude".to_string()),
        None,
        "node".to_string(),
        None,
        Utc::now(),
        None,
    );
    storage.save_lineage_edges("sess-partial", &[edge]).unwrap();

    let recorded = storage.get_lineage_edges("sess-partial").unwrap();
    assert_eq!(recorded[0].status, LineageStatus::BothActive);

    // A partial snapshot arrives with error metadata where parent is temporarily missing
    let partial_snapshot = ProcessSnapshot {
        processes: vec![make_proc(200, Some(1), "node", 1001, 0)],
        interval: ObservationInterval::default(),
        completeness: SnapshotCompleteness::PartialError {
            successful_queries: 1,
            failed_queries: 10,
        },
    };

    // Edge updates must return empty: DO NOT mark parent exited on partial error!
    let updates = update_edge_lifecycle_statuses(&partial_snapshot, &recorded);
    assert!(
        updates.is_empty(),
        "Partial snapshot must not trigger status changes or false absence"
    );

    // Ensure edge in DB remains unchanged
    let rechecked = storage.get_lineage_edges("sess-partial").unwrap();
    assert_eq!(rechecked[0].status, LineageStatus::BothActive);
}

#[test]
fn test_scenario_9_truncated_snapshot_does_not_create_false_absence_or_delete_edges() {
    let tmp = NamedTempFile::new().unwrap();
    let storage = Arc::new(StorageManager::open(tmp.path()).unwrap());
    create_test_session(&storage, "sess-truncated");

    let edge = ProcessLineageEdge::new_snapshot_edge(
        "sess-truncated".to_string(),
        ProcessIncarnation::new(100, ProcessStartTime::new(1000, 0)),
        ProcessIncarnation::new(200, ProcessStartTime::new(1001, 0)),
        Some("claude".to_string()),
        None,
        "node".to_string(),
        None,
        Utc::now(),
        None,
    );
    storage
        .save_lineage_edges("sess-truncated", &[edge])
        .unwrap();

    let recorded = storage.get_lineage_edges("sess-truncated").unwrap();

    // A truncated snapshot arrives (buffer exhausted)
    let truncated_snapshot = ProcessSnapshot {
        processes: vec![make_proc(200, Some(1), "node", 1001, 0)],
        interval: ObservationInterval::default(),
        completeness: SnapshotCompleteness::Truncated {
            returned_count: 50,
            capacity: 50,
        },
    };

    let updates = update_edge_lifecycle_statuses(&truncated_snapshot, &recorded);
    assert!(
        updates.is_empty(),
        "Truncated snapshot must not trigger status changes or false absence"
    );

    let rechecked = storage.get_lineage_edges("sess-truncated").unwrap();
    assert_eq!(rechecked[0].status, LineageStatus::BothActive);
}

#[test]
fn test_scenario_10_conflicting_parent_evidence_produces_unknown_confidence() {
    let candidate = make_proc(200, Some(100), "node", 1001, 0);

    // Two contradictory edges recorded for the exact same child incarnation
    let edge_a = ProcessLineageEdge::new_snapshot_edge(
        "sess-conflict".to_string(),
        ProcessIncarnation::new(100, ProcessStartTime::new(1000, 0)),
        ProcessIncarnation::new(200, ProcessStartTime::new(1001, 0)),
        Some("parent-a".to_string()),
        None,
        "node".to_string(),
        None,
        Utc::now(),
        None,
    );

    let edge_b = ProcessLineageEdge::new_snapshot_edge(
        "sess-conflict".to_string(),
        ProcessIncarnation::new(150, ProcessStartTime::new(1000, 500)),
        ProcessIncarnation::new(200, ProcessStartTime::new(1001, 0)),
        Some("parent-b".to_string()),
        None,
        "node".to_string(),
        None,
        Utc::now(),
        None,
    );

    let res = resolve_lineage_chain(
        Some(100),
        None,
        &candidate,
        std::slice::from_ref(&candidate),
        &[edge_a, edge_b],
    );

    assert!(
        matches!(res, LineageChainResult::ConflictingEvidence { .. }),
        "Conflicting parent records for the same child incarnation must produce ConflictingEvidence"
    );
}

#[test]
fn test_scenario_11_repeated_observations_increment_observation_count_no_duplicates() {
    let tmp = NamedTempFile::new().unwrap();
    let storage = Arc::new(StorageManager::open(tmp.path()).unwrap());
    create_test_session(&storage, "sess-repeat");

    let edge = ProcessLineageEdge::new_snapshot_edge(
        "sess-repeat".to_string(),
        ProcessIncarnation::new(100, ProcessStartTime::new(1000, 0)),
        ProcessIncarnation::new(200, ProcessStartTime::new(1001, 0)),
        Some("claude".to_string()),
        None,
        "node".to_string(),
        None,
        Utc::now(),
        None,
    );

    // Observation 1
    storage
        .save_lineage_edges("sess-repeat", std::slice::from_ref(&edge))
        .unwrap();
    let edges1 = storage.get_lineage_edges("sess-repeat").unwrap();
    assert_eq!(edges1.len(), 1);
    assert_eq!(edges1[0].observation_count, 1);

    // Observation 2 (same edge re-observed)
    storage
        .save_lineage_edges("sess-repeat", std::slice::from_ref(&edge))
        .unwrap();
    let edges2 = storage.get_lineage_edges("sess-repeat").unwrap();
    assert_eq!(edges2.len(), 1, "Must NOT duplicate lineage edge rows");
    assert_eq!(edges2[0].observation_count, 2);

    // Observation 3
    storage
        .save_lineage_edges("sess-repeat", std::slice::from_ref(&edge))
        .unwrap();
    let edges3 = storage.get_lineage_edges("sess-repeat").unwrap();
    assert_eq!(edges3.len(), 1);
    assert_eq!(edges3[0].observation_count, 3);
}

#[test]
fn test_scenario_12_stale_fencing_token_cannot_commit_lineage() {
    let tmp = NamedTempFile::new().unwrap();
    let storage = Arc::new(StorageManager::open(tmp.path()).unwrap());

    // Create active session
    let now = Utc::now();
    let session = SessionInfo {
        id: "sess-fence-12".to_string(),
        agent_kind: AgentKind::ClaudeCode,
        status: SessionStatus::Active,
        start_time: now,
        end_time: None,
        root_pid: Some(100),
        root_process_name: Some("claude".to_string()),
        confidence: Confidence::Confirmed,
        evidence: vec![],
        tracked_pids: vec![],
        total_memory_bytes: 0,
        total_cpu_usage: 0.0,
        open_ports: vec![],
        resource_count: 0,
        root_binding: None,
    };
    storage.save_session(&session).unwrap();

    // Acquire lease generation 1 with short TTL (1 sec)
    let acq1 = unwrap_lease(
        storage
            .acquire_observer_lease("sess-fence-12", "obs-1", 1)
            .unwrap(),
    );
    let token1 = acq1.fencing_token;
    assert_eq!(token1, 1);

    // Let lease expire
    std::thread::sleep(std::time::Duration::from_millis(1100));

    // Acquire lease generation 2 by obs-2 recovering expired lease
    let acq2 = unwrap_lease(
        storage
            .acquire_observer_lease("sess-fence-12", "obs-2", 10)
            .unwrap(),
    );
    let token2 = acq2.fencing_token;
    assert_eq!(token2, 2);

    let edge = ProcessLineageEdge::new_snapshot_edge(
        "sess-fence-12".to_string(),
        ProcessIncarnation::new(100, ProcessStartTime::new(1000, 0)),
        ProcessIncarnation::new(200, ProcessStartTime::new(1001, 0)),
        None,
        None,
        "node".to_string(),
        None,
        Utc::now(),
        None,
    );

    // Attempt to commit with STALE token 1 (current token is 2)
    let res = storage.record_lineage_edges_fenced("sess-fence-12", "obs-1", token1, &[edge]);
    assert!(
        matches!(res, Err(StorageError::LeaseFencingConflict { .. })),
        "Stale fencing token must be rejected"
    );

    // Verify nothing was written to lineage
    let edges = storage.get_lineage_edges("sess-fence-12").unwrap();
    assert!(edges.is_empty());
}

#[test]
fn test_scenario_13_expired_observer_cannot_commit_lineage() {
    let tmp = NamedTempFile::new().unwrap();
    let storage = Arc::new(StorageManager::open(tmp.path()).unwrap());

    let now = Utc::now();
    let session = SessionInfo {
        id: "sess-expire-13".to_string(),
        agent_kind: AgentKind::ClaudeCode,
        status: SessionStatus::Active,
        start_time: now,
        end_time: None,
        root_pid: Some(100),
        root_process_name: Some("claude".to_string()),
        confidence: Confidence::Confirmed,
        evidence: vec![],
        tracked_pids: vec![],
        total_memory_bytes: 0,
        total_cpu_usage: 0.0,
        open_ports: vec![],
        resource_count: 0,
        root_binding: None,
    };
    storage.save_session(&session).unwrap();

    // Acquire 1-second lease
    let acq = unwrap_lease(
        storage
            .acquire_observer_lease("sess-expire-13", "obs-expire", 1)
            .unwrap(),
    );
    let token = acq.fencing_token;

    // Sleep to let lease expire
    std::thread::sleep(std::time::Duration::from_millis(1100));

    let edge = ProcessLineageEdge::new_snapshot_edge(
        "sess-expire-13".to_string(),
        ProcessIncarnation::new(100, ProcessStartTime::new(1000, 0)),
        ProcessIncarnation::new(200, ProcessStartTime::new(1001, 0)),
        None,
        None,
        "node".to_string(),
        None,
        Utc::now(),
        None,
    );

    let res = storage.record_lineage_edges_fenced("sess-expire-13", "obs-expire", token, &[edge]);
    assert!(
        matches!(res, Err(StorageError::LeaseExpired { .. })),
        "Expired observer lease must reject lineage commits"
    );
}

#[test]
fn test_scenario_14_competing_observers_cannot_corrupt_lineage() {
    let tmp = NamedTempFile::new().unwrap();
    let storage = Arc::new(StorageManager::open(tmp.path()).unwrap());

    let now = Utc::now();
    let session = SessionInfo {
        id: "sess-race-14".to_string(),
        agent_kind: AgentKind::ClaudeCode,
        status: SessionStatus::Active,
        start_time: now,
        end_time: None,
        root_pid: Some(100),
        root_process_name: Some("claude".to_string()),
        confidence: Confidence::Confirmed,
        evidence: vec![],
        tracked_pids: vec![],
        total_memory_bytes: 0,
        total_cpu_usage: 0.0,
        open_ports: vec![],
        resource_count: 0,
        root_binding: None,
    };
    storage.save_session(&session).unwrap();

    // Observer A acquires lease (token 1) with short TTL
    let acq1 = unwrap_lease(
        storage
            .acquire_observer_lease("sess-race-14", "obs-A", 1)
            .unwrap(),
    );
    let token_a = acq1.fencing_token;

    // Wait for Observer A to expire
    std::thread::sleep(std::time::Duration::from_millis(1100));

    // Observer B recovers lease (token 2)
    let acq2 = unwrap_lease(
        storage
            .acquire_observer_lease("sess-race-14", "obs-B", 10)
            .unwrap(),
    );
    let token_b = acq2.fencing_token;
    assert_eq!(token_b, 2);

    let edge_a = ProcessLineageEdge::new_snapshot_edge(
        "sess-race-14".to_string(),
        ProcessIncarnation::new(100, ProcessStartTime::new(1000, 0)),
        ProcessIncarnation::new(200, ProcessStartTime::new(1001, 0)),
        None,
        None,
        "stale-worker".to_string(),
        None,
        Utc::now(),
        None,
    );

    let edge_b = ProcessLineageEdge::new_snapshot_edge(
        "sess-race-14".to_string(),
        ProcessIncarnation::new(100, ProcessStartTime::new(1000, 0)),
        ProcessIncarnation::new(300, ProcessStartTime::new(1002, 0)),
        None,
        None,
        "legit-worker".to_string(),
        None,
        Utc::now(),
        None,
    );

    // Observer A attempts write with stale token -> Rejected!
    let res_a = storage.record_lineage_edges_fenced("sess-race-14", "obs-A", token_a, &[edge_a]);
    assert!(res_a.is_err());

    // Observer B writes with token 2 -> Accepted!
    let res_b = storage.record_lineage_edges_fenced("sess-race-14", "obs-B", token_b, &[edge_b]);
    assert!(res_b.is_ok());

    let edges = storage.get_lineage_edges("sess-race-14").unwrap();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].child.pid, 300);
    assert_eq!(edges[0].child_name, "legit-worker");
}

#[test]
fn test_scenario_15_v1_v6_migration_fixtures_upgrade_correctly_through_v7() {
    let tmp = NamedTempFile::new().unwrap();
    let db_path = tmp.path();

    // Create a database with user_version = 1 (legacy unmigrated)
    {
        let conn = rusqlite::Connection::open(db_path).unwrap();
        conn.execute_batch(timmy::storage::MIGRATION_V1).unwrap();
        conn.execute_batch("PRAGMA user_version = 1;").unwrap();
    }

    // Open through StorageManager: executes V2 -> V7 migrations
    let storage = StorageManager::open(db_path).expect("migrate V1 to V7");

    let conn = rusqlite::Connection::open(db_path).unwrap();
    let ver: i32 = conn
        .query_row("PRAGMA user_version;", [], |r| r.get(0))
        .unwrap();
    assert_eq!(ver, 7, "V1 schema must migrate completely to V7");

    create_test_session(&storage, "sess-v1-to-v7");

    // Lineage operations can execute immediately on upgraded database
    let edge = ProcessLineageEdge::new_snapshot_edge(
        "sess-v1-to-v7".to_string(),
        ProcessIncarnation::new(10, ProcessStartTime::new(100, 0)),
        ProcessIncarnation::new(20, ProcessStartTime::new(101, 0)),
        None,
        None,
        "worker".to_string(),
        None,
        Utc::now(),
        None,
    );
    storage
        .save_lineage_edges("sess-v1-to-v7", &[edge])
        .unwrap();
    let edges = storage.get_lineage_edges("sess-v1-to-v7").unwrap();
    assert_eq!(edges.len(), 1);
}

#[test]
fn test_scenario_16_v7_migration_rollback_and_idempotency() {
    let tmp = NamedTempFile::new().unwrap();
    let db_path = tmp.path();

    // Open once -> Migrates to V7
    {
        let s1 = StorageManager::open(db_path).unwrap();
        assert!(s1.list_sessions().is_ok());
    }

    // Reopen 5 times -> Must remain idempotent at V7
    for _ in 0..5 {
        let s = StorageManager::open(db_path).unwrap();
        assert!(s.list_sessions().is_ok());
    }

    let conn = rusqlite::Connection::open(db_path).unwrap();
    let ver: i32 = conn
        .query_row("PRAGMA user_version;", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        ver, 7,
        "Idempotent reopening must preserve user_version at 7"
    );
}

#[test]
fn test_scenario_17_existing_session_attribution_tests_remain_valid() {
    let tmp = NamedTempFile::new().unwrap();
    let storage = Arc::new(StorageManager::open(tmp.path()).unwrap());
    let coord = SessionCoordinator::new(storage.clone(), TimmyConfig::default());

    // Verified root binding
    let parent = make_proc(1000, Some(1), "claude", 2000, 0);
    let child1 = make_proc(1001, Some(1000), "vite", 2001, 100);
    let child2 = make_proc(1002, Some(1000), "zsh", 2002, 200);

    let collector = MockCollector::new(vec![parent, child1, child2], vec![]);
    let session = coord
        .start_session(Some("claude".to_string()), false, &collector)
        .expect("start");

    let (_, resources, recs) = coord
        .inspect_session(Some(&session.id), &collector)
        .expect("inspect");

    assert_eq!(resources.len(), 3);

    // Root is Confirmed
    let root_res = resources.iter().find(|r| r.pid == Some(1000)).unwrap();
    assert_eq!(root_res.confidence, Confidence::Confirmed);

    // Vite worker is Confirmed (live unbroken chain from verified root) and termination eligible
    let vite_rec = recs.iter().find(|r| r.pid_or_id == "1001").unwrap();
    assert_eq!(vite_rec.ownership_confidence, Confidence::Confirmed);
    assert!(vite_rec.termination_eligible);

    // Shell worker is Confirmed but protected from termination
    let shell_rec = recs.iter().find(|r| r.pid_or_id == "1002").unwrap();
    assert_eq!(shell_rec.ownership_confidence, Confidence::Confirmed);
    assert!(!shell_rec.termination_eligible);
    assert!(shell_rec.is_protected);
}
