use chrono::Utc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use timmy::model::agent::{AgentKind, Confidence};
use timmy::model::session::{SessionInfo, SessionStatus, TrackedResource};
use timmy::storage::{LeaseAcquisitionResult, StorageError, StorageManager};

fn create_test_session(
    storage: &StorageManager,
    session_id: &str,
    status: SessionStatus,
) -> SessionInfo {
    let now = Utc::now();
    let session = SessionInfo {
        id: session_id.to_string(),
        agent_kind: AgentKind::ClaudeCode,
        status,
        start_time: now,
        end_time: if status == SessionStatus::Stopped {
            Some(now)
        } else {
            None
        },
        root_pid: Some(100),
        root_process_name: Some("test-agent".to_string()),
        confidence: Confidence::Confirmed,
        evidence: vec!["Test setup session".to_string()],
        tracked_pids: vec![],
        total_memory_bytes: 0,
        total_cpu_usage: 0.0,
        open_ports: vec![],
        resource_count: 0,
        root_binding: None,
    };
    storage
        .save_session(&session)
        .expect("Must save test session");
    session
}

#[test]
fn test_scenario_1_acquire_lease_successfully_on_active_session() {
    let storage = StorageManager::open_in_memory().expect("Must open in-memory DB");
    create_test_session(&storage, "sess-01", SessionStatus::Active);

    let res = storage
        .acquire_observer_lease("sess-01", "owner-alpha", 6)
        .expect("Must succeed");

    match res {
        LeaseAcquisitionResult::Acquired(lease) => {
            assert_eq!(lease.session_id, "sess-01");
            assert_eq!(lease.owner_id, "owner-alpha");
            assert_eq!(lease.fencing_token, 1);
            assert!(!lease.is_expired());
            assert!(lease.expires_at > lease.acquired_at);
        }
        other => panic!("Expected Acquired, got {:?}", other),
    }

    let current = storage
        .get_observer_lease("sess-01")
        .expect("Must get lease")
        .expect("Lease must exist");
    assert_eq!(current.owner_id, "owner-alpha");
    assert_eq!(current.fencing_token, 1);
    assert!(!current.is_expired());
}

#[test]
fn test_scenario_2_reject_second_unexpired_lease_acquisition() {
    let storage = StorageManager::open_in_memory().expect("Must open in-memory DB");
    create_test_session(&storage, "sess-02", SessionStatus::Active);

    // First observer acquires lease
    let res1 = storage
        .acquire_observer_lease("sess-02", "owner-alpha", 10)
        .expect("Alpha must acquire");
    assert!(matches!(res1, LeaseAcquisitionResult::Acquired(_)));

    // Second observer attempts to acquire while Alpha's lease is active and unexpired
    let res2 = storage
        .acquire_observer_lease("sess-02", "owner-bravo", 10)
        .expect("Must return result, not error");

    match res2 {
        LeaseAcquisitionResult::AlreadyHeld {
            current_owner,
            current_generation,
            expires_at,
        } => {
            assert_eq!(current_owner, "owner-alpha");
            assert_eq!(current_generation, 1);
            assert!(expires_at > Utc::now());
        }
        other => panic!("Expected AlreadyHeld, got {:?}", other),
    }

    // Alpha can renew its own lease preserving fencing token 1
    let renew_res = storage
        .acquire_observer_lease("sess-02", "owner-alpha", 10)
        .expect("Alpha renewal must succeed");
    match renew_res {
        LeaseAcquisitionResult::Renewed(l) => {
            assert_eq!(l.fencing_token, 1);
        }
        other => panic!("Expected Renewed, got {:?}", other),
    }
}

#[test]
fn test_scenario_3_read_only_inspection_allowed_while_lease_held() {
    let storage = StorageManager::open_in_memory().expect("Must open in-memory DB");
    create_test_session(&storage, "sess-03", SessionStatus::Active);

    // Alpha holds lease
    storage
        .acquire_observer_lease("sess-03", "owner-alpha", 10)
        .expect("Alpha must acquire");

    // Read queries must succeed without locking or blocking
    let sess = storage
        .get_session("sess-03")
        .expect("Must query session")
        .expect("Session must exist");
    assert_eq!(sess.id, "sess-03");

    let resources = storage
        .get_session_resources("sess-03")
        .expect("Must query resources");
    assert!(resources.is_empty());

    let lease = storage
        .get_observer_lease("sess-03")
        .expect("Must query lease")
        .expect("Lease must exist");
    assert_eq!(lease.owner_id, "owner-alpha");
    assert_eq!(lease.fencing_token, 1);
    assert!(!lease.is_expired());
}

#[test]
fn test_scenario_4_normal_lease_release_allows_immediate_reacquisition() {
    let storage = StorageManager::open_in_memory().expect("Must open in-memory DB");
    create_test_session(&storage, "sess-04", SessionStatus::Active);

    // Alpha acquires (fencing token = 1)
    let acq = storage
        .acquire_observer_lease("sess-04", "owner-alpha", 10)
        .expect("Alpha acquires");
    let alpha_token = match acq {
        LeaseAcquisitionResult::Acquired(l) => l.fencing_token,
        _ => panic!("Expected Acquired"),
    };
    assert_eq!(alpha_token, 1);

    // Alpha releases cleanly on exit
    let released = storage
        .release_observer_lease("sess-04", "owner-alpha", alpha_token)
        .expect("Must release");
    assert!(released);

    assert!(storage
        .get_observer_lease("sess-04")
        .expect("Must query")
        .is_none());

    // Bravo can now acquire immediately and gets a NEW incremented generation token!
    let res = storage
        .acquire_observer_lease("sess-04", "owner-bravo", 10)
        .expect("Bravo must acquire");
    match res {
        LeaseAcquisitionResult::Acquired(l) => {
            assert_eq!(l.owner_id, "owner-bravo");
            assert_eq!(l.fencing_token, 2);
        }
        other => panic!("Expected Acquired for bravo, got {:?}", other),
    }
}

#[test]
fn test_scenario_5_crash_expiry_recovery_by_new_owner() {
    let storage = StorageManager::open_in_memory().expect("Must open in-memory DB");
    create_test_session(&storage, "sess-05", SessionStatus::Active);

    // Alpha acquires with a 1-second TTL (generation 1)
    let acq = storage
        .acquire_observer_lease("sess-05", "owner-crashed-alpha", 1)
        .expect("Alpha acquires");
    assert_eq!(
        match acq {
            LeaseAcquisitionResult::Acquired(l) => l.fencing_token,
            _ => 0,
        },
        1
    );

    // Wait for the 1-second TTL to naturally expire
    thread::sleep(Duration::from_millis(1100));

    // Bravo attempts acquisition and should recover the expired lease with a NEW generation (2)
    let res = storage
        .acquire_observer_lease("sess-05", "owner-bravo", 10)
        .expect("Bravo must succeed with recovery");

    match res {
        LeaseAcquisitionResult::RecoveredFromExpired {
            lease,
            previous_owner,
        } => {
            assert_eq!(previous_owner, "owner-crashed-alpha");
            assert_eq!(lease.owner_id, "owner-bravo");
            assert_eq!(lease.session_id, "sess-05");
            assert_eq!(lease.fencing_token, 2);
            assert!(!lease.is_expired());
        }
        other => panic!("Expected RecoveredFromExpired, got {:?}", other),
    }
}

#[test]
fn test_scenario_6_competing_acquisition_serialization() {
    let temp_dir = tempfile::tempdir().expect("Must create temp dir");
    let db_path = temp_dir.path().join("competing.db");

    let storage = Arc::new(StorageManager::open(&db_path).expect("Must open DB"));
    create_test_session(&storage, "sess-06", SessionStatus::Active);

    let num_competitors = 10;
    let mut handles = Vec::new();

    for i in 0..num_competitors {
        let storage_clone = storage.clone();
        let owner_id = format!("competitor-{}", i);
        let handle =
            thread::spawn(move || storage_clone.acquire_observer_lease("sess-06", &owner_id, 10));
        handles.push(handle);
    }

    let mut acquired_count = 0;
    let mut already_held_count = 0;

    for h in handles {
        let res = h
            .join()
            .expect("Thread must not panic")
            .expect("Lease query must succeed");
        match res {
            LeaseAcquisitionResult::Acquired(l) => {
                acquired_count += 1;
                assert_eq!(l.fencing_token, 1);
            }
            LeaseAcquisitionResult::AlreadyHeld { .. } => already_held_count += 1,
            other => panic!("Unexpected result: {:?}", other),
        }
    }

    assert_eq!(
        acquired_count, 1,
        "Exactly one thread must acquire the lease"
    );
    assert_eq!(
        already_held_count,
        num_competitors - 1,
        "All other threads must be rejected with AlreadyHeld"
    );
}

#[test]
fn test_scenario_7_session_stop_or_replace_invalidates_lease() {
    let storage = StorageManager::open_in_memory().expect("Must open in-memory DB");
    create_test_session(&storage, "sess-07", SessionStatus::Active);

    // Alpha acquires lease (token 1)
    let acq = storage
        .acquire_observer_lease("sess-07", "owner-alpha", 10)
        .expect("Alpha acquires");
    let token = match acq {
        LeaseAcquisitionResult::Acquired(l) => l.fencing_token,
        _ => panic!("Expected Acquired"),
    };

    // Session transitions to Stopped
    let mut session = storage
        .get_session("sess-07")
        .expect("Get session")
        .unwrap();
    session.status = SessionStatus::Stopped;
    session.end_time = Some(Utc::now());
    storage.save_session(&session).expect("Update session");

    // Renewal must fail cleanly and report false
    let renewed = storage
        .renew_observer_lease("sess-07", "owner-alpha", token, 10)
        .expect("Must query without error");
    assert!(
        !renewed,
        "Renewal must return false when session is stopped"
    );

    // Lease was pruned from active leases table
    let lease = storage.get_observer_lease("sess-07").expect("Query lease");
    assert!(lease.is_none());
}

#[test]
fn test_scenario_8_stopped_session_rejects_lease_acquisition() {
    let storage = StorageManager::open_in_memory().expect("Must open in-memory DB");
    create_test_session(&storage, "sess-08", SessionStatus::Stopped);

    let res = storage.acquire_observer_lease("sess-08", "owner-alpha", 10);
    match res {
        Err(StorageError::SessionNotActive(s)) => {
            assert_eq!(s, "sess-08");
        }
        other => panic!("Expected SessionNotActive error, got {:?}", other),
    }
}

#[test]
fn test_scenario_9_cross_session_renewal_rejection() {
    let storage = StorageManager::open_in_memory().expect("Must open in-memory DB");
    create_test_session(&storage, "sess-09a", SessionStatus::Active);
    create_test_session(&storage, "sess-09b", SessionStatus::Active);

    // Alpha acquires lease for sess-09a
    storage
        .acquire_observer_lease("sess-09a", "owner-alpha", 10)
        .expect("Alpha acquires sess-09a");

    // Alpha attempts to renew lease for sess-09b (where it has no lease)
    let renewed = storage
        .renew_observer_lease("sess-09b", "owner-alpha", 1, 10)
        .expect("Must query");
    assert!(
        !renewed,
        "Cannot renew a lease for a session that caller has not acquired"
    );
}

#[test]
fn test_scenario_10_owner_identity_enforcement() {
    let storage = StorageManager::open_in_memory().expect("Must open in-memory DB");
    create_test_session(&storage, "sess-10", SessionStatus::Active);

    // Alpha acquires lease (token 1)
    let acq = storage
        .acquire_observer_lease("sess-10", "owner-alpha", 10)
        .expect("Alpha acquires");
    let token = match acq {
        LeaseAcquisitionResult::Acquired(l) => l.fencing_token,
        _ => panic!("Expected Acquired"),
    };

    // Bravo attempts to renew Alpha's lease
    let renewed = storage
        .renew_observer_lease("sess-10", "owner-bravo", token, 10)
        .expect("Query");
    assert!(!renewed, "Bravo cannot renew Alpha's lease");

    // Bravo attempts to release Alpha's lease
    let released = storage
        .release_observer_lease("sess-10", "owner-bravo", token)
        .expect("Query");
    assert!(!released, "Bravo cannot release Alpha's lease");

    // Alpha's lease remains valid and untouched
    let lease = storage
        .get_observer_lease("sess-10")
        .expect("Query")
        .expect("Lease must remain");
    assert_eq!(lease.owner_id, "owner-alpha");
    assert_eq!(lease.fencing_token, 1);
    assert!(!lease.is_expired());
}

#[test]
fn test_scenario_11_atomic_commit_rejects_stale_fencing_token() {
    let storage = StorageManager::open_in_memory().expect("Must open in-memory DB");
    let session = create_test_session(&storage, "sess-11", SessionStatus::Active);

    // Observer 1 acquires lease (generation 1)
    let acq1 = storage
        .acquire_observer_lease("sess-11", "observer-1", 1)
        .expect("Obs 1 acquires");
    let token1 = match acq1 {
        LeaseAcquisitionResult::Acquired(l) => l.fencing_token,
        _ => panic!("Expected Acquired"),
    };
    assert_eq!(token1, 1);

    // Observer 1 pauses; lease expires
    thread::sleep(Duration::from_millis(1100));

    // Observer 2 recovers lease and receives generation 2
    let acq2 = storage
        .acquire_observer_lease("sess-11", "observer-2", 10)
        .expect("Obs 2 recovers");
    let token2 = match acq2 {
        LeaseAcquisitionResult::RecoveredFromExpired { lease, .. } => lease.fencing_token,
        _ => panic!("Expected RecoveredFromExpired"),
    };
    assert_eq!(token2, 2);

    // Stale Observer 1 wakes up and attempts to commit an observation snapshot using stale generation 1
    let sample_resource = TrackedResource {
        session_id: "sess-11".to_string(),
        pid: Some(9999),
        name: "stale-worker".to_string(),
        exe_path: None,
        memory_bytes: Some(1024),
        cpu_usage: Some(0.1),
        listening_ports: vec![8080],
        confidence: Confidence::Inferred,
        evidence: vec!["Stale observation write attempt".to_string()],
        is_detached: false,
        is_protected: false,
        safe_to_terminate: false,
        first_seen: Utc::now(),
        last_seen: Utc::now(),
        process_start_time: Some(100),
        provenance: None,
    };

    let commit_err = storage
        .commit_session_observation(
            "sess-11",
            "observer-1",
            token1,
            &session,
            &[sample_resource],
            (1, 1024, 0.1, 1),
        )
        .unwrap_err();

    match commit_err {
        StorageError::LeaseFencingConflict {
            session_id,
            expected_token,
            current_token,
            current_owner,
        } => {
            assert_eq!(session_id, "sess-11");
            assert_eq!(expected_token, 1);
            assert_eq!(current_token, 2);
            assert_eq!(current_owner, "observer-2");
        }
        other => panic!("Expected LeaseFencingConflict, got {:?}", other),
    }

    // Verify that the stale resource was NOT written to the database
    let stored_resources = storage
        .get_session_resources("sess-11")
        .expect("Query resources");
    assert!(
        stored_resources.is_empty(),
        "Stale observer must NOT write any resources"
    );
}

#[test]
fn test_scenario_12_fencing_history_preserved_across_lease_deletion() {
    let storage = StorageManager::open_in_memory().expect("Must open in-memory DB");
    create_test_session(&storage, "sess-12", SessionStatus::Active);

    // Observer 1 acquires lease (token 1)
    let acq1 = storage
        .acquire_observer_lease("sess-12", "observer-1", 10)
        .expect("Obs 1 acquires");
    let token1 = match acq1 {
        LeaseAcquisitionResult::Acquired(l) => l.fencing_token,
        _ => panic!("Expected Acquired"),
    };
    assert_eq!(token1, 1);

    // Observer 1 releases lease: row is deleted from observer_leases
    storage
        .release_observer_lease("sess-12", "observer-1", token1)
        .expect("Release");
    assert!(storage
        .get_observer_lease("sess-12")
        .expect("Query")
        .is_none());

    // Generation sequence table still remembers last generation = 1
    let last_gen = storage
        .get_last_fencing_token("sess-12")
        .expect("Query last generation");
    assert_eq!(last_gen, 1);

    // Observer 2 acquires a new lease: must receive token 2!
    let acq2 = storage
        .acquire_observer_lease("sess-12", "observer-2", 10)
        .expect("Obs 2 acquires");
    let token2 = match acq2 {
        LeaseAcquisitionResult::Acquired(l) => l.fencing_token,
        _ => panic!("Expected Acquired"),
    };
    assert_eq!(
        token2, 2,
        "Generation values must strictly increment and not be reused after release"
    );

    // Observer 2 releases lease
    storage
        .release_observer_lease("sess-12", "observer-2", token2)
        .expect("Release 2");
    assert_eq!(storage.get_last_fencing_token("sess-12").unwrap(), 2);

    // Observer 3 acquires: must receive token 3!
    let acq3 = storage
        .acquire_observer_lease("sess-12", "observer-3", 10)
        .expect("Obs 3 acquires");
    let token3 = match acq3 {
        LeaseAcquisitionResult::Acquired(l) => l.fencing_token,
        _ => panic!("Expected Acquired"),
    };
    assert_eq!(token3, 3);
}
