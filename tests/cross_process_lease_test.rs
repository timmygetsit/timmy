use chrono::Utc;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;
use timmy::model::agent::{AgentKind, Confidence};
use timmy::model::session::{SessionInfo, SessionStatus, TrackedResource};
use timmy::storage::{LeaseAcquisitionResult, StorageError, StorageManager};

// =============================================================================
// WORKER SUB-PROCESS ENTRYPOINT
// =============================================================================

#[test]
#[ignore]
fn worker_entry() {
    let action = match std::env::var("TIMMY_WORKER_ACTION") {
        Ok(a) if !a.is_empty() => a,
        _ => return,
    };

    let db_path = std::env::var("TIMMY_WORKER_DB").expect("TIMMY_WORKER_DB required");
    let session_id = std::env::var("TIMMY_WORKER_SESSION").expect("TIMMY_WORKER_SESSION required");
    let owner_id = std::env::var("TIMMY_WORKER_OWNER").expect("TIMMY_WORKER_OWNER required");

    let storage = StorageManager::open(&db_path).expect("Worker must open DB");

    match action.as_str() {
        "compete" => {
            let ttl: u64 = std::env::var("TIMMY_WORKER_TTL")
                .ok()
                .and_then(|t| t.parse().ok())
                .unwrap_or(10);

            match storage.acquire_observer_lease(&session_id, &owner_id, ttl) {
                Ok(LeaseAcquisitionResult::Acquired(l)) => {
                    println!("[IPC] RESULT: Acquired {}", l.fencing_token);
                }
                Ok(LeaseAcquisitionResult::Renewed(l)) => {
                    println!("[IPC] RESULT: Renewed {}", l.fencing_token);
                }
                Ok(LeaseAcquisitionResult::RecoveredFromExpired {
                    lease,
                    previous_owner,
                }) => {
                    println!(
                        "[IPC] RESULT: RecoveredFromExpired {} {}",
                        previous_owner, lease.fencing_token
                    );
                }
                Ok(LeaseAcquisitionResult::AlreadyHeld {
                    current_owner,
                    current_generation,
                    ..
                }) => {
                    println!(
                        "[IPC] RESULT: AlreadyHeld {} {}",
                        current_owner, current_generation
                    );
                }
                Err(e) => {
                    println!("[IPC] RESULT: Error {}", e);
                }
            }
            std::io::stdout().flush().unwrap();
        }
        "hold_and_watch" => {
            let ttl: u64 = std::env::var("TIMMY_WORKER_TTL")
                .ok()
                .and_then(|t| t.parse().ok())
                .unwrap_or(10);

            let acq = storage
                .acquire_observer_lease(&session_id, &owner_id, ttl)
                .expect("Initial acquire");

            let token = match acq {
                LeaseAcquisitionResult::Acquired(l) => l.fencing_token,
                LeaseAcquisitionResult::Renewed(l) => l.fencing_token,
                LeaseAcquisitionResult::RecoveredFromExpired { lease, .. } => lease.fencing_token,
                other => panic!("Worker failed initial acquire: {:?}", other),
            };

            // Handshake: Notify coordinator of readiness with token
            println!("[IPC] READY: {}", token);
            std::io::stdout().flush().unwrap();

            let stdin = std::io::stdin();
            let mut lines = stdin.lock().lines();

            while let Some(Ok(line)) = lines.next() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.is_empty() {
                    continue;
                }
                match parts[0] {
                    "RENEW" => {
                        let tok: u64 = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(token);
                        let renewed = storage
                            .renew_observer_lease(&session_id, &owner_id, tok, ttl)
                            .unwrap_or(false);
                        println!("[IPC] RENEWED: {}", renewed);
                        std::io::stdout().flush().unwrap();
                    }
                    "RELEASE" => {
                        let tok: u64 = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(token);
                        let released = storage
                            .release_observer_lease(&session_id, &owner_id, tok)
                            .unwrap_or(false);
                        println!("[IPC] RELEASED: {}", released);
                        std::io::stdout().flush().unwrap();
                    }
                    "WRITE" => {
                        let tok: u64 = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(token);
                        let session = storage
                            .get_session(&session_id)
                            .unwrap()
                            .expect("Session must exist");
                        let sample_res = TrackedResource {
                            session_id: session_id.clone(),
                            pid: Some(std::process::id()),
                            name: format!("worker-{}", owner_id),
                            exe_path: None,
                            memory_bytes: Some(1024 * 1024),
                            cpu_usage: Some(0.5),
                            listening_ports: vec![9090],
                            confidence: Confidence::HighConfidence,
                            evidence: vec!["Cross-process worker observation".to_string()],
                            is_detached: false,
                            is_protected: false,
                            safe_to_terminate: true,
                            first_seen: Utc::now(),
                            last_seen: Utc::now(),
                            process_start_time: Some(100),
                            provenance: None,
                        };

                        let write_res = storage.commit_session_observation(
                            &session_id,
                            &owner_id,
                            tok,
                            &session,
                            &[sample_res],
                            (1, 1024 * 1024, 0.5, 1),
                        );

                        match write_res {
                            Ok(()) => println!("[IPC] WRITTEN: OK"),
                            Err(StorageError::LeaseFencingConflict {
                                expected_token,
                                current_token,
                                ..
                            }) => {
                                println!(
                                    "[IPC] WRITTEN: ERROR LeaseFencingConflict {} {}",
                                    expected_token, current_token
                                );
                            }
                            Err(StorageError::SessionNotActive(_)) => {
                                println!("[IPC] WRITTEN: ERROR SessionNotActive");
                            }
                            Err(e) => println!("[IPC] WRITTEN: ERROR {}", e),
                        }
                        std::io::stdout().flush().unwrap();
                    }
                    "EXIT" => break,
                    _ => {}
                }
            }
        }
        "inspect" => {
            let session = storage.get_session(&session_id).expect("Query session");
            let resources = storage
                .get_session_resources(&session_id)
                .expect("Query resources");
            let lease = storage
                .get_observer_lease(&session_id)
                .expect("Query lease");

            let lease_owner = lease
                .as_ref()
                .map(|l| l.owner_id.as_str())
                .unwrap_or("none");
            let sess_exists = session.is_some();
            println!(
                "[IPC] INSPECT: session_exists={}, resources_count={}, lease_owner={}",
                sess_exists,
                resources.len(),
                lease_owner
            );
            std::io::stdout().flush().unwrap();
        }
        _ => eprintln!("Unknown worker action: {}", action),
    }

    std::process::exit(0);
}

// =============================================================================
// COORDINATOR HELPERS
// =============================================================================

fn spawn_worker_process(
    action: &str,
    db_path: &std::path::Path,
    session_id: &str,
    owner_id: &str,
    extra_env: &[(&str, &str)],
) -> Child {
    let exe = std::env::current_exe().expect("current test exe path");
    let mut cmd = Command::new(exe);
    cmd.arg("worker_entry")
        .arg("--exact")
        .arg("--ignored")
        .arg("--nocapture")
        .env("TIMMY_WORKER_ACTION", action)
        .env("TIMMY_WORKER_DB", db_path.to_str().unwrap())
        .env("TIMMY_WORKER_SESSION", session_id)
        .env("TIMMY_WORKER_OWNER", owner_id)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    for (k, v) in extra_env {
        cmd.env(k, v);
    }

    cmd.spawn().expect("Must spawn worker process")
}

fn read_worker_ipc_line<R: BufRead>(reader: &mut R) -> String {
    let mut line = String::new();
    loop {
        line.clear();
        let bytes = reader.read_line(&mut line).expect("read line from worker");
        if bytes == 0 {
            return String::new();
        }
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("[IPC] ") {
            return rest.to_string();
        }
    }
}

fn create_coordinator_session(
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
        evidence: vec!["Cross-process test session".to_string()],
        tracked_pids: vec![],
        total_memory_bytes: 0,
        total_cpu_usage: 0.0,
        open_ports: vec![],
        resource_count: 0,
        root_binding: None,
    };
    storage
        .save_session(&session)
        .expect("Must save coordinator session");
    session
}

// =============================================================================
// CROSS-PROCESS TEST SCENARIOS
// =============================================================================

#[test]
fn test_cross_process_scenario_1_competing_acquisition_exactly_one_succeeds() {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let db_path = temp_dir.path().join("cross_compete.db");

    let storage = StorageManager::open(&db_path).expect("Open coordinator DB");
    create_coordinator_session(&storage, "sess-cp-01", SessionStatus::Active);

    // Launch two independent operating-system processes competing simultaneously
    let mut p1 = spawn_worker_process("compete", &db_path, "sess-cp-01", "proc-alpha", &[]);
    let mut p2 = spawn_worker_process("compete", &db_path, "sess-cp-01", "proc-bravo", &[]);

    let out1 = {
        let mut r = BufReader::new(p1.stdout.take().unwrap());
        read_worker_ipc_line(&mut r)
    };
    let out2 = {
        let mut r = BufReader::new(p2.stdout.take().unwrap());
        read_worker_ipc_line(&mut r)
    };

    p1.wait().unwrap();
    p2.wait().unwrap();

    let mut acquired_count = 0;
    let mut already_held_count = 0;

    for out in [&out1, &out2] {
        if out.starts_with("RESULT: Acquired 1") {
            acquired_count += 1;
        } else if out.starts_with("RESULT: AlreadyHeld") {
            already_held_count += 1;
        }
    }

    assert_eq!(
        acquired_count, 1,
        "Exactly one independent process must acquire generation 1"
    );
    assert_eq!(
        already_held_count, 1,
        "The competing process must be rejected with AlreadyHeld"
    );
}

#[test]
fn test_cross_process_scenario_2_second_process_rejected_on_unexpired_lease() {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let db_path = temp_dir.path().join("cross_unexpired.db");

    let storage = StorageManager::open(&db_path).expect("Open coordinator DB");
    create_coordinator_session(&storage, "sess-cp-02", SessionStatus::Active);

    // Process 1 acquires and holds lease (TTL 15 seconds)
    let mut p1 = spawn_worker_process(
        "hold_and_watch",
        &db_path,
        "sess-cp-02",
        "proc-holder",
        &[("TIMMY_WORKER_TTL", "15")],
    );

    let mut p1_out = BufReader::new(p1.stdout.take().unwrap());
    let ready_line = read_worker_ipc_line(&mut p1_out);
    assert_eq!(ready_line, "READY: 1");

    // Process 2 attempts acquisition while Process 1 holds the unexpired lease
    let mut p2 = spawn_worker_process("compete", &db_path, "sess-cp-02", "proc-challenger", &[]);
    let p2_out = {
        let mut r = BufReader::new(p2.stdout.take().unwrap());
        read_worker_ipc_line(&mut r)
    };
    p2.wait().unwrap();

    assert_eq!(
        p2_out, "RESULT: AlreadyHeld proc-holder 1",
        "Second process must be rejected with AlreadyHeld identifying current owner and generation"
    );

    // Cleanly instruct Process 1 to exit
    let mut p1_in = p1.stdin.take().unwrap();
    writeln!(p1_in, "EXIT").unwrap();
    p1.wait().unwrap();
}

#[test]
fn test_cross_process_scenario_3_recovery_of_expired_lease_creates_new_generation() {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let db_path = temp_dir.path().join("cross_expiry.db");

    let storage = StorageManager::open(&db_path).expect("Open coordinator DB");
    create_coordinator_session(&storage, "sess-cp-03", SessionStatus::Active);

    // Process 1 acquires lease with 1-second TTL
    let mut p1 = spawn_worker_process(
        "hold_and_watch",
        &db_path,
        "sess-cp-03",
        "proc-expiring",
        &[("TIMMY_WORKER_TTL", "1")],
    );

    let mut p1_out = BufReader::new(p1.stdout.take().unwrap());
    let ready_line = read_worker_ipc_line(&mut p1_out);
    assert_eq!(ready_line, "READY: 1");

    // Let Process 1 exit without releasing (simulating observer ungraceful shutdown)
    p1_in_or_kill(&mut p1);

    // Wait 1.1s for the 1-second lease TTL to expire
    thread::sleep(Duration::from_millis(1100));

    // Process 2 attempts acquisition and must recover the expired lease with a NEW generation (2)
    let mut p2 = spawn_worker_process("compete", &db_path, "sess-cp-03", "proc-recoverer", &[]);
    let p2_out = {
        let mut r = BufReader::new(p2.stdout.take().unwrap());
        read_worker_ipc_line(&mut r)
    };
    p2.wait().unwrap();

    assert_eq!(
        p2_out, "RESULT: RecoveredFromExpired proc-expiring 2",
        "Process 2 must recover expired lease with new generation 2"
    );
}

#[test]
fn test_cross_process_scenario_4_old_observer_cannot_renew_or_release_newer_lease() {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let db_path = temp_dir.path().join("cross_stale_renew.db");

    let storage = StorageManager::open(&db_path).expect("Open coordinator DB");
    create_coordinator_session(&storage, "sess-cp-04", SessionStatus::Active);

    // Process 1 acquires lease (TTL 1s, generation 1)
    let mut p1 = spawn_worker_process(
        "hold_and_watch",
        &db_path,
        "sess-cp-04",
        "proc-alpha",
        &[("TIMMY_WORKER_TTL", "1")],
    );

    let mut p1_out = BufReader::new(p1.stdout.take().unwrap());
    let ready_line = read_worker_ipc_line(&mut p1_out);
    assert_eq!(ready_line, "READY: 1");

    // Wait 1.1s for Process 1's lease to expire
    thread::sleep(Duration::from_millis(1100));

    // Process 2 recovers the lease and receives generation 2
    let mut p2 = spawn_worker_process("compete", &db_path, "sess-cp-04", "proc-bravo", &[]);
    let p2_out = {
        let mut r = BufReader::new(p2.stdout.take().unwrap());
        read_worker_ipc_line(&mut r)
    };
    p2.wait().unwrap();
    assert_eq!(p2_out, "RESULT: RecoveredFromExpired proc-alpha 2");

    // Now old Process 1 wakes up and attempts to renew using its old token 1
    let mut p1_in = p1.stdin.take().unwrap();
    writeln!(p1_in, "RENEW 1").unwrap();
    let renew_resp = read_worker_ipc_line(&mut p1_out);
    assert_eq!(
        renew_resp, "RENEWED: false",
        "Old observer must NOT be able to renew lease owned by newer observer"
    );

    // Old Process 1 attempts to release lease
    writeln!(p1_in, "RELEASE 1").unwrap();
    let release_resp = read_worker_ipc_line(&mut p1_out);
    assert_eq!(
        release_resp, "RELEASED: false",
        "Old observer must NOT be able to release lease owned by newer observer"
    );

    writeln!(p1_in, "EXIT").unwrap();
    p1.wait().unwrap();

    // Verify Process 2's lease is still intact
    let active_lease = storage.get_observer_lease("sess-cp-04").unwrap().unwrap();
    assert_eq!(active_lease.owner_id, "proc-bravo");
    assert_eq!(active_lease.fencing_token, 2);
}

#[test]
fn test_cross_process_scenario_5_stale_observer_cannot_write_after_newer_generation() {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let db_path = temp_dir.path().join("cross_stale_write.db");

    let storage = StorageManager::open(&db_path).expect("Open coordinator DB");
    create_coordinator_session(&storage, "sess-cp-05", SessionStatus::Active);

    // Process 1 acquires lease (generation 1, TTL 1s)
    let mut p1 = spawn_worker_process(
        "hold_and_watch",
        &db_path,
        "sess-cp-05",
        "proc-stale-writer",
        &[("TIMMY_WORKER_TTL", "1")],
    );

    let mut p1_out = BufReader::new(p1.stdout.take().unwrap());
    let ready_line = read_worker_ipc_line(&mut p1_out);
    assert_eq!(ready_line, "READY: 1");

    // Wait 1.1s for Process 1's lease to expire
    thread::sleep(Duration::from_millis(1100));

    // Process 2 recovers the lease and receives generation 2
    let mut p2 = spawn_worker_process("compete", &db_path, "sess-cp-05", "proc-new-writer", &[]);
    p2.wait().unwrap();

    // Stale Process 1 attempts to write an observation snapshot using token 1
    let mut p1_in = p1.stdin.take().unwrap();
    writeln!(p1_in, "WRITE 1").unwrap();
    let write_resp = read_worker_ipc_line(&mut p1_out);

    assert!(
        write_resp.contains("ERROR LeaseFencingConflict 1 2"),
        "Atomic observation commit must reject stale observer's write: got '{}'",
        write_resp
    );

    // Verify no resources were written by the stale process
    let resources = storage.get_session_resources("sess-cp-05").unwrap();
    assert!(
        resources.is_empty(),
        "Database must remain uncorrupted by stale writes"
    );

    writeln!(p1_in, "EXIT").unwrap();
    p1.wait().unwrap();
}

#[test]
fn test_cross_process_scenario_6_session_replacement_invalidates_previous_observer() {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let db_path = temp_dir.path().join("cross_session_stop.db");

    let storage = StorageManager::open(&db_path).expect("Open coordinator DB");
    let mut session = create_coordinator_session(&storage, "sess-cp-06", SessionStatus::Active);

    // Process 1 starts observing session
    let mut p1 = spawn_worker_process(
        "hold_and_watch",
        &db_path,
        "sess-cp-06",
        "proc-active-watcher",
        &[("TIMMY_WORKER_TTL", "10")],
    );

    let mut p1_out = BufReader::new(p1.stdout.take().unwrap());
    let ready_line = read_worker_ipc_line(&mut p1_out);
    assert_eq!(ready_line, "READY: 1");

    // Coordinator transitions session to Stopped (simulating `timmy session stop` or `start --replace`)
    session.status = SessionStatus::Stopped;
    session.end_time = Some(Utc::now());
    storage.save_session(&session).expect("Stop session");

    // Process 1 attempts to renew: must fail
    let mut p1_in = p1.stdin.take().unwrap();
    writeln!(p1_in, "RENEW 1").unwrap();
    let renew_resp = read_worker_ipc_line(&mut p1_out);
    assert_eq!(
        renew_resp, "RENEWED: false",
        "Renewal must return false on stopped/replaced session"
    );

    // Process 1 attempts atomic write: must be rejected with SessionNotActive
    writeln!(p1_in, "WRITE 1").unwrap();
    let write_resp = read_worker_ipc_line(&mut p1_out);
    assert_eq!(
        write_resp, "WRITTEN: ERROR SessionNotActive",
        "Atomic write must reject on stopped/replaced session"
    );

    writeln!(p1_in, "EXIT").unwrap();
    p1.wait().unwrap();
}

#[test]
fn test_cross_process_scenario_7_readonly_inspection_while_lease_held() {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let db_path = temp_dir.path().join("cross_inspect.db");

    let storage = StorageManager::open(&db_path).expect("Open coordinator DB");
    create_coordinator_session(&storage, "sess-cp-07", SessionStatus::Active);

    // Process 1 acquires and holds lease
    let mut p1 = spawn_worker_process(
        "hold_and_watch",
        &db_path,
        "sess-cp-07",
        "proc-holder",
        &[("TIMMY_WORKER_TTL", "10")],
    );

    let mut p1_out = BufReader::new(p1.stdout.take().unwrap());
    let ready_line = read_worker_ipc_line(&mut p1_out);
    assert_eq!(ready_line, "READY: 1");

    // Process 2 executes read-only inspection against the same database
    let mut p2 = spawn_worker_process("inspect", &db_path, "sess-cp-07", "proc-inspector", &[]);
    let p2_out = {
        let mut r = BufReader::new(p2.stdout.take().unwrap());
        read_worker_ipc_line(&mut r)
    };
    p2.wait().unwrap();

    assert_eq!(
        p2_out, "INSPECT: session_exists=true, resources_count=0, lease_owner=proc-holder",
        "Read-only inspection must succeed cleanly while lease is held"
    );

    let mut p1_in = p1.stdin.take().unwrap();
    writeln!(p1_in, "EXIT").unwrap();
    p1.wait().unwrap();
}

#[test]
fn test_cross_process_scenario_8_crashed_observer_becomes_recoverable_after_expiry() {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let db_path = temp_dir.path().join("cross_crash.db");

    let storage = StorageManager::open(&db_path).expect("Open coordinator DB");
    create_coordinator_session(&storage, "sess-cp-08", SessionStatus::Active);

    // Process 1 acquires lease with 1-second TTL
    let mut p1 = spawn_worker_process(
        "hold_and_watch",
        &db_path,
        "sess-cp-08",
        "proc-crasher",
        &[("TIMMY_WORKER_TTL", "1")],
    );

    let mut p1_out = BufReader::new(p1.stdout.take().unwrap());
    let ready_line = read_worker_ipc_line(&mut p1_out);
    assert_eq!(ready_line, "READY: 1");

    // Kill Process 1 abruptly with SIGKILL (simulating crash)
    unsafe {
        libc::kill(p1.id() as i32, libc::SIGKILL);
    }
    p1.wait().unwrap();

    // Immediately after crash, lease is still within TTL: challenger is rejected
    let mut p2_early =
        spawn_worker_process("compete", &db_path, "sess-cp-08", "proc-challenger", &[]);
    let p2_early_out = {
        let mut r = BufReader::new(p2_early.stdout.take().unwrap());
        read_worker_ipc_line(&mut r)
    };
    p2_early.wait().unwrap();
    assert!(p2_early_out.starts_with("RESULT: AlreadyHeld proc-crasher 1"));

    // Wait for crash TTL (1s) to naturally expire
    thread::sleep(Duration::from_millis(1100));

    // Process 3 acquires: must recover expired lease with generation 2
    let mut p3 = spawn_worker_process("compete", &db_path, "sess-cp-08", "proc-survivor", &[]);
    let p3_out = {
        let mut r = BufReader::new(p3.stdout.take().unwrap());
        read_worker_ipc_line(&mut r)
    };
    p3.wait().unwrap();

    assert_eq!(
        p3_out, "RESULT: RecoveredFromExpired proc-crasher 2",
        "Crashed observer lease must be recovered by survivor with incremented generation 2"
    );
}

fn p1_in_or_kill(p: &mut Child) {
    if let Some(mut stdin) = p.stdin.take() {
        let _ = writeln!(stdin, "EXIT");
    }
    let _ = p.wait();
}
