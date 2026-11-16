use rusqlite::params;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;
use timmy::engine::register_shutdown_signals;
use timmy::storage::{LeaseAcquisitionResult, StorageManager};

/// Worker entry point executed when spawned as a child process for signal testing.
#[test]
#[ignore]
fn signal_worker_entry() {
    let mode = match std::env::var("TIMMY_SIGNAL_TEST_MODE") {
        Ok(m) => m,
        Err(_) => return, // Normal test runner run; ignore helper entry
    };

    let db_path = std::env::var("TIMMY_TEST_DB").expect("TIMMY_TEST_DB env");
    let session_id = std::env::var("TIMMY_TEST_SESSION_ID").expect("TIMMY_TEST_SESSION_ID env");
    let ttl_secs: u64 = std::env::var("TIMMY_TEST_TTL")
        .unwrap_or_else(|_| "6".to_string())
        .parse()
        .unwrap_or(6);

    let storage = StorageManager::open(&db_path).expect("open db in worker");
    let owner_id = format!("worker-{}", std::process::id());

    let stop_signal = Arc::new(AtomicBool::new(false));

    // Register async-signal-safe handlers with policy:
    // 1st signal: graceful shutdown
    // 2nd signal: conditional default termination
    register_shutdown_signals(Arc::clone(&stop_signal)).expect("register signals");

    let lease_res = storage
        .acquire_observer_lease(&session_id, &owner_id, ttl_secs)
        .expect("acquire lease");

    let fencing_token = match lease_res {
        LeaseAcquisitionResult::Acquired(l) | LeaseAcquisitionResult::Renewed(l) => l.fencing_token,
        LeaseAcquisitionResult::RecoveredFromExpired { lease, .. } => lease.fencing_token,
        LeaseAcquisitionResult::AlreadyHeld { .. } => panic!("Lease already held"),
    };

    // Notify coordinator process that worker is ready and holding the lease
    println!(
        "[IPC] READY {} {} {}",
        std::process::id(),
        owner_id,
        fencing_token
    );
    let _ = std::io::stdout().flush();

    match mode.as_str() {
        "graceful" => {
            // Loop until signal arrives
            while !stop_signal.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(10));
            }

            // Normal graceful cleanup outside signal handler
            let released = storage
                .release_observer_lease(&session_id, &owner_id, fencing_token)
                .expect("release lease");
            assert!(released, "Worker lease must be released");

            println!("[IPC] CLEAN_EXIT");
            let _ = std::io::stdout().flush();
            std::process::exit(0);
        }
        "stall_on_first_signal" => {
            // Wait for 1st signal
            while !stop_signal.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(10));
            }

            // Acknowledge first signal, but intentionally stall without releasing the lease
            println!("[IPC] FIRST_SIGNAL_HANDLED");
            let _ = std::io::stdout().flush();

            // Stall: waiting for 2nd signal which must trigger default termination
            loop {
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        _ => panic!("Unknown mode: {}", mode),
    }
}

/// Helper to setup a test database with an active session.
fn setup_test_db(session_id: &str) -> (NamedTempFile, StorageManager) {
    let tmp = NamedTempFile::new().expect("temp db");
    let storage = StorageManager::open(tmp.path()).expect("open db");

    let conn = rusqlite::Connection::open(tmp.path()).expect("open raw");
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO sessions (id, agent_kind, status, start_time, confidence, evidence, created_at)
         VALUES (?1, 'claude', 'ACTIVE', ?2, 2, '[]', ?3)",
        params![session_id, now, now],
    )
    .expect("insert session");

    (tmp, storage)
}

/// Helper to read a specific IPC line from child process stdout.
fn wait_for_ipc_line<R: BufRead>(reader: &mut R, prefix: &str, timeout: Duration) -> String {
    let start = Instant::now();
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => panic!("Child closed stdout while waiting for '{}'", prefix),
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.starts_with(prefix) {
                    return trimmed.to_string();
                }
            }
            Err(e) => panic!("Failed to read stdout: {}", e),
        }
        if start.elapsed() > timeout {
            panic!("Timed out waiting for IPC prefix '{}'", prefix);
        }
    }
}

#[test]
fn test_signal_scenario_1_first_sigint_graceful_shutdown() {
    let session_id = "sess-sigint-graceful";
    let (tmp, storage) = setup_test_db(session_id);

    let mut child = Command::new(std::env::current_exe().expect("current exe"))
        .arg("signal_worker_entry")
        .arg("--exact")
        .arg("--ignored")
        .arg("--nocapture")
        .env("TIMMY_SIGNAL_TEST_MODE", "graceful")
        .env("TIMMY_TEST_DB", tmp.path())
        .env("TIMMY_TEST_SESSION_ID", session_id)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn worker");

    let stdout = child.stdout.take().expect("child stdout");
    let mut reader = BufReader::new(stdout);

    let ready_line = wait_for_ipc_line(&mut reader, "[IPC] READY", Duration::from_secs(3));
    let child_pid = child.id() as i32;
    assert!(ready_line.contains(&child_pid.to_string()));

    // Verify lease is held by worker
    let lease = storage.get_observer_lease(session_id).unwrap().unwrap();
    assert_eq!(lease.owner_id, format!("worker-{}", child_pid));

    // Send first SIGINT to child
    unsafe {
        libc::kill(child_pid, libc::SIGINT);
    }

    // Verify child exited cleanly
    let exit_line = wait_for_ipc_line(&mut reader, "[IPC] CLEAN_EXIT", Duration::from_secs(3));
    assert_eq!(exit_line, "[IPC] CLEAN_EXIT");

    let status = child.wait().expect("wait child");
    assert!(
        status.success(),
        "First SIGINT must exit with code 0 (graceful)"
    );

    // Requirement 5: Verify lease was cleanly released in SQLite
    let lease_after = storage.get_observer_lease(session_id).unwrap();
    assert!(
        lease_after.is_none(),
        "Observer lease must be released on graceful shutdown"
    );
}

#[test]
fn test_signal_scenario_2_first_sigterm_graceful_shutdown() {
    let session_id = "sess-sigterm-graceful";
    let (tmp, storage) = setup_test_db(session_id);

    let mut child = Command::new(std::env::current_exe().expect("current exe"))
        .arg("signal_worker_entry")
        .arg("--exact")
        .arg("--ignored")
        .arg("--nocapture")
        .env("TIMMY_SIGNAL_TEST_MODE", "graceful")
        .env("TIMMY_TEST_DB", tmp.path())
        .env("TIMMY_TEST_SESSION_ID", session_id)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn worker");

    let stdout = child.stdout.take().expect("child stdout");
    let mut reader = BufReader::new(stdout);

    let ready_line = wait_for_ipc_line(&mut reader, "[IPC] READY", Duration::from_secs(3));
    let child_pid = child.id() as i32;
    assert!(ready_line.contains(&child_pid.to_string()));

    // Send first SIGTERM to child
    unsafe {
        libc::kill(child_pid, libc::SIGTERM);
    }

    let exit_line = wait_for_ipc_line(&mut reader, "[IPC] CLEAN_EXIT", Duration::from_secs(3));
    assert_eq!(exit_line, "[IPC] CLEAN_EXIT");

    let status = child.wait().expect("wait child");
    assert!(
        status.success(),
        "First SIGTERM must exit with code 0 (graceful)"
    );

    // Verify lease was cleanly released
    let lease_after = storage.get_observer_lease(session_id).unwrap();
    assert!(
        lease_after.is_none(),
        "Observer lease must be released on graceful SIGTERM"
    );
}

#[test]
fn test_signal_scenario_3_repeated_sigint_forced_termination() {
    let session_id = "sess-sigint-repeat";
    let (tmp, _storage) = setup_test_db(session_id);

    let mut child = Command::new(std::env::current_exe().expect("current exe"))
        .arg("signal_worker_entry")
        .arg("--exact")
        .arg("--ignored")
        .arg("--nocapture")
        .env("TIMMY_SIGNAL_TEST_MODE", "stall_on_first_signal")
        .env("TIMMY_TEST_DB", tmp.path())
        .env("TIMMY_TEST_SESSION_ID", session_id)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn worker");

    let stdout = child.stdout.take().expect("child stdout");
    let mut reader = BufReader::new(stdout);

    wait_for_ipc_line(&mut reader, "[IPC] READY", Duration::from_secs(3));
    let child_pid = child.id() as i32;

    // Send first SIGINT
    unsafe {
        libc::kill(child_pid, libc::SIGINT);
    }

    // Verify first signal handled and worker entered stall
    wait_for_ipc_line(
        &mut reader,
        "[IPC] FIRST_SIGNAL_HANDLED",
        Duration::from_secs(3),
    );

    // Verify child is still alive during stall
    let check_alive = unsafe { libc::kill(child_pid, 0) };
    assert_eq!(
        check_alive, 0,
        "Child must still be alive after first SIGINT"
    );

    // Send repeated (second) SIGINT
    unsafe {
        libc::kill(child_pid, libc::SIGINT);
    }

    // Verify child terminates promptly via default action (not hung)
    let start = Instant::now();
    let status = child.wait().expect("wait on child");
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "Second SIGINT must terminate child immediately"
    );
    assert!(
        !status.success(),
        "Second SIGINT must result in abnormal/signal termination"
    );
}

#[test]
fn test_signal_scenario_4_repeated_sigterm_forced_termination() {
    let session_id = "sess-sigterm-repeat";
    let (tmp, _storage) = setup_test_db(session_id);

    let mut child = Command::new(std::env::current_exe().expect("current exe"))
        .arg("signal_worker_entry")
        .arg("--exact")
        .arg("--ignored")
        .arg("--nocapture")
        .env("TIMMY_SIGNAL_TEST_MODE", "stall_on_first_signal")
        .env("TIMMY_TEST_DB", tmp.path())
        .env("TIMMY_TEST_SESSION_ID", session_id)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn worker");

    let stdout = child.stdout.take().expect("child stdout");
    let mut reader = BufReader::new(stdout);

    wait_for_ipc_line(&mut reader, "[IPC] READY", Duration::from_secs(3));
    let child_pid = child.id() as i32;

    // Send first SIGTERM
    unsafe {
        libc::kill(child_pid, libc::SIGTERM);
    }

    wait_for_ipc_line(
        &mut reader,
        "[IPC] FIRST_SIGNAL_HANDLED",
        Duration::from_secs(3),
    );

    // Send repeated (second) SIGTERM
    unsafe {
        libc::kill(child_pid, libc::SIGTERM);
    }

    // Verify child terminates promptly via default action
    let start = Instant::now();
    let status = child.wait().expect("wait child");
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "Second SIGTERM must terminate child immediately"
    );
    assert!(
        !status.success(),
        "Second SIGTERM must result in signal termination"
    );
}

#[test]
fn test_signal_scenario_5_lease_release_enables_immediate_reacquisition() {
    let session_id = "sess-immediate-reacq";
    let (tmp, storage) = setup_test_db(session_id);

    // 1. Worker 1 acquires lease and cleanly shuts down on SIGINT
    let mut child = Command::new(std::env::current_exe().expect("current exe"))
        .arg("signal_worker_entry")
        .arg("--exact")
        .arg("--ignored")
        .arg("--nocapture")
        .env("TIMMY_SIGNAL_TEST_MODE", "graceful")
        .env("TIMMY_TEST_DB", tmp.path())
        .env("TIMMY_TEST_SESSION_ID", session_id)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn worker");

    let stdout = child.stdout.take().expect("child stdout");
    let mut reader = BufReader::new(stdout);

    wait_for_ipc_line(&mut reader, "[IPC] READY", Duration::from_secs(3));
    let child_pid = child.id() as i32;

    unsafe {
        libc::kill(child_pid, libc::SIGINT);
    }

    let _ = child.wait().expect("child wait");

    // 2. Worker 2 immediately acquires lease with zero wait time
    let res = storage
        .acquire_observer_lease(session_id, "worker-2", 6)
        .expect("acquire worker 2");

    match res {
        LeaseAcquisitionResult::Acquired(l) => {
            assert_eq!(l.owner_id, "worker-2");
            assert_eq!(
                l.fencing_token, 2,
                "Generation increments to 2 after release"
            );
        }
        _ => panic!("Expected immediate acquisition after graceful lease release"),
    }
}

#[test]
fn test_signal_scenario_6_forced_termination_allows_expiry_based_recovery() {
    let session_id = "sess-forced-recovery";
    let (tmp, storage) = setup_test_db(session_id);

    // 1. Worker acquires lease with short TTL = 1s and stalls on first signal
    let mut child = Command::new(std::env::current_exe().expect("current exe"))
        .arg("signal_worker_entry")
        .arg("--exact")
        .arg("--ignored")
        .arg("--nocapture")
        .env("TIMMY_SIGNAL_TEST_MODE", "stall_on_first_signal")
        .env("TIMMY_TEST_DB", tmp.path())
        .env("TIMMY_TEST_SESSION_ID", session_id)
        .env("TIMMY_TEST_TTL", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn worker");

    let stdout = child.stdout.take().expect("child stdout");
    let mut reader = BufReader::new(stdout);

    wait_for_ipc_line(&mut reader, "[IPC] READY", Duration::from_secs(3));
    let child_pid = child.id() as i32;

    // Send first SIGINT to arm, then second SIGINT to force-terminate
    unsafe {
        libc::kill(child_pid, libc::SIGINT);
    }
    wait_for_ipc_line(
        &mut reader,
        "[IPC] FIRST_SIGNAL_HANDLED",
        Duration::from_secs(3),
    );
    unsafe {
        libc::kill(child_pid, libc::SIGINT);
    }
    let _ = child.wait().expect("child exit");

    // 2. Immediately after crash, lease row still exists in DB because worker was abruptly killed
    let unexpired_lease = storage.get_observer_lease(session_id).unwrap().unwrap();
    assert_eq!(unexpired_lease.owner_id, format!("worker-{}", child_pid));
    assert_eq!(unexpired_lease.fencing_token, 1);

    // Attempting acquisition before TTL expires reports AlreadyHeld
    let premature_acq = storage
        .acquire_observer_lease(session_id, "recovery-owner", 6)
        .unwrap();
    match premature_acq {
        LeaseAcquisitionResult::AlreadyHeld { current_owner, .. } => {
            assert_eq!(current_owner, format!("worker-{}", child_pid));
        }
        _ => panic!("Expected AlreadyHeld prior to TTL expiration"),
    }

    // 3. Wait for TTL to expire (> 1s)
    std::thread::sleep(Duration::from_millis(1100));

    // 4. New owner recovers lease via RecoveredFromExpired with new generation token
    let recovered_acq = storage
        .acquire_observer_lease(session_id, "recovery-owner", 6)
        .expect("recovery acquisition");

    match recovered_acq {
        LeaseAcquisitionResult::RecoveredFromExpired {
            lease,
            previous_owner,
        } => {
            assert_eq!(previous_owner, format!("worker-{}", child_pid));
            assert_eq!(lease.owner_id, "recovery-owner");
            assert_eq!(
                lease.fencing_token, 2,
                "Recovered lease gets incremented token 2"
            );
        }
        _ => panic!("Expected RecoveredFromExpired after TTL expiration"),
    }

    assert_eq!(storage.get_last_fencing_token(session_id).unwrap(), 2);
}
