#![cfg(target_os = "macos")]

use chrono::Utc;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use timmy::config::TimmyConfig;
use timmy::engine::session::SessionCoordinator;
use timmy::model::agent::{AgentKind, Confidence};
use timmy::model::session::{SessionInfo, SessionStatus};
use timmy::platform::create_platform_collector;
use timmy::storage::StorageManager;

#[test]
fn test_actual_macos_process_reparenting_integration() {
    // -------------------------------------------------------------------------
    // 1. Spawn a controlled parent process that will spawn a child process
    // -------------------------------------------------------------------------
    let python_script = r#"
import subprocess, sys, os, time

# Spawn child process running /bin/sleep 60
child = subprocess.Popen(["/bin/sleep", "60"])
print(f"{os.getpid()} {child.pid}")
sys.stdout.flush()

# Keep parent alive until stdin is closed or signaled
try:
    sys.stdin.readline()
except:
    pass
sys.exit(0)
"#;

    let mut parent_child = Command::new("/usr/bin/python3")
        .arg("-c")
        .arg(python_script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Must spawn parent python3 process on macOS");

    let stdout = parent_child
        .stdout
        .take()
        .expect("Must capture parent stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .expect("Must read PID output from parent");

    let parts: Vec<&str> = line.split_whitespace().collect();
    assert_eq!(
        parts.len(),
        2,
        "Parent must print parent_pid and child_pid, got '{}'",
        line
    );
    let parent_pid: u32 = parts[0].parse().expect("Valid parent PID");
    let child_pid: u32 = parts[1].parse().expect("Valid child PID");

    println!(
        "Spawned macOS processes: Parent PID={}, Child PID={}",
        parent_pid, child_pid
    );

    // RAII guard to guarantee child process cleanup even if test panics
    struct ProcessCleaner(u32);
    impl Drop for ProcessCleaner {
        fn drop(&mut self) {
            unsafe {
                libc::kill(self.0 as i32, libc::SIGKILL);
            }
        }
    }
    let _cleaner = ProcessCleaner(child_pid);

    // Let the processes initialize
    thread::sleep(Duration::from_millis(150));

    // -------------------------------------------------------------------------
    // 2. Query OS via TIMMY's native MacOsCollector to verify initial state
    // -------------------------------------------------------------------------
    let platform = create_platform_collector();
    let initial_procs = platform
        .collect_processes()
        .expect("Platform must collect live processes");

    let child_live = initial_procs
        .iter()
        .find(|p| p.pid == child_pid)
        .expect("Child process must exist in live process table");

    // Verify that macOS kernel reports child's actual PPID is parent_pid while parent is alive
    assert_eq!(
        child_live.ppid,
        Some(parent_pid),
        "Initial child PPID from macOS kernel must match parent PID"
    );

    // -------------------------------------------------------------------------
    // 3. Ensure TIMMY observes the child while the parent is alive
    // -------------------------------------------------------------------------
    let config = TimmyConfig::default();
    let storage = Arc::new(StorageManager::open_in_memory().expect("Must open DB"));
    let coordinator = SessionCoordinator::new(storage.clone(), config);

    let session = SessionInfo {
        id: "sess-macos-reparenting".to_string(),
        agent_kind: AgentKind::ClaudeCode,
        status: SessionStatus::Active,
        start_time: Utc::now() - chrono::Duration::seconds(5),
        end_time: None,
        root_pid: Some(parent_pid),
        root_process_name: Some("python3".to_string()),
        confidence: Confidence::Confirmed,
        evidence: vec!["Controlled test parent agent process".to_string()],
        tracked_pids: vec![],
        total_memory_bytes: 0,
        total_cpu_usage: 0.0,
        open_ports: vec![],
        resource_count: 0,
        root_binding: None,
    };
    storage
        .save_session(&session)
        .expect("Must save initial session");

    let (sess1, resources_pass1) = coordinator
        .observe_and_update(&session, platform.as_ref())
        .expect("Pass 1 observation must succeed");

    // -------------------------------------------------------------------------
    // 4. Record the child's process identity and attribution evidence
    // -------------------------------------------------------------------------
    let child_tracked_pass1 = resources_pass1
        .iter()
        .find(|r| r.pid == Some(child_pid))
        .expect("Child process must be tracked by TIMMY in Pass 1");

    assert!(!child_tracked_pass1.is_detached);
    assert_eq!(
        child_tracked_pass1.confidence,
        Confidence::HighConfidence,
        "Child descendant must have HighConfidence while parent is alive"
    );

    let child_start_time = child_tracked_pass1.process_start_time;
    let child_first_seen = child_tracked_pass1.first_seen;
    let child_name = child_tracked_pass1.name.clone();

    println!(
        "Pass 1: Child tracked as '{}', start_time={:?}, detached={}, confidence={:?}",
        child_name,
        child_start_time,
        child_tracked_pass1.is_detached,
        child_tracked_pass1.confidence
    );

    // -------------------------------------------------------------------------
    // 5. Terminate the parent process normally
    // -------------------------------------------------------------------------
    // Closing parent's stdin triggers sys.stdin.readline() -> exit(0)
    drop(parent_child.stdin.take());
    let parent_exit_status = parent_child
        .wait()
        .expect("Parent process must wait and exit normally");
    assert!(
        parent_exit_status.success(),
        "Parent process exited cleanly"
    );

    // -------------------------------------------------------------------------
    // 6. Allow macOS to perform the actual re-parenting
    // -------------------------------------------------------------------------
    let mut observed_child_ppid = None;
    let mut child_still_alive = false;

    // Poll actual OS process table for kernel re-parenting
    for _ in 0..30 {
        thread::sleep(Duration::from_millis(50));
        let procs = platform
            .collect_processes()
            .expect("Collect processes after parent exit");
        if let Some(child_proc) = procs.iter().find(|p| p.pid == child_pid) {
            child_still_alive = true;
            if child_proc.ppid != Some(parent_pid) {
                observed_child_ppid = child_proc.ppid;
                break;
            }
        }
    }

    // -------------------------------------------------------------------------
    // 7. Verify that the child remains alive
    // -------------------------------------------------------------------------
    assert!(
        child_still_alive,
        "Child process must remain alive after parent terminates"
    );

    // -------------------------------------------------------------------------
    // 8. Observe the child's actual PPID after the parent exits
    // -------------------------------------------------------------------------
    let actual_new_ppid =
        observed_child_ppid.expect("macOS kernel must report updated PPID for orphaned child");
    println!(
        "Actual macOS kernel re-parented child PPID: {}",
        actual_new_ppid
    );
    // On macOS, orphaned processes are adopted by launchd (PID 1)
    assert_eq!(
        actual_new_ppid, 1,
        "macOS kernel re-parents orphaned child processes to launchd (PID 1)"
    );

    // -------------------------------------------------------------------------
    // 9. Verify that TIMMY retains the child's previous session association
    // 10. Verify that the resource is marked detached
    // 11. Verify that its process identity remains consistent
    // -------------------------------------------------------------------------
    let (_sess2, resources_pass2) = coordinator
        .observe_and_update(&sess1, platform.as_ref())
        .expect("Pass 2 observation after re-parenting must succeed");

    let child_tracked_pass2 = resources_pass2
        .iter()
        .find(|r| r.pid == Some(child_pid))
        .expect("Child process must retain session association in Pass 2");

    assert_eq!(
        child_tracked_pass2.session_id, session.id,
        "Child must retain previous session association"
    );
    assert!(
        child_tracked_pass2.is_detached,
        "Child must now be marked detached = true by TIMMY"
    );
    assert_eq!(
        child_tracked_pass2.confidence,
        Confidence::HighConfidence,
        "TIMMY must retain HighConfidence previously established while parent was alive"
    );
    assert_eq!(
        child_tracked_pass2.name, child_name,
        "Process identity name must remain consistent"
    );
    assert_eq!(
        child_tracked_pass2.first_seen, child_first_seen,
        "first_seen timestamp must remain consistent"
    );
    assert_eq!(
        child_tracked_pass2.process_start_time, child_start_time,
        "process_start_time must remain consistent"
    );

    let has_detached_evidence = child_tracked_pass2
        .evidence
        .iter()
        .any(|ev| ev.contains("Orphaned/detached process (now under PID 1)"));
    assert!(
        has_detached_evidence,
        "Attribution evidence must record detachment under PID 1: {:?}",
        child_tracked_pass2.evidence
    );

    // -------------------------------------------------------------------------
    // 12. Stop monitoring
    // -------------------------------------------------------------------------
    let stopped_sess = coordinator
        .stop_session(Some(&session.id))
        .expect("Must stop session");
    assert_eq!(stopped_sess.status, SessionStatus::Stopped);

    // -------------------------------------------------------------------------
    // 13. Confirm that the child was not terminated by TIMMY
    // -------------------------------------------------------------------------
    let final_procs = platform
        .collect_processes()
        .expect("Collect processes after monitoring stopped");
    let child_is_still_running = final_procs.iter().any(|p| p.pid == child_pid);
    assert!(
        child_is_still_running,
        "TIMMY must NOT have terminated the child process at any point"
    );

    // -------------------------------------------------------------------------
    // 14. Clean up the test processes
    // -------------------------------------------------------------------------
    unsafe {
        libc::kill(child_pid as i32, libc::SIGTERM);
    }
    thread::sleep(Duration::from_millis(50));
    println!("Test cleanup complete: child PID {} terminated.", child_pid);
}
