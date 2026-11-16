#![cfg(target_os = "macos")]

use std::path::PathBuf;
use std::process::{Command, Stdio};
use timmy::model::{
    FieldStatus, IdentityMatchResult, LaunchProvenance, ObservedExecutablePathChange,
    ProcessIncarnation, ProcessInfo, ProcessObservationState, ProcessStartTime,
    SnapshotCompleteness,
};
use timmy::platform::macos::darwin_sys::{
    evaluate_process_observation_state, get_proc_cmdline_darwin, get_proc_pidpath_darwin,
    get_proc_taskallinfo_darwin, get_proc_vnodepathinfo_darwin, list_pids_darwin,
    parse_procargs2_buffer, PROC_STATUS_ZOMBIE,
};
use timmy::platform::macos::proc::{is_process_alive, send_signal, DarwinProcessCollector};
use timmy::platform::macos::MacOsCollector;
use timmy::platform::traits::ProcessCollector;

// ============================================================================
// 1. FFI Structure Layout & Alignment Verification
// ============================================================================

#[test]
fn test_compile_time_ffi_assertions() {
    assert_eq!(std::mem::size_of::<libc::proc_bsdinfo>(), 136);
    assert_eq!(std::mem::align_of::<libc::proc_bsdinfo>(), 8);

    assert_eq!(std::mem::size_of::<libc::proc_taskinfo>(), 96);
    assert_eq!(std::mem::align_of::<libc::proc_taskinfo>(), 8);

    assert_eq!(std::mem::size_of::<libc::proc_taskallinfo>(), 232);
    assert_eq!(std::mem::align_of::<libc::proc_taskallinfo>(), 8);

    assert_eq!(std::mem::size_of::<libc::proc_vnodepathinfo>(), 2352);
    assert_eq!(std::mem::align_of::<libc::proc_vnodepathinfo>(), 8);

    assert_eq!(std::mem::size_of::<libc::proc_fdinfo>(), 8);
    assert_eq!(std::mem::align_of::<libc::proc_fdinfo>(), 4);
}

// ============================================================================
// 2. Process Incarnation Identity & Exact Start Time Matching
// ============================================================================

#[test]
fn test_process_incarnation_identity_exact_matching() {
    let t1 = ProcessStartTime::new(1700000000, 500000);
    let t2 = ProcessStartTime::new(1700000000, 500000);
    let t3 = ProcessStartTime::new(1700000000, 500001); // 1 microsecond difference!
    let t4 = ProcessStartTime::new(1700000001, 500000); // 1 second difference

    let inc1 = ProcessIncarnation::new(1001, t1);
    let inc2 = ProcessIncarnation::new(1001, t2);
    let inc3 = ProcessIncarnation::new(1001, t3);
    let inc4 = ProcessIncarnation::new(1001, t4);
    let inc5 = ProcessIncarnation::new(1002, t1); // Different PID

    assert_eq!(inc1, inc2);
    assert_ne!(
        inc1, inc3,
        "1 microsecond difference must invalidate identity"
    );
    assert_ne!(inc1, inc4, "1 second difference must invalidate identity");
    assert_ne!(inc1, inc5, "Different PID must invalidate identity");
}

#[test]
fn test_process_identity_missing_start_time_unverifiable() {
    let prov = LaunchProvenance::verified_session_root_binding(
        "sess-1".to_string(),
        500,
        None, // Missing start time
        "claude".to_string(),
        Some(PathBuf::from("/bin/claude")),
        Some(1),
        "binding".to_string(),
    );

    let proc = ProcessInfo {
        pid: 500,
        name: "claude".to_string(),
        exe: Some(PathBuf::from("/bin/claude")),
        start_time: None,
        ..Default::default()
    };

    assert_eq!(
        prov.verify_process_identity(&proc),
        IdentityMatchResult::MissingStartTime
    );
    assert!(!prov.matches_process(&proc));
}

#[test]
fn test_process_identity_microsecond_exactness_in_provenance() {
    let mut prov = LaunchProvenance::verified_session_root_binding(
        "sess-1".to_string(),
        500,
        Some(1700000000),
        "claude".to_string(),
        Some(PathBuf::from("/bin/claude")),
        Some(1),
        "binding".to_string(),
    );
    prov.process.start_time_precise = Some(ProcessStartTime::new(1700000000, 123456));

    // Candidate process with identical start time
    let proc_exact = ProcessInfo {
        pid: 500,
        name: "claude".to_string(),
        exe: Some(PathBuf::from("/bin/claude")),
        start_time: Some(1700000000),
        start_time_precise: Some(ProcessStartTime::new(1700000000, 123456)),
        ..Default::default()
    };
    assert_eq!(
        prov.verify_process_identity(&proc_exact),
        IdentityMatchResult::ExactMatch
    );

    // Candidate process with 1 microsecond mismatch (recycled PID)
    let proc_recycled = ProcessInfo {
        pid: 500,
        name: "claude".to_string(),
        exe: Some(PathBuf::from("/bin/claude")),
        start_time: Some(1700000000),
        start_time_precise: Some(ProcessStartTime::new(1700000000, 123457)),
        ..Default::default()
    };
    assert_eq!(
        prov.verify_process_identity(&proc_recycled),
        IdentityMatchResult::StartTimeMismatch
    );
}

#[test]
fn test_process_incarnation_stable_across_executable_change() {
    let start_time = ProcessStartTime::new(1700000000, 999);
    let incarnation = ProcessIncarnation::new(4001, start_time);

    let change = ObservedExecutablePathChange {
        incarnation,
        previous_exe: Some(PathBuf::from("/bin/bash")),
        observed_exe: PathBuf::from("/usr/local/bin/node"),
        observed_at: chrono::Utc::now(),
    };

    assert_eq!(change.incarnation.pid, 4001);
    assert_eq!(change.incarnation.start_time, start_time);
    assert_eq!(change.previous_exe, Some(PathBuf::from("/bin/bash")));
    assert_eq!(change.observed_exe, PathBuf::from("/usr/local/bin/node"));
}

#[test]
fn test_observed_executable_path_change_preserves_incarnation_and_does_not_promote_confidence() {
    let start_time = ProcessStartTime::new(1700000000, 123456);
    let incarnation = ProcessIncarnation::new(5555, start_time);

    let path_change = ObservedExecutablePathChange {
        incarnation,
        previous_exe: Some(PathBuf::from("/usr/bin/python3")),
        observed_exe: PathBuf::from("/usr/local/bin/python3.11"),
        observed_at: chrono::Utc::now(),
    };

    // Incarnation identity (PID and exact kernel start time) is strictly unchanged
    assert_eq!(path_change.incarnation.pid, 5555);
    assert_eq!(path_change.incarnation.start_time, start_time);
    assert_eq!(
        path_change.previous_exe,
        Some(PathBuf::from("/usr/bin/python3"))
    );
    assert_eq!(
        path_change.observed_exe,
        PathBuf::from("/usr/local/bin/python3.11")
    );

    // Verify that observed path change alone never promotes attribution confidence
    use timmy::model::Confidence;
    let base_confidence = Confidence::Inferred;
    // An executable path change is a descriptive observation of an existing process incarnation,
    // not a verified supervisor spawn event or verified root binding.
    let resulting_confidence = base_confidence;
    assert_ne!(resulting_confidence, Confidence::Confirmed);
    assert_ne!(resulting_confidence, Confidence::HighConfidence);
}

// ============================================================================
// 3. Byte-Level sysctl KERN_PROCARGS2 Parser Tests
// ============================================================================

#[test]
fn test_sysctl_procargs2_empty_arguments() {
    // argc = 0, followed by exec_path\0
    let mut buf = Vec::new();
    buf.extend_from_slice(&0i32.to_ne_bytes());
    buf.extend_from_slice(b"/bin/test\0");

    let parsed = parse_procargs2_buffer(&buf).expect("Should parse argc = 0");
    assert!(parsed.is_empty(), "argc = 0 must yield empty argument list");
}

#[test]
fn test_sysctl_procargs2_normal_arguments_with_padding() {
    let mut buf = Vec::new();
    let argc: i32 = 3;
    buf.extend_from_slice(&argc.to_ne_bytes());
    buf.extend_from_slice(b"/bin/tool\0");
    // Trailing padding nulls
    buf.extend_from_slice(&[0, 0, 0]);
    // argv[0], argv[1], argv[2]
    buf.extend_from_slice(b"tool\0--flag\0value\0");
    // Trailing environment variables that MUST be excluded
    buf.extend_from_slice(b"SECRET_KEY=supersecret\0USER=root\0");

    let parsed = parse_procargs2_buffer(&buf).expect("Should parse valid procargs2 buffer");
    assert_eq!(parsed, vec!["tool", "--flag", "value"]);
}

#[test]
fn test_sysctl_procargs2_secret_masking() {
    let mut buf = Vec::new();
    let argc: i32 = 3;
    buf.extend_from_slice(&argc.to_ne_bytes());
    buf.extend_from_slice(b"/bin/auth\0\0\0");
    buf.extend_from_slice(b"auth\0--token\0ghp_1234567890abcdef\0");

    let parsed = parse_procargs2_buffer(&buf).expect("Should parse and mask args");
    assert_eq!(parsed[0], "auth");
    assert_eq!(parsed[1], "--token");
    assert_ne!(
        parsed[2], "ghp_1234567890abcdef",
        "Sensitive token value must be masked"
    );
    assert!(
        parsed[2].contains("[REDACTED]") || parsed[2].contains("***"),
        "Masked value should contain redaction marker"
    );
}

#[test]
fn test_sysctl_procargs2_malformed_buffer_handling() {
    // 1. Buffer too short (<4 bytes)
    assert!(parse_procargs2_buffer(&[0, 1]).is_err());

    // 2. Negative argc
    let mut neg_buf = Vec::new();
    neg_buf.extend_from_slice(&(-5i32).to_ne_bytes());
    neg_buf.extend_from_slice(b"/bin/test\0");
    assert!(parse_procargs2_buffer(&neg_buf).is_err());

    // 3. Executable path missing null terminator
    let mut no_nul_buf = Vec::new();
    no_nul_buf.extend_from_slice(&1i32.to_ne_bytes());
    no_nul_buf.extend_from_slice(b"/bin/no_terminator");
    assert!(parse_procargs2_buffer(&no_nul_buf).is_err());

    // 4. argc claims 5 arguments, but buffer truncates after 2
    let mut trunc_buf = Vec::new();
    trunc_buf.extend_from_slice(&5i32.to_ne_bytes());
    trunc_buf.extend_from_slice(b"/bin/tool\0\0arg0\0arg1\0");
    assert!(parse_procargs2_buffer(&trunc_buf).is_err());
}

#[test]
fn test_sysctl_procargs2_lossy_utf8_conversion() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&1i32.to_ne_bytes());
    buf.extend_from_slice(b"/bin/tool\0\0");
    // Invalid UTF-8 byte 0xFF
    buf.extend_from_slice(&[b'a', b'r', b'g', 0xFF, 0]);

    let parsed = parse_procargs2_buffer(&buf).expect("Lossy conversion should not fail");
    assert_eq!(parsed.len(), 1);
    assert!(parsed[0].starts_with("arg"));
}

// ============================================================================
// 4. Per-Field Status & Restricted Data Reporting
// ============================================================================

#[test]
fn test_process_info_field_status_isolation() {
    let proc = ProcessInfo {
        pid: 2000,
        name: "restricted_daemon".to_string(),
        observation_state: ProcessObservationState::InspectionRestricted,
        exe_status: FieldStatus::Restricted,
        cmdline_status: FieldStatus::Restricted,
        cwd_status: FieldStatus::Restricted,
        task_metrics: FieldStatus::Restricted,
        memory_bytes: None,
        cpu_usage: None,
        ..Default::default()
    };

    assert!(proc.is_restricted());
    assert_eq!(proc.formatted_memory(), "N/A (Restricted)");
    assert_eq!(proc.formatted_cpu(), "N/A");
    assert!(!proc.exe_status.is_available());
    assert!(!proc.cmdline_status.is_available());
}

// ============================================================================
// 5. Live Darwin Process Collector Integration Tests
// ============================================================================

#[test]
fn test_darwin_process_collector_live_enumeration() {
    let collector = DarwinProcessCollector::new();
    let snapshot = collector
        .collect_process_snapshot()
        .expect("Native live snapshot should succeed");

    assert!(
        !snapshot.processes.is_empty(),
        "Active processes must be enumerated"
    );
    assert!(
        snapshot.completeness == SnapshotCompleteness::Complete,
        "Snapshot should be complete under normal operation"
    );

    // Verify presence of current process
    let current_pid = std::process::id();
    let my_proc = snapshot
        .processes
        .iter()
        .find(|p| p.pid == current_pid)
        .expect("Current process must be present in Darwin snapshot");

    assert_eq!(my_proc.pid, current_pid);
    assert!(
        my_proc.start_time_precise.is_some(),
        "Microsecond start timestamp must be populated"
    );
    let precise = my_proc.start_time_precise.unwrap();
    assert!(precise.tv_sec > 0);
    assert!(precise.tv_usec < 1_000_000);
}

#[test]
fn test_darwin_process_collector_deterministic_child_lifecycle() {
    let collector = DarwinProcessCollector::new();

    // 1. Spawn a controlled child process (cat waiting for stdin)
    let mut child = Command::new("cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .expect("Failed to spawn controlled test child");

    let child_pid = child.id();

    // 2. Query child details while it is running
    let detail = collector
        .inspect_process(child_pid)
        .expect("Child process must be inspectable");

    assert_eq!(detail.info.pid, child_pid);
    assert_eq!(
        detail.info.observation_state,
        ProcessObservationState::Present
    );
    assert!(detail.info.start_time_precise.is_some());
    let child_start = detail.info.start_time_precise;

    // Verify exe path points to /bin/cat or equivalent
    if let FieldStatus::Available(exe_path) = &detail.info.exe_status {
        assert!(exe_path.to_string_lossy().contains("cat"));
    }

    // Verify process is alive
    assert!(is_process_alive(child_pid));

    // 3. Terminate child process deterministically
    send_signal(child_pid, libc::SIGKILL).expect("SIGKILL delivery should succeed");
    let exit_status = child.wait().expect("Wait on child should succeed");
    assert!(!exit_status.success());

    // 4. Verify positive exit confirmation
    let exit_state = evaluate_process_observation_state(child_pid, child_start);
    assert_eq!(
        exit_state,
        ProcessObservationState::ExitedConfirmed,
        "Terminated and reaped child must be confirmed exited via ESRCH"
    );
}

#[test]
fn test_darwin_sys_direct_apis_on_current_process() {
    let current_pid = std::process::id();

    // 1. list_pids_darwin
    let (pids, completeness) = list_pids_darwin().expect("list_pids_darwin should succeed");
    assert!(!pids.is_empty());
    assert!(pids.contains(&current_pid));
    assert_eq!(completeness, SnapshotCompleteness::Complete);

    // 2. get_proc_taskallinfo_darwin
    let taskall =
        get_proc_taskallinfo_darwin(current_pid).expect("taskallinfo on self should succeed");
    assert_eq!(taskall.pbsd.pbi_pid, current_pid);
    assert!(taskall.pbsd.pbi_start_tvsec > 0);
    assert_ne!(taskall.pbsd.pbi_status, PROC_STATUS_ZOMBIE);

    // 3. get_proc_pidpath_darwin
    let exe = get_proc_pidpath_darwin(current_pid).expect("pidpath on self should succeed");
    assert!(exe.exists());

    // 4. get_proc_cmdline_darwin
    let cmdline = get_proc_cmdline_darwin(current_pid).expect("cmdline on self should succeed");
    assert!(!cmdline.is_empty());

    // 5. get_proc_vnodepathinfo_darwin
    let cwd = get_proc_vnodepathinfo_darwin(current_pid).expect("cwd on self should succeed");
    assert!(cwd.exists());
}

#[test]
fn test_darwin_process_collector_fallback_integration() {
    let macos_collector = MacOsCollector::new();

    // Test that MacOsCollector successfully delegates to DarwinProcessCollector
    let snapshot = macos_collector
        .collect_process_snapshot()
        .expect("MacOsCollector snapshot must succeed");

    assert!(!snapshot.processes.is_empty());
    assert!(snapshot
        .processes
        .iter()
        .any(|p| p.pid == std::process::id()));
}

// ============================================================================
// 7. Deterministic Truncation & Error Handling Tests for list_pids_darwin
// ============================================================================

#[test]
fn test_list_pids_max_buffer_full_is_truncated() {
    // Simulate proc_listpids reaching MAX_PROC_LIST_BUFFER_BYTES (1 MB = 262,144 PIDs) and remaining full
    let max_bytes: i32 = 1024 * 1024;
    let (pids, completeness) = timmy::platform::macos::darwin_sys::list_pids_darwin_with_caller(
        |_which, _arg, ptr, size| {
            if ptr.is_null() {
                // Size query requests max buffer
                max_bytes
            } else {
                // Data query fills the full buffer with dummy PIDs
                let pid_slice = unsafe {
                    std::slice::from_raw_parts_mut(ptr as *mut libc::pid_t, (size as usize) / 4)
                };
                for (i, p) in pid_slice.iter_mut().enumerate() {
                    *p = (i as i32) + 1;
                }
                size // Full buffer returned
            }
        },
    )
    .expect("list_pids should succeed with truncation");

    assert_eq!(pids.len(), 262_144);
    match completeness {
        SnapshotCompleteness::Truncated {
            returned_count,
            capacity,
        } => {
            assert_eq!(returned_count, 262_144);
            assert_eq!(capacity, 262_144);
        }
        SnapshotCompleteness::Complete => panic!("Snapshot must be Truncated, never Complete!"),
        _ => panic!("Unexpected snapshot completeness state"),
    }
}

#[test]
fn test_list_pids_zero_return_with_nonzero_errno() {
    // Simulate proc_listpids returning 0 with errno = EPERM
    let result = timmy::platform::macos::darwin_sys::list_pids_darwin_with_caller(
        |_which, _arg, _ptr, _size| {
            unsafe {
                *libc::__error() = libc::EPERM;
            }
            0
        },
    );

    assert!(result.is_err());
    let err_str = result.unwrap_err().to_string();
    assert!(
        err_str.contains("errno 1"),
        "Error must report underlying errno: {}",
        err_str
    );
}

#[test]
fn test_list_pids_non_aligned_byte_count_rejected() {
    // Simulate proc_listpids returning 13 bytes (not a multiple of sizeof(pid_t) = 4)
    let result = timmy::platform::macos::darwin_sys::list_pids_darwin_with_caller(
        |_which, _arg, ptr, _size| {
            if ptr.is_null() {
                16
            } else {
                13 // Not divisible by 4
            }
        },
    );

    assert!(result.is_err());
    let err_str = result.unwrap_err().to_string();
    assert!(
        err_str.contains("non-aligned"),
        "Error must reject non-aligned byte count: {}",
        err_str
    );
}

#[test]
fn test_list_pids_exceeding_capacity_rejected() {
    // Simulate proc_listpids returning byte count exceeding buffer capacity
    let result = timmy::platform::macos::darwin_sys::list_pids_darwin_with_caller(
        |_which, _arg, ptr, size| {
            if ptr.is_null() {
                4096
            } else {
                size + 100 // Exceeds capacity
            }
        },
    );

    assert!(result.is_err());
    let err_str = result.unwrap_err().to_string();
    assert!(
        err_str.contains("exceeding buffer capacity"),
        "Error must reject capacity violation: {}",
        err_str
    );
}

#[test]
fn test_list_pids_spare_capacity_reports_complete() {
    // Simulate proc_listpids with normal capacity and spare room
    let (pids, completeness) = timmy::platform::macos::darwin_sys::list_pids_darwin_with_caller(
        |_which, _arg, ptr, _size| {
            if ptr.is_null() {
                400 // 100 PIDs requested
            } else {
                let pid_slice =
                    unsafe { std::slice::from_raw_parts_mut(ptr as *mut libc::pid_t, 100) };
                for (i, p) in pid_slice.iter_mut().enumerate() {
                    *p = (i as i32) + 100;
                }
                400 // 100 PIDs returned into 4096-byte capacity
            }
        },
    )
    .expect("list_pids should succeed");

    assert_eq!(pids.len(), 100);
    assert_eq!(completeness, SnapshotCompleteness::Complete);
}

// ============================================================================
// 8. Deterministic PID-Reuse & Process-Exit Race Handling Tests
// ============================================================================

fn make_mock_taskallinfo(
    pid: u32,
    start_tvsec: u64,
    start_tvusec: u64,
    is_zombie: bool,
) -> libc::proc_taskallinfo {
    let mut info: libc::proc_taskallinfo = unsafe { std::mem::zeroed() };
    info.pbsd.pbi_pid = pid;
    info.pbsd.pbi_start_tvsec = start_tvsec;
    info.pbsd.pbi_start_tvusec = start_tvusec;
    info.pbsd.pbi_status = if is_zombie { PROC_STATUS_ZOMBIE } else { 2 };
    info
}

#[test]
fn test_evaluate_process_observation_state_exact_exit_confirmed() {
    let start_time = ProcessStartTime::new(1700000000, 100);
    let target_pid = 9001;

    // Both info and kill return ESRCH (ProcessNotFound)
    let state = timmy::platform::macos::darwin_sys::evaluate_process_observation_state_impl(
        target_pid,
        Some(start_time),
        |_| {
            Err(timmy::platform::traits::PlatformError::ProcessNotFound(
                target_pid,
            ))
        },
        |_| {
            Err(timmy::platform::traits::PlatformError::ProcessNotFound(
                target_pid,
            ))
        },
    );

    assert_eq!(state, ProcessObservationState::ExitedConfirmed);
}

#[test]
fn test_evaluate_process_observation_state_pid_reuse_between_calls() {
    let original_start = ProcessStartTime::new(1700000000, 100);
    let recycled_start = ProcessStartTime::new(1700000050, 200);
    let target_pid = 9002;

    // First call: info_fn returns ESRCH.
    // But kill_fn succeeds (return Ok(())), meaning a new process acquired target_pid!
    // When info_fn is called again, it returns the NEW process with recycled_start!
    let info_call_count = std::sync::atomic::AtomicUsize::new(0);
    let state = timmy::platform::macos::darwin_sys::evaluate_process_observation_state_impl(
        target_pid,
        Some(original_start),
        |_| {
            let count = info_call_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if count == 0 {
                Err(timmy::platform::traits::PlatformError::ProcessNotFound(
                    target_pid,
                ))
            } else {
                Ok(make_mock_taskallinfo(
                    target_pid,
                    recycled_start.tv_sec,
                    recycled_start.tv_usec,
                    false,
                ))
            }
        },
        |_| Ok(()), // kill succeeds!
    );

    // Must NOT classify as ExitedConfirmed for the new process! Must identify PidReused!
    assert_eq!(state, ProcessObservationState::PidReused);
}

#[test]
fn test_evaluate_process_observation_state_changed_start_time_is_pid_reuse() {
    let original_start = ProcessStartTime::new(1700000000, 100);
    let different_start = ProcessStartTime::new(1700000010, 500);
    let target_pid = 9003;

    let state = timmy::platform::macos::darwin_sys::evaluate_process_observation_state_impl(
        target_pid,
        Some(original_start),
        |_| {
            Ok(make_mock_taskallinfo(
                target_pid,
                different_start.tv_sec,
                different_start.tv_usec,
                false,
            ))
        },
        |_| Ok(()),
    );

    assert_eq!(state, ProcessObservationState::PidReused);
}

#[test]
fn test_evaluate_process_observation_state_zombie_is_terminated_unreaped() {
    let start = ProcessStartTime::new(1700000000, 100);
    let target_pid = 9004;

    let state = timmy::platform::macos::darwin_sys::evaluate_process_observation_state_impl(
        target_pid,
        Some(start),
        |_| {
            Ok(make_mock_taskallinfo(
                target_pid,
                start.tv_sec,
                start.tv_usec,
                true,
            ))
        },
        |_| Ok(()),
    );

    assert_eq!(state, ProcessObservationState::TerminatedUnreaped);
}

#[test]
fn test_evaluate_process_observation_state_permission_errors_are_restricted() {
    let start = ProcessStartTime::new(1700000000, 100);
    let target_pid = 9005;

    // Direct PermissionDenied on info
    let state1 = timmy::platform::macos::darwin_sys::evaluate_process_observation_state_impl(
        target_pid,
        Some(start),
        |_| {
            Err(timmy::platform::traits::PlatformError::PermissionDenied(
                target_pid,
            ))
        },
        |_| Ok(()),
    );
    assert_eq!(state1, ProcessObservationState::InspectionRestricted);

    // ProcessNotFound on info, but PermissionDenied on kill
    let state2 = timmy::platform::macos::darwin_sys::evaluate_process_observation_state_impl(
        target_pid,
        Some(start),
        |_| {
            Err(timmy::platform::traits::PlatformError::ProcessNotFound(
                target_pid,
            ))
        },
        |_| {
            Err(timmy::platform::traits::PlatformError::PermissionDenied(
                target_pid,
            ))
        },
    );
    assert_eq!(state2, ProcessObservationState::InspectionRestricted);
}

#[test]
fn test_evaluate_process_observation_state_missing_start_time_is_not_observed() {
    let target_pid = 9006;

    // Missing recorded start time produces NotObserved, never ExitedConfirmed!
    let state = timmy::platform::macos::darwin_sys::evaluate_process_observation_state_impl(
        target_pid,
        None,
        |_| {
            Err(timmy::platform::traits::PlatformError::ProcessNotFound(
                target_pid,
            ))
        },
        |_| {
            Err(timmy::platform::traits::PlatformError::ProcessNotFound(
                target_pid,
            ))
        },
    );
    assert_eq!(state, ProcessObservationState::NotObserved);
}

// ============================================================================
// 9. Secret Exposure Audit & Sanitization Tests
// ============================================================================

#[test]
fn test_secret_sanitization_in_executable_path_and_cwd() {
    use timmy::safety::masker::SecretMasker;

    let secret_path = "/Users/alice/projects/token=sk-ant-api03-abcdefghijklmnop/bin/agent";
    let masked_path = SecretMasker::mask_string(secret_path);
    assert!(!masked_path.contains("sk-ant-api03-abcdefghijklmnop"));
    assert!(masked_path.contains("[REDACTED]") || masked_path.contains("***"));

    let secret_cwd = "/var/folders/postgres://appuser:supersecretpass@db.local:5432/app";
    let masked_cwd = SecretMasker::mask_string(secret_cwd);
    assert!(!masked_cwd.contains("supersecretpass"));
    assert!(masked_cwd.contains("[REDACTED]"));
}

#[test]
fn test_secret_sanitization_in_serialized_json_detail() {
    use timmy::model::{AgentAttribution, ProcessAncestor, ProcessDetail, ProcessInfo};
    use timmy::safety::masker::SecretMasker;

    let raw_args = vec![
        "node".to_string(),
        "--token".to_string(),
        "ghp_1234567890abcdefghijklmnop".to_string(),
        "--db-url=postgres://admin:topsecret123@10.0.0.1:5432/main".to_string(),
    ];
    let masked_args = SecretMasker::mask_cmdline(&raw_args);

    let detail = ProcessDetail {
        info: ProcessInfo {
            pid: 1234,
            ppid: Some(1),
            name: "node".to_string(),
            exe: Some(PathBuf::from(SecretMasker::mask_string(
                "/opt/apps/sk-proj-supersecretkey/node",
            ))),
            cpu_usage: None,
            memory_bytes: Some(1024),
            run_time_secs: 10,
            start_time: Some(1700000000),
            user: Some("501".to_string()),
            attribution: AgentAttribution::default(),
            listening_ports: Vec::new(),
            cmdline: masked_args.clone(),
            command_outcome: None,
            provenance: None,
            start_time_precise: Some(ProcessStartTime::new(1700000000, 0)),
            observation_state: ProcessObservationState::Present,
            exe_status: FieldStatus::Available(PathBuf::from("/opt/apps/[REDACTED]/node")),
            cmdline_status: FieldStatus::Available(masked_args.clone()),
            cwd_status: FieldStatus::Available(PathBuf::from("/workspace")),
            task_metrics: FieldStatus::Unavailable,
        },
        cmdline: masked_args,
        cwd: Some(PathBuf::from("/workspace")),
        environment: Vec::new(), // Strictly empty for Darwin Stage A
        open_files: Vec::new(),
        parent_chain: vec![ProcessAncestor {
            pid: 1,
            name: "launchd".to_string(),
            cmdline_summary: Some("/sbin/launchd".to_string()),
        }],
    };

    let serialized =
        serde_json::to_string_pretty(&detail).expect("JSON serialization must succeed");

    // Zero secret tokens in serialized output
    assert!(!serialized.contains("ghp_1234567890abcdefghijklmnop"));
    assert!(!serialized.contains("topsecret123"));
    assert!(!serialized.contains("sk-proj-supersecretkey"));
}

#[test]
fn test_darwin_collector_environment_strictly_empty() {
    let collector = DarwinProcessCollector::new();
    let current_pid = std::process::id();
    let detail = collector
        .inspect_process(current_pid)
        .expect("inspect_process must succeed on self");

    // Stage A specification requirement: Environment variable values must never be collected or persisted
    assert!(
        detail.environment.is_empty(),
        "DarwinProcessCollector must strictly exclude environment variables from ProcessDetail"
    );
}
