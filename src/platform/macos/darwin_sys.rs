use crate::model::{
    ListeningPort, ProcessObservationState, ProcessStartTime, Protocol, SnapshotCompleteness,
    SocketState,
};
use crate::platform::traits::PlatformError;
use crate::safety::masker::SecretMasker;
use std::path::PathBuf;

/// Darwin process enumeration scope: all active processes.
pub const PROC_ALL_PIDS: u32 = 1;

/// Darwin flavor for listing process file descriptors.
pub const PROC_PIDLISTFDS: libc::c_int = 1;

/// Darwin flavor for querying socket file descriptor details.
pub const PROC_PIDFDSOCKETINFO: libc::c_int = 3;

/// File descriptor type for sockets (PROX_FDTYPE_SOCKET = 2).
pub const PROX_FDTYPE_SOCKET: u32 = 2;

/// TCP socket state for listening sockets (TSI_S_LISTEN = 1).
pub const TSI_S_LISTEN: i32 = 1;

/// Size of struct socket_fdinfo in Darwin SDK (792 bytes).
pub const SOCKET_FDINFO_SIZE: usize = 792;

// ============================================================================
// Compile-time structure size and alignment assertions (arm64 & x86_64)
// ============================================================================
#[cfg(target_os = "macos")]
const _: () = {
    assert!(std::mem::size_of::<libc::proc_bsdinfo>() == 136);
    assert!(std::mem::align_of::<libc::proc_bsdinfo>() == 8);
    assert!(std::mem::size_of::<libc::proc_taskinfo>() == 96);
    assert!(std::mem::align_of::<libc::proc_taskinfo>() == 8);
    assert!(std::mem::size_of::<libc::proc_taskallinfo>() == 232);
    assert!(std::mem::align_of::<libc::proc_taskallinfo>() == 8);
    assert!(std::mem::size_of::<libc::proc_vnodepathinfo>() == 2352);
    assert!(std::mem::align_of::<libc::proc_vnodepathinfo>() == 8);
    assert!(std::mem::size_of::<libc::proc_fdinfo>() == 8);
    assert!(std::mem::align_of::<libc::proc_fdinfo>() == 4);
    assert!(SOCKET_FDINFO_SIZE == 792);
};

/// Maximum allocation buffer for process listing: 1 MB (262,144 PIDs).
pub const MAX_PROC_LIST_BUFFER_BYTES: usize = 1024 * 1024;

/// Maximum buffer size for command-line arguments: 256 KB (Darwin ARG_MAX / NCARGS).
pub const MAX_ARG_MAX_BYTES: usize = 262_144;

/// Maximum path buffer size: 4096 bytes (Darwin PROC_PIDPATHINFO_MAXSIZE).
pub const MAX_PIDPATH_BYTES: usize = 4096;

/// Darwin process status flag: Zombie process (SZOMB = 5).
pub const PROC_STATUS_ZOMBIE: u32 = 5;

// ============================================================================
// Native Darwin process enumeration via proc_listpids
// ============================================================================

/// Enumerates all active process IDs using Darwin's `proc_listpids()`.
///
/// Implements strict error handling:
/// - Clears `errno` before invocations.
/// - Checks `errno` when return value is 0 (as libproc converts -1 to 0).
/// - Validates buffer bounds and byte alignment (`sizeof(pid_t)` = 4).
/// - Dynamically expands buffer with 25% headroom on truncation (up to 3 retries).
/// - Bounded by `MAX_PROC_LIST_BUFFER_BYTES` to prevent fork-bomb DOS.
pub fn list_pids_darwin() -> Result<(Vec<u32>, SnapshotCompleteness), PlatformError> {
    list_pids_darwin_with_caller(|which, arg, ptr, size| unsafe {
        libc::proc_listpids(which, arg, ptr, size)
    })
}

/// Parameterized implementation of Darwin PID enumeration allowing deterministic test injection.
pub fn list_pids_darwin_with_caller<F>(
    mut proc_listpids_fn: F,
) -> Result<(Vec<u32>, SnapshotCompleteness), PlatformError>
where
    F: FnMut(u32, u32, *mut libc::c_void, i32) -> i32,
{
    let pid_size = std::mem::size_of::<libc::pid_t>(); // 4 bytes
    let mut retries = 0;

    loop {
        // Step 1: Clear errno immediately before query
        unsafe {
            *libc::__error() = 0;
        }

        // Step 2: Query required size in bytes
        let needed_bytes = proc_listpids_fn(PROC_ALL_PIDS, 0, std::ptr::null_mut(), 0);
        if needed_bytes == 0 {
            let err = unsafe { *libc::__error() };
            if err != 0 {
                return Err(PlatformError::Other(format!(
                    "proc_listpids size query failed with errno {}",
                    err
                )));
            }
            return Ok((Vec::new(), SnapshotCompleteness::Complete));
        } else if needed_bytes < 0 {
            return Err(PlatformError::Other(format!(
                "proc_listpids returned negative size: {}",
                needed_bytes
            )));
        }

        // Step 3: Allocate with 25% headroom, bounded by MAX_PROC_LIST_BUFFER_BYTES
        let needed_usize = needed_bytes as usize;
        let mut capacity_bytes = (needed_usize * 5 / 4).max(4096);
        if capacity_bytes > MAX_PROC_LIST_BUFFER_BYTES {
            capacity_bytes = MAX_PROC_LIST_BUFFER_BYTES;
        }

        let mut pid_buf: Vec<libc::pid_t> = vec![0; capacity_bytes / pid_size];

        // Step 4: Clear errno and retrieve PIDs
        unsafe {
            *libc::__error() = 0;
        }
        let bytes_written = proc_listpids_fn(
            PROC_ALL_PIDS,
            0,
            pid_buf.as_mut_ptr() as *mut libc::c_void,
            capacity_bytes as i32,
        );

        if bytes_written == 0 {
            let err = unsafe { *libc::__error() };
            if err != 0 {
                return Err(PlatformError::Other(format!(
                    "proc_listpids data query failed with errno {}",
                    err
                )));
            }
            return Ok((Vec::new(), SnapshotCompleteness::Complete));
        }

        if bytes_written < 0 {
            return Err(PlatformError::Other(format!(
                "proc_listpids returned negative byte count: {}",
                bytes_written
            )));
        }

        let bytes_written_usize = bytes_written as usize;

        // Step 5: Validate protocol invariants
        if bytes_written_usize > capacity_bytes {
            return Err(PlatformError::Other(format!(
                "Kernel protocol violation: proc_listpids returned {} bytes exceeding buffer capacity {}",
                bytes_written_usize, capacity_bytes
            )));
        }

        if !bytes_written_usize.is_multiple_of(pid_size) {
            return Err(PlatformError::Other(format!(
                "Kernel protocol violation: proc_listpids returned non-aligned byte count: {}",
                bytes_written_usize
            )));
        }

        // Step 6: Truncation check
        let is_truncated = bytes_written_usize >= capacity_bytes;
        if is_truncated && capacity_bytes < MAX_PROC_LIST_BUFFER_BYTES && retries < 3 {
            retries += 1;
            continue; // Retry with expanded capacity
        }

        let completeness = if is_truncated {
            SnapshotCompleteness::Truncated {
                returned_count: bytes_written_usize / pid_size,
                capacity: capacity_bytes / pid_size,
            }
        } else {
            SnapshotCompleteness::Complete
        };

        // Step 7: Filter valid non-zero PIDs
        let count = bytes_written_usize / pid_size;
        let valid_pids: Vec<u32> = pid_buf[..count]
            .iter()
            .copied()
            .filter(|&p| p > 0)
            .map(|p| p as u32)
            .collect();

        return Ok((valid_pids, completeness));
    }
}

// ============================================================================
// Process Task & BSD Detail via proc_pidinfo
// ============================================================================

/// Retrieves `proc_taskallinfo` containing both BSD info and task metrics.
///
/// Enforces exact return-size validation to prevent reading undersized buffers.
pub fn get_proc_taskallinfo_darwin(pid: u32) -> Result<libc::proc_taskallinfo, PlatformError> {
    let mut info: libc::proc_taskallinfo = unsafe { std::mem::zeroed() };
    let expected_size = std::mem::size_of::<libc::proc_taskallinfo>();

    unsafe {
        *libc::__error() = 0;
    }

    let ret = unsafe {
        libc::proc_pidinfo(
            pid as i32,
            libc::PROC_PIDTASKALLINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            expected_size as i32,
        )
    };

    if ret != expected_size as i32 {
        let err = unsafe { *libc::__error() };
        if err == libc::ESRCH {
            return Err(PlatformError::ProcessNotFound(pid));
        } else if err == libc::EPERM || err == libc::EACCES {
            return Err(PlatformError::PermissionDenied(pid));
        } else {
            return Err(PlatformError::Other(format!(
                "proc_pidinfo(PROC_PIDTASKALLINFO) failed for PID {}: returned {} (expected {}), errno: {}",
                pid, ret, expected_size, err
            )));
        }
    }

    Ok(info)
}

/// Retrieves the resolved absolute binary path for a process via `proc_pidpath()`.
///
/// Enforces safe buffer size bounds and explicit null termination.
pub fn get_proc_pidpath_darwin(pid: u32) -> Result<PathBuf, PlatformError> {
    let mut buf = [0u8; MAX_PIDPATH_BYTES];

    unsafe {
        *libc::__error() = 0;
    }

    let ret = unsafe {
        libc::proc_pidpath(
            pid as i32,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len() as u32,
        )
    };

    if ret <= 0 {
        let err = unsafe { *libc::__error() };
        if err == libc::ESRCH {
            return Err(PlatformError::ProcessNotFound(pid));
        } else if err == libc::EPERM || err == libc::EACCES {
            return Err(PlatformError::PermissionDenied(pid));
        } else {
            return Err(PlatformError::Other(format!(
                "proc_pidpath failed for PID {}: returned {}, errno: {}",
                pid, ret, err
            )));
        }
    }

    let ret_usize = ret as usize;
    if ret_usize >= buf.len() {
        return Err(PlatformError::Other(format!(
            "proc_pidpath returned path length {} exceeding buffer {}",
            ret_usize,
            buf.len()
        )));
    }

    // Guarantee null termination
    buf[ret_usize] = 0;

    let path_str = String::from_utf8_lossy(&buf[..ret_usize]).to_string();
    if path_str.trim().is_empty() {
        return Err(PlatformError::Other(format!(
            "proc_pidpath returned empty path for PID {}",
            pid
        )));
    }

    let masked = SecretMasker::mask_string(path_str.trim());
    Ok(PathBuf::from(masked))
}

/// Retrieves the current working directory for a process via `proc_pidinfo(PROC_PIDVNODEPATHINFO)`.
pub fn get_proc_vnodepathinfo_darwin(pid: u32) -> Result<PathBuf, PlatformError> {
    let mut vnode: libc::proc_vnodepathinfo = unsafe { std::mem::zeroed() };
    let expected_size = std::mem::size_of::<libc::proc_vnodepathinfo>();

    unsafe {
        *libc::__error() = 0;
    }

    let ret = unsafe {
        libc::proc_pidinfo(
            pid as i32,
            libc::PROC_PIDVNODEPATHINFO,
            0,
            &mut vnode as *mut _ as *mut libc::c_void,
            expected_size as i32,
        )
    };

    if ret != expected_size as i32 {
        let err = unsafe { *libc::__error() };
        if err == libc::ESRCH {
            return Err(PlatformError::ProcessNotFound(pid));
        } else if err == libc::EPERM || err == libc::EACCES {
            return Err(PlatformError::PermissionDenied(pid));
        } else {
            return Err(PlatformError::Other(format!(
                "proc_pidinfo(PROC_PIDVNODEPATHINFO) failed for PID {}: returned {}, errno: {}",
                pid, ret, err
            )));
        }
    }

    // Extract pvi_cdir.vip_path
    let raw_bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(
            vnode.pvi_cdir.vip_path.as_ptr() as *const u8,
            std::mem::size_of_val(&vnode.pvi_cdir.vip_path),
        )
    };
    let nul_pos = raw_bytes
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(raw_bytes.len());

    let path_str = String::from_utf8_lossy(&raw_bytes[..nul_pos])
        .trim()
        .to_string();

    if path_str.is_empty() {
        return Err(PlatformError::Other(format!(
            "Empty cwd returned for PID {}",
            pid
        )));
    }

    let masked = SecretMasker::mask_string(&path_str);
    Ok(PathBuf::from(masked))
}

// ============================================================================
// Byte-level sysctl KERN_PROCARGS2 Parser
// ============================================================================

/// Pure byte-level parser for `sysctl KERN_PROCARGS2` output.
///
/// Contract:
/// 1. First 4 bytes: `int32_t argc` (native endian). Validate `0 <= argc <= 16384`.
/// 2. Offset 4..N: Executable path string, null-terminated.
/// 3. Offset N..M: Contiguous null padding bytes ('\0').
/// 4. Extract exactly `argc` null-terminated argument strings.
/// 5. Strictly exclude all remaining environment strings.
/// 6. Convert lossily without panicking.
/// 7. Mask all argument tokens through `SecretMasker`.
pub fn parse_procargs2_buffer(buf: &[u8]) -> Result<Vec<String>, PlatformError> {
    if buf.len() < 4 {
        return Err(PlatformError::Other(
            "KERN_PROCARGS2 buffer too short (<4 bytes)".to_string(),
        ));
    }

    // Step 1: Read argc
    let argc = i32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if !(0..=16_384).contains(&argc) {
        return Err(PlatformError::Other(format!(
            "KERN_PROCARGS2 invalid argc: {}",
            argc
        )));
    }

    if argc == 0 {
        return Ok(Vec::new());
    }

    let argc_usize = argc as usize;
    let mut cursor = 4;

    // Step 2: Skip executable path up to first '\0'
    let exec_end = match buf[cursor..].iter().position(|&b| b == 0) {
        Some(pos) => cursor + pos,
        None => {
            return Err(PlatformError::Other(
                "KERN_PROCARGS2 missing null terminator for executable path".to_string(),
            ));
        }
    };
    cursor = exec_end + 1;

    // Step 3: Skip all contiguous padding null bytes
    while cursor < buf.len() && buf[cursor] == 0 {
        cursor += 1;
    }

    if cursor >= buf.len() {
        return Err(PlatformError::Other(
            "KERN_PROCARGS2 unexpected EOF while searching for argv[0]".to_string(),
        ));
    }

    // Step 4: Extract exactly argc arguments
    let mut args = Vec::with_capacity(argc_usize);
    for _ in 0..argc_usize {
        if cursor >= buf.len() {
            return Err(PlatformError::Other(
                "KERN_PROCARGS2 buffer truncated before extracting all arguments".to_string(),
            ));
        }

        let arg_end = match buf[cursor..].iter().position(|&b| b == 0) {
            Some(pos) => cursor + pos,
            None => {
                // If the last argument extends to the end of buffer without trailing null, accept it
                buf.len()
            }
        };

        let arg_bytes = &buf[cursor..arg_end];
        let arg_str = String::from_utf8_lossy(arg_bytes).to_string();
        args.push(arg_str);

        cursor = arg_end + 1;
    }

    // Step 5: Strictly ignore all remaining bytes (they are environment variables KEY=VALUE\0)

    // Step 6: Mask sensitive command-line tokens
    let masked_args = SecretMasker::mask_cmdline(&args);

    Ok(masked_args)
}

/// Retrieves the argument vector for a process via `sysctl KERN_PROCARGS2`.
pub fn get_proc_cmdline_darwin(pid: u32) -> Result<Vec<String>, PlatformError> {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as i32];
    let mut size: libc::size_t = 0;

    unsafe {
        *libc::__error() = 0;
    }

    // Query size
    let ret = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };

    if ret != 0 {
        let err = unsafe { *libc::__error() };
        if err == libc::ESRCH {
            return Err(PlatformError::ProcessNotFound(pid));
        } else if err == libc::EPERM || err == libc::EACCES {
            return Err(PlatformError::PermissionDenied(pid));
        } else {
            return Err(PlatformError::Other(format!(
                "sysctl(KERN_PROCARGS2) size query failed for PID {}: errno {}",
                pid, err
            )));
        }
    }

    if !(4..=MAX_ARG_MAX_BYTES).contains(&size) {
        return Err(PlatformError::Other(format!(
            "sysctl(KERN_PROCARGS2) invalid size {} for PID {}",
            size, pid
        )));
    }

    let mut buf = vec![0u8; size];

    unsafe {
        *libc::__error() = 0;
    }

    let ret = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };

    if ret != 0 {
        let err = unsafe { *libc::__error() };
        if err == libc::ESRCH {
            return Err(PlatformError::ProcessNotFound(pid));
        } else if err == libc::EPERM || err == libc::EACCES {
            return Err(PlatformError::PermissionDenied(pid));
        } else {
            return Err(PlatformError::Other(format!(
                "sysctl(KERN_PROCARGS2) data query failed for PID {}: errno {}",
                pid, err
            )));
        }
    }

    parse_procargs2_buffer(&buf[..size])
}

// ============================================================================
// Process Observation & Positive Exit Confirmation
// ============================================================================

/// Evaluates the observation state of a process with respect to an optional previously recorded start time.
///
/// Implements positive kernel proofs:
/// 1. Exact incarnation matching: PID plus precise kernel start time (`tv_sec`, `tv_usec`).
/// 2. `proc_pidinfo` / `kill(pid, 0)` returning `ESRCH` -> `ExitedConfirmed` ONLY if recorded start time exists.
/// 3. `proc_pidinfo` returning `EPERM` / `EACCES` -> `InspectionRestricted` (never exited!).
/// 4. Process found but start time differs (`current_start != rec`) -> `PidReused` (identity mismatch / PID reuse).
/// 5. Process status `SZOMB` -> `TerminatedUnreaped` (zombie; terminated-but-unreaped).
/// 6. Missing or inconclusive evidence (e.g. missing recorded start time when process disappeared) -> `NotObserved` (never `ExitedConfirmed`).
pub fn evaluate_process_observation_state(
    pid: u32,
    recorded_start: Option<ProcessStartTime>,
) -> ProcessObservationState {
    evaluate_process_observation_state_impl(pid, recorded_start, get_proc_taskallinfo_darwin, |p| {
        let res = unsafe { libc::kill(p as libc::pid_t, 0) };
        if res == 0 {
            Ok(())
        } else {
            let err = std::io::Error::last_os_error().raw_os_error();
            if err == Some(libc::ESRCH) {
                Err(PlatformError::ProcessNotFound(p))
            } else if err == Some(libc::EPERM) || err == Some(libc::EACCES) {
                Err(PlatformError::PermissionDenied(p))
            } else {
                Err(PlatformError::Other(format!("kill failed: {:?}", err)))
            }
        }
    })
}

/// Parameterized implementation allowing deterministic simulation of kernel state and race conditions.
pub fn evaluate_process_observation_state_impl<FInfo, FKill>(
    pid: u32,
    recorded_start: Option<ProcessStartTime>,
    info_fn: FInfo,
    kill_fn: FKill,
) -> ProcessObservationState
where
    FInfo: Fn(u32) -> Result<libc::proc_taskallinfo, PlatformError>,
    FKill: Fn(u32) -> Result<(), PlatformError>,
{
    let rec = match recorded_start {
        Some(s) => s,
        None => {
            // Missing recorded start time means evidence is inconclusive to confirm an exit.
            return match info_fn(pid) {
                Ok(info) => {
                    if info.pbsd.pbi_status == PROC_STATUS_ZOMBIE {
                        ProcessObservationState::TerminatedUnreaped
                    } else {
                        ProcessObservationState::Present
                    }
                }
                Err(PlatformError::PermissionDenied(_)) => {
                    ProcessObservationState::InspectionRestricted
                }
                _ => ProcessObservationState::NotObserved,
            };
        }
    };

    match info_fn(pid) {
        Ok(info) => {
            let current_start = ProcessStartTime::from_bsdinfo(&info.pbsd);
            if current_start != rec {
                // Changed start time proves PID reuse / identity mismatch!
                return ProcessObservationState::PidReused;
            }

            if info.pbsd.pbi_status == PROC_STATUS_ZOMBIE {
                ProcessObservationState::TerminatedUnreaped
            } else {
                ProcessObservationState::Present
            }
        }
        Err(PlatformError::ProcessNotFound(_)) => {
            // proc_pidinfo returned ESRCH. Verify positive exit with kill(pid, 0)
            match kill_fn(pid) {
                Err(PlatformError::ProcessNotFound(_)) => {
                    // Positive proof that no process with this PID exists
                    ProcessObservationState::ExitedConfirmed
                }
                Err(PlatformError::PermissionDenied(_)) => {
                    ProcessObservationState::InspectionRestricted
                }
                Ok(()) => {
                    // kill succeeded: a new process with this PID exists (PID re-acquired between calls)!
                    // Check if this newly acquired process matches the recorded incarnation:
                    if let Ok(info) = info_fn(pid) {
                        let current_start = ProcessStartTime::from_bsdinfo(&info.pbsd);
                        if current_start != rec {
                            ProcessObservationState::PidReused
                        } else if info.pbsd.pbi_status == PROC_STATUS_ZOMBIE {
                            ProcessObservationState::TerminatedUnreaped
                        } else {
                            ProcessObservationState::Present
                        }
                    } else {
                        ProcessObservationState::NotObserved
                    }
                }
                _ => ProcessObservationState::NotObserved,
            }
        }
        Err(PlatformError::PermissionDenied(_)) => ProcessObservationState::InspectionRestricted,
        Err(_) => ProcessObservationState::NotObserved,
    }
}

// ============================================================================
// Native Darwin socket & port discovery via PROC_PIDLISTFDS & PROC_PIDFDSOCKETINFO
// ============================================================================

extern "C" {
    fn proc_pidfdinfo(
        pid: libc::c_int,
        fd: libc::c_int,
        flavor: libc::c_int,
        buffer: *mut libc::c_void,
        buffersize: libc::c_int,
    ) -> libc::c_int;
}

/// Raw representation of Darwin's `struct socket_fdinfo` (792 bytes).
/// Provides verified accessor methods for protocol, port, state, and IP addresses.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SocketFdInfo {
    pub raw: [u8; SOCKET_FDINFO_SIZE],
}

impl Default for SocketFdInfo {
    fn default() -> Self {
        Self {
            raw: [0u8; SOCKET_FDINFO_SIZE],
        }
    }
}

impl SocketFdInfo {
    pub fn new() -> Self {
        Self::default()
    }

    /// Protocol (e.g. IPPROTO_TCP = 6, IPPROTO_UDP = 17). Offset 180 (i32).
    pub fn protocol(&self) -> i32 {
        i32::from_ne_bytes(self.raw[180..184].try_into().unwrap_or([0; 4]))
    }

    /// Address family (e.g. AF_INET = 2, AF_INET6 = 30). Offset 184 (i32).
    pub fn family(&self) -> i32 {
        i32::from_ne_bytes(self.raw[184..188].try_into().unwrap_or([0; 4]))
    }

    /// Local port in host byte order. Offset 268 (int32 in network byte order).
    pub fn local_port(&self) -> u16 {
        let raw_val = i32::from_ne_bytes(self.raw[268..272].try_into().unwrap_or([0; 4]));
        u16::from_be((raw_val & 0xFFFF) as u16)
    }

    /// Foreign port in host byte order. Offset 264 (int32 in network byte order).
    pub fn foreign_port(&self) -> u16 {
        let raw_val = i32::from_ne_bytes(self.raw[264..268].try_into().unwrap_or([0; 4]));
        u16::from_be((raw_val & 0xFFFF) as u16)
    }

    /// TCP socket state (e.g. TSI_S_LISTEN = 1). Offset 344 (i32).
    pub fn tcp_state(&self) -> i32 {
        i32::from_ne_bytes(self.raw[344..348].try_into().unwrap_or([0; 4]))
    }

    /// Local IP address as formatted string.
    pub fn ip_address(&self) -> String {
        let fam = self.family();
        if fam == libc::AF_INET {
            let b0 = self.raw[324];
            let b1 = self.raw[325];
            let b2 = self.raw[326];
            let b3 = self.raw[327];
            let addr = std::net::Ipv4Addr::new(b0, b1, b2, b3);
            addr.to_string()
        } else if fam == libc::AF_INET6 {
            let bytes: [u8; 16] = self.raw[312..328].try_into().unwrap_or([0; 16]);
            let addr = std::net::Ipv6Addr::from(bytes);
            addr.to_string()
        } else {
            "0.0.0.0".to_string()
        }
    }
}

/// Enumerates all open file descriptors for a specific process ID using Darwin's `proc_pidinfo(PROC_PIDLISTFDS)`.
pub fn list_process_fds(pid: u32) -> Result<Vec<libc::proc_fdinfo>, PlatformError> {
    unsafe {
        *libc::__error() = 0;
        let needed = libc::proc_pidinfo(
            pid as libc::c_int,
            PROC_PIDLISTFDS,
            0,
            std::ptr::null_mut(),
            0,
        );
        if needed <= 0 {
            let err = *libc::__error();
            if err == libc::ESRCH {
                return Err(PlatformError::ProcessNotFound(pid));
            } else if err == libc::EPERM || err == libc::EACCES {
                return Err(PlatformError::PermissionDenied(pid));
            } else {
                return Ok(Vec::new());
            }
        }

        let fdinfo_size = std::mem::size_of::<libc::proc_fdinfo>();
        let mut buffer = vec![0u8; needed as usize];
        let bytes_read = libc::proc_pidinfo(
            pid as libc::c_int,
            PROC_PIDLISTFDS,
            0,
            buffer.as_mut_ptr() as *mut libc::c_void,
            needed,
        );

        if bytes_read <= 0 {
            return Ok(Vec::new());
        }

        let count = (bytes_read as usize) / fdinfo_size;
        let mut fds = Vec::with_capacity(count);
        let ptr = buffer.as_ptr() as *const libc::proc_fdinfo;
        for i in 0..count {
            fds.push(*ptr.add(i));
        }
        Ok(fds)
    }
}

/// Retrieves detailed socket descriptor info for a specific process and file descriptor.
pub fn get_socket_fdinfo(pid: u32, fd: i32) -> Result<SocketFdInfo, PlatformError> {
    unsafe {
        *libc::__error() = 0;
        let mut info = SocketFdInfo::new();
        let ret = proc_pidfdinfo(
            pid as libc::c_int,
            fd,
            PROC_PIDFDSOCKETINFO,
            info.raw.as_mut_ptr() as *mut libc::c_void,
            SOCKET_FDINFO_SIZE as libc::c_int,
        );
        if ret == SOCKET_FDINFO_SIZE as libc::c_int {
            Ok(info)
        } else {
            let err = *libc::__error();
            if err == libc::ESRCH {
                Err(PlatformError::ProcessNotFound(pid))
            } else if err == libc::EPERM || err == libc::EACCES {
                Err(PlatformError::PermissionDenied(pid))
            } else {
                Err(PlatformError::Other(format!(
                    "proc_pidfdinfo failed for PID {} FD {} with errno {}",
                    pid, fd, err
                )))
            }
        }
    }
}

/// Collects listening sockets for a given process PID natively without subprocess invocation.
pub fn collect_process_listening_sockets(
    pid: u32,
    proc_name: Option<&str>,
) -> Result<Vec<ListeningPort>, PlatformError> {
    let fds = match list_process_fds(pid) {
        Ok(fds) => fds,
        Err(PlatformError::PermissionDenied(_)) | Err(PlatformError::ProcessNotFound(_)) => {
            return Ok(Vec::new());
        }
        Err(e) => return Err(e),
    };

    let mut ports = Vec::new();
    for fd_info in fds {
        if fd_info.proc_fdtype == PROX_FDTYPE_SOCKET {
            if let Ok(sock) = get_socket_fdinfo(pid, fd_info.proc_fd) {
                let proto = sock.protocol();
                let port_num = sock.local_port();
                if port_num == 0 {
                    continue;
                }

                if proto == libc::IPPROTO_TCP {
                    if sock.tcp_state() == TSI_S_LISTEN {
                        ports.push(ListeningPort {
                            port: port_num,
                            protocol: Protocol::Tcp,
                            ip: sock.ip_address(),
                            pid: Some(pid),
                            process_name: proc_name.map(|s| s.to_string()),
                            state: SocketState::Listen,
                        });
                    }
                } else if proto == libc::IPPROTO_UDP {
                    ports.push(ListeningPort {
                        port: port_num,
                        protocol: Protocol::Udp,
                        ip: sock.ip_address(),
                        pid: Some(pid),
                        process_name: proc_name.map(|s| s.to_string()),
                        state: SocketState::Listen,
                    });
                }
            }
        }
    }
    Ok(ports)
}

/// Discovers all listening TCP and UDP sockets across all active Darwin processes natively.
pub fn collect_all_listening_sockets_darwin() -> Result<Vec<ListeningPort>, PlatformError> {
    let (pids, _) = list_pids_darwin()?;
    let mut all_ports = Vec::new();

    for pid in pids {
        if pid == 0 {
            continue;
        }
        let proc_name = get_proc_taskallinfo_darwin(pid).ok().map(|taskall| {
            let comm_bytes: Vec<u8> = taskall
                .pbsd
                .pbi_comm
                .iter()
                .take_while(|&&c| c != 0)
                .map(|&c| c as u8)
                .collect();
            String::from_utf8_lossy(&comm_bytes).trim().to_string()
        });

        if let Ok(mut ports) = collect_process_listening_sockets(pid, proc_name.as_deref()) {
            all_ports.append(&mut ports);
        }
    }

    all_ports.sort_by_key(|p| p.port);
    all_ports.dedup_by(|a, b| a.port == b.port && a.pid == b.pid && a.protocol == b.protocol);

    Ok(all_ports)
}
