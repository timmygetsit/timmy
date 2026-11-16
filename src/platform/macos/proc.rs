use super::darwin_sys::{
    get_proc_cmdline_darwin, get_proc_pidpath_darwin, get_proc_taskallinfo_darwin,
    get_proc_vnodepathinfo_darwin, list_pids_darwin, PROC_STATUS_ZOMBIE,
};
use crate::model::{
    AgentAttribution, FieldStatus, ObservationInterval, ProcessAncestor, ProcessDetail,
    ProcessInfo, ProcessObservationState, ProcessSnapshot, ProcessStartTime, ProcessTaskMetrics,
};
use crate::platform::traits::{PlatformError, ProcessCollector};
use chrono::Utc;

/// Safe wrapper around POSIX `libc::kill` to send signals directly without shell invocation.
pub fn send_signal(pid: u32, signal: i32) -> Result<(), PlatformError> {
    let res = unsafe { libc::kill(pid as libc::pid_t, signal) };
    if res == 0 {
        Ok(())
    } else {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            Err(PlatformError::ProcessNotFound(pid))
        } else if err.raw_os_error() == Some(libc::EPERM) {
            Err(PlatformError::PermissionDenied(pid))
        } else {
            Err(PlatformError::Io(err))
        }
    }
}

/// Checks if a process with the given PID is currently active.
pub fn is_process_alive(pid: u32) -> bool {
    // Sending signal 0 performs error checking without actually delivering a signal
    let res = unsafe { libc::kill(pid as libc::pid_t, 0) };
    res == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Native macOS process discovery collector using Darwin kernel APIs (`libproc` and `sysctl`).
#[derive(Debug, Default, Clone)]
pub struct DarwinProcessCollector;

impl DarwinProcessCollector {
    pub fn new() -> Self {
        Self
    }
}

impl ProcessCollector for DarwinProcessCollector {
    fn collect_processes(&self) -> Result<Vec<ProcessInfo>, PlatformError> {
        self.collect_process_snapshot().map(|s| s.processes)
    }

    fn collect_process_snapshot(&self) -> Result<ProcessSnapshot, PlatformError> {
        let start_wall_clock = Utc::now();

        // Step 1: Enumerate active PIDs via proc_listpids
        let (pids, completeness) = list_pids_darwin()?;

        let mut processes = Vec::with_capacity(pids.len());
        let now_epoch_secs = start_wall_clock.timestamp().max(0) as u64;

        // Step 2: Query details for each PID
        for pid in pids {
            match get_proc_taskallinfo_darwin(pid) {
                Ok(taskall) => {
                    let pbsd = &taskall.pbsd;
                    let ptinfo = &taskall.ptinfo;

                    // Extract process name from pbi_name or pbi_comm
                    let name = {
                        let name_bytes: Vec<u8> = pbsd
                            .pbi_name
                            .iter()
                            .take_while(|&&c| c != 0)
                            .map(|&c| c as u8)
                            .collect();
                        let name_str = String::from_utf8_lossy(&name_bytes).trim().to_string();
                        if !name_str.is_empty() {
                            name_str
                        } else {
                            let comm_bytes: Vec<u8> = pbsd
                                .pbi_comm
                                .iter()
                                .take_while(|&&c| c != 0)
                                .map(|&c| c as u8)
                                .collect();
                            String::from_utf8_lossy(&comm_bytes).trim().to_string()
                        }
                    };

                    let ppid = if pbsd.pbi_ppid > 0 {
                        Some(pbsd.pbi_ppid)
                    } else {
                        None
                    };

                    let start_time_precise = ProcessStartTime::from_bsdinfo(pbsd);
                    let start_time = Some(pbsd.pbi_start_tvsec);
                    let run_time_secs = now_epoch_secs.saturating_sub(pbsd.pbi_start_tvsec);

                    let observation_state = if pbsd.pbi_status == PROC_STATUS_ZOMBIE {
                        ProcessObservationState::TerminatedUnreaped
                    } else {
                        ProcessObservationState::Present
                    };

                    let memory_bytes = Some(ptinfo.pti_resident_size);
                    let task_metrics = FieldStatus::Available(ProcessTaskMetrics {
                        virtual_size_bytes: ptinfo.pti_virtual_size,
                        resident_size_bytes: ptinfo.pti_resident_size,
                        total_user_time_ms: ptinfo.pti_total_user / 1_000_000,
                        total_system_time_ms: ptinfo.pti_total_system / 1_000_000,
                    });

                    // Query executable path
                    let (exe, exe_status) = match get_proc_pidpath_darwin(pid) {
                        Ok(p) => (Some(p.clone()), FieldStatus::Available(p)),
                        Err(PlatformError::PermissionDenied(_)) => (None, FieldStatus::Restricted),
                        Err(_) => (None, FieldStatus::Unavailable),
                    };

                    // Query command line arguments (masked)
                    let (cmdline, cmdline_status) = match get_proc_cmdline_darwin(pid) {
                        Ok(args) => (args.clone(), FieldStatus::Available(args)),
                        Err(PlatformError::PermissionDenied(_)) => {
                            (Vec::new(), FieldStatus::Restricted)
                        }
                        Err(_) => (Vec::new(), FieldStatus::Unavailable),
                    };

                    // Query working directory
                    let cwd_status = match get_proc_vnodepathinfo_darwin(pid) {
                        Ok(p) => FieldStatus::Available(p),
                        Err(PlatformError::PermissionDenied(_)) => FieldStatus::Restricted,
                        Err(_) => FieldStatus::Unavailable,
                    };

                    processes.push(ProcessInfo {
                        pid,
                        ppid,
                        name,
                        exe,
                        cpu_usage: None,
                        memory_bytes,
                        run_time_secs,
                        start_time,
                        user: Some(pbsd.pbi_uid.to_string()),
                        attribution: AgentAttribution::default(),
                        listening_ports: Vec::new(),
                        cmdline,
                        command_outcome: None,
                        provenance: None,
                        start_time_precise: Some(start_time_precise),
                        observation_state,
                        exe_status,
                        cmdline_status,
                        cwd_status,
                        task_metrics,
                    });
                }
                Err(PlatformError::ProcessNotFound(_)) => {
                    // Process exited between list and detail inspection (cleanly omitted)
                    continue;
                }
                Err(PlatformError::PermissionDenied(_)) => {
                    // Process exists but inspection was blocked (EPERM / SIP / sandbox)
                    processes.push(ProcessInfo {
                        pid,
                        ppid: None,
                        name: format!("PID {}", pid),
                        exe: None,
                        cpu_usage: None,
                        memory_bytes: None,
                        run_time_secs: 0,
                        start_time: None,
                        user: None,
                        attribution: AgentAttribution::default(),
                        listening_ports: Vec::new(),
                        cmdline: Vec::new(),
                        command_outcome: None,
                        provenance: None,
                        start_time_precise: None,
                        observation_state: ProcessObservationState::InspectionRestricted,
                        exe_status: FieldStatus::Restricted,
                        cmdline_status: FieldStatus::Restricted,
                        cwd_status: FieldStatus::Restricted,
                        task_metrics: FieldStatus::Restricted,
                    });
                }
                Err(_) => {
                    // Non-fatal per-process query error; omit without failing snapshot
                    continue;
                }
            }
        }

        let end_wall_clock = Utc::now();
        let duration_ms = end_wall_clock
            .signed_duration_since(start_wall_clock)
            .num_milliseconds()
            .max(0) as u64;

        Ok(ProcessSnapshot {
            processes,
            interval: ObservationInterval {
                start_wall_clock,
                end_wall_clock,
                duration_ms,
                completeness: completeness.clone(),
            },
            completeness,
        })
    }

    fn inspect_process(&self, target_pid: u32) -> Result<ProcessDetail, PlatformError> {
        let taskall = get_proc_taskallinfo_darwin(target_pid)?;
        let pbsd = &taskall.pbsd;
        let ptinfo = &taskall.ptinfo;

        let name = {
            let name_bytes: Vec<u8> = pbsd
                .pbi_name
                .iter()
                .take_while(|&&c| c != 0)
                .map(|&c| c as u8)
                .collect();
            let name_str = String::from_utf8_lossy(&name_bytes).trim().to_string();
            if !name_str.is_empty() {
                name_str
            } else {
                let comm_bytes: Vec<u8> = pbsd
                    .pbi_comm
                    .iter()
                    .take_while(|&&c| c != 0)
                    .map(|&c| c as u8)
                    .collect();
                String::from_utf8_lossy(&comm_bytes).trim().to_string()
            }
        };

        let ppid = if pbsd.pbi_ppid > 0 {
            Some(pbsd.pbi_ppid)
        } else {
            None
        };

        let start_time_precise = ProcessStartTime::from_bsdinfo(pbsd);
        let start_time = Some(pbsd.pbi_start_tvsec);
        let now_epoch_secs = Utc::now().timestamp().max(0) as u64;
        let run_time_secs = now_epoch_secs.saturating_sub(pbsd.pbi_start_tvsec);

        let observation_state = if pbsd.pbi_status == PROC_STATUS_ZOMBIE {
            ProcessObservationState::TerminatedUnreaped
        } else {
            ProcessObservationState::Present
        };

        let (exe, exe_status) = match get_proc_pidpath_darwin(target_pid) {
            Ok(p) => (Some(p.clone()), FieldStatus::Available(p)),
            Err(PlatformError::PermissionDenied(_)) => (None, FieldStatus::Restricted),
            Err(_) => (None, FieldStatus::Unavailable),
        };

        let (cmdline, cmdline_status) = match get_proc_cmdline_darwin(target_pid) {
            Ok(args) => (args.clone(), FieldStatus::Available(args)),
            Err(PlatformError::PermissionDenied(_)) => (Vec::new(), FieldStatus::Restricted),
            Err(_) => (Vec::new(), FieldStatus::Unavailable),
        };

        let cwd_status = match get_proc_vnodepathinfo_darwin(target_pid) {
            Ok(p) => FieldStatus::Available(p),
            Err(PlatformError::PermissionDenied(_)) => FieldStatus::Restricted,
            Err(_) => FieldStatus::Unavailable,
        };

        let cwd = cwd_status.as_ref().cloned();

        let info = ProcessInfo {
            pid: target_pid,
            ppid,
            name: name.clone(),
            exe,
            cpu_usage: None,
            memory_bytes: Some(ptinfo.pti_resident_size),
            run_time_secs,
            start_time,
            user: Some(pbsd.pbi_uid.to_string()),
            attribution: AgentAttribution::default(),
            listening_ports: Vec::new(),
            cmdline: cmdline.clone(),
            command_outcome: None,
            provenance: None,
            start_time_precise: Some(start_time_precise),
            observation_state,
            exe_status,
            cmdline_status,
            cwd_status,
            task_metrics: FieldStatus::Available(ProcessTaskMetrics {
                virtual_size_bytes: ptinfo.pti_virtual_size,
                resident_size_bytes: ptinfo.pti_resident_size,
                total_user_time_ms: ptinfo.pti_total_user / 1_000_000,
                total_system_time_ms: ptinfo.pti_total_system / 1_000_000,
            }),
        };

        // Construct parent chain
        let mut parent_chain = Vec::new();
        let mut curr_parent = ppid;
        let mut visited = std::collections::HashSet::new();

        while let Some(p_pid) = curr_parent {
            if p_pid <= 1 || visited.contains(&p_pid) {
                break;
            }
            visited.insert(p_pid);

            if let Ok(p_info) = get_proc_taskallinfo_darwin(p_pid) {
                let p_comm_bytes: Vec<u8> = p_info
                    .pbsd
                    .pbi_comm
                    .iter()
                    .take_while(|&&c| c != 0)
                    .map(|&c| c as u8)
                    .collect();
                let p_name = String::from_utf8_lossy(&p_comm_bytes).trim().to_string();
                let p_cmd = get_proc_cmdline_darwin(p_pid).ok().map(|c| c.join(" "));

                parent_chain.push(ProcessAncestor {
                    pid: p_pid,
                    name: p_name,
                    cmdline_summary: p_cmd,
                });

                curr_parent = if p_info.pbsd.pbi_ppid > 0 {
                    Some(p_info.pbsd.pbi_ppid)
                } else {
                    None
                };
            } else {
                break;
            }
        }

        Ok(ProcessDetail {
            info,
            cmdline,
            cwd,
            environment: Vec::new(),
            open_files: Vec::new(),
            parent_chain,
        })
    }
}
