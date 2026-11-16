use super::docker::BollardDockerCollector;
use super::traits::{
    DockerCollector, PlatformError, PortCollector, ProcessCollector, ServiceCollector,
};
use crate::model::{
    AgentAttribution, ContainerDetail, ContainerInfo, ContainerStats, DockerStatus, ListeningPort,
    ProcessAncestor, ProcessDetail, ProcessInfo, ServiceInfo,
};
use crate::safety::masker::SecretMasker;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

/// Portable process and system collector powered by `sysinfo` and `bollard`.
pub struct PortableCollector {
    system: Mutex<System>,
    docker: BollardDockerCollector,
}

impl PortableCollector {
    pub fn new() -> Self {
        Self::with_docker_config(None, Duration::from_millis(2000))
    }

    pub fn with_docker_config(custom_socket: Option<String>, timeout: Duration) -> Self {
        let mut sys = System::new();
        sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing()
                .with_cpu()
                .with_memory()
                .with_cmd(sysinfo::UpdateKind::OnlyIfNotSet)
                .with_exe(sysinfo::UpdateKind::OnlyIfNotSet)
                .with_user(sysinfo::UpdateKind::OnlyIfNotSet),
        );
        Self {
            system: Mutex::new(sys),
            docker: BollardDockerCollector::new(custom_socket, timeout),
        }
    }
}

impl Default for PortableCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessCollector for PortableCollector {
    fn collect_processes(&self) -> Result<Vec<ProcessInfo>, PlatformError> {
        let mut sys = self
            .system
            .lock()
            .map_err(|e| PlatformError::Other(e.to_string()))?;
        sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing()
                .with_cpu()
                .with_memory()
                .with_cmd(sysinfo::UpdateKind::OnlyIfNotSet)
                .with_exe(sysinfo::UpdateKind::OnlyIfNotSet)
                .with_user(sysinfo::UpdateKind::OnlyIfNotSet),
        );

        let mut results = Vec::new();
        for (pid, proc) in sys.processes() {
            let pid_u32 = pid.as_u32();
            let ppid_u32 = proc.parent().map(|p| p.as_u32());
            let name = proc.name().to_string_lossy().to_string();
            let exe = proc
                .exe()
                .map(|p| PathBuf::from(SecretMasker::mask_string(&p.to_string_lossy())));
            let cpu = proc.cpu_usage();
            let mem = proc.memory();
            let runtime = proc.run_time();
            let start_time = Some(proc.start_time());
            let user = proc.user_id().map(|u| u.to_string());
            let raw_cmdline: Vec<String> = proc
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect();
            let cmdline = SecretMasker::mask_cmdline(&raw_cmdline);

            let exe_status = match &exe {
                Some(p) => crate::model::FieldStatus::Available(p.clone()),
                None => crate::model::FieldStatus::Unavailable,
            };
            let cmdline_status = if cmdline.is_empty() {
                crate::model::FieldStatus::Unavailable
            } else {
                crate::model::FieldStatus::Available(cmdline.clone())
            };

            results.push(ProcessInfo {
                pid: pid_u32,
                ppid: ppid_u32,
                name,
                exe,
                cpu_usage: Some(cpu),
                memory_bytes: Some(mem),
                run_time_secs: runtime,
                start_time,
                user,
                attribution: AgentAttribution::default(),
                listening_ports: Vec::new(),
                cmdline,
                command_outcome: None,
                provenance: None,
                start_time_precise: start_time.map(|s| crate::model::ProcessStartTime::new(s, 0)),
                observation_state: crate::model::ProcessObservationState::Present,
                exe_status,
                cmdline_status,
                cwd_status: crate::model::FieldStatus::Unavailable,
                task_metrics: crate::model::FieldStatus::Available(
                    crate::model::ProcessTaskMetrics {
                        virtual_size_bytes: 0,
                        resident_size_bytes: mem,
                        total_user_time_ms: 0,
                        total_system_time_ms: 0,
                    },
                ),
            });
        }

        // Sort primarily by CPU usage descending
        results.sort_by(|a, b| {
            b.cpu_usage
                .unwrap_or(0.0)
                .partial_cmp(&a.cpu_usage.unwrap_or(0.0))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        Ok(results)
    }

    fn inspect_process(&self, target_pid: u32) -> Result<ProcessDetail, PlatformError> {
        let sys = self
            .system
            .lock()
            .map_err(|e| PlatformError::Other(e.to_string()))?;
        let pid = Pid::from_u32(target_pid);

        let proc = sys
            .process(pid)
            .ok_or(PlatformError::ProcessNotFound(target_pid))?;

        let raw_cmdline: Vec<String> = proc
            .cmd()
            .iter()
            .map(|s| s.to_string_lossy().to_string())
            .collect();

        // Redact any sensitive tokens/passwords from the command line arguments
        let cmdline = SecretMasker::mask_cmdline(&raw_cmdline);

        let exe_path = proc
            .exe()
            .map(|p| PathBuf::from(SecretMasker::mask_string(&p.to_string_lossy())));
        let exe_status = match &exe_path {
            Some(p) => crate::model::FieldStatus::Available(p.clone()),
            None => crate::model::FieldStatus::Unavailable,
        };
        let cmdline_status = if raw_cmdline.is_empty() {
            crate::model::FieldStatus::Unavailable
        } else {
            crate::model::FieldStatus::Available(cmdline.clone())
        };
        let cwd_path = proc
            .cwd()
            .map(|p| PathBuf::from(SecretMasker::mask_string(&p.to_string_lossy())));
        let cwd_status = match &cwd_path {
            Some(p) => crate::model::FieldStatus::Available(p.clone()),
            None => crate::model::FieldStatus::Unavailable,
        };

        let info = ProcessInfo {
            pid: target_pid,
            ppid: proc.parent().map(|p| p.as_u32()),
            name: proc.name().to_string_lossy().to_string(),
            exe: exe_path,
            cpu_usage: Some(proc.cpu_usage()),
            memory_bytes: Some(proc.memory()),
            run_time_secs: proc.run_time(),
            start_time: Some(proc.start_time()),
            user: proc.user_id().map(|u| u.to_string()),
            attribution: AgentAttribution::default(),
            listening_ports: Vec::new(),
            cmdline: cmdline.clone(),
            command_outcome: None,
            provenance: None,
            start_time_precise: Some(crate::model::ProcessStartTime::new(proc.start_time(), 0)),
            observation_state: crate::model::ProcessObservationState::Present,
            exe_status,
            cmdline_status,
            cwd_status,
            task_metrics: crate::model::FieldStatus::Available(crate::model::ProcessTaskMetrics {
                virtual_size_bytes: 0,
                resident_size_bytes: proc.memory(),
                total_user_time_ms: 0,
                total_system_time_ms: 0,
            }),
        };

        let cwd = cwd_path;

        let mut environment = Vec::new();
        for entry in proc.environ() {
            let entry_str = entry.to_string_lossy();
            if let Some((k, v)) = entry_str.split_once('=') {
                let masked = SecretMasker::mask_env_var(k, v);
                environment.push((k.to_string(), masked));
            }
        }

        // Walk ancestors up to root
        let mut parent_chain = Vec::new();
        let mut curr_parent = proc.parent();
        while let Some(ppid) = curr_parent {
            if let Some(parent_proc) = sys.process(ppid) {
                parent_chain.push(ProcessAncestor {
                    pid: ppid.as_u32(),
                    name: parent_proc.name().to_string_lossy().to_string(),
                    cmdline_summary: parent_proc
                        .cmd()
                        .first()
                        .map(|s| SecretMasker::mask_string(&s.to_string_lossy())),
                });
                curr_parent = parent_proc.parent();
            } else {
                break;
            }
        }

        Ok(ProcessDetail {
            info,
            cmdline,
            cwd,
            environment,
            open_files: Vec::new(),
            parent_chain,
        })
    }
}

impl PortCollector for PortableCollector {
    fn collect_listening_ports(&self) -> Result<Vec<ListeningPort>, PlatformError> {
        // Portable fallback returns empty or parsed from system when available
        Ok(Vec::new())
    }
}

impl ServiceCollector for PortableCollector {
    fn collect_services(&self) -> Result<Vec<ServiceInfo>, PlatformError> {
        Ok(Vec::new())
    }
}

impl DockerCollector for PortableCollector {
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
