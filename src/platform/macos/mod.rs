pub mod darwin_sys;
pub mod launchd;
pub mod ports;
pub mod proc;

pub use ports::DarwinPortCollector;
pub use proc::DarwinProcessCollector;

use super::docker::BollardDockerCollector;
use super::portable::PortableCollector;
use super::traits::{
    DockerCollector, PlatformError, PortCollector, ProcessCollector, ServiceCollector,
};
use crate::model::{
    ContainerDetail, ContainerInfo, ContainerStats, DockerStatus, ListeningPort, ProcessDetail,
    ProcessInfo, ProcessSnapshot, ServiceInfo,
};
use std::time::Duration;

/// macOS platform-specific collector combining high-performance native Darwin
/// process discovery with launchd, lsof, POSIX signals, and Bollard Docker inspection,
/// featuring automatic fallback to `PortableCollector`.
pub struct MacOsCollector {
    native_proc: DarwinProcessCollector,
    portable: PortableCollector,
    docker: BollardDockerCollector,
}

impl MacOsCollector {
    pub fn new() -> Self {
        Self {
            native_proc: DarwinProcessCollector::new(),
            portable: PortableCollector::new(),
            docker: BollardDockerCollector::new(None, Duration::from_millis(2000)),
        }
    }

    pub fn with_docker_config(socket: Option<String>, timeout: Duration) -> Self {
        Self {
            native_proc: DarwinProcessCollector::new(),
            portable: PortableCollector::new(),
            docker: BollardDockerCollector::new(socket, timeout),
        }
    }
}

impl Default for MacOsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessCollector for MacOsCollector {
    fn collect_process_snapshot(&self) -> Result<ProcessSnapshot, PlatformError> {
        match self.native_proc.collect_process_snapshot() {
            Ok(snapshot) => Ok(snapshot),
            Err(_err) => {
                // Safe fallback to PortableCollector when native discovery fails
                let mut fallback_snapshot = self.portable.collect_process_snapshot()?;
                fallback_snapshot.completeness = crate::model::SnapshotCompleteness::PartialError {
                    successful_queries: fallback_snapshot.processes.len(),
                    failed_queries: 1,
                };
                fallback_snapshot.interval.completeness = fallback_snapshot.completeness.clone();
                Ok(fallback_snapshot)
            }
        }
    }

    fn collect_processes(&self) -> Result<Vec<ProcessInfo>, PlatformError> {
        self.collect_process_snapshot().map(|s| s.processes)
    }

    fn inspect_process(&self, pid: u32) -> Result<ProcessDetail, PlatformError> {
        match self.native_proc.inspect_process(pid) {
            Ok(detail) => Ok(detail),
            Err(_) => self.portable.inspect_process(pid),
        }
    }
}

impl PortCollector for MacOsCollector {
    fn collect_listening_ports(&self) -> Result<Vec<ListeningPort>, PlatformError> {
        ports::discover_listening_ports()
    }
}

impl ServiceCollector for MacOsCollector {
    fn collect_services(&self) -> Result<Vec<ServiceInfo>, PlatformError> {
        launchd::discover_launchd_services()
    }
}

impl DockerCollector for MacOsCollector {
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
