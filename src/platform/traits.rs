use crate::model::{
    ContainerDetail, ContainerInfo, ContainerStats, DockerStatus, ListeningPort, ProcessDetail,
    ProcessInfo, ProcessSnapshot, ServiceInfo,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("Process not found: PID {0}")]
    ProcessNotFound(u32),
    #[error("Permission denied inspecting process: PID {0}")]
    PermissionDenied(u32),
    #[error("Docker daemon is not running or socket is unreachable: {0}")]
    DockerNotRunning(String),
    #[error("Docker is not installed on this system")]
    DockerNotInstalled,
    #[error("Docker daemon is stopped: {0}")]
    DockerDaemonStopped(String),
    #[error("Docker socket not found: {0}")]
    DockerSocketMissing(String),
    #[error("Permission denied accessing Docker socket: {0}")]
    DockerPermissionDenied(String),
    #[error("Invalid Docker endpoint: {0}")]
    DockerInvalidEndpoint(String),
    #[error(
        "Unsupported remote Docker endpoint '{0}': TIMMY is strictly local-only in this milestone"
    )]
    DockerUnsupportedRemote(String),
    #[error("Docker API version incompatible: {0}")]
    DockerApiIncompatible(String),
    #[error("Docker container not found: {0}")]
    ContainerNotFound(String),
    #[error("Docker API error: {0}")]
    DockerApi(String),
    #[error("I/O error during discovery: {0}")]
    Io(#[from] std::io::Error),
    #[error("Platform specific error: {0}")]
    Other(String),
}

impl Clone for PlatformError {
    fn clone(&self) -> Self {
        match self {
            Self::ProcessNotFound(p) => Self::ProcessNotFound(*p),
            Self::PermissionDenied(p) => Self::PermissionDenied(*p),
            Self::DockerNotRunning(s) => Self::DockerNotRunning(s.clone()),
            Self::DockerNotInstalled => Self::DockerNotInstalled,
            Self::DockerDaemonStopped(s) => Self::DockerDaemonStopped(s.clone()),
            Self::DockerSocketMissing(s) => Self::DockerSocketMissing(s.clone()),
            Self::DockerPermissionDenied(s) => Self::DockerPermissionDenied(s.clone()),
            Self::DockerInvalidEndpoint(s) => Self::DockerInvalidEndpoint(s.clone()),
            Self::DockerUnsupportedRemote(s) => Self::DockerUnsupportedRemote(s.clone()),
            Self::DockerApiIncompatible(s) => Self::DockerApiIncompatible(s.clone()),
            Self::ContainerNotFound(s) => Self::ContainerNotFound(s.clone()),
            Self::DockerApi(s) => Self::DockerApi(s.clone()),
            Self::Io(e) => Self::Io(std::io::Error::new(e.kind(), e.to_string())),
            Self::Other(s) => Self::Other(s.clone()),
        }
    }
}

/// Trait defining process discovery capabilities.
pub trait ProcessCollector: Send + Sync {
    /// Collect a snapshot of all active processes visible to the current user.
    fn collect_processes(&self) -> Result<Vec<ProcessInfo>, PlatformError>;

    /// Collect a complete process snapshot with observation interval and completeness metadata.
    fn collect_process_snapshot(&self) -> Result<ProcessSnapshot, PlatformError> {
        let start_wc = chrono::Utc::now();
        let procs = self.collect_processes()?;
        let end_wc = chrono::Utc::now();
        let duration_ms = end_wc
            .signed_duration_since(start_wc)
            .num_milliseconds()
            .max(0) as u64;
        Ok(ProcessSnapshot {
            processes: procs,
            interval: crate::model::ObservationInterval {
                start_wall_clock: start_wc,
                end_wall_clock: end_wc,
                duration_ms,
                completeness: crate::model::SnapshotCompleteness::Complete,
            },
            completeness: crate::model::SnapshotCompleteness::Complete,
        })
    }

    /// Inspect a single process in detail.
    fn inspect_process(&self, pid: u32) -> Result<ProcessDetail, PlatformError>;
}

/// Trait defining open port and socket discovery capabilities.
pub trait PortCollector: Send + Sync {
    /// Collect active listening TCP/UDP ports.
    fn collect_listening_ports(&self) -> Result<Vec<ListeningPort>, PlatformError>;
}

/// Trait defining background service discovery (launchd, systemd, etc.).
pub trait ServiceCollector: Send + Sync {
    /// Collect active background services and daemons.
    fn collect_services(&self) -> Result<Vec<ServiceInfo>, PlatformError>;
}

/// Trait defining Docker container discovery and inspection capabilities.
pub trait DockerCollector: Send + Sync {
    /// Inspect overall Docker Engine availability, versions, and daemon health.
    fn docker_status(&self) -> Result<DockerStatus, PlatformError>;

    /// Check whether Docker daemon is reachable.
    fn is_available(&self) -> bool {
        self.docker_status().map(|s| s.running).unwrap_or(false)
    }

    /// Collect all Docker containers (running and non-running) with resource metrics.
    fn collect_containers(&self) -> Result<Vec<ContainerInfo>, PlatformError>;

    /// Deeply inspect an individual container by ID or name.
    fn inspect_container(&self, id: &str) -> Result<ContainerDetail, PlatformError>;

    /// Collect live resource statistics for an individual container.
    fn collect_container_stats(&self, id: &str) -> Result<ContainerStats, PlatformError>;

    /// Signals cancellation of any in-flight Docker operations (where supported by collector).
    fn cancel(&self) {}
}
