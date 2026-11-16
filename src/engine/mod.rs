pub mod attribution;
pub mod discovery;
pub mod docker;
pub mod inspection;
pub mod lineage;
pub mod monitor;
pub mod ports;
pub mod services;
pub mod session;
pub mod terminator;

pub use attribution::AttributionEngine;
pub use discovery::ProcessDiscoveryCoordinator;
pub use docker::DockerCoordinator;
pub use inspection::ProcessInspectionCoordinator;
pub use lineage::{
    build_session_lineage_tree, extract_snapshot_lineage_edges, format_lineage_tree_unicode,
    resolve_lineage_chain, update_edge_lifecycle_statuses, validate_lineage_edge, LineageTreeNode,
    LineageValidationError,
};
pub use monitor::{ResourceMonitor, ResourceSnapshot};
pub use ports::PortDiscoveryCoordinator;
pub use services::ServiceDiscoveryCoordinator;
pub use session::{register_shutdown_signals, SessionCoordinator, SessionError};
pub use terminator::{ProcessTerminator, TerminationError};

use crate::config::TimmyConfig;
use crate::model::session::{CleanupRecommendation, SessionInfo, TrackedResource};
use crate::model::{
    ContainerDetail, ContainerInfo, ContainerStats, DockerStatus, ListeningPort, ProcessDetail,
    ProcessInfo, ServiceInfo,
};
use crate::platform::{PlatformError, SystemCollector};
use crate::storage::StorageManager;
use std::sync::Arc;

/// Complete snapshot of the system's active developer state.
#[derive(Debug, Clone, Default)]
pub struct SystemSnapshot {
    pub processes: Vec<ProcessInfo>,
    pub ports: Vec<ListeningPort>,
    pub services: Vec<ServiceInfo>,
    pub containers: Vec<ContainerInfo>,
    pub metrics: ResourceSnapshot,
    pub active_session: Option<SessionInfo>,
    pub sessions: Vec<SessionInfo>,
}

/// Central orchestrator connecting all discovery, monitoring, session tracking, and safety engines.
pub struct EngineOrchestrator {
    platform: Arc<dyn SystemCollector>,
    discovery: ProcessDiscoveryCoordinator,
    terminator: ProcessTerminator,
    session: Option<SessionCoordinator>,
    storage: Option<Arc<StorageManager>>,
    config: TimmyConfig,
}

impl EngineOrchestrator {
    pub fn new(config: TimmyConfig, storage: Option<Arc<StorageManager>>) -> Self {
        let platform = crate::platform::create_platform_collector_with_config(&config);
        let attribution = AttributionEngine::new(config.agents.custom_rules.clone());
        let discovery = ProcessDiscoveryCoordinator::new(attribution);
        let terminator = ProcessTerminator::new();
        let session = storage
            .as_ref()
            .map(|s| SessionCoordinator::new(Arc::clone(s), config.clone()));

        Self {
            platform,
            discovery,
            terminator,
            session,
            storage,
            config,
        }
    }

    /// Creates an orchestrator with a custom platform collector (e.g. for mock testing).
    pub fn with_collector(
        config: TimmyConfig,
        storage: Option<Arc<StorageManager>>,
        platform: Arc<dyn SystemCollector>,
    ) -> Self {
        let attribution = AttributionEngine::new(config.agents.custom_rules.clone());
        let discovery = ProcessDiscoveryCoordinator::new(attribution);
        let terminator = ProcessTerminator::new();
        let session = storage
            .as_ref()
            .map(|s| SessionCoordinator::new(Arc::clone(s), config.clone()));

        Self {
            platform,
            discovery,
            terminator,
            session,
            storage,
            config,
        }
    }

    /// Captures a fresh snapshot of processes, ports, services, metrics, and session states.
    pub fn refresh_snapshot(&self) -> Result<SystemSnapshot, PlatformError> {
        let processes = self
            .discovery
            .discover_all(self.platform.as_ref(), self.platform.as_ref())?;

        let ports = PortDiscoveryCoordinator::discover_listening(self.platform.as_ref())?;
        let mut services = ServiceDiscoveryCoordinator::discover_services(self.platform.as_ref())?;
        let mut containers = if self.config.general.enable_docker {
            DockerCoordinator::discover_containers(self.platform.as_ref()).unwrap_or_default()
        } else {
            Vec::new()
        };
        let metrics = ResourceMonitor::calculate_summary(&processes);

        let (active_session, sessions) = if let Some(coord) = &self.session {
            let list = coord.list_sessions().unwrap_or_default();
            let mut active = list
                .iter()
                .find(|s| s.status == crate::model::SessionStatus::Active)
                .cloned();

            // If active session exists, run a background observation cycle unless an active observer lease is held
            if let Some(ref act) = active {
                let is_lease_held = self
                    .storage
                    .as_ref()
                    .and_then(|s| s.get_observer_lease(&act.id).ok().flatten())
                    .map(|l| !l.is_expired())
                    .unwrap_or(false);

                if !is_lease_held {
                    if let Ok((updated, _)) = coord.observe_and_update(act, self.platform.as_ref())
                    {
                        active = Some(updated);
                    }
                }
            }

            (active, list)
        } else {
            (None, Vec::new())
        };

        // Correlate discovered containers with known sessions
        DockerCoordinator::correlate_containers(&mut containers, &sessions, &processes);

        // Correlate discovered background services with known sessions and running processes
        ServiceDiscoveryCoordinator::correlate_services(&mut services, &processes, &sessions);

        Ok(SystemSnapshot {
            processes,
            ports,
            services,
            containers,
            metrics,
            active_session,
            sessions,
        })
    }

    /// Captures local system state (processes, ports, sessions, metrics) without blocking on Docker socket or launchctl I/O.
    /// Used by the TUI loop to guarantee non-blocking responsiveness while Docker and Services data are collected asynchronously.
    pub fn refresh_local_snapshot(&self) -> Result<SystemSnapshot, PlatformError> {
        let processes = self
            .discovery
            .discover_all(self.platform.as_ref(), self.platform.as_ref())?;

        let ports = PortDiscoveryCoordinator::discover_listening(self.platform.as_ref())?;
        let metrics = ResourceMonitor::calculate_summary(&processes);

        let (active_session, sessions) = if let Some(coord) = &self.session {
            let list = coord.list_sessions().unwrap_or_default();
            let mut active = list
                .iter()
                .find(|s| s.status == crate::model::SessionStatus::Active)
                .cloned();

            if let Some(ref act) = active {
                let is_lease_held = self
                    .storage
                    .as_ref()
                    .and_then(|s| s.get_observer_lease(&act.id).ok().flatten())
                    .map(|l| !l.is_expired())
                    .unwrap_or(false);

                if !is_lease_held {
                    if let Ok((updated, _)) = coord.observe_and_update(act, self.platform.as_ref())
                    {
                        active = Some(updated);
                    }
                }
            }

            (active, list)
        } else {
            (None, Vec::new())
        };

        Ok(SystemSnapshot {
            processes,
            ports,
            services: Vec::new(),
            containers: Vec::new(),
            metrics,
            active_session,
            sessions,
        })
    }

    pub fn is_docker_enabled(&self) -> bool {
        self.config.general.enable_docker
    }

    pub fn platform_docker_collector(&self) -> Arc<dyn crate::platform::DockerCollector> {
        Arc::clone(&self.platform) as Arc<dyn crate::platform::DockerCollector>
    }

    pub fn platform_service_collector(&self) -> Arc<dyn crate::platform::ServiceCollector> {
        Arc::clone(&self.platform) as Arc<dyn crate::platform::ServiceCollector>
    }

    /// Inspects overall Docker daemon connectivity and status.
    pub fn docker_status(&self) -> Result<DockerStatus, PlatformError> {
        DockerCoordinator::docker_status(self.platform.as_ref())
    }

    /// Lists Docker containers, optionally filtered by session identifier.
    pub fn list_containers(
        &self,
        session_filter: Option<&str>,
    ) -> Result<Vec<ContainerInfo>, PlatformError> {
        let mut containers = DockerCoordinator::discover_containers(self.platform.as_ref())?;
        let sessions = self
            .session
            .as_ref()
            .map(|s| s.list_sessions().unwrap_or_default())
            .unwrap_or_default();
        let processes = self
            .discovery
            .discover_all(self.platform.as_ref(), self.platform.as_ref())
            .unwrap_or_default();

        DockerCoordinator::correlate_containers(&mut containers, &sessions, &processes);

        if let Some(sid) = session_filter {
            containers.retain(|c| c.session_id.as_deref() == Some(sid));
        }

        Ok(containers)
    }

    /// Deeply inspects an individual container.
    pub fn inspect_container(&self, id: &str) -> Result<ContainerDetail, PlatformError> {
        let mut detail = DockerCoordinator::inspect_container(self.platform.as_ref(), id)?;
        let sessions = self
            .session
            .as_ref()
            .map(|s| s.list_sessions().unwrap_or_default())
            .unwrap_or_default();
        let processes = self
            .discovery
            .discover_all(self.platform.as_ref(), self.platform.as_ref())
            .unwrap_or_default();

        DockerCoordinator::correlate_container_with_mounts(
            &mut detail.info,
            &detail.mounts,
            &sessions,
            &processes,
        );

        Ok(detail)
    }

    /// Collects live resource stats for an individual container.
    pub fn collect_container_stats(&self, id: &str) -> Result<ContainerStats, PlatformError> {
        DockerCoordinator::collect_container_stats(self.platform.as_ref(), id)
    }

    /// Deeply inspects an individual process.
    pub fn inspect_process(&self, pid: u32) -> Result<ProcessDetail, PlatformError> {
        ProcessInspectionCoordinator::inspect(self.platform.as_ref(), pid)
    }

    /// Safely terminates a process with identity verification and audit logging.
    pub fn terminate_process(
        &self,
        pid: u32,
        name: &str,
        start_time: Option<u64>,
        attribution: &str,
        force: bool,
    ) -> Result<bool, TerminationError> {
        let storage_ref = self.storage.as_deref();
        if force {
            self.terminator
                .force_kill(pid, name, start_time, attribution, storage_ref)
        } else {
            self.terminator
                .terminate_gracefully(pid, name, start_time, attribution, storage_ref)
        }
    }

    // =========================================================================
    // SESSION MANAGEMENT DISPATCH
    // =========================================================================

    pub fn start_session(
        &self,
        agent_flag: Option<String>,
        replace: bool,
    ) -> Result<SessionInfo, SessionError> {
        let coord = self.session.as_ref().ok_or_else(|| {
            SessionError::Storage(crate::storage::StorageError::Lock(
                "Storage not initialized".into(),
            ))
        })?;
        coord.start_session(agent_flag, replace, self.platform.as_ref())
    }

    pub fn observe_active_session(
        &self,
    ) -> Result<Option<(SessionInfo, Vec<TrackedResource>)>, SessionError> {
        let coord = self.session.as_ref().ok_or_else(|| {
            SessionError::Storage(crate::storage::StorageError::Lock(
                "Storage not initialized".into(),
            ))
        })?;

        let active = self
            .storage
            .as_ref()
            .and_then(|s| s.get_active_session().ok().flatten());
        if let Some(act) = active {
            let res = coord.observe_and_update(&act, self.platform.as_ref())?;
            Ok(Some(res))
        } else {
            Ok(None)
        }
    }

    pub fn watch_session<F>(
        &self,
        session_id: &str,
        interval: std::time::Duration,
        stop_signal: std::sync::Arc<std::sync::atomic::AtomicBool>,
        on_tick: F,
    ) -> Result<SessionInfo, SessionError>
    where
        F: FnMut(&SessionInfo, &[TrackedResource]),
    {
        let coord = self.session.as_ref().ok_or_else(|| {
            SessionError::Storage(crate::storage::StorageError::Lock(
                "Storage not initialized".into(),
            ))
        })?;
        coord.watch_session(
            session_id,
            interval,
            stop_signal,
            self.platform.as_ref(),
            on_tick,
        )
    }

    pub fn stop_session(&self, session_id: Option<&str>) -> Result<SessionInfo, SessionError> {
        let coord = self.session.as_ref().ok_or_else(|| {
            SessionError::Storage(crate::storage::StorageError::Lock(
                "Storage not initialized".into(),
            ))
        })?;
        coord.stop_session(session_id)
    }

    pub fn list_sessions(&self) -> Result<Vec<SessionInfo>, SessionError> {
        let coord = self.session.as_ref().ok_or_else(|| {
            SessionError::Storage(crate::storage::StorageError::Lock(
                "Storage not initialized".into(),
            ))
        })?;
        coord.list_sessions()
    }

    pub fn inspect_session(
        &self,
        session_id: Option<&str>,
    ) -> Result<
        (
            SessionInfo,
            Vec<TrackedResource>,
            Vec<CleanupRecommendation>,
        ),
        SessionError,
    > {
        let coord = self.session.as_ref().ok_or_else(|| {
            SessionError::Storage(crate::storage::StorageError::Lock(
                "Storage not initialized".into(),
            ))
        })?;
        coord.inspect_session(session_id, self.platform.as_ref())
    }

    pub fn get_session_resources(
        &self,
        session_id: Option<&str>,
    ) -> Result<(SessionInfo, Vec<TrackedResource>), SessionError> {
        let coord = self.session.as_ref().ok_or_else(|| {
            SessionError::Storage(crate::storage::StorageError::Lock(
                "Storage not initialized".into(),
            ))
        })?;
        coord.get_session_resources(session_id, self.platform.as_ref())
    }

    pub fn get_session_lineage_tree(
        &self,
        session_id: &str,
        show_exited: bool,
    ) -> Result<Vec<LineageTreeNode>, SessionError> {
        let coord = self.session.as_ref().ok_or_else(|| {
            SessionError::Storage(crate::storage::StorageError::Lock(
                "Storage not initialized".into(),
            ))
        })?;
        coord.get_session_lineage_tree(session_id, show_exited)
    }

    pub fn get_lineage_edges(
        &self,
        session_id: &str,
    ) -> Result<Vec<crate::model::lineage::ProcessLineageEdge>, SessionError> {
        let coord = self.session.as_ref().ok_or_else(|| {
            SessionError::Storage(crate::storage::StorageError::Lock(
                "Storage not initialized".into(),
            ))
        })?;
        coord.get_lineage_edges(session_id)
    }

    pub fn session_coordinator(&self) -> Option<&SessionCoordinator> {
        self.session.as_ref()
    }

    pub fn config(&self) -> &TimmyConfig {
        &self.config
    }
}
