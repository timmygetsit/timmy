pub mod docker;
pub mod portable;
pub mod service_worker;
pub mod traits;

#[cfg(target_os = "macos")]
pub mod macos;

pub use docker::{DockerBackgroundWorker, WorkerShutdownResult, MAX_CACHED_INSPECTIONS};
pub use service_worker::{ServiceBackgroundWorker, ServiceWorkerState, SnapshotStatus};
pub use traits::{
    DockerCollector, PlatformError, PortCollector, ProcessCollector, ServiceCollector,
};

use std::sync::Arc;

/// Combined platform collector interface.
pub trait SystemCollector:
    ProcessCollector + PortCollector + ServiceCollector + DockerCollector
{
}

impl<T> SystemCollector for T where
    T: ProcessCollector + PortCollector + ServiceCollector + DockerCollector
{
}

/// Factory function to return the optimal system collector for the current host OS,
/// configured with TIMMY runtime settings.
pub fn create_platform_collector_with_config(
    config: &crate::config::TimmyConfig,
) -> Arc<dyn SystemCollector> {
    let custom_socket = if config.general.docker_socket.trim().is_empty() {
        None
    } else {
        Some(config.general.docker_socket.trim().to_string())
    };
    let timeout = std::time::Duration::from_millis(config.general.docker_timeout_ms.max(500));

    #[cfg(target_os = "macos")]
    {
        Arc::new(macos::MacOsCollector::with_docker_config(
            custom_socket,
            timeout,
        ))
    }

    #[cfg(not(target_os = "macos"))]
    {
        Arc::new(portable::PortableCollector::with_docker_config(
            custom_socket,
            timeout,
        ))
    }
}

/// Factory function to return the optimal system collector with default configuration.
pub fn create_platform_collector() -> Arc<dyn SystemCollector> {
    create_platform_collector_with_config(&Default::default())
}
