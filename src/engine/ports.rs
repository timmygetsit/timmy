use crate::model::ListeningPort;
use crate::platform::traits::{PlatformError, PortCollector};

/// Network and port discovery coordinator.
pub struct PortDiscoveryCoordinator;

impl PortDiscoveryCoordinator {
    pub fn discover_listening(
        collector: &dyn PortCollector,
    ) -> Result<Vec<ListeningPort>, PlatformError> {
        collector.collect_listening_ports()
    }
}
