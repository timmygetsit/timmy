use crate::model::ProcessDetail;
use crate::platform::traits::{PlatformError, ProcessCollector};

/// Process inspection coordinator.
pub struct ProcessInspectionCoordinator;

impl ProcessInspectionCoordinator {
    /// Deeply inspects an individual process.
    pub fn inspect(
        collector: &dyn ProcessCollector,
        pid: u32,
    ) -> Result<ProcessDetail, PlatformError> {
        collector.inspect_process(pid)
    }
}
