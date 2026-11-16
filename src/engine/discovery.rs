use super::attribution::AttributionEngine;
use crate::model::ProcessInfo;
use crate::platform::traits::{PlatformError, PortCollector, ProcessCollector};
use std::collections::HashMap;

/// Discovery coordinator bringing together raw processes, ports, and agent attribution.
pub struct ProcessDiscoveryCoordinator {
    attribution: AttributionEngine,
}

impl ProcessDiscoveryCoordinator {
    pub fn new(attribution: AttributionEngine) -> Self {
        Self { attribution }
    }

    /// Performs complete process discovery with port correlation and attribution.
    pub fn discover_all(
        &self,
        process_collector: &dyn ProcessCollector,
        port_collector: &dyn PortCollector,
    ) -> Result<Vec<ProcessInfo>, PlatformError> {
        let mut processes = process_collector.collect_processes()?;

        // Correlate open listening ports
        if let Ok(ports) = port_collector.collect_listening_ports() {
            let mut pid_to_ports: HashMap<u32, Vec<u16>> = HashMap::new();
            for port in ports {
                if let Some(pid) = port.pid {
                    pid_to_ports.entry(pid).or_default().push(port.port);
                }
            }

            for proc in processes.iter_mut() {
                if let Some(mut p_list) = pid_to_ports.remove(&proc.pid) {
                    p_list.sort_unstable();
                    p_list.dedup();
                    proc.listening_ports = p_list;
                }
            }
        }

        // Run attribution heuristics and process-tree lineage propagation
        self.attribution.propagate_tree_attribution(&mut processes);

        Ok(processes)
    }
}
