use crate::model::ProcessInfo;
use serde::{Deserialize, Serialize};

/// Snapshot of aggregated system resource consumption by AI agents vs total system.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceSnapshot {
    pub total_agent_processes: usize,
    pub total_agent_cpu_usage: f32,
    pub total_agent_memory_bytes: u64,
    pub total_listening_ports: usize,
}

impl ResourceSnapshot {
    pub fn formatted_memory(&self) -> String {
        let bytes = self.total_agent_memory_bytes;
        if bytes >= 1024 * 1024 * 1024 {
            format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
        } else if bytes >= 1024 * 1024 {
            format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
        } else {
            format!("{:.0} KB", bytes as f64 / 1024.0)
        }
    }

    pub fn formatted_cpu(&self) -> String {
        format!("{:.1}%", self.total_agent_cpu_usage)
    }
}

/// Resource monitoring and delta calculation engine.
pub struct ResourceMonitor;

impl ResourceMonitor {
    /// Computes summary metrics for a list of discovered processes.
    pub fn calculate_summary(processes: &[ProcessInfo]) -> ResourceSnapshot {
        let mut snapshot = ResourceSnapshot::default();

        for proc in processes {
            // Count processes that have some degree of AI agent attribution
            if proc.attribution.confidence > crate::model::Confidence::Unknown {
                snapshot.total_agent_processes += 1;
                if let Some(cpu) = proc.cpu_usage {
                    snapshot.total_agent_cpu_usage += cpu;
                }
                if let Some(mem) = proc.memory_bytes {
                    snapshot.total_agent_memory_bytes += mem;
                }
                snapshot.total_listening_ports += proc.listening_ports.len();
            }
        }

        snapshot
    }
}
