use crate::platform::macos::proc;
use crate::safety::{SafetyShield, SafetyViolation};
use crate::storage::{AuditRecord, StorageManager};
use std::thread::sleep;
use std::time::Duration;
use sysinfo::{Pid, System};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TerminationError {
    #[error("Safety violation: {0}")]
    Safety(#[from] SafetyViolation),
    #[error("Target process does not exist or exited before signal could be delivered (PID {0})")]
    ProcessGone(u32),
    #[error("PID reuse detected (TOCTOU protection): PID {pid} is currently running '{found}', but expected '{expected}'")]
    ProcessIdentityMismatch {
        pid: u32,
        expected: String,
        found: String,
    },
    #[error("System signal error: {0}")]
    System(String),
}

/// Safe process termination engine with safety guardrails and audit logging.
pub struct ProcessTerminator {
    shield: SafetyShield,
}

impl ProcessTerminator {
    pub fn new() -> Self {
        Self {
            shield: SafetyShield::new(),
        }
    }

    /// Verifies that the target PID still belongs to the expected process right before signaling.
    /// This directly protects against Time-Of-Check to Time-Of-Use (TOCTOU) and PID reuse vulnerabilities.
    pub fn verify_target_identity(
        &self,
        pid: u32,
        expected_name: &str,
        expected_start_time: Option<u64>,
    ) -> Result<(), TerminationError> {
        // 1. Static safety shield check
        self.shield.validate_termination(pid, expected_name)?;

        // 2. Immediate liveness check
        if !proc::is_process_alive(pid) {
            return Err(TerminationError::ProcessGone(pid));
        }

        // 3. Process table snapshot for identity verification
        let mut sys = System::new();
        sys.refresh_processes(
            sysinfo::ProcessesToUpdate::Some(&[Pid::from_u32(pid)]),
            true,
        );

        if let Some(live_proc) = sys.process(Pid::from_u32(pid)) {
            let live_name = live_proc.name().to_string_lossy();

            // Check if process name matches (allowing for command-line truncation or matching prefix)
            let matches_name = live_name.eq_ignore_ascii_case(expected_name)
                || expected_name
                    .to_lowercase()
                    .starts_with(&live_name.to_lowercase())
                || live_name
                    .to_lowercase()
                    .starts_with(&expected_name.to_lowercase());

            if !matches_name {
                return Err(TerminationError::ProcessIdentityMismatch {
                    pid,
                    expected: expected_name.to_string(),
                    found: live_name.to_string(),
                });
            }

            // Check start time if available
            if let Some(expected_time) = expected_start_time {
                let live_start = live_proc.start_time();
                if live_start != 0 && expected_time != 0 && live_start != expected_time {
                    return Err(TerminationError::ProcessIdentityMismatch {
                        pid,
                        expected: format!("start_time: {}", expected_time),
                        found: format!("start_time: {}", live_start),
                    });
                }
            }
        } else {
            return Err(TerminationError::ProcessGone(pid));
        }

        Ok(())
    }

    /// Sends a graceful termination signal (SIGTERM) after validating safety and verifying process identity.
    pub fn terminate_gracefully(
        &self,
        pid: u32,
        process_name: &str,
        expected_start_time: Option<u64>,
        agent_attribution: &str,
        storage: Option<&StorageManager>,
    ) -> Result<bool, TerminationError> {
        // Enforce safety constraints and verify process identity immediately prior to signal dispatch
        self.verify_target_identity(pid, process_name, expected_start_time)?;

        // Send SIGTERM (15) directly through POSIX kill syscall
        let success = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) } == 0;

        let record = AuditRecord {
            timestamp: chrono::Utc::now().to_rfc3339(),
            pid,
            process_name: process_name.to_string(),
            agent_attribution: agent_attribution.to_string(),
            signal_sent: "SIGTERM".to_string(),
            success,
            note: if success {
                Some("Sent SIGTERM gracefully".to_string())
            } else {
                Some(format!(
                    "libc::kill error: {}",
                    std::io::Error::last_os_error()
                ))
            },
        };

        if let Some(store) = storage {
            let _ = store.log_termination(&record);
        }

        if !success {
            return Err(TerminationError::System(
                std::io::Error::last_os_error().to_string(),
            ));
        }

        Ok(true)
    }

    /// Checks if a process has exited within a specified grace timeout.
    pub fn wait_for_exit(&self, pid: u32, timeout: Duration) -> bool {
        let interval = Duration::from_millis(100);
        let mut elapsed = Duration::from_secs(0);

        while elapsed < timeout {
            let alive = unsafe { libc::kill(pid as libc::pid_t, 0) == 0 };
            if !alive {
                return true;
            }
            sleep(interval);
            elapsed += interval;
        }

        // Final check
        unsafe { libc::kill(pid as libc::pid_t, 0) != 0 }
    }

    /// Sends a forceful kill signal (SIGKILL) after explicit user confirmation.
    pub fn force_kill(
        &self,
        pid: u32,
        process_name: &str,
        expected_start_time: Option<u64>,
        agent_attribution: &str,
        storage: Option<&StorageManager>,
    ) -> Result<bool, TerminationError> {
        // Enforce safety constraints and verify process identity immediately prior to signal dispatch
        self.verify_target_identity(pid, process_name, expected_start_time)?;

        // Send SIGKILL (9)
        let success = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) } == 0;

        let record = AuditRecord {
            timestamp: chrono::Utc::now().to_rfc3339(),
            pid,
            process_name: process_name.to_string(),
            agent_attribution: agent_attribution.to_string(),
            signal_sent: "SIGKILL".to_string(),
            success,
            note: if success {
                Some("Force kill with SIGKILL after user confirmation".to_string())
            } else {
                Some(format!(
                    "libc::kill error: {}",
                    std::io::Error::last_os_error()
                ))
            },
        };

        if let Some(store) = storage {
            let _ = store.log_termination(&record);
        }

        if !success {
            return Err(TerminationError::System(
                std::io::Error::last_os_error().to_string(),
            ));
        }

        Ok(true)
    }
}

impl Default for ProcessTerminator {
    fn default() -> Self {
        Self::new()
    }
}
