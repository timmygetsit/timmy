pub mod masker;
pub mod rules;

use std::collections::HashSet;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SafetyViolation {
    #[error("PID {0} is a protected system process (PID <= 1)")]
    ProtectedPid(u32),

    #[error("Process '{0}' (PID {1}) is a critical system service and cannot be terminated")]
    CriticalSystemProcess(String, u32),

    #[error("Process '{0}' (PID {1}) is a terminal emulator or multiplexer session")]
    TerminalHost(String, u32),

    #[error("Process '{0}' (PID {1}) is TIMMY itself or one of its ancestor shells/terminals")]
    SelfOrAncestorProcess(String, u32),

    #[error("Process '{0}' (PID {1}) is located in protected system path '{2}'")]
    ProtectedSystemPath(String, u32, String),

    #[error("Target process does not exist or has already exited (PID {0})")]
    ProcessNotFound(u32),

    #[error("Process identity mismatch (TOCTOU): PID {0} is now '{1}', expected '{2}'")]
    ProcessIdentityMismatch(u32, String, String),
}

/// Safety enforcement shield that prevents destructive operations on critical processes.
pub struct SafetyShield {
    protected_ancestor_pids: HashSet<u32>,
}

impl SafetyShield {
    /// Creates a new safety shield, dynamically capturing TIMMY's full ancestor chain.
    pub fn new() -> Self {
        let mut ancestors = HashSet::new();

        let current_pid = std::process::id();
        ancestors.insert(current_pid);

        // Climb the PPID chain up to PID 1
        let mut curr = current_pid;
        for _ in 0..32 {
            let ppid = unsafe { libc::getppid() as u32 };
            if ppid <= 1 || ppid == curr {
                if ppid == 1 {
                    ancestors.insert(1);
                }
                break;
            }
            ancestors.insert(ppid);
            curr = ppid;
        }

        Self {
            protected_ancestor_pids: ancestors,
        }
    }

    /// Verifies whether a process can be safely signaled/terminated.
    pub fn validate_termination(
        &self,
        pid: u32,
        process_name: &str,
    ) -> Result<(), SafetyViolation> {
        // Rule 1: Never terminate PID 0 or PID 1
        if rules::is_protected_pid(pid) {
            return Err(SafetyViolation::ProtectedPid(pid));
        }

        // Rule 2: Never terminate TIMMY itself or ANY process in its ancestor lineage
        if self.protected_ancestor_pids.contains(&pid) || process_name.eq_ignore_ascii_case("timmy")
        {
            return Err(SafetyViolation::SelfOrAncestorProcess(
                process_name.to_string(),
                pid,
            ));
        }

        // Rule 3: Never terminate critical macOS system processes
        if rules::is_critical_system_process(process_name) {
            return Err(SafetyViolation::CriticalSystemProcess(
                process_name.to_string(),
                pid,
            ));
        }

        // Rule 4: Never terminate terminal emulators or session multiplexers
        if rules::is_terminal_host(process_name) {
            return Err(SafetyViolation::TerminalHost(process_name.to_string(), pid));
        }

        Ok(())
    }

    /// Extended validation including binary executable path.
    pub fn validate_termination_with_path<P: AsRef<Path>>(
        &self,
        pid: u32,
        process_name: &str,
        exe_path: Option<P>,
    ) -> Result<(), SafetyViolation> {
        self.validate_termination(pid, process_name)?;

        if let Some(path) = exe_path {
            let p = path.as_ref();
            if rules::is_system_binary_path(p) {
                return Err(SafetyViolation::ProtectedSystemPath(
                    process_name.to_string(),
                    pid,
                    p.to_string_lossy().to_string(),
                ));
            }
        }

        Ok(())
    }
}

impl Default for SafetyShield {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blocks_pid_0_and_1() {
        let shield = SafetyShield::new();
        assert!(matches!(
            shield.validate_termination(0, "kernel"),
            Err(SafetyViolation::ProtectedPid(0))
        ));
        assert!(matches!(
            shield.validate_termination(1, "launchd"),
            Err(SafetyViolation::ProtectedPid(1))
        ));
    }

    #[test]
    fn test_blocks_critical_system_processes() {
        let shield = SafetyShield::new();
        assert!(matches!(
            shield.validate_termination(4242, "WindowServer"),
            Err(SafetyViolation::CriticalSystemProcess(_, 4242))
        ));
        assert!(matches!(
            shield.validate_termination(5252, "Dock"),
            Err(SafetyViolation::CriticalSystemProcess(_, 5252))
        ));
    }

    #[test]
    fn test_blocks_terminal_emulators() {
        let shield = SafetyShield::new();
        assert!(matches!(
            shield.validate_termination(8888, "Terminal"),
            Err(SafetyViolation::TerminalHost(_, 8888))
        ));
        assert!(matches!(
            shield.validate_termination(8889, "iTerm2"),
            Err(SafetyViolation::TerminalHost(_, 8889))
        ));
        assert!(matches!(
            shield.validate_termination(8890, "tmux"),
            Err(SafetyViolation::TerminalHost(_, 8890))
        ));
    }

    #[test]
    fn test_blocks_timmy_self_and_ancestors() {
        let shield = SafetyShield::new();
        let my_pid = std::process::id();
        assert!(matches!(
            shield.validate_termination(my_pid, "timmy"),
            Err(SafetyViolation::SelfOrAncestorProcess(_, _))
        ));
    }

    #[test]
    fn test_blocks_system_paths() {
        let shield = SafetyShield::new();
        assert!(matches!(
            shield.validate_termination_with_path(
                9999,
                "some_daemon",
                Some(Path::new("/System/Library/CoreServices/some_daemon"))
            ),
            Err(SafetyViolation::ProtectedSystemPath(_, 9999, _))
        ));
    }

    #[test]
    fn test_allows_safe_user_processes() {
        let shield = SafetyShield::new();
        assert!(shield.validate_termination(99999, "node").is_ok());
        assert!(shield.validate_termination(99998, "python3").is_ok());
        assert!(shield.validate_termination(99997, "vite").is_ok());
    }
}
