use super::agent::AgentAttribution;
use super::docker::CreationOutcome;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

/// Microsecond-precision start timestamp directly from kernel process info.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProcessStartTime {
    /// Seconds since Unix epoch.
    pub tv_sec: u64,
    /// Microseconds within the second (0..999,999).
    pub tv_usec: u64,
}

impl ProcessStartTime {
    pub const fn new(tv_sec: u64, tv_usec: u64) -> Self {
        Self { tv_sec, tv_usec }
    }

    #[cfg(target_os = "macos")]
    pub fn from_bsdinfo(pbsd: &libc::proc_bsdinfo) -> Self {
        Self {
            tv_sec: pbsd.pbi_start_tvsec,
            tv_usec: pbsd.pbi_start_tvusec,
        }
    }

    pub fn as_secs(&self) -> u64 {
        self.tv_sec
    }
}

impl fmt::Display for ProcessStartTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:06}s", self.tv_sec, self.tv_usec)
    }
}

/// Immutable process incarnation identity anchored strictly to kernel process allocation.
/// Stable across `execve()` image replacements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProcessIncarnation {
    pub pid: u32,
    pub start_time: ProcessStartTime,
}

impl ProcessIncarnation {
    pub const fn new(pid: u32, start_time: ProcessStartTime) -> Self {
        Self { pid, start_time }
    }
}

impl fmt::Display for ProcessIncarnation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PID {} (started {})", self.pid, self.start_time)
    }
}

/// Discrete observation state of a process in a snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum ProcessObservationState {
    /// Process is alive and was successfully inspected in the current snapshot with matching incarnation.
    #[default]
    Present,
    /// Process was previously recorded as Present and has positively terminated (proven by kernel ESRCH with matching incarnation history).
    ExitedConfirmed,
    /// Process has terminated but has not been reaped by its parent (zombie / SZOMB state).
    TerminatedUnreaped,
    /// Process start time differs from the recorded incarnation, indicating PID reuse by another process.
    PidReused,
    /// Process was not seen in this snapshot, or evidence is missing / inconclusive.
    NotObserved,
    /// Process is in the process table, but detailed inspection was blocked (EPERM / EACCES / Sandbox / SIP).
    InspectionRestricted,
}

impl fmt::Display for ProcessObservationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Present => write!(f, "PRESENT"),
            Self::ExitedConfirmed => write!(f, "EXITED_CONFIRMED"),
            Self::TerminatedUnreaped => write!(f, "TERMINATED_UNREAPED"),
            Self::PidReused => write!(f, "PID_REUSED"),
            Self::NotObserved => write!(f, "NOT_OBSERVED"),
            Self::InspectionRestricted => write!(f, "INSPECTION_RESTRICTED"),
        }
    }
}

/// Independent inspection status and value for an individual process attribute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum FieldStatus<T> {
    /// Attribute was successfully retrieved and verified.
    Available(T),
    /// Attribute query returned EPERM or EACCES (SIP, sandbox, foreign user).
    Restricted,
    /// Attribute could not be retrieved (ESRCH, malformed data, or unsupported).
    #[default]
    Unavailable,
}

impl<T> FieldStatus<T> {
    pub fn as_ref(&self) -> Option<&T> {
        match self {
            FieldStatus::Available(val) => Some(val),
            _ => None,
        }
    }

    pub fn into_option(self) -> Option<T> {
        match self {
            FieldStatus::Available(val) => Some(val),
            _ => None,
        }
    }

    pub fn is_available(&self) -> bool {
        matches!(self, FieldStatus::Available(_))
    }

    pub fn is_restricted(&self) -> bool {
        matches!(self, FieldStatus::Restricted)
    }

    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> FieldStatus<U> {
        match self {
            FieldStatus::Available(val) => FieldStatus::Available(f(val)),
            FieldStatus::Restricted => FieldStatus::Restricted,
            FieldStatus::Unavailable => FieldStatus::Unavailable,
        }
    }
}

/// Low-level task memory and CPU consumption metrics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ProcessTaskMetrics {
    pub virtual_size_bytes: u64,
    pub resident_size_bytes: u64,
    pub total_user_time_ms: u64,
    pub total_system_time_ms: u64,
}

/// Quality and completeness classification of an overall process snapshot enumeration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SnapshotCompleteness {
    /// All active PIDs in the kernel process table were enumerated without truncation.
    #[default]
    Complete,
    /// PID list was truncated because process count exceeded buffer allocation limits.
    Truncated {
        returned_count: usize,
        capacity: usize,
    },
    /// Process enumeration encountered a non-fatal partial error.
    PartialError {
        successful_queries: usize,
        failed_queries: usize,
    },
}

/// Bounded observation time window and completeness for a process snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationInterval {
    pub start_wall_clock: DateTime<Utc>,
    pub end_wall_clock: DateTime<Utc>,
    pub duration_ms: u64,
    pub completeness: SnapshotCompleteness,
}

impl Default for ObservationInterval {
    fn default() -> Self {
        let now = Utc::now();
        Self {
            start_wall_clock: now,
            end_wall_clock: now,
            duration_ms: 0,
            completeness: SnapshotCompleteness::Complete,
        }
    }
}

/// A coherent, bounded snapshot of running processes and enumeration metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessSnapshot {
    pub processes: Vec<ProcessInfo>,
    pub interval: ObservationInterval,
    pub completeness: SnapshotCompleteness,
}

/// High-level summary of an active process.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub exe: Option<PathBuf>,
    pub cpu_usage: Option<f32>,
    pub memory_bytes: Option<u64>,
    pub run_time_secs: u64,
    pub start_time: Option<u64>,
    pub user: Option<String>,
    pub attribution: AgentAttribution,
    pub listening_ports: Vec<u16>,
    #[serde(default)]
    pub cmdline: Vec<String>,
    /// Structured result of a CLI command execution if known to a platform collector.
    #[serde(default)]
    pub command_outcome: Option<CreationOutcome>,
    /// Structured launch provenance binding this process to a session, if established.
    #[serde(default)]
    pub provenance: Option<super::provenance::LaunchProvenance>,
    /// Microsecond-precision kernel start time, when available.
    #[serde(default)]
    pub start_time_precise: Option<ProcessStartTime>,
    /// Observation state in the current snapshot.
    #[serde(default)]
    pub observation_state: ProcessObservationState,
    /// Detailed status of executable path query.
    #[serde(default)]
    pub exe_status: FieldStatus<PathBuf>,
    /// Detailed status of command-line arguments query.
    #[serde(default)]
    pub cmdline_status: FieldStatus<Vec<String>>,
    /// Detailed status of current working directory query.
    #[serde(default)]
    pub cwd_status: FieldStatus<PathBuf>,
    /// Detailed status of task memory/CPU metrics.
    #[serde(default)]
    pub task_metrics: FieldStatus<ProcessTaskMetrics>,
}

impl Default for ProcessInfo {
    fn default() -> Self {
        Self {
            pid: 0,
            ppid: None,
            name: String::new(),
            exe: None,
            cpu_usage: None,
            memory_bytes: None,
            run_time_secs: 0,
            start_time: None,
            user: None,
            attribution: AgentAttribution::default(),
            listening_ports: Vec::new(),
            cmdline: Vec::new(),
            command_outcome: None,
            provenance: None,
            start_time_precise: None,
            observation_state: ProcessObservationState::Present,
            exe_status: FieldStatus::Unavailable,
            cmdline_status: FieldStatus::Unavailable,
            cwd_status: FieldStatus::Unavailable,
            task_metrics: FieldStatus::Unavailable,
        }
    }
}

impl ProcessInfo {
    /// Returns the exact process incarnation identity if start time is known.
    pub fn incarnation(&self) -> Option<ProcessIncarnation> {
        if let Some(precise) = self.start_time_precise {
            Some(ProcessIncarnation::new(self.pid, precise))
        } else {
            self.start_time
                .map(|secs| ProcessIncarnation::new(self.pid, ProcessStartTime::new(secs, 0)))
        }
    }

    /// Returns true if inspection was restricted due to permissions (EPERM / SIP).
    pub fn is_restricted(&self) -> bool {
        self.observation_state == ProcessObservationState::InspectionRestricted
            || self.exe_status.is_restricted()
            || self.cmdline_status.is_restricted()
            || self.task_metrics.is_restricted()
    }

    /// Formatted memory string (e.g., "128.4 MB" or "N/A (Restricted)")
    pub fn formatted_memory(&self) -> String {
        if self.task_metrics.is_restricted() || self.memory_bytes == Some(0) {
            return "N/A (Restricted)".to_string();
        }
        match self.memory_bytes {
            Some(bytes) => {
                if bytes >= 1024 * 1024 * 1024 {
                    format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
                } else if bytes >= 1024 * 1024 {
                    format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
                } else if bytes >= 1024 {
                    format!("{:.1} KB", bytes as f64 / 1024.0)
                } else {
                    format!("{} B", bytes)
                }
            }
            None => "N/A".to_string(),
        }
    }

    /// Formatted CPU string (e.g., "4.2%" or "N/A")
    pub fn formatted_cpu(&self) -> String {
        match self.cpu_usage {
            Some(cpu) => format!("{:.1}%", cpu),
            None => "N/A".to_string(),
        }
    }

    /// Formatted runtime string (e.g. "1h 23m 45s")
    pub fn formatted_runtime(&self) -> String {
        let secs = self.run_time_secs;
        let hours = secs / 3600;
        let mins = (secs % 3600) / 60;
        let s = secs % 60;
        if hours > 0 {
            format!("{}h {}m {}s", hours, mins, s)
        } else if mins > 0 {
            format!("{}m {}s", mins, s)
        } else {
            format!("{}s", s)
        }
    }
}

/// Detailed deep inspection data for a process.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessDetail {
    pub info: ProcessInfo,
    pub cmdline: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub environment: Vec<(String, String)>,
    pub open_files: Vec<PathBuf>,
    pub parent_chain: Vec<ProcessAncestor>,
}

/// Ancestor element in process lineage tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessAncestor {
    pub pid: u32,
    pub name: String,
    pub cmdline_summary: Option<String>,
}
