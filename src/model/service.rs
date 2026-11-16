use crate::model::agent::Confidence;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

/// Operating system background service category.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ServiceKind {
    LaunchAgentUser,
    LaunchDaemonSystem,
    LaunchDaemonApple,
    UserSystemd,
    WindowsService,
    Other(String),
}

impl fmt::Display for ServiceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceKind::LaunchAgentUser => write!(f, "LaunchAgent (User)"),
            ServiceKind::LaunchDaemonSystem => write!(f, "LaunchDaemon (System)"),
            ServiceKind::LaunchDaemonApple => write!(f, "LaunchDaemon (Apple)"),
            ServiceKind::UserSystemd => write!(f, "systemd (User)"),
            ServiceKind::WindowsService => write!(f, "Windows Service"),
            ServiceKind::Other(k) => write!(f, "{}", k),
        }
    }
}

/// macOS launchd domain context.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LaunchdDomain {
    /// User launch agents: ~/Library/LaunchAgents or user GUI domain
    User,
    /// System-wide third-party launch daemons: /Library/LaunchDaemons
    SystemThirdParty,
    /// System-managed Apple launch daemons: /System/Library/LaunchDaemons
    SystemApple,
    /// Unknown or custom domain
    Unknown(String),
}

impl fmt::Display for LaunchdDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LaunchdDomain::User => write!(f, "User Agent"),
            LaunchdDomain::SystemThirdParty => write!(f, "System (3rd-party)"),
            LaunchdDomain::SystemApple => write!(f, "System (Apple)"),
            LaunchdDomain::Unknown(s) => write!(f, "{}", s),
        }
    }
}

/// Independent on-disk plist file discovery and syntactic validity state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlistStatus {
    /// No plist file was discovered on disk
    NotDiscovered,
    /// Plist file exists on disk and parsed successfully
    Valid { path: PathBuf },
    /// Plist file exists on disk but could not be read (I/O, permission, missing)
    Unreadable { path: PathBuf, error: String },
    /// Plist file exists on disk but its syntax/format is malformed
    Malformed { path: PathBuf, error: String },
}

impl PlistStatus {
    pub fn is_error(&self) -> bool {
        matches!(
            self,
            PlistStatus::Unreadable { .. } | PlistStatus::Malformed { .. }
        )
    }

    pub fn error_message(&self) -> Option<&str> {
        match self {
            PlistStatus::Unreadable { error, .. } => Some(error),
            PlistStatus::Malformed { error, .. } => Some(error),
            _ => None,
        }
    }

    pub fn path(&self) -> Option<&PathBuf> {
        match self {
            PlistStatus::Valid { path }
            | PlistStatus::Unreadable { path, .. }
            | PlistStatus::Malformed { path, .. } => Some(path),
            PlistStatus::NotDiscovered => None,
        }
    }
}

/// Independent launchd runtime registration, execution, and process status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuntimeStatus {
    /// Service is not registered or loaded in launchd runtime
    NotLoaded,
    /// Service is loaded in launchd runtime, but process is not actively running
    Loaded,
    /// Service is loaded and actively executing with a verified PID
    Running { pid: u32 },
    /// Service is registered, but its last execution finished with a non-zero exit code
    Failed { exit_code: i32 },
    /// launchctl command execution or runtime inspection failed (timeout, permission, error)
    InspectionFailed(String),
    /// Runtime state could not be determined
    Unknown,
}

impl RuntimeStatus {
    pub fn is_running(&self) -> bool {
        matches!(self, RuntimeStatus::Running { .. })
    }
}

/// Detailed lifecycle and observational state of a service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceState {
    /// Discovered as a plist file on disk, but not loaded into launchd
    DiscoveredOnDisk,
    /// Loaded in launchd runtime, but no running process active
    Loaded,
    /// Loaded and currently executing with an active PID
    Running,
    /// Loaded previously or configured, but process has stopped / not running
    NotRunning,
    /// State cannot be reliably determined
    Unknown,
    /// Error inspecting or parsing service metadata
    Error(String),
}

impl fmt::Display for ServiceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceState::DiscoveredOnDisk => write!(f, "ON DISK"),
            ServiceState::Loaded => write!(f, "LOADED"),
            ServiceState::Running => write!(f, "RUNNING"),
            ServiceState::NotRunning => write!(f, "NOT RUNNING"),
            ServiceState::Unknown => write!(f, "UNKNOWN"),
            ServiceState::Error(err) => write!(f, "ERROR: {}", err),
        }
    }
}

/// Legacy/summary status of a background service for backwards compatibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceStatus {
    Running,
    Stopped,
    Loaded,
    Failed(String),
    Unknown,
}

impl fmt::Display for ServiceStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceStatus::Running => write!(f, "RUNNING"),
            ServiceStatus::Stopped => write!(f, "STOPPED"),
            ServiceStatus::Loaded => write!(f, "LOADED"),
            ServiceStatus::Failed(err) => write!(f, "FAILED: {}", err),
            ServiceStatus::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

impl From<&ServiceState> for ServiceStatus {
    fn from(state: &ServiceState) -> Self {
        match state {
            ServiceState::Running => ServiceStatus::Running,
            ServiceState::Loaded => ServiceStatus::Loaded,
            ServiceState::NotRunning => ServiceStatus::Stopped,
            ServiceState::DiscoveredOnDisk => ServiceStatus::Stopped,
            ServiceState::Error(e) => ServiceStatus::Failed(e.clone()),
            ServiceState::Unknown => ServiceStatus::Unknown,
        }
    }
}

impl From<ServiceState> for ServiceStatus {
    fn from(state: ServiceState) -> Self {
        ServiceStatus::from(&state)
    }
}

/// KeepAlive configuration parsed from launchd plist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeepAliveDetail {
    Simple(bool),
    Conditional(String),
}

impl fmt::Display for KeepAliveDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeepAliveDetail::Simple(b) => write!(f, "{}", b),
            KeepAliveDetail::Conditional(c) => write!(f, "Conditional ({})", c),
        }
    }
}

/// Information parsed directly from a launchd plist file on disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchdPlistDetail {
    /// File system path to the plist file
    pub source_path: PathBuf,
    /// Service label defined in plist (e.g. "com.example.service")
    pub label: Option<String>,
    /// Path to program executable
    pub program: Option<String>,
    /// Program invocation arguments (with secrets masked)
    pub program_arguments: Vec<String>,
    /// Effective executable path (Program or argv[0])
    pub executable_path: Option<String>,
    /// Working directory configured for the service
    pub working_directory: Option<String>,
    /// Whether service should be launched at load time
    pub run_at_load: Option<bool>,
    /// Keep-alive policy (boolean or conditional requirements)
    pub keep_alive: Option<KeepAliveDetail>,
    /// Periodic repeat interval in seconds
    pub start_interval: Option<u64>,
    /// Calendar repeat interval specification
    pub start_calendar_interval: Option<String>,
    /// Named sockets listening for incoming IPC/network requests
    pub sockets: Vec<String>,
    /// Registered Mach services
    pub mach_services: Vec<String>,
    /// File path where standard output is redirected
    pub standard_out_path: Option<String>,
    /// File path where standard error is redirected
    pub standard_error_path: Option<String>,
    /// Environment variable names configured in plist (NAMES ONLY, values are never stored)
    pub environment_variable_names: Vec<String>,
    /// User name to execute service as
    pub user_name: Option<String>,
    /// Group name to execute service as
    pub group_name: Option<String>,
    /// Non-fatal parsing error or warning message
    pub parse_error: Option<String>,
}

/// Live launchd runtime execution state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchdRuntimeInfo {
    /// Whether launchd currently has this job registered/loaded
    pub is_loaded: bool,
    /// Active process identifier, if currently running
    pub pid: Option<u32>,
    /// Exit status code from the most recent run (e.g. 0, non-zero exit, or signal)
    pub last_exit_status: Option<i32>,
    /// launchd domain context
    pub domain: Option<LaunchdDomain>,
    /// Process execution state string (e.g. "running", "waiting", "exited")
    pub process_state: Option<String>,
    /// Timestamp when runtime state was observed
    pub last_observed: chrono::DateTime<chrono::Utc>,
}

/// Discovered background service or daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceInfo {
    /// Human-friendly display name (derived from label or file name)
    pub name: String,
    /// Service category / kind
    pub kind: ServiceKind,
    /// High-level status (backwards compatible)
    pub status: ServiceStatus,
    /// Fine-grained observational lifecycle state
    pub state: ServiceState,
    /// Independent on-disk plist discovery status (never overwritten by runtime state)
    pub plist_status: PlistStatus,
    /// Independent launchd runtime status (never overwritten by on-disk file errors)
    pub runtime_status: RuntimeStatus,
    /// Running PID if active
    pub pid: Option<u32>,
    /// Canonical service label (e.g. "com.anthropic.claudecode")
    pub label: String,
    /// File system path to the plist or service definition
    pub path: Option<String>,
    /// launchd domain context
    pub domain: Option<LaunchdDomain>,
    /// Last exit status code reported by launchd
    pub last_exit_status: Option<i32>,
    /// Live launchd runtime state details
    pub runtime: Option<LaunchdRuntimeInfo>,
    /// Parsed plist file details from disk
    pub plist: Option<LaunchdPlistDetail>,

    // AI agent correlation & attribution
    /// Associated AI agent session identifier, if correlated
    pub session_id: Option<String>,
    /// Attribution confidence grade
    pub confidence: Confidence,
    /// Evidence trail justifying attribution and process correlation
    pub evidence: Vec<String>,
    /// Whether this service discovery was based on partial or truncated inspection data
    pub is_partial: bool,
}

impl ServiceInfo {
    /// Formatted status summary for display in tables and headers.
    pub fn formatted_state(&self) -> String {
        let base = match &self.runtime_status {
            RuntimeStatus::Running { pid } => {
                if self.plist_status.is_error() {
                    format!("RUNNING ({}) [Plist Error]", pid)
                } else {
                    format!("RUNNING ({})", pid)
                }
            }
            RuntimeStatus::Loaded => {
                if let Some(code) = self.last_exit_status {
                    format!("LOADED (Exit: {})", code)
                } else {
                    "LOADED".to_string()
                }
            }
            RuntimeStatus::Failed { exit_code } => format!("STOPPED (Exit: {})", exit_code),
            RuntimeStatus::InspectionFailed(_) => {
                if self.plist_status.is_error() {
                    "PLIST ERROR [Inspect Failed]".to_string()
                } else if matches!(self.plist_status, PlistStatus::Valid { .. }) {
                    "ON DISK [Inspect Failed]".to_string()
                } else {
                    "INSPECTION FAILED".to_string()
                }
            }
            RuntimeStatus::NotLoaded => match &self.plist_status {
                PlistStatus::Malformed { .. } => "MALFORMED PLIST".to_string(),
                PlistStatus::Unreadable { .. } => "UNREADABLE PLIST".to_string(),
                PlistStatus::Valid { .. } => "ON DISK".to_string(),
                PlistStatus::NotDiscovered => "NOT LOADED".to_string(),
            },
            RuntimeStatus::Unknown => match &self.state {
                ServiceState::Error(_) => "ERROR".to_string(),
                _ => "UNKNOWN".to_string(),
            },
        };

        if self.is_partial {
            format!("{} [Partial]", base)
        } else {
            base
        }
    }

    /// Best available executable or program path.
    pub fn executable_or_program(&self) -> Option<&str> {
        if let Some(ref p) = self.plist {
            if let Some(ref exe) = p.executable_path {
                return Some(exe.as_str());
            }
            if let Some(ref prog) = p.program {
                return Some(prog.as_str());
            }
            if let Some(first_arg) = p.program_arguments.first() {
                return Some(first_arg.as_str());
            }
        }
        self.path.as_deref()
    }

    /// Formatted domain string.
    pub fn formatted_domain(&self) -> String {
        if let Some(ref d) = self.domain {
            d.to_string()
        } else {
            self.kind.to_string()
        }
    }

    /// Formatted session attribution string.
    pub fn formatted_session(&self) -> String {
        self.session_id.clone().unwrap_or_else(|| "-".to_string())
    }
}
