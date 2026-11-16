use crate::model::Confidence;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// State of a container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContainerState {
    Running,
    Paused,
    Restarting,
    Exited,
    Dead,
    Created,
    Unknown(String),
}

impl fmt::Display for ContainerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContainerState::Running => write!(f, "RUNNING"),
            ContainerState::Paused => write!(f, "PAUSED"),
            ContainerState::Restarting => write!(f, "RESTARTING"),
            ContainerState::Exited => write!(f, "EXITED"),
            ContainerState::Dead => write!(f, "DEAD"),
            ContainerState::Created => write!(f, "CREATED"),
            ContainerState::Unknown(s) => write!(f, "{}", s),
        }
    }
}

impl std::str::FromStr for ContainerState {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "running" => Ok(ContainerState::Running),
            "paused" => Ok(ContainerState::Paused),
            "restarting" => Ok(ContainerState::Restarting),
            "exited" => Ok(ContainerState::Exited),
            "dead" => Ok(ContainerState::Dead),
            "created" => Ok(ContainerState::Created),
            other => Ok(ContainerState::Unknown(other.to_uppercase())),
        }
    }
}

/// Port mapping between container and host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortBinding {
    pub host_ip: String,
    pub host_port: u16,
    pub container_port: u16,
    pub protocol: String,
}

impl fmt::Display for PortBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}->{}/{}",
            self.host_ip, self.host_port, self.container_port, self.protocol
        )
    }
}

/// Real-time resource consumption statistics for a Docker container.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ContainerStats {
    /// Calculated CPU usage percentage (e.g. 1.25%).
    /// `None` indicates metric is currently unavailable or uncalculated.
    pub cpu_percentage: Option<f32>,
    /// Resident / raw memory consumption in bytes reported by daemon.
    pub memory_usage_bytes: Option<u64>,
    /// Adjusted working-set memory consumption in bytes (excluding inactive page cache).
    /// On cgroups v2: `usage - inactive_file`.
    /// On cgroups v1: `usage - cache` (or `usage - total_inactive_file`).
    pub memory_working_set_bytes: Option<u64>,
    /// Configured container memory limit in bytes.
    pub memory_limit_bytes: Option<u64>,
    /// Calculated memory usage percentage of limit.
    pub memory_percentage: Option<f32>,
    /// Total network received bytes across all container interfaces.
    pub network_rx_bytes: Option<u64>,
    /// Total network transmitted bytes across all container interfaces.
    pub network_tx_bytes: Option<u64>,
    /// Block I/O read bytes.
    pub block_read_bytes: Option<u64>,
    /// Block I/O written bytes.
    pub block_write_bytes: Option<u64>,
    /// Number of running processes inside the container.
    pub pids_count: Option<u32>,
}

/// High-level information about a Docker container.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContainerInfo {
    /// Full 64-character hexadecimal container ID.
    pub id: String,
    /// Short 12-character container ID for compact displays.
    pub short_id: String,
    /// Friendly container name (leading '/' stripped).
    pub name: String,
    /// Image repository and tag (e.g. "postgres:16-alpine").
    pub image: String,
    /// Hexadecimal image ID if available.
    pub image_id: Option<String>,
    /// Current lifecycle state.
    pub state: ContainerState,
    /// Human-readable status string (e.g. "Up 2 hours", "Exited (0) 5 minutes ago").
    pub status: String,
    /// Published port mappings.
    pub ports: Vec<PortBinding>,
    /// Container creation timestamp (ISO 8601 string).
    pub created_at: Option<String>,
    /// Container start timestamp if started (ISO 8601 string).
    pub started_at: Option<String>,
    /// Process exit code if container has terminated.
    pub exit_code: Option<i64>,
    /// Health status if healthcheck configured (e.g. "healthy", "unhealthy", "starting").
    pub health_status: Option<String>,
    /// Number of times the container has restarted.
    pub restart_count: Option<u64>,
    /// Initial execution command (secret masked).
    pub command: Option<String>,
    /// Container entrypoint (secret masked).
    pub entrypoint: Option<String>,
    /// Configured working directory.
    pub working_dir: Option<String>,
    /// Container labels (sensitive values masked).
    pub labels: HashMap<String, String>,
    /// Container runtime (e.g. "runc").
    pub runtime: Option<String>,
    /// Attached network names.
    pub networks: Vec<String>,
    /// Assigned IP addresses on container networks.
    pub ip_addresses: Vec<String>,
    /// Network mode (e.g. "bridge", "host", "none").
    pub network_mode: Option<String>,
    /// Latest resource usage metrics.
    pub stats: Option<ContainerStats>,
    /// Associated AI agent session identifier if correlated.
    pub session_id: Option<String>,
    /// Declared session identifier from container metadata/labels (unverified ownership).
    #[serde(default)]
    pub declared_session_id: Option<String>,
    /// Sessions with conflicting claims over this container.
    #[serde(default)]
    pub conflicting_sessions: Vec<String>,
    /// Confidence tier of AI agent session correlation.
    pub confidence: Confidence,
    /// Evidence trail justifying session correlation.
    pub evidence: Vec<String>,
    /// Observed or verified outcome of container creation by a session command.
    #[serde(default)]
    pub creation_outcome: CreationOutcome,
    /// Explicit evidence basis for session attribution.
    #[serde(default)]
    pub attribution_basis: AttributionBasis,
}

impl ContainerInfo {
    /// Formatted CPU usage string (e.g., "1.5%" or "N/A").
    pub fn formatted_cpu(&self) -> String {
        match self.stats.as_ref().and_then(|s| s.cpu_percentage) {
            Some(cpu) => format!("{:.1}%", cpu),
            None => "N/A".to_string(),
        }
    }

    /// Formatted memory usage string (e.g., "128.4 MB" or "N/A").
    pub fn formatted_memory(&self) -> String {
        match self.stats.as_ref().and_then(|s| s.memory_usage_bytes) {
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

    /// Formatted ports string (e.g., "0.0.0.0:8080->80/tcp" or "-").
    pub fn formatted_ports(&self) -> String {
        if self.ports.is_empty() {
            "-".to_string()
        } else {
            self.ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        }
    }

    /// Formatted session attribution string.
    pub fn formatted_session(&self) -> String {
        match &self.session_id {
            Some(sid) => format!("{} ({})", sid, self.confidence),
            None => "None".to_string(),
        }
    }
}

/// Filesystem mount / volume bound into a container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountInfo {
    pub source: String,
    pub destination: String,
    pub mount_type: String,
    pub read_only: bool,
}

/// Deep inspection details for an individual Docker container.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContainerDetail {
    pub info: ContainerInfo,
    /// Discovered environment variable names (values are suppressed for security).
    pub env_keys: Vec<String>,
    /// Attached storage volumes / binds.
    pub mounts: Vec<MountInfo>,
    /// Restart policy name (e.g. "always", "unless-stopped", "no").
    pub restart_policy: String,
    /// Operating system platform (e.g. "linux/arm64").
    pub platform: Option<String>,
}

/// Category of error encountered during Docker daemon communication or discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DockerErrorCategory {
    None,
    NotInstalled,
    DaemonStopped,
    SocketMissing,
    PermissionDenied,
    InvalidEndpoint,
    UnsupportedRemote,
    ApiIncompatible,
    Other,
}

impl fmt::Display for DockerErrorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "NONE"),
            Self::NotInstalled => write!(f, "NOT_INSTALLED"),
            Self::DaemonStopped => write!(f, "DAEMON_STOPPED"),
            Self::SocketMissing => write!(f, "SOCKET_MISSING"),
            Self::PermissionDenied => write!(f, "PERMISSION_DENIED"),
            Self::InvalidEndpoint => write!(f, "INVALID_ENDPOINT"),
            Self::UnsupportedRemote => write!(f, "UNSUPPORTED_REMOTE"),
            Self::ApiIncompatible => write!(f, "API_INCOMPATIBLE"),
            Self::Other => write!(f, "OTHER"),
        }
    }
}

/// Overall diagnostic and operational status of the local Docker Engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DockerStatus {
    /// Whether Docker binary or desktop application is detected on the system.
    pub installed: bool,
    /// Whether the Docker daemon UNIX socket is reachable and responding.
    pub running: bool,
    /// Active UNIX domain socket path inspected.
    pub socket_path: String,
    /// Docker API version supported by the daemon.
    pub api_version: Option<String>,
    /// Docker Engine version (e.g. "27.3.1").
    pub engine_version: Option<String>,
    /// Operating system reported by daemon.
    pub os: Option<String>,
    /// Hardware architecture reported by daemon.
    pub arch: Option<String>,
    /// Current Docker context name (e.g. "desktop-linux", "default").
    pub active_context: Option<String>,
    /// Error message if Docker is unreachable or connection failed.
    pub error_message: Option<String>,
    /// Granular error classification category.
    #[serde(default)]
    pub error_category: Option<DockerErrorCategory>,
}

impl Default for DockerStatus {
    fn default() -> Self {
        Self {
            installed: true,
            running: true,
            socket_path: "/var/run/docker.sock".to_string(),
            api_version: Some("1.44".to_string()),
            engine_version: Some("25.0.3".to_string()),
            os: Some("linux".to_string()),
            arch: Some("aarch64".to_string()),
            active_context: Some("default".to_string()),
            error_message: None,
            error_category: Some(DockerErrorCategory::None),
        }
    }
}

/// Independent verification status of a Docker CLI container creation operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum CreationOutcome {
    /// Independent evidence establishes that the Docker CLI creation operation succeeded.
    Succeeded,
    /// Independent evidence establishes that the Docker CLI creation operation failed.
    Failed,
    /// TIMMY cannot independently establish whether the creation operation succeeded or failed.
    #[default]
    Unknown,
}

impl fmt::Display for CreationOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Succeeded => write!(f, "SUCCEEDED"),
            Self::Failed => write!(f, "FAILED"),
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Explicit classification of the evidence basis for container-to-session attribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AttributionBasis {
    /// Regular user or system container with no AI agent session attribution.
    #[default]
    None,
    /// Tracked session process attempted container creation (run/create/compose up) with unverified outcome.
    AttemptedCreation,
    /// Independent evidence establishes that the Docker CLI creation operation succeeded.
    VerifiedSuccessfulCreation,
    /// Independent evidence establishes that the Docker CLI creation operation failed.
    VerifiedFailedCreation,
    /// Historical inferred association retained across process termination or container state changes.
    HistoricalInferred,
    /// Declared metadata / labels from container configuration (unverified ownership).
    DeclaredMetadata,
    /// Ambient environmental signals (matching time window, mount/working directory, shared ports).
    InferredSignals,
}

impl fmt::Display for AttributionBasis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "NONE"),
            Self::AttemptedCreation => write!(f, "ATTEMPTED_CREATION"),
            Self::VerifiedSuccessfulCreation => write!(f, "VERIFIED_SUCCESSFUL_CREATION"),
            Self::VerifiedFailedCreation => write!(f, "VERIFIED_FAILED_CREATION"),
            Self::HistoricalInferred => write!(f, "HISTORICAL_INFERRED"),
            Self::DeclaredMetadata => write!(f, "DECLARED_METADATA"),
            Self::InferredSignals => write!(f, "INFERRED_SIGNALS"),
        }
    }
}
