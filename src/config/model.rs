use serde::{Deserialize, Serialize};

/// Master configuration model for TIMMY.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TimmyConfig {
    #[serde(default)]
    pub general: GeneralConfig,
    #[serde(default)]
    pub safety: SafetyConfig,
    #[serde(default)]
    pub ui: UiConfig,
    #[serde(default)]
    pub agents: AgentRuleConfig,
    #[serde(default)]
    pub session: SessionConfig,
}

/// General runtime configurations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    /// Refresh interval for resource metrics in milliseconds.
    pub refresh_interval_ms: u64,
    /// Whether Docker container discovery is enabled.
    pub enable_docker: bool,
    /// Custom Docker daemon socket path (empty string defaults to standard socket).
    pub docker_socket: String,
    /// Docker connection and request timeout in milliseconds.
    #[serde(default = "default_docker_timeout_ms")]
    pub docker_timeout_ms: u64,
}

fn default_docker_timeout_ms() -> u64 {
    2000
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            refresh_interval_ms: 1000,
            enable_docker: true,
            docker_socket: String::new(),
            docker_timeout_ms: default_docker_timeout_ms(),
        }
    }
}

/// Safety and termination thresholds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyConfig {
    /// Grace period in seconds to wait after SIGTERM before offering force kill.
    pub graceful_timeout_secs: u64,
    /// Ports that should never be flagged as orphan or terminated.
    pub protected_ports: Vec<u16>,
    /// Additional custom process names that should be protected.
    pub custom_protected_processes: Vec<String>,
}

impl Default for SafetyConfig {
    fn default() -> Self {
        Self {
            graceful_timeout_secs: 3,
            protected_ports: vec![22, 53, 80, 443], // SSH, DNS, HTTP, HTTPS
            custom_protected_processes: Vec::new(),
        }
    }
}

/// Terminal user interface settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiConfig {
    /// Color theme: "default", "monochrome", "nord", "catppuccin"
    pub theme: String,
    /// Show full command-line arguments in table preview
    pub show_cmdline_in_table: bool,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            theme: "default".to_string(),
            show_cmdline_in_table: false,
        }
    }
}

/// User-definable agent attribution rules.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentRuleConfig {
    /// List of custom agent signature rules.
    pub custom_rules: Vec<CustomAgentRule>,
}

/// Individual custom agent detection rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomAgentRule {
    pub name: String,
    pub binary_patterns: Vec<String>,
    pub cmdline_patterns: Vec<String>,
    pub env_var_markers: Vec<String>,
}

/// AI agent coding session tracking settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Monitoring interval in seconds while session tracking is active.
    pub monitor_interval_secs: u64,
    /// Maximum snapshots to retain per session in SQLite.
    pub max_snapshots_per_session: usize,
    /// Days to retain historical session records.
    pub retention_days: u32,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            monitor_interval_secs: 5,
            max_snapshots_per_session: 500,
            retention_days: 14,
        }
    }
}
