use crate::model::agent::{AgentKind, Confidence};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Lifecycle status of an AI agent coding session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SessionStatus {
    /// Active session currently being tracked.
    Active,
    /// Manually or automatically stopped tracking session.
    Stopped,
    /// Session concluded and all resources released.
    Completed,
}

impl fmt::Display for SessionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionStatus::Active => write!(f, "ACTIVE"),
            SessionStatus::Stopped => write!(f, "STOPPED"),
            SessionStatus::Completed => write!(f, "COMPLETED"),
        }
    }
}

impl std::str::FromStr for SessionStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "ACTIVE" => Ok(SessionStatus::Active),
            "STOPPED" => Ok(SessionStatus::Stopped),
            "COMPLETED" => Ok(SessionStatus::Completed),
            other => Err(format!("Unknown session status: {}", other)),
        }
    }
}

/// Metadata and high-level tracking summary of an AI coding session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionInfo {
    /// Unique identifier for the session (e.g. "sess-20261111-134500-a8f3")
    pub id: String,
    /// Known or detected AI agent kind
    pub agent_kind: AgentKind,
    /// Current tracking status
    pub status: SessionStatus,
    /// Start timestamp
    pub start_time: DateTime<Utc>,
    /// End timestamp (if stopped or completed)
    pub end_time: Option<DateTime<Utc>>,
    /// Root agent process PID if identified
    pub root_pid: Option<u32>,
    /// Root agent process name if identified
    pub root_process_name: Option<String>,
    /// Overall attribution confidence for this session
    pub confidence: Confidence,
    /// Evidence supporting agent identity and session ownership
    pub evidence: Vec<String>,
    /// List of tracked process IDs currently associated with the session
    pub tracked_pids: Vec<u32>,
    /// Total aggregate memory consumption across all tracked processes
    pub total_memory_bytes: u64,
    /// Total aggregate CPU percentage across all tracked processes
    pub total_cpu_usage: f32,
    /// Distinct listening ports held by session processes
    pub open_ports: Vec<u16>,
    /// Total count of tracked resources (active + detached)
    pub resource_count: usize,
    /// Structured launch provenance binding the session to a verified root agent process.
    #[serde(default)]
    pub root_binding: Option<crate::model::provenance::LaunchProvenance>,
}

impl SessionInfo {
    /// Formatted memory string (e.g., "152.4 MB")
    pub fn formatted_memory(&self) -> String {
        let bytes = self.total_memory_bytes;
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

    /// Formatted CPU string (e.g., "2.5%")
    pub fn formatted_cpu(&self) -> String {
        format!("{:.1}%", self.total_cpu_usage)
    }

    /// Elapsed duration formatted as "Xh Ym Zs"
    pub fn duration_str(&self) -> String {
        let end = self.end_time.unwrap_or_else(Utc::now);
        let duration = end.signed_duration_since(self.start_time);
        let total_secs = duration.num_seconds().max(0);
        let hours = total_secs / 3600;
        let mins = (total_secs % 3600) / 60;
        let secs = total_secs % 60;
        if hours > 0 {
            format!("{}h {}m {}s", hours, mins, secs)
        } else if mins > 0 {
            format!("{}m {}s", mins, secs)
        } else {
            format!("{}s", secs)
        }
    }

    /// Comma-separated list of listening ports
    pub fn ports_str(&self) -> String {
        if self.open_ports.is_empty() {
            "-".to_string()
        } else {
            self.open_ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        }
    }
}

/// An individual system resource tracked as part of a session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrackedResource {
    pub session_id: String,
    pub pid: Option<u32>,
    pub name: String,
    pub exe_path: Option<String>,
    pub memory_bytes: Option<u64>,
    pub cpu_usage: Option<f32>,
    pub listening_ports: Vec<u16>,
    pub confidence: Confidence,
    pub evidence: Vec<String>,
    pub is_detached: bool,
    pub is_protected: bool,
    pub safe_to_terminate: bool,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub process_start_time: Option<u64>,
    /// Structured provenance classifying observation origin and exact process identity.
    #[serde(default)]
    pub provenance: Option<crate::model::provenance::LaunchProvenance>,
}

impl TrackedResource {
    pub fn formatted_memory(&self) -> String {
        match self.memory_bytes {
            Some(0) => "N/A (Restricted)".to_string(),
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

    pub fn formatted_cpu(&self) -> String {
        match self.cpu_usage {
            Some(cpu) => format!("{:.1}%", cpu),
            None => "N/A".to_string(),
        }
    }

    pub fn ports_str(&self) -> String {
        if self.listening_ports.is_empty() {
            "-".to_string()
        } else {
            self.listening_ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        }
    }
}

/// A structured recommendation item for future session cleanup workflows.
///
/// Strictly separates three distinct concepts:
/// 1. **Attribution (Ownership)**: Does this resource belong to the AI coding session?
/// 2. **Termination Eligibility**: Does this resource pass all system safety checks to be safely stopped?
/// 3. **User Authorization**: Has the human user explicitly authorized stopping this resource?
///    (Always `false` in this milestone; authorization is NEVER inferred).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CleanupRecommendation {
    pub resource_name: String,
    pub pid_or_id: String,
    pub memory_formatted: String,
    pub associated_ports: Vec<u16>,
    /// Attribution confidence: how confidently this process belongs to the session
    pub ownership_confidence: Confidence,
    /// Attribution evidence: reasons for session membership
    pub ownership_evidence: String,
    /// Whether the process is shielded by system/user protection rules
    pub is_protected: bool,
    /// Whether the process passes all safety checks and is eligible for termination
    pub termination_eligible: bool,
    /// Detailed diagnostic reason explaining why the process is or is not eligible
    pub eligibility_reason: String,
    /// Explicit human authorization for termination (NEVER inferred from attribution or eligibility)
    pub user_authorized: bool,
    /// Whether the process survived parent exit and is detached/orphaned
    pub is_detached: bool,

    // Deprecated fields retained for backward-compatibility
    pub confidence: Confidence,
    pub safe_to_terminate: bool,
    pub evidence: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_status_display_and_parse() {
        assert_eq!(SessionStatus::Active.to_string(), "ACTIVE");
        assert_eq!(SessionStatus::Stopped.to_string(), "STOPPED");
        assert_eq!(SessionStatus::Completed.to_string(), "COMPLETED");

        assert_eq!(
            "active".parse::<SessionStatus>().unwrap(),
            SessionStatus::Active
        );
        assert_eq!(
            "STOPPED".parse::<SessionStatus>().unwrap(),
            SessionStatus::Stopped
        );
    }

    #[test]
    fn test_session_duration_format() {
        let start = Utc::now() - chrono::Duration::seconds(125);
        let end = start + chrono::Duration::seconds(125);
        let session = SessionInfo {
            id: "sess-test".to_string(),
            agent_kind: AgentKind::ClaudeCode,
            status: SessionStatus::Stopped,
            start_time: start,
            end_time: Some(end),
            root_pid: Some(1234),
            root_process_name: Some("claude".to_string()),
            confidence: Confidence::Confirmed,
            evidence: vec!["Explicit test".to_string()],
            tracked_pids: vec![1234],
            total_memory_bytes: 1024 * 1024 * 40,
            total_cpu_usage: 1.5,
            open_ports: vec![3000],
            resource_count: 1,
            root_binding: None,
        };

        assert_eq!(session.duration_str(), "2m 5s");
        assert_eq!(session.formatted_memory(), "40.0 MB");
        assert_eq!(session.ports_str(), "3000");
    }
}
