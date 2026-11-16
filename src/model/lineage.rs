use super::process::ProcessIncarnation;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

/// Origin and verification quality of a recorded parent-child process lineage edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LineageSource {
    /// Both parent and child process incarnations were present and verified in the same complete process snapshot.
    CompleteSnapshotObservation,
    /// Explicit launch event observed and recorded by the session supervisor.
    SupervisorSpawn,
}

impl fmt::Display for LineageSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CompleteSnapshotObservation => write!(f, "COMPLETE_SNAPSHOT_OBSERVATION"),
            Self::SupervisorSpawn => write!(f, "SUPERVISOR_SPAWN"),
        }
    }
}

impl std::str::FromStr for LineageSource {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "COMPLETE_SNAPSHOT_OBSERVATION" => Ok(Self::CompleteSnapshotObservation),
            "SUPERVISOR_SPAWN" => Ok(Self::SupervisorSpawn),
            _ => Ok(Self::CompleteSnapshotObservation),
        }
    }
}

/// Lifecycle and observation status of a recorded parent-child lineage relationship.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LineageStatus {
    /// Both parent and child incarnations were observed active in the most recent complete observation.
    BothActive,
    /// The parent incarnation has exited, but the historical parent-child relationship is preserved.
    ParentExited,
    /// The child was observed alive under PPID 1 following the parent's exit (operating system reparenting).
    ReparentedToPid1,
    /// Both parent and child process incarnations have positively exited.
    BothExited,
}

impl fmt::Display for LineageStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BothActive => write!(f, "BOTH_ACTIVE"),
            Self::ParentExited => write!(f, "PARENT_EXITED"),
            Self::ReparentedToPid1 => write!(f, "REPARENTED_TO_PID1"),
            Self::BothExited => write!(f, "BOTH_EXITED"),
        }
    }
}

impl std::str::FromStr for LineageStatus {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "BOTH_ACTIVE" => Ok(Self::BothActive),
            "PARENT_EXITED" => Ok(Self::ParentExited),
            "REPARENTED_TO_PID1" => Ok(Self::ReparentedToPid1),
            "BOTH_EXITED" => Ok(Self::BothExited),
            _ => Ok(Self::BothActive),
        }
    }
}

/// A persistent, verified parent-child relationship between two exact process incarnations.
///
/// Anchored strictly to `ProcessIncarnation = (PID, exact ProcessStartTime)`.
/// Historical edges are retained even after intermediate or parent processes exit and
/// surviving children are reparented to PID 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessLineageEdge {
    /// Internal SQLite primary key (if persisted).
    pub id: Option<i64>,
    /// Session identifier that observed and owns this relationship.
    pub session_id: String,
    /// Exact parent process incarnation identity.
    pub parent: ProcessIncarnation,
    /// Exact child process incarnation identity.
    pub child: ProcessIncarnation,
    /// Parent process name captured at observation time.
    pub parent_name: Option<String>,
    /// Parent process executable path captured at observation time.
    pub parent_exe: Option<PathBuf>,
    /// Child process name captured at observation time.
    pub child_name: String,
    /// Child process executable path captured at observation time.
    pub child_exe: Option<PathBuf>,
    /// Timestamp when this exact relationship was first observed.
    pub first_observed_at: DateTime<Utc>,
    /// Timestamp when this exact relationship was most recently verified.
    pub last_observed_at: DateTime<Utc>,
    /// Monotonically incrementing count of snapshot observations confirming this edge.
    pub observation_count: u64,
    /// Optional reference to `session_snapshots(id)`.
    pub snapshot_id: Option<i64>,
    /// Evidence source for this relationship.
    pub source: LineageSource,
    /// Current lifecycle status of this relationship.
    pub status: LineageStatus,
    /// Factual, structured validation notes.
    pub validation_details: Option<String>,
}

impl ProcessLineageEdge {
    /// Creates a new verified lineage edge from two validated process incarnations.
    #[allow(clippy::too_many_arguments)]
    pub fn new_snapshot_edge(
        session_id: String,
        parent: ProcessIncarnation,
        child: ProcessIncarnation,
        parent_name: Option<String>,
        parent_exe: Option<PathBuf>,
        child_name: String,
        child_exe: Option<PathBuf>,
        observed_at: DateTime<Utc>,
        snapshot_id: Option<i64>,
    ) -> Self {
        Self {
            id: None,
            session_id,
            parent,
            child,
            parent_name,
            parent_exe,
            child_name,
            child_exe,
            first_observed_at: observed_at,
            last_observed_at: observed_at,
            observation_count: 1,
            snapshot_id,
            source: LineageSource::CompleteSnapshotObservation,
            status: LineageStatus::BothActive,
            validation_details: Some(format!(
                "Observed child PID {} (started {}) under parent PID {} (started {})",
                child.pid, child.start_time, parent.pid, parent.start_time
            )),
        }
    }

    /// Checks if this edge matches the given child incarnation.
    pub fn matches_child(&self, inc: &ProcessIncarnation) -> bool {
        self.child == *inc
    }

    /// Checks if this edge matches the given parent incarnation.
    pub fn matches_parent(&self, inc: &ProcessIncarnation) -> bool {
        self.parent == *inc
    }
}

/// Evaluation of an ancestry chain reconstructed from persistent lineage records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineageChainResult {
    /// Complete, unbroken chain from session root to target process, with all intermediate
    /// processes verified and actively running. (Qualifies for `Confidence::Confirmed`).
    UnbrokenAllActive {
        root: ProcessIncarnation,
        chain: Vec<ProcessLineageEdge>,
    },
    /// Complete, unbroken chain from session root to target process, where one or more intermediate
    /// processes have exited, but their recorded historical incarnations and edges are verified.
    /// (Qualifies for `Confidence::HighConfidence`).
    UnbrokenHistoricalWithExits {
        root: ProcessIncarnation,
        chain: Vec<ProcessLineageEdge>,
        exited_ancestors: Vec<ProcessIncarnation>,
    },
    /// A process first seen under PID 1 with no recorded parent edge, or lacking sufficient
    /// verifiable evidence to link to session root. (Qualifies for `Confidence::Inferred`).
    NoRecordedParentEdge { target: ProcessIncarnation },
    /// Broken chain: an intermediate parent has no recorded parent edge leading back to session root.
    BrokenChain {
        target: ProcessIncarnation,
        missing_parent_for: ProcessIncarnation,
    },
    /// Conflicting parent records or conflicting session claims. (Produces `Confidence::Unknown`).
    ConflictingEvidence { details: String },
    /// Process incarnation could not be verified (missing start time, PID reuse).
    IdentityMismatch { details: String },
}
