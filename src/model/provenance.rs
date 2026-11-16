use super::process::{ProcessIncarnation, ProcessStartTime};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Recorded change of an executable path observed across snapshot polls on a stable process incarnation.
///
/// NOTE: Polling observes that the process's executable path changed between observation snapshots;
/// it does NOT capture or prove an exact kernel `execve` event or sequence.
/// The original process incarnation identity (PID and kernel start time) is strictly preserved.
/// An observed executable path change does NOT elevate or promote attribution confidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedExecutablePathChange {
    pub incarnation: ProcessIncarnation,
    pub previous_exe: Option<PathBuf>,
    pub observed_exe: PathBuf,
    pub observed_at: DateTime<Utc>,
}

/// Normalizes a filesystem path lexically by resolving '.' and '..' components,
/// ensuring deterministic comparison across relative and absolute path representations.
pub fn normalize_path(p: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in p.components() {
        match component {
            std::path::Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            std::path::Component::RootDir => normalized.push(std::path::MAIN_SEPARATOR.to_string()),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            std::path::Component::Normal(c) => normalized.push(c),
        }
    }
    normalized
}

/// Origin and verification tier of a process launch or association event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProvenanceSource {
    /// Authentic session root agent process bound at session start with verified identity.
    /// (NOTE: This records a verified process selection, NOT an observed launch event).
    #[serde(alias = "RootBinding")]
    VerifiedSessionRootBinding,
    /// Explicit kernel or process-supervisor event observing process spawn (e.g. fork/clone).
    ObservedSpawn,
    /// Explicit kernel or process-supervisor event observing binary execution (execve).
    ObservedExec,
    /// Process discovered through process-tree ancestry traversal during a periodic snapshot.
    /// (NOTE: This is NOT an observed launch event; it is a snapshot-based tree discovery).
    DiscoveredDescendant,
    /// Process associated heuristically (e.g. orphan dev server on a listening port).
    HeuristicAssociation,
    /// Unknown or unverified provenance.
    Unknown,
}

impl std::fmt::Display for ProvenanceSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProvenanceSource::VerifiedSessionRootBinding => {
                write!(f, "VERIFIED_SESSION_ROOT_BINDING")
            }
            ProvenanceSource::ObservedSpawn => write!(f, "OBSERVED_SPAWN"),
            ProvenanceSource::ObservedExec => write!(f, "OBSERVED_EXEC"),
            ProvenanceSource::DiscoveredDescendant => write!(f, "DISCOVERED_DESCENDANT"),
            ProvenanceSource::HeuristicAssociation => write!(f, "HEURISTIC_ASSOCIATION"),
            ProvenanceSource::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Result of verifying a candidate live process against recorded provenance identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityMatchResult {
    /// Exact match: PID, non-null start times, process name, and executable path all match.
    ExactMatch,
    /// PID matches and executable/name match, but process start time is missing from either record.
    /// PID recycling cannot be disproven; Confirmed confidence is forbidden.
    MissingStartTime,
    /// PID matches, but start times differ. The PID was recycled by another process.
    StartTimeMismatch,
    /// PID matches, but process executable or name differs.
    BinaryMismatch,
    /// PID does not match.
    PidMismatch,
}

impl IdentityMatchResult {
    /// Returns true if this is a verified exact match with non-null start times.
    pub fn is_exact(&self) -> bool {
        matches!(self, IdentityMatchResult::ExactMatch)
    }

    /// Returns true if the PID was recycled or taken by a different binary.
    pub fn is_recycled_or_mismatch(&self) -> bool {
        matches!(
            self,
            IdentityMatchResult::StartTimeMismatch | IdentityMatchResult::BinaryMismatch
        )
    }
}

/// Exact process identity captured at the moment of observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_time: Option<u64>,
    #[serde(default)]
    pub start_time_precise: Option<ProcessStartTime>,
    pub name: String,
    pub exe: Option<PathBuf>,
}

impl ProcessIdentity {
    pub fn incarnation(&self) -> Option<ProcessIncarnation> {
        if let Some(precise) = self.start_time_precise {
            Some(ProcessIncarnation::new(self.pid, precise))
        } else {
            self.start_time
                .map(|s| ProcessIncarnation::new(self.pid, ProcessStartTime::new(s, 0)))
        }
    }
}

/// Parent process identity observed at the moment of observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ParentIdentity {
    pub ppid: u32,
    pub start_time: Option<u64>,
    #[serde(default)]
    pub start_time_precise: Option<ProcessStartTime>,
    pub name: Option<String>,
}

/// Structured evidence binding a process to an AI agent session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchProvenance {
    /// The session identifier claiming this process.
    pub session_id: String,
    /// The observation source and reliability classification.
    pub source: ProvenanceSource,
    /// Exact process identity.
    pub process: ProcessIdentity,
    /// Parent process identity at the time of observation, if available.
    pub parent: Option<ParentIdentity>,
    /// Wall-clock timestamp when this observation occurred.
    pub observed_at: DateTime<Utc>,
    /// Factual, structured note explaining the observation mechanism.
    pub details: String,
}

impl LaunchProvenance {
    /// Creates a verified session root binding record.
    ///
    /// NOTE: This records a verified process selection at session start,
    /// NOT an observed process launch event.
    pub fn verified_session_root_binding(
        session_id: String,
        pid: u32,
        start_time: Option<u64>,
        name: String,
        exe: Option<PathBuf>,
        ppid: Option<u32>,
        details: String,
    ) -> Self {
        Self {
            session_id,
            source: ProvenanceSource::VerifiedSessionRootBinding,
            process: ProcessIdentity {
                pid,
                start_time,
                start_time_precise: None,
                name,
                exe,
            },
            parent: ppid.map(|p| ParentIdentity {
                ppid: p,
                start_time: None,
                start_time_precise: None,
                name: None,
            }),
            observed_at: Utc::now(),
            details,
        }
    }

    /// Legacy constructor forwarding to verified_session_root_binding.
    pub fn root_binding(
        session_id: String,
        pid: u32,
        start_time: Option<u64>,
        name: String,
        exe: Option<PathBuf>,
        ppid: Option<u32>,
        details: String,
    ) -> Self {
        Self::verified_session_root_binding(session_id, pid, start_time, name, exe, ppid, details)
    }

    /// Attaches an exact microsecond-precision start timestamp to the process identity.
    pub fn with_precise_start_time(
        mut self,
        precise: Option<crate::model::process::ProcessStartTime>,
    ) -> Self {
        self.process.start_time_precise = precise;
        self
    }

    /// Creates an observed spawn event (when a real launch supervisor/hook captured the spawn).
    pub fn observed_spawn(
        session_id: String,
        pid: u32,
        start_time: Option<u64>,
        name: String,
        exe: Option<PathBuf>,
        parent: ParentIdentity,
        details: String,
    ) -> Self {
        Self {
            session_id,
            source: ProvenanceSource::ObservedSpawn,
            process: ProcessIdentity {
                pid,
                start_time,
                start_time_precise: None,
                name,
                exe,
            },
            parent: Some(parent),
            observed_at: Utc::now(),
            details,
        }
    }

    /// Creates an observed exec event.
    pub fn observed_exec(
        session_id: String,
        pid: u32,
        start_time: Option<u64>,
        name: String,
        exe: Option<PathBuf>,
        parent: Option<ParentIdentity>,
        details: String,
    ) -> Self {
        Self {
            session_id,
            source: ProvenanceSource::ObservedExec,
            process: ProcessIdentity {
                pid,
                start_time,
                start_time_precise: None,
                name,
                exe,
            },
            parent,
            observed_at: Utc::now(),
            details,
        }
    }

    /// Creates a discovered descendant record from a periodic process-tree scan.
    pub fn discovered_descendant(
        session_id: String,
        pid: u32,
        start_time: Option<u64>,
        name: String,
        exe: Option<PathBuf>,
        parent_pid: u32,
        details: String,
    ) -> Self {
        Self {
            session_id,
            source: ProvenanceSource::DiscoveredDescendant,
            process: ProcessIdentity {
                pid,
                start_time,
                start_time_precise: None,
                name,
                exe,
            },
            parent: Some(ParentIdentity {
                ppid: parent_pid,
                start_time: None,
                start_time_precise: None,
                name: None,
            }),
            observed_at: Utc::now(),
            details,
        }
    }

    /// Creates a heuristic association record (e.g. orphan dev server on listening port).
    pub fn heuristic_association(
        session_id: String,
        pid: u32,
        start_time: Option<u64>,
        name: String,
        exe: Option<PathBuf>,
        details: String,
    ) -> Self {
        Self {
            session_id,
            source: ProvenanceSource::HeuristicAssociation,
            process: ProcessIdentity {
                pid,
                start_time,
                start_time_precise: None,
                name,
                exe,
            },
            parent: None,
            observed_at: Utc::now(),
            details,
        }
    }

    /// Verifies whether this provenance record matches a candidate process's exact identity.
    ///
    /// Specifically checks:
    /// 1. PID match.
    /// 2. Process start-time match (guards against PID recycling!).
    ///    CRITICAL: `None == None` does NOT validate identity; returns `IdentityMatchResult::MissingStartTime`.
    /// 3. Process name match (case-insensitive).
    /// 4. Executable path match with lexical normalization.
    pub fn verify_process_identity(&self, proc: &crate::model::ProcessInfo) -> IdentityMatchResult {
        // 1. PID match
        if self.process.pid != proc.pid {
            return IdentityMatchResult::PidMismatch;
        }

        // 2. Start time check (CRITICAL: None == None does NOT validate identity!)
        // Exact microsecond matching takes precedence if both records provide precise timestamps
        if let (Some(rec_precise), Some(proc_precise)) =
            (self.process.start_time_precise, proc.start_time_precise)
        {
            if rec_precise != proc_precise {
                return IdentityMatchResult::StartTimeMismatch;
            }
        } else {
            match (self.process.start_time, proc.start_time) {
                (Some(rec_st), Some(proc_st)) => {
                    if rec_st != proc_st {
                        return IdentityMatchResult::StartTimeMismatch;
                    }
                }
                _ => {
                    // One or both start times are missing; PID recycling cannot be disproven!
                    return IdentityMatchResult::MissingStartTime;
                }
            }
        }

        // 3. Process name check
        if !self.process.name.eq_ignore_ascii_case(&proc.name) {
            return IdentityMatchResult::BinaryMismatch;
        }

        // 4. Executable path check with normalization
        if let (Some(rec_exe), Some(proc_exe)) = (&self.process.exe, &proc.exe) {
            let norm_rec = normalize_path(rec_exe);
            let norm_proc = normalize_path(proc_exe);
            if norm_rec != norm_proc {
                return IdentityMatchResult::BinaryMismatch;
            }
        }

        IdentityMatchResult::ExactMatch
    }

    /// Helper that returns true only on an exact identity match with verified start times.
    pub fn matches_process(&self, proc: &crate::model::ProcessInfo) -> bool {
        self.verify_process_identity(proc).is_exact()
    }
}
