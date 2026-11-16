use crate::config::TimmyConfig;
use crate::engine::attribution::AttributionEngine;
use crate::model::agent::{AgentKind, Confidence};
use crate::model::lineage::{LineageChainResult, ProcessLineageEdge};
use crate::model::process::{
    ObservationInterval, ProcessInfo, ProcessSnapshot, SnapshotCompleteness,
};
use crate::model::session::{CleanupRecommendation, SessionInfo, SessionStatus, TrackedResource};
use crate::platform::SystemCollector;
use crate::safety::rules;
use crate::safety::SafetyShield;
use crate::storage::{StorageError, StorageManager};
use chrono::Utc;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("Platform error: {0}")]
    Platform(#[from] crate::platform::PlatformError),
    #[error("No active session found")]
    NoActiveSession,
    #[error("Session '{0}' not found")]
    SessionNotFound(String),
    #[error("Session '{0}' is already stopped")]
    SessionAlreadyStopped(String),
    #[error("Cannot observe inactive or stopped session '{0}'")]
    CannotObserveInactiveSession(String),
    #[error("An active session '{id}' for agent '{agent}' is already running (started at {started}). Stop it with `timmy session stop` or pass `--replace` to close it.")]
    ActiveSessionAlreadyExists {
        id: String,
        agent: String,
        started: String,
    },
    #[error("Observer lease for session '{session_id}' is already held by '{owner_id}' (expires at {expires_at})")]
    ObserverLeaseAlreadyHeld {
        session_id: String,
        owner_id: String,
        expires_at: String,
    },
    #[error("Observer lease for session '{session_id}' lost fencing race: active generation is {current_token} (owned by '{current_owner}'), expected generation {expected_token}")]
    ObserverLeaseFencingConflict {
        session_id: String,
        expected_token: u64,
        current_token: u64,
        current_owner: String,
    },
    #[error("Observer lease for session '{session_id}' expired at {expired_at}")]
    ObserverLeaseExpired {
        session_id: String,
        owner_id: String,
        expired_at: String,
    },
}

/// Central coordinator for AI coding agent session tracking and resource discovery.
pub struct SessionCoordinator {
    storage: Arc<StorageManager>,
    config: TimmyConfig,
    safety: SafetyShield,
}

impl SessionCoordinator {
    pub fn new(storage: Arc<StorageManager>, config: TimmyConfig) -> Self {
        Self {
            storage,
            config,
            safety: SafetyShield::new(),
        }
    }

    /// Generates a unique, readable session identifier (e.g. "sess-20261111-134500-a8f3").
    pub fn generate_session_id() -> String {
        let now = Utc::now();
        let timestamp = now.format("%Y%m%d-%H%M%S");
        let nanos = now.timestamp_subsec_nanos();
        let rand_hex = format!("{:04x}", nanos % 0xFFFF);
        format!("sess-{}-{}", timestamp, rand_hex)
    }

    /// Starts a new session record.
    /// Fails safely if an active session already exists, unless `replace` is true.
    pub fn start_session(
        &self,
        agent_flag: Option<String>,
        replace: bool,
        platform: &dyn SystemCollector,
    ) -> Result<SessionInfo, SessionError> {
        // 1. Guard against silent overwrite of active sessions
        if let Some(mut existing) = self.storage.get_active_session()? {
            if !replace {
                return Err(SessionError::ActiveSessionAlreadyExists {
                    id: existing.id.clone(),
                    agent: existing.agent_kind.to_string(),
                    started: existing
                        .start_time
                        .format("%Y-%m-%d %H:%M:%S UTC")
                        .to_string(),
                });
            } else {
                existing.status = SessionStatus::Stopped;
                existing.end_time = Some(Utc::now());
                self.storage.save_session(&existing)?;
            }
        }

        // 2. Discover running processes to identify agent root
        let live_procs = platform.collect_processes()?;
        let ports = platform.collect_listening_ports().unwrap_or_default();
        let attribution_engine = AttributionEngine::new(self.config.agents.custom_rules.clone());

        // 3. Determine agent kind, confidence, and root binding
        let session_id = Self::generate_session_id();

        let (agent_kind, confidence, root_binding, evidence) = if let Some(name) = agent_flag {
            let kind = AgentKind::from_str_name(&name);
            // Search for an authentic live process independently verified by AttributionEngine
            let verified_proc = live_procs.iter().find(|p| {
                let attr = attribution_engine.attribute_process(p);
                attr.kind == kind && attr.confidence >= Confidence::HighConfidence
            });

            match verified_proc {
                Some(p) => {
                    let binding = crate::model::provenance::LaunchProvenance::root_binding(
                        session_id.clone(),
                        p.pid,
                        p.start_time,
                        p.name.clone(),
                        p.exe.clone(),
                        p.ppid,
                        format!(
                            "Verified live agent process '{}' bound as session root at start",
                            p.name
                        ),
                    )
                    .with_precise_start_time(p.start_time_precise);
                    let ev = vec![
                        format!("Session agent declared as '{}' via --agent", name),
                        format!(
                            "Independently verified authentic root agent process '{}' (PID {})",
                            p.name, p.pid
                        ),
                    ];
                    (kind, Confidence::Confirmed, Some(binding), ev)
                }
                None => {
                    let ev = vec![
                        format!("Session agent declared as '{}' via --agent", name),
                        "No verified root agent process found running at session start; tracking spawned developer resources".to_string(),
                    ];
                    (kind, Confidence::Confirmed, None, ev)
                }
            }
        } else {
            // Auto-detection attempt
            let mut detected: Option<&ProcessInfo> = None;

            for p in &live_procs {
                let attr = attribution_engine.attribute_process(p);
                if attr.confidence == Confidence::Confirmed {
                    detected = Some(p);
                    break;
                }
            }

            match detected {
                Some(p) => {
                    let attr = attribution_engine.attribute_process(p);
                    let binding = crate::model::provenance::LaunchProvenance::root_binding(
                        session_id.clone(),
                        p.pid,
                        p.start_time,
                        p.name.clone(),
                        p.exe.clone(),
                        p.ppid,
                        format!("Automatically identified running AI agent '{}' bound as session root at start", p.name),
                    )
                    .with_precise_start_time(p.start_time_precise);
                    (
                        attr.kind,
                        Confidence::HighConfidence,
                        Some(binding),
                        vec![format!(
                            "Automatically identified running AI agent '{}' (PID {})",
                            p.name, p.pid
                        )],
                    )
                }
                None => (
                    AgentKind::Unknown,
                    Confidence::Unknown,
                    None,
                    vec![
                        "Uncertain: No active AI agent detected on session start; tracking all newly spawned developer resources"
                            .to_string(),
                    ],
                ),
            }
        };

        let start_time = Utc::now();
        let root_pid = root_binding.as_ref().map(|b| b.process.pid);
        let root_name = root_binding.as_ref().map(|b| b.process.name.clone());

        let mut session = SessionInfo {
            id: session_id.clone(),
            agent_kind,
            status: SessionStatus::Active,
            start_time,
            end_time: None,
            root_pid,
            root_process_name: root_name,
            confidence,
            evidence,
            tracked_pids: Vec::new(),
            total_memory_bytes: 0,
            total_cpu_usage: 0.0,
            open_ports: Vec::new(),
            resource_count: 0,
            root_binding,
        };

        // 4. Initial resource correlation & lineage extraction
        let snapshot = platform
            .collect_process_snapshot()
            .unwrap_or_else(|_| ProcessSnapshot {
                processes: live_procs.clone(),
                interval: ObservationInterval::default(),
                completeness: SnapshotCompleteness::Complete,
            });
        let initial_edges = crate::engine::lineage::extract_snapshot_lineage_edges(
            &session_id,
            session.root_pid,
            session.root_binding.as_ref(),
            &snapshot,
            &[],
            None,
        );
        let tracked = self.correlate_resources(&session, &live_procs, &ports, &[], &initial_edges);
        Self::enrich_session_summary(&mut session, &tracked);

        // 5. Persist to SQLite
        self.storage.save_session(&session)?;
        self.storage.save_session_resources(&session_id, &tracked)?;
        let snap_id = self.storage.record_session_snapshot(
            &session_id,
            tracked.len(),
            session.total_memory_bytes,
            session.total_cpu_usage,
            session.open_ports.len(),
        )?;
        if !initial_edges.is_empty() {
            let edges_with_snap: Vec<_> = initial_edges
                .into_iter()
                .map(|mut e| {
                    if e.snapshot_id.is_none() {
                        e.snapshot_id = Some(snap_id);
                    }
                    e
                })
                .collect();
            let _ = self
                .storage
                .save_lineage_edges(&session_id, &edges_with_snap);
        }

        Ok(session)
    }

    /// Stops tracking the specified session (or current active session if None).
    /// Does NOT terminate any processes.
    pub fn stop_session(&self, session_id: Option<&str>) -> Result<SessionInfo, SessionError> {
        let mut session = match session_id {
            Some(id) => self
                .storage
                .get_session(id)?
                .ok_or_else(|| SessionError::SessionNotFound(id.to_string()))?,
            None => self
                .storage
                .get_active_session()?
                .ok_or(SessionError::NoActiveSession)?,
        };

        if session.status == SessionStatus::Stopped {
            return Err(SessionError::SessionAlreadyStopped(session.id));
        }

        session.status = SessionStatus::Stopped;
        session.end_time = Some(Utc::now());

        self.storage.save_session(&session)?;
        Ok(session)
    }

    /// Lists all sessions recorded in the database.
    pub fn list_sessions(&self) -> Result<Vec<SessionInfo>, SessionError> {
        let sessions = self.storage.list_sessions()?;
        Ok(sessions)
    }

    /// Retrieves all recorded process lineage edges for a given session.
    pub fn get_lineage_edges(
        &self,
        session_id: &str,
    ) -> Result<Vec<crate::model::lineage::ProcessLineageEdge>, SessionError> {
        self.storage
            .get_lineage_edges(session_id)
            .map_err(SessionError::Storage)
    }

    /// Constructs the hierarchical process lineage tree for a given session.
    pub fn get_session_lineage_tree(
        &self,
        session_id: &str,
        show_exited: bool,
    ) -> Result<Vec<crate::engine::lineage::LineageTreeNode>, SessionError> {
        let session = self
            .storage
            .get_session(session_id)?
            .ok_or_else(|| SessionError::SessionNotFound(session_id.to_string()))?;
        let resources = self.storage.get_session_resources(session_id)?;
        let edges = self.storage.get_lineage_edges(session_id)?;
        Ok(crate::engine::lineage::build_session_lineage_tree(
            &session,
            &resources,
            &edges,
            show_exited,
        ))
    }

    /// Deeply inspects a session, refreshing its active resources if it is active.
    pub fn inspect_session(
        &self,
        session_id: Option<&str>,
        platform: &dyn SystemCollector,
    ) -> Result<
        (
            SessionInfo,
            Vec<TrackedResource>,
            Vec<CleanupRecommendation>,
        ),
        SessionError,
    > {
        let session = match session_id {
            Some(id) => self
                .storage
                .get_session(id)?
                .ok_or_else(|| SessionError::SessionNotFound(id.to_string()))?,
            None => self
                .storage
                .get_active_session()?
                .ok_or(SessionError::NoActiveSession)?,
        };

        // If the session is currently active, run a fresh observation pass unless another observer holds the lease.
        // If an active observer lease is held by another process, operate in read-only mode.
        // If the session is stopped, strictly return historical snapshot without mutation!
        let (updated_session, resources) = if session.status == SessionStatus::Active {
            let lease_held = self
                .storage
                .get_observer_lease(&session.id)
                .ok()
                .flatten()
                .map(|l| !l.is_expired())
                .unwrap_or(false);

            if lease_held {
                let res = self.storage.get_session_resources(&session.id)?;
                (session, res)
            } else {
                self.observe_and_update(&session, platform)?
            }
        } else {
            let res = self.storage.get_session_resources(&session.id)?;
            (session, res)
        };

        let recommendations = self.generate_cleanup_recommendations(&resources);
        Ok((updated_session, resources, recommendations))
    }

    /// Gets resources for a session (active or specified).
    pub fn get_session_resources(
        &self,
        session_id: Option<&str>,
        platform: &dyn SystemCollector,
    ) -> Result<(SessionInfo, Vec<TrackedResource>), SessionError> {
        let session = match session_id {
            Some(id) => self
                .storage
                .get_session(id)?
                .ok_or_else(|| SessionError::SessionNotFound(id.to_string()))?,
            None => self
                .storage
                .get_active_session()?
                .ok_or(SessionError::NoActiveSession)?,
        };

        if session.status == SessionStatus::Active {
            let lease_held = self
                .storage
                .get_observer_lease(&session.id)
                .ok()
                .flatten()
                .map(|l| !l.is_expired())
                .unwrap_or(false);

            if lease_held {
                let res = self.storage.get_session_resources(&session.id)?;
                Ok((session, res))
            } else {
                self.observe_and_update(&session, platform)
            }
        } else {
            let res = self.storage.get_session_resources(&session.id)?;
            Ok((session, res))
        }
    }

    /// Periodically observes the system, detects new/detached processes and PID reuse,
    /// updates metrics, and saves snapshots to SQLite.
    pub fn observe_and_update(
        &self,
        session: &SessionInfo,
        platform: &dyn SystemCollector,
    ) -> Result<(SessionInfo, Vec<TrackedResource>), SessionError> {
        self.observe_and_update_with_lease(session, platform, None)
    }

    /// Atomically performs an observation pass, validating lease ownership and fencing token before write.
    pub fn observe_and_update_with_lease(
        &self,
        session: &SessionInfo,
        platform: &dyn SystemCollector,
        lease_auth: Option<(&str, u64)>,
    ) -> Result<(SessionInfo, Vec<TrackedResource>), SessionError> {
        // Authoritatively verify current status from the database
        let db_session = self
            .storage
            .get_session(&session.id)?
            .ok_or_else(|| SessionError::SessionNotFound(session.id.clone()))?;

        if db_session.status != SessionStatus::Active {
            return Err(SessionError::CannotObserveInactiveSession(
                session.id.clone(),
            ));
        }

        let snapshot = platform.collect_process_snapshot()?;
        let live_procs = &snapshot.processes;
        let ports = platform.collect_listening_ports().unwrap_or_default();
        let prev_resources = self.storage.get_session_resources(&session.id)?;
        let existing_edges = self
            .storage
            .get_lineage_edges(&session.id)
            .unwrap_or_default();

        let new_edges = crate::engine::lineage::extract_snapshot_lineage_edges(
            &session.id,
            db_session.root_pid,
            db_session.root_binding.as_ref(),
            &snapshot,
            &existing_edges,
            None,
        );

        let status_updates =
            crate::engine::lineage::update_edge_lifecycle_statuses(&snapshot, &existing_edges);

        let mut all_edges = existing_edges.clone();
        for edge in &new_edges {
            if let Some(pos) = all_edges
                .iter()
                .position(|e| e.parent == edge.parent && e.child == edge.child)
            {
                all_edges[pos] = edge.clone();
            } else {
                all_edges.push(edge.clone());
            }
        }
        for edge in &status_updates {
            if let Some(pos) = all_edges
                .iter()
                .position(|e| e.parent == edge.parent && e.child == edge.child)
            {
                all_edges[pos] = edge.clone();
            }
        }

        let edges_to_commit: Vec<ProcessLineageEdge> =
            new_edges.into_iter().chain(status_updates).collect();

        let current_resources =
            self.correlate_resources(&db_session, live_procs, &ports, &prev_resources, &all_edges);

        let mut updated_session = db_session.clone();
        Self::enrich_session_summary(&mut updated_session, &current_resources);

        let snapshot_metrics = (
            current_resources.len(),
            updated_session.total_memory_bytes,
            updated_session.total_cpu_usage,
            updated_session.open_ports.len(),
        );

        match lease_auth {
            Some((owner_id, fencing_token)) => {
                // Authoritative observer: commit atomically with active lease and fencing token
                match self.storage.commit_session_observation_with_lineage(
                    &session.id,
                    owner_id,
                    fencing_token,
                    &updated_session,
                    &current_resources,
                    snapshot_metrics,
                    &edges_to_commit,
                ) {
                    Ok(()) => {}
                    Err(StorageError::LeaseFencingConflict {
                        session_id,
                        expected_token,
                        current_token,
                        current_owner,
                    }) => {
                        return Err(SessionError::ObserverLeaseFencingConflict {
                            session_id,
                            expected_token,
                            current_token,
                            current_owner,
                        });
                    }
                    Err(StorageError::LeaseExpired {
                        session_id,
                        owner_id,
                        expired_at,
                    }) => {
                        return Err(SessionError::ObserverLeaseExpired {
                            session_id,
                            owner_id,
                            expired_at,
                        });
                    }
                    Err(StorageError::SessionNotActive(id)) => {
                        return Err(SessionError::CannotObserveInactiveSession(id));
                    }
                    Err(e) => return Err(SessionError::Storage(e)),
                }
            }
            None => {
                // Ad-hoc observation (e.g. from CLI or initial run):
                // If another observer lease is currently held, do not mutate state; return read-only data!
                let lease_held = self
                    .storage
                    .get_observer_lease(&session.id)
                    .ok()
                    .flatten()
                    .map(|l| !l.is_expired())
                    .unwrap_or(false);

                if !lease_held {
                    // Acquire transient short lease to guarantee atomic generation progression
                    let transient_owner = format!("transient-{}", std::process::id());
                    if let Ok(acq) =
                        self.storage
                            .acquire_observer_lease(&session.id, &transient_owner, 4)
                    {
                        let token = match acq {
                            crate::storage::LeaseAcquisitionResult::Acquired(l) => l.fencing_token,
                            crate::storage::LeaseAcquisitionResult::Renewed(l) => l.fencing_token,
                            crate::storage::LeaseAcquisitionResult::RecoveredFromExpired {
                                lease,
                                ..
                            } => lease.fencing_token,
                            _ => 0,
                        };
                        if token > 0 {
                            let _ = self.storage.commit_session_observation_with_lineage(
                                &session.id,
                                &transient_owner,
                                token,
                                &updated_session,
                                &current_resources,
                                snapshot_metrics,
                                &edges_to_commit,
                            );
                            let _ = self.storage.release_observer_lease(
                                &session.id,
                                &transient_owner,
                                token,
                            );
                        }
                    }
                }
            }
        }

        // Prune older snapshots
        let _ = self.storage.prune_history(
            self.config.session.retention_days,
            self.config.session.max_snapshots_per_session,
        );

        Ok((updated_session, current_resources))
    }

    /// Periodically observes a session in the foreground until interrupted or until the session stops.
    ///
    /// Observes state on each tick, persists snapshot records, and checks authoritative
    /// database status on each iteration. If the session is stopped or replaced, the watcher
    /// exits cleanly without mutating historical records.
    pub fn watch_session<F>(
        &self,
        session_id: &str,
        interval: std::time::Duration,
        stop_signal: std::sync::Arc<std::sync::atomic::AtomicBool>,
        platform: &dyn SystemCollector,
        mut on_tick: F,
    ) -> Result<SessionInfo, SessionError>
    where
        F: FnMut(&SessionInfo, &[TrackedResource]),
    {
        use std::sync::atomic::Ordering;

        let initial_session = self
            .storage
            .get_session(session_id)?
            .ok_or_else(|| SessionError::SessionNotFound(session_id.to_string()))?;

        if initial_session.status != SessionStatus::Active {
            return Err(SessionError::CannotObserveInactiveSession(
                session_id.to_string(),
            ));
        }

        let owner_id = format!(
            "watcher-{}-{}",
            std::process::id(),
            Utc::now().timestamp_millis()
        );
        let lease_ttl_secs = 6;

        let initial_lease =
            match self
                .storage
                .acquire_observer_lease(session_id, &owner_id, lease_ttl_secs)?
            {
                crate::storage::LeaseAcquisitionResult::Acquired(l)
                | crate::storage::LeaseAcquisitionResult::Renewed(l) => l,
                crate::storage::LeaseAcquisitionResult::RecoveredFromExpired { lease, .. } => lease,
                crate::storage::LeaseAcquisitionResult::AlreadyHeld {
                    current_owner,
                    expires_at,
                    ..
                } => {
                    return Err(SessionError::ObserverLeaseAlreadyHeld {
                        session_id: session_id.to_string(),
                        owner_id: current_owner,
                        expires_at: expires_at.to_rfc3339(),
                    });
                }
            };

        let fencing_token = initial_lease.fencing_token;

        struct LeaseGuard<'a> {
            storage: &'a StorageManager,
            session_id: &'a str,
            owner_id: &'a str,
            fencing_token: u64,
        }
        impl<'a> Drop for LeaseGuard<'a> {
            fn drop(&mut self) {
                let _ = self.storage.release_observer_lease(
                    self.session_id,
                    self.owner_id,
                    self.fencing_token,
                );
            }
        }

        let _guard = LeaseGuard {
            storage: &self.storage,
            session_id,
            owner_id: &owner_id,
            fencing_token,
        };

        let mut current_session = initial_session;

        while !stop_signal.load(Ordering::SeqCst) {
            let tick_start = std::time::Instant::now();

            // 1. Authoritative check & lease renewal
            let renewed = self.storage.renew_observer_lease(
                session_id,
                &owner_id,
                fencing_token,
                lease_ttl_secs,
            )?;
            if !renewed {
                if let Some(s) = self.storage.get_session(session_id)? {
                    current_session = s;
                }
                break;
            }

            let latest_db = match self.storage.get_session(session_id)? {
                Some(s) => s,
                None => break, // Session record was pruned or deleted
            };

            if latest_db.status != SessionStatus::Active {
                // Session was stopped or replaced by another command.
                // Cleanly exit watch loop without modifying stopped session!
                current_session = latest_db;
                break;
            }

            // 2. Perform live observation and atomic commit with fencing token
            match self.observe_and_update_with_lease(
                &latest_db,
                platform,
                Some((&owner_id, fencing_token)),
            ) {
                Ok((updated, resources)) => {
                    on_tick(&updated, &resources);
                    current_session = updated;
                }
                Err(SessionError::ObserverLeaseFencingConflict { .. })
                | Err(SessionError::ObserverLeaseExpired { .. })
                | Err(SessionError::CannotObserveInactiveSession(_)) => {
                    // Lease lost or fencing conflict or session stopped: cleanly exit
                    break;
                }
                Err(e) => return Err(e),
            }

            // 3. Monotonic sleep scheduling
            let elapsed_ms = tick_start.elapsed().as_millis() as u64;
            let total_ms = interval.as_millis() as u64;
            let remaining_ms = total_ms.saturating_sub(elapsed_ms);

            let slice_ms = 100;
            let slices = (remaining_ms / slice_ms).max(1);
            for _ in 0..slices {
                if stop_signal.load(Ordering::SeqCst) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(slice_ms));
            }
        }

        Ok(current_session)
    }

    /// Generates structured cleanup recommendations for all session resources with fail-safe defaults.
    pub fn generate_cleanup_recommendations(
        &self,
        resources: &[TrackedResource],
    ) -> Vec<CleanupRecommendation> {
        resources
            .iter()
            .map(|r| {
                let is_system_protected = r.is_protected
                    || self
                        .safety
                        .validate_termination(r.pid.unwrap_or(0), &r.name)
                        .is_err();

                let is_shell = rules::is_interactive_shell(&r.name);
                let is_terminal = rules::is_terminal_host(&r.name);
                let (termination_eligible, eligibility_reason) = Self::evaluate_termination_safety(
                    r.pid,
                    &r.name,
                    r.confidence,
                    r.is_detached,
                    false,
                    is_shell,
                    is_terminal,
                    is_system_protected,
                );

                let safe_to_terminate =
                    r.safe_to_terminate && termination_eligible && !is_system_protected;

                let evidence_summary = if r.evidence.is_empty() {
                    "None".to_string()
                } else {
                    r.evidence.join(" | ")
                };

                CleanupRecommendation {
                    resource_name: r.name.clone(),
                    pid_or_id: r
                        .pid
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "N/A".to_string()),
                    memory_formatted: r.formatted_memory(),
                    associated_ports: r.listening_ports.clone(),
                    ownership_confidence: r.confidence,
                    ownership_evidence: evidence_summary.clone(),
                    is_protected: is_system_protected || is_shell || is_terminal,
                    termination_eligible: safe_to_terminate,
                    eligibility_reason,
                    user_authorized: false, // Explicit user grant required; NEVER inferred
                    is_detached: r.is_detached,
                    confidence: r.confidence,
                    safe_to_terminate,
                    evidence: evidence_summary,
                }
            })
            .collect()
    }

    // =========================================================================
    // RESOURCE CORRELATION, DETACHED PROCESSES & PID REUSE DETECTION
    // =========================================================================

    fn correlate_resources(
        &self,
        session: &SessionInfo,
        live_procs: &[ProcessInfo],
        ports: &[crate::model::ListeningPort],
        prev_resources: &[TrackedResource],
        lineage_edges: &[ProcessLineageEdge],
    ) -> Vec<TrackedResource> {
        let current_pid = std::process::id();
        let session_start_unix = session.start_time.timestamp() as u64;

        // Map live PIDs to ports
        let mut pid_to_ports: HashMap<u32, Vec<u16>> = HashMap::new();
        for port in ports {
            if let Some(pid) = port.pid {
                pid_to_ports.entry(pid).or_default().push(port.port);
            }
        }

        // Map live PIDs for quick lookup
        let live_map: HashMap<u32, &ProcessInfo> = live_procs.iter().map(|p| (p.pid, p)).collect();

        // Build ancestor lookup map
        let pid_to_ppid: HashMap<u32, u32> = live_procs
            .iter()
            .filter_map(|p| p.ppid.map(|ppid| (p.pid, ppid)))
            .collect();

        let mut tracked = Vec::new();
        let mut processed_pids: HashSet<u32> = HashSet::new();

        // ---------------------------------------------------------------------
        // 1. Process PREVIOUSLY OBSERVED resources
        // ---------------------------------------------------------------------
        for prev in prev_resources {
            if let Some(pid) = prev.pid {
                if let Some(live) = live_map.get(&pid) {
                    // PID REUSE VERIFICATION:
                    // If start time exists and differs, or if binary name changed, REJECT the recycled PID!
                    let prev_precise = prev
                        .provenance
                        .as_ref()
                        .and_then(|p| p.process.start_time_precise);
                    let is_same_process = match (live.start_time_precise, prev_precise) {
                        (Some(live_st), Some(prev_st)) => live_st == prev_st,
                        _ => match (live.start_time, prev.process_start_time) {
                            (Some(live_st), Some(prev_st)) => live_st == prev_st,
                            _ => live.name.eq_ignore_ascii_case(&prev.name),
                        },
                    };

                    if !is_same_process {
                        // Recycled PID detected: The original process exited and OS reassigned PID.
                        // Reject and do NOT associate this new process with the session!
                        continue;
                    }

                    // DETACHED PROCESS DETECTION:
                    let is_root_agent = session.root_pid == Some(pid);
                    let is_detached = match live.ppid {
                        Some(1) => true,
                        Some(parent_pid) => !live_map.contains_key(&parent_pid),
                        None => true,
                    };

                    let mut confidence = prev.confidence;
                    let mut evidence = prev.evidence.clone();

                    if is_root_agent {
                        if let Some(binding) = &session.root_binding {
                            let match_res = binding.verify_process_identity(live);
                            if match_res.is_exact() {
                                confidence = Confidence::Confirmed;
                            } else if match_res.is_recycled_or_mismatch() {
                                continue;
                            } else {
                                confidence = Confidence::Inferred;
                            }
                        } else {
                            confidence = Confidence::Inferred;
                        }
                    } else {
                        let chain_res = crate::engine::lineage::resolve_lineage_chain(
                            session.root_pid,
                            session.root_binding.as_ref(),
                            live,
                            live_procs,
                            lineage_edges,
                        );

                        match chain_res {
                            LineageChainResult::UnbrokenAllActive { .. } => {
                                if session.root_binding.is_some() {
                                    confidence = Confidence::Confirmed;
                                } else {
                                    confidence = Confidence::HighConfidence;
                                }
                            }
                            LineageChainResult::UnbrokenHistoricalWithExits {
                                exited_ancestors,
                                ..
                            } => {
                                confidence = Confidence::HighConfidence;
                                if !prev
                                    .evidence
                                    .iter()
                                    .any(|e| e.starts_with("Verified persistent process lineage"))
                                {
                                    evidence.push(format!(
                                        "Verified persistent process lineage: unbroken historical chain from session root; intermediate ancestor(s) {:?} exited; surviving process reparented (HighConfidence)",
                                        exited_ancestors
                                    ));
                                }
                            }
                            LineageChainResult::ConflictingEvidence { details } => {
                                confidence = Confidence::Unknown;
                                evidence.push(format!("Conflicting lineage evidence: {}", details));
                            }
                            LineageChainResult::IdentityMismatch { details } => {
                                confidence = Confidence::Unknown;
                                evidence.push(format!("Lineage identity mismatch: {}", details));
                            }
                            LineageChainResult::BrokenChain {
                                missing_parent_for, ..
                            } => {
                                confidence = prev.confidence.min(Confidence::Inferred);
                                evidence.push(format!(
                                    "Broken lineage chain: intermediate parent {} not found",
                                    missing_parent_for
                                ));
                            }
                            LineageChainResult::NoRecordedParentEdge { .. } => {
                                // Retain previous confidence
                            }
                        }
                    }

                    if is_detached
                        && !prev.is_detached
                        && !evidence.iter().any(|e| e.contains("Orphaned/detached"))
                    {
                        evidence.push(
                            "Orphaned/detached process (now under PID 1): previously observed under agent tree; survived agent parent exit"
                                .to_string(),
                        );
                    }

                    let ports_list = pid_to_ports.get(&pid).cloned().unwrap_or_default();
                    let is_shell = rules::is_interactive_shell(&live.name);
                    let is_terminal = rules::is_terminal_host(&live.name);
                    let is_protected = is_shell
                        || is_terminal
                        || is_root_agent
                        || self.safety.validate_termination(pid, &live.name).is_err();

                    let (safe_to_terminate, _) = Self::evaluate_termination_safety(
                        Some(pid),
                        &live.name,
                        confidence,
                        is_detached,
                        is_root_agent,
                        is_shell,
                        is_terminal,
                        is_protected,
                    );

                    tracked.push(TrackedResource {
                        session_id: session.id.clone(),
                        pid: Some(pid),
                        name: live.name.clone(),
                        exe_path: live.exe.as_ref().map(|p| p.to_string_lossy().to_string()),
                        memory_bytes: live.memory_bytes,
                        cpu_usage: live.cpu_usage,
                        listening_ports: ports_list,
                        confidence,
                        evidence,
                        is_detached,
                        is_protected,
                        safe_to_terminate,
                        first_seen: prev.first_seen,
                        last_seen: Utc::now(),
                        process_start_time: live.start_time.or(prev.process_start_time),
                        provenance: prev.provenance.clone(),
                    });

                    processed_pids.insert(pid);
                }
            }
        }

        // ---------------------------------------------------------------------
        // 2. Discover NEW candidate processes running right now
        // ---------------------------------------------------------------------
        let known_dev_servers = [
            "node", "vite", "esbuild", "next", "webpack", "uvicorn", "gunicorn", "python",
            "python3", "ruby", "cargo", "rustc", "go", "php", "java", "dotnet",
        ];

        for proc in live_procs {
            if processed_pids.contains(&proc.pid) {
                continue;
            }

            // Exclude TIMMY itself
            if proc.pid == current_pid || proc.name.eq_ignore_ascii_case("timmy") {
                continue;
            }

            let is_root = session.root_pid == Some(proc.pid);
            let is_descendant = session
                .root_pid
                .map(|r_pid| Self::is_descendant_of(proc.pid, r_pid, &pid_to_ppid))
                .unwrap_or(false);

            let started_during_session = proc
                .start_time
                .map(|st| st >= session_start_unix)
                .unwrap_or(false);

            let has_ports = pid_to_ports.contains_key(&proc.pid);
            let is_shell = rules::is_interactive_shell(&proc.name);
            let is_terminal = rules::is_terminal_host(&proc.name);
            let proc_name_lower = proc.name.to_lowercase();
            let is_dev_server = known_dev_servers
                .iter()
                .any(|&w| proc_name_lower == w || proc_name_lower.starts_with(w));

            let is_unobserved_orphan = proc.ppid == Some(1) && started_during_session;

            let mut should_track = false;
            let mut confidence = Confidence::Unknown;
            let mut evidence = Vec::new();
            let mut is_detached = false;
            let mut provenance = None;

            if is_root {
                should_track = true;
                if let Some(binding) = &session.root_binding {
                    let match_res = binding.verify_process_identity(proc);
                    if match_res.is_exact() {
                        confidence = Confidence::Confirmed;
                        evidence.push(format!(
                            "Verified root AI agent process '{}' for session",
                            proc.name
                        ));
                        provenance = Some(binding.clone());
                    } else if match_res.is_recycled_or_mismatch() {
                        should_track = false;
                    } else {
                        confidence = Confidence::Inferred;
                        evidence.push(format!(
                            "Root process '{}' (PID {}) lacks microsecond start time; confidence capped at Inferred",
                            proc.name, proc.pid
                        ));
                        provenance = Some(binding.clone());
                    }
                } else {
                    confidence = Confidence::Inferred;
                    evidence.push(format!(
                        "Root process '{}' (PID {}) has matching PID but no independently recorded root binding; confidence capped at Inferred",
                        proc.name, proc.pid
                    ));
                    provenance = Some(
                        crate::model::provenance::LaunchProvenance::verified_session_root_binding(
                            session.id.clone(),
                            proc.pid,
                            proc.start_time,
                            proc.name.clone(),
                            proc.exe.clone(),
                            proc.ppid,
                            format!("Session root process '{}' (PID {})", proc.name, proc.pid),
                        )
                        .with_precise_start_time(proc.start_time_precise),
                    );
                }
            } else {
                let chain_res = crate::engine::lineage::resolve_lineage_chain(
                    session.root_pid,
                    session.root_binding.as_ref(),
                    proc,
                    live_procs,
                    lineage_edges,
                );

                match chain_res {
                    LineageChainResult::UnbrokenAllActive { root, chain } => {
                        should_track = true;
                        if session.root_binding.is_some() {
                            confidence = Confidence::Confirmed;
                            evidence.push(format!(
                                "Unbroken live process lineage chain from verified session root PID {} (Confirmed)",
                                root.pid
                            ));
                        } else {
                            confidence = Confidence::HighConfidence;
                            evidence.push(format!(
                                "Unbroken live process lineage chain from session root PID {} (HighConfidence)",
                                root.pid
                            ));
                        }
                        is_detached = false;
                        let parent_pid = chain
                            .last()
                            .map(|e| e.parent.pid)
                            .or(proc.ppid)
                            .unwrap_or(0);
                        provenance = Some(
                            crate::model::provenance::LaunchProvenance::discovered_descendant(
                                session.id.clone(),
                                proc.pid,
                                proc.start_time,
                                proc.name.clone(),
                                proc.exe.clone(),
                                parent_pid,
                                format!(
                                    "Discovered as active descendant in session process tree (Root PID {:?})",
                                    session.root_pid
                                ),
                            )
                            .with_precise_start_time(proc.start_time_precise),
                        );
                    }
                    LineageChainResult::UnbrokenHistoricalWithExits {
                        root,
                        chain,
                        exited_ancestors,
                    } => {
                        should_track = true;
                        confidence = Confidence::HighConfidence;
                        is_detached = true;
                        evidence.push(format!(
                            "Verified persistent process lineage: unbroken historical chain from session root PID {}; intermediate ancestor(s) {:?} exited; surviving process reparented (HighConfidence)",
                            root.pid, exited_ancestors
                        ));
                        let parent_pid = chain
                            .last()
                            .map(|e| e.parent.pid)
                            .or(proc.ppid)
                            .unwrap_or(0);
                        provenance = Some(
                            crate::model::provenance::LaunchProvenance::discovered_descendant(
                                session.id.clone(),
                                proc.pid,
                                proc.start_time,
                                proc.name.clone(),
                                proc.exe.clone(),
                                parent_pid,
                                format!(
                                    "Discovered via verified persistent process lineage from session root PID {}",
                                    root.pid
                                ),
                            )
                            .with_precise_start_time(proc.start_time_precise),
                        );
                    }
                    LineageChainResult::ConflictingEvidence { details } => {
                        should_track = true;
                        confidence = Confidence::Unknown;
                        evidence.push(format!("Conflicting lineage evidence: {}", details));
                    }
                    LineageChainResult::IdentityMismatch { details } => {
                        should_track = true;
                        confidence = Confidence::Unknown;
                        evidence.push(format!("Process identity mismatch: {}", details));
                    }
                    LineageChainResult::NoRecordedParentEdge { .. }
                    | LineageChainResult::BrokenChain { .. } => {
                        if is_descendant {
                            should_track = true;
                            confidence = Confidence::HighConfidence;
                            evidence.push(format!(
                                "Active descendant spawned within session process tree (Root PID {:?})",
                                session.root_pid
                            ));
                            provenance = Some(
                                crate::model::provenance::LaunchProvenance::discovered_descendant(
                                    session.id.clone(),
                                    proc.pid,
                                    proc.start_time,
                                    proc.name.clone(),
                                    proc.exe.clone(),
                                    proc.ppid.unwrap_or(0),
                                    format!(
                                        "Discovered as active descendant in session process tree (Root PID {:?})",
                                        session.root_pid
                                    ),
                                )
                                .with_precise_start_time(proc.start_time_precise),
                            );
                        } else if is_unobserved_orphan && is_dev_server && has_ports {
                            should_track = true;
                            confidence = Confidence::Inferred;
                            is_detached = true;
                            evidence.push(format!(
                                "Unobserved orphan process under PID 1 started after session start holding port(s) {:?}; unverified lineage (Inferred)",
                                pid_to_ports.get(&proc.pid).unwrap_or(&vec![])
                            ));
                            provenance = Some(
                                crate::model::provenance::LaunchProvenance::heuristic_association(
                                    session.id.clone(),
                                    proc.pid,
                                    proc.start_time,
                                    proc.name.clone(),
                                    proc.exe.clone(),
                                    "Unobserved orphan process under PID 1 holding listening ports"
                                        .to_string(),
                                )
                                .with_precise_start_time(proc.start_time_precise),
                            );
                        } else if started_during_session && is_dev_server && has_ports {
                            should_track = true;
                            confidence = Confidence::Inferred;
                            evidence.push(format!(
                                "Development server started during session holding port(s) {:?}; unverified lineage (Inferred)",
                                pid_to_ports.get(&proc.pid).unwrap_or(&vec![])
                            ));
                            provenance = Some(
                                crate::model::provenance::LaunchProvenance::heuristic_association(
                                    session.id.clone(),
                                    proc.pid,
                                    proc.start_time,
                                    proc.name.clone(),
                                    proc.exe.clone(),
                                    "Development server started during session holding listening ports"
                                        .to_string(),
                                )
                                .with_precise_start_time(proc.start_time_precise),
                            );
                        }
                    }
                }
            }

            if should_track {
                let is_root_agent = is_root;
                let is_protected = is_shell
                    || is_terminal
                    || is_root_agent
                    || self
                        .safety
                        .validate_termination(proc.pid, &proc.name)
                        .is_err();

                if is_shell {
                    evidence.push("Protected developer shell session".to_string());
                }

                // Fail-safe calculation
                let (safe_to_terminate, _) = Self::evaluate_termination_safety(
                    Some(proc.pid),
                    &proc.name,
                    confidence,
                    is_detached,
                    is_root_agent,
                    is_shell,
                    is_terminal,
                    is_protected,
                );

                let ports_list = pid_to_ports.get(&proc.pid).cloned().unwrap_or_default();

                tracked.push(TrackedResource {
                    session_id: session.id.clone(),
                    pid: Some(proc.pid),
                    name: proc.name.clone(),
                    exe_path: proc.exe.as_ref().map(|p| p.to_string_lossy().to_string()),
                    memory_bytes: proc.memory_bytes,
                    cpu_usage: proc.cpu_usage,
                    listening_ports: ports_list,
                    confidence,
                    evidence,
                    is_detached,
                    is_protected,
                    safe_to_terminate,
                    first_seen: Utc::now(),
                    last_seen: Utc::now(),
                    process_start_time: proc.start_time,
                    provenance,
                });

                processed_pids.insert(proc.pid);
            }
        }

        tracked
    }

    /// Evaluates termination eligibility strictly following the fail-safe default principle.
    ///
    /// Distinguishes resource attribution (does it belong to the session) from termination
    /// eligibility (passes all safety shields, not a shell/terminal/root agent, and is a disposable worker).
    ///
    /// Returns `(is_eligible, diagnostic_reason)`.
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_termination_safety(
        pid: Option<u32>,
        name: &str,
        confidence: Confidence,
        is_detached: bool,
        is_root_agent: bool,
        is_shell: bool,
        is_terminal: bool,
        is_system_protected: bool,
    ) -> (bool, String) {
        let pid_val = match pid {
            Some(p) => p,
            None => {
                return (
                    false,
                    "Missing PID: Cannot verify process identity".to_string(),
                )
            }
        };

        // 1. Hard shields
        if pid_val == 0 || pid_val == 1 {
            return (
                false,
                "Kernel or init process (PID 0 or 1) protected by hard safety shield".to_string(),
            );
        }
        if pid_val == std::process::id() || name.eq_ignore_ascii_case("timmy") {
            return (
                false,
                "TIMMY self-process protected from termination".to_string(),
            );
        }

        // 2. Protected OS processes, shells, terminals, or root IDE/agent app
        if is_shell {
            return (
                false,
                "Interactive developer shell session (protected from termination)".to_string(),
            );
        }
        if is_terminal {
            return (
                false,
                "Terminal emulator host process (protected from termination)".to_string(),
            );
        }
        if is_root_agent {
            return (
                false,
                "Primary AI agent / IDE application root process (protected from termination)"
                    .to_string(),
            );
        }
        if is_system_protected {
            return (
                false,
                "System or user process protected by SafetyShield blocklist".to_string(),
            );
        }

        // 3. FAIL-SAFE: UNKNOWN and INFERRED must ALWAYS fail closed!
        if confidence == Confidence::Unknown {
            return (
                false,
                "Attribution unknown: Cannot terminate unverified process".to_string(),
            );
        }
        if confidence == Confidence::Inferred {
            return (
                false,
                "Fail-Closed: Attribution confidence is Inferred; lineage unconfirmed".to_string(),
            );
        }

        // 4. Must have at least HighConfidence or Confirmed, AND be a recognizable disposable dev server / worker task or detached server
        let known_dev_workers = [
            "node", "vite", "esbuild", "next", "webpack", "uvicorn", "gunicorn", "python",
            "python3", "ruby", "cargo", "rustc", "go", "php", "java", "dotnet",
        ];
        let name_lower = name.to_lowercase();
        let is_dev_worker = known_dev_workers
            .iter()
            .any(|&w| name_lower == w || name_lower.starts_with(w));

        if !is_dev_worker && !is_detached {
            return (
                false,
                "Process is not a recognized disposable development worker or detached server"
                    .to_string(),
            );
        }

        (
            true,
            "Eligible: Verified session-spawned worker/server process; passes all safety checks"
                .to_string(),
        )
    }

    fn is_descendant_of(pid: u32, ancestor_pid: u32, pid_to_ppid: &HashMap<u32, u32>) -> bool {
        let mut curr = pid;
        let mut depth = 0;
        while let Some(&parent) = pid_to_ppid.get(&curr) {
            if parent == ancestor_pid {
                return true;
            }
            if parent == 0 || parent == 1 || parent == curr || depth > 50 {
                break;
            }
            curr = parent;
            depth += 1;
        }
        false
    }

    fn enrich_session_summary(session: &mut SessionInfo, resources: &[TrackedResource]) {
        let mut pids = Vec::new();
        let mut ports = Vec::new();
        let mut total_mem = 0u64;
        let mut total_cpu = 0.0f32;

        for r in resources {
            if let Some(pid) = r.pid {
                pids.push(pid);
            }
            for p in &r.listening_ports {
                ports.push(*p);
            }
            if let Some(mem) = r.memory_bytes {
                total_mem += mem;
            }
            if let Some(cpu) = r.cpu_usage {
                total_cpu += cpu;
            }
        }

        ports.sort_unstable();
        ports.dedup();

        session.tracked_pids = pids;
        session.open_ports = ports;
        session.total_memory_bytes = total_mem;
        session.total_cpu_usage = total_cpu;
        session.resource_count = resources.len();
    }
}

/// Registers async-signal-safe handlers for SIGINT and SIGTERM.
///
/// Policy:
/// 1. First SIGINT or SIGTERM sets `stop_signal` to `true`, requesting graceful shutdown.
/// 2. Subsequent SIGINT or SIGTERM (while `stop_signal` is already `true`) invokes the
///    default action (`SIG_DFL`), terminating the process immediately.
///
/// Ordering is critical: `register_conditional_default` MUST be registered before `register`
/// so that the first signal handler invocation does not observe the flag set in the same tick.
pub fn register_shutdown_signals(
    stop_signal: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<(), std::io::Error> {
    // 1. Conditional default termination on already-armed flag
    signal_hook::flag::register_conditional_default(
        signal_hook::consts::SIGINT,
        std::sync::Arc::clone(&stop_signal),
    )?;
    signal_hook::flag::register_conditional_default(
        signal_hook::consts::SIGTERM,
        std::sync::Arc::clone(&stop_signal),
    )?;

    // 2. Arm the stop flag to true on the first signal
    signal_hook::flag::register(
        signal_hook::consts::SIGINT,
        std::sync::Arc::clone(&stop_signal),
    )?;
    signal_hook::flag::register(
        signal_hook::consts::SIGTERM,
        std::sync::Arc::clone(&stop_signal),
    )?;

    Ok(())
}
