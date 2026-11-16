use crate::model::agent::Confidence;
use crate::model::session::{SessionInfo, SessionStatus};
use crate::model::{
    AttributionBasis, ContainerDetail, ContainerInfo, ContainerStats, CreationOutcome,
    DockerStatus, ProcessInfo,
};
use crate::platform::traits::{DockerCollector, PlatformError};
use chrono::{DateTime, Utc};

/// Docker container discovery, inspection, and session correlation coordinator.
pub struct DockerCoordinator;

impl DockerCoordinator {
    /// Checks overall Docker daemon health and availability.
    pub fn docker_status(collector: &dyn DockerCollector) -> Result<DockerStatus, PlatformError> {
        collector.docker_status()
    }

    /// Checks whether the Docker daemon UNIX socket is reachable.
    pub fn is_docker_running(collector: &dyn DockerCollector) -> bool {
        collector.is_available()
    }

    /// Collects all Docker containers on the host.
    pub fn discover_containers(
        collector: &dyn DockerCollector,
    ) -> Result<Vec<ContainerInfo>, PlatformError> {
        collector.collect_containers()
    }

    /// Deeply inspects an individual container.
    pub fn inspect_container(
        collector: &dyn DockerCollector,
        id: &str,
    ) -> Result<ContainerDetail, PlatformError> {
        collector.inspect_container(id)
    }

    /// Collects real-time resource statistics for an individual container.
    pub fn collect_container_stats(
        collector: &dyn DockerCollector,
        id: &str,
    ) -> Result<ContainerStats, PlatformError> {
        collector.collect_container_stats(id)
    }

    /// Correlates a collection of containers with known AI agent sessions.
    pub fn correlate_containers(
        containers: &mut [ContainerInfo],
        sessions: &[SessionInfo],
        processes: &[ProcessInfo],
    ) {
        for container in containers.iter_mut() {
            Self::correlate_single_container(container, None, sessions, processes);
        }
    }

    /// Correlates a single container with mounts from deep inspection.
    pub fn correlate_container_with_mounts(
        container: &mut ContainerInfo,
        mounts: &[crate::model::MountInfo],
        sessions: &[SessionInfo],
        processes: &[ProcessInfo],
    ) {
        Self::correlate_single_container(container, Some(mounts), sessions, processes);
    }

    /// Verifies whether a process command-line represents a direct, unambiguous container lifecycle operation
    /// targeting the specified container.
    ///
    /// GUARANTEES:
    /// - Requires originating process to execute a container-creating or container-lifecycle command (`run`, `create`, `up`).
    /// - Strictly rejects read-only inspection and non-creation commands (`ps`, `logs`, `inspect`, `images`, `info`, `version`,
    ///   `top`, `port`, `stats`, `stop`, `kill`, `restart`, `pause`, `unpause`, `rm`, `rmi`, `attach`, `exec`, `wait`, `diff`).
    /// - Requires exact `--name` argument match for container name; never matches substrings or partial names.
    /// - Rejects ambiguous or unresolvable container identities.
    /// - Command-line match alone proves only an operation attempt, NEVER confirmed container ownership.
    pub fn verify_direct_provenance(
        cmdline: &[String],
        container: &ContainerInfo,
    ) -> Option<String> {
        let clean_name = container.name.trim_start_matches('/');
        if clean_name.is_empty() && container.id.is_empty() {
            return None;
        }

        if cmdline.is_empty() {
            return None;
        }

        // Subcommands that create or directly instantiate containers
        const CONTAINER_OPS: &[&str] = &["run", "create", "up"];

        // Non-lifecycle subcommands that should never grant ownership
        const NON_LIFECYCLE_OPS: &[&str] = &[
            "ps", "images", "version", "info", "login", "logout", "search", "network", "volume",
            "logs", "top", "port", "stats", "stop", "kill", "restart", "pause", "unpause", "rm",
            "rmi", "attach", "exec", "wait", "inspect", "diff", "events", "history",
        ];

        // Ensure the command does not start with a non-lifecycle operation
        for arg in cmdline.iter().skip(1) {
            let lower = arg.to_lowercase();
            if NON_LIFECYCLE_OPS.contains(&lower.as_str()) {
                return None;
            }
            if CONTAINER_OPS.contains(&lower.as_str()) {
                break;
            }
        }

        // Must contain a valid lifecycle operation
        let has_lifecycle_op = cmdline.iter().skip(1).any(|arg| {
            let lower = arg.to_lowercase();
            CONTAINER_OPS.contains(&lower.as_str())
        });
        if !has_lifecycle_op {
            return None;
        }

        // Explicit --name argument: `--name <val>` or `--name=<val>`
        let mut i = 0;
        while i < cmdline.len() {
            let arg = &cmdline[i];
            if arg == "--name" && i + 1 < cmdline.len() {
                let val = cmdline[i + 1].trim_start_matches('/');
                if !clean_name.is_empty() && val == clean_name {
                    return Some(format!("Executed 'docker ... --name {}'", val));
                }
            } else if let Some(val) = arg.strip_prefix("--name=") {
                let val_clean = val.trim_start_matches('/');
                if !clean_name.is_empty() && val_clean == clean_name {
                    return Some(format!("Executed 'docker ... --name={}'", val_clean));
                }
            }
            i += 1;
        }

        None
    }

    fn correlate_single_container(
        container: &mut ContainerInfo,
        mounts: Option<&[crate::model::MountInfo]>,
        sessions: &[SessionInfo],
        processes: &[ProcessInfo],
    ) {
        // Requirement 18 & Audit Item 2.7: Retain existing attribution across session termination
        // Surviving containers retain their prior attribution without falsely elevating confidence.
        if let Some(ref existing_sid) = container.session_id {
            if let Some(sess) = sessions.iter().find(|s| &s.id == existing_sid) {
                if sess.status == SessionStatus::Stopped {
                    let retention_msg = format!(
                        "Retained attribution to terminated session {}",
                        existing_sid
                    );
                    if !container.evidence.iter().any(|e| e.contains("Retained")) {
                        container.evidence.push(retention_msg);
                    }
                    return;
                }
            }
        }

        // Track existing attribution to an active session for historical continuity
        let existing_attribution = container.session_id.clone().and_then(|sid| {
            sessions
                .iter()
                .find(|s| s.id == sid)
                .map(|s| (s.id.clone(), container.confidence))
        });

        // TIER EVALUATION: Gather candidate claims across ALL sessions
        // Rules:
        // 1. A command-line match alone must never establish Confidence::Confirmed.
        // 2. A container label or environment-derived declaration must never establish
        //    Confidence::Confirmed or Confidence::HighConfidence ownership.
        // 3. A container name, image, working directory, mount path, port overlap or timestamp
        //    must not independently establish ownership.
        // 4. Preserve declared metadata separately from verified attribution.
        // 5. Use Inferred or Unknown where ownership cannot be independently established.
        // 6. Only assign Confirmed if the implementation can demonstrate a reliable chain of
        //    evidence linking a successful operation initiated by a tracked session to the exact
        //    resulting container ID.
        // 7. Since TIMMY's read-only architecture cannot establish that unbroken chain,
        //    Confirmed is never assigned to Docker containers.
        struct CandidateClaim {
            session_id: String,
            confidence: Confidence,
            evidence: Vec<String>,
            creation_outcome: CreationOutcome,
            attribution_basis: AttributionBasis,
        }

        let mut claims: Vec<CandidateClaim> = Vec::new();

        // 1. Explicit metadata label matching (INFERRED, unverified declared ownership)
        const SESSION_LABEL_KEYS: &[&str] = &[
            "timmy.session.id",
            "com.timmy.session_id",
            "agent.session",
            "session_id",
            "timmy.session",
        ];

        for &key in SESSION_LABEL_KEYS {
            if let Some(label_val) = container.labels.get(key) {
                let trimmed = label_val.trim();
                container.declared_session_id = Some(trimmed.to_string());

                for sess in sessions {
                    if sess.id == trimmed {
                        claims.push(CandidateClaim {
                            session_id: sess.id.clone(),
                            // Rule 2: Container label MUST NEVER establish Confirmed or HighConfidence
                            confidence: Confidence::Inferred,
                            evidence: vec![format!(
                                "Declared session metadata via container label '{}' (unverified runtime ownership)",
                                key
                            )],
                            creation_outcome: CreationOutcome::Unknown,
                            attribution_basis: AttributionBasis::DeclaredMetadata,
                        });
                    }
                }
            }
        }

        // 2. Evaluate operational signals per session
        let container_created_dt = container
            .created_at
            .as_ref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc));

        // Track if a session process attempted a command that failed
        let mut failed_attempt_rejection: Option<(u32, String)> = None;

        for sess in sessions {
            let session_start = sess.start_time;
            let session_end = sess.end_time.unwrap_or_else(Utc::now);

            let created_during_session = if let Some(cdt) = container_created_dt {
                cdt >= session_start && cdt <= (session_end + chrono::Duration::seconds(60))
            } else {
                false
            };

            // Check mount or working directory match
            let mut mount_or_cwd_matched = false;
            let mut matched_path = String::new();

            if let Some(m_list) = mounts {
                for m in m_list {
                    if !m.source.is_empty()
                        && m.source != "/"
                        && m.source != "/tmp"
                        && m.source != "/var"
                    {
                        for proc in processes {
                            if sess.tracked_pids.contains(&proc.pid)
                                || sess.root_pid == Some(proc.pid)
                            {
                                if let Some(ref exe) = proc.exe {
                                    if exe.starts_with(&m.source) {
                                        mount_or_cwd_matched = true;
                                        matched_path = m.source.clone();
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if let Some(ref cwd) = container.working_dir {
                if !cwd.is_empty() && cwd != "/" && cwd != "/root" && cwd != "/app" {
                    for proc in processes {
                        if sess.tracked_pids.contains(&proc.pid) || sess.root_pid == Some(proc.pid)
                        {
                            if let Some(ref exe) = proc.exe {
                                if exe.starts_with(cwd) {
                                    mount_or_cwd_matched = true;
                                    matched_path = cwd.clone();
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            // Check shared port communication with session process
            let mut shared_port_link = false;
            let mut linked_port = 0u16;
            for p in &container.ports {
                if sess.open_ports.contains(&p.host_port)
                    || sess.open_ports.contains(&p.container_port)
                {
                    shared_port_link = true;
                    linked_port = p.host_port;
                    break;
                }
            }

            // Check process command execution
            let mut proc_command_attempt: Option<(u32, String, CreationOutcome)> = None;
            for proc in processes {
                if sess.tracked_pids.contains(&proc.pid) || sess.root_pid == Some(proc.pid) {
                    let is_docker_bin = proc.name == "docker"
                        || proc.name == "docker-compose"
                        || proc
                            .exe
                            .as_ref()
                            .and_then(|p| p.file_name())
                            .map(|f| f == "docker" || f == "docker-compose")
                            .unwrap_or(false);

                    if is_docker_bin {
                        if let Some(cmd_provenance) =
                            Self::verify_direct_provenance(&proc.cmdline, container)
                        {
                            // Required Semantics:
                            // Succeeded: independent evidence establishes CLI creation succeeded.
                            // Failed: independent evidence establishes CLI creation failed.
                            // Unknown: TIMMY cannot independently establish either outcome.
                            //
                            // A tracked process invoking docker run, docker create, or docker compose up
                            // proves an attempted operation. It does not establish success or failure.
                            //
                            // A free-text reason containing "failed" or substring matching is REMOVED.
                            // Do not infer CLI operation's exit status from container workload's exit code or state.
                            let outcome = proc.command_outcome.unwrap_or(CreationOutcome::Unknown);
                            proc_command_attempt = Some((proc.pid, cmd_provenance, outcome));
                            break;
                        }
                    }
                }
            }

            // Synthesize claims based on corroboration
            if let Some((pid, cmd_info, outcome)) = proc_command_attempt {
                match outcome {
                    CreationOutcome::Failed => {
                        // Independent structured evidence establishes that the Docker CLI creation operation failed.
                        // Reject attribution for this session.
                        failed_attempt_rejection = Some((pid, cmd_info));
                        claims.retain(|c| c.session_id != sess.id);
                    }
                    CreationOutcome::Succeeded => {
                        let mut ev = vec![format!(
                            "Session process (PID {}) executed container creation command (verified succeeded): {}",
                            pid, cmd_info
                        )];
                        if created_during_session {
                            ev.push(format!(
                                "Container created during active session window ({})",
                                session_start.format("%H:%M:%S")
                            ));
                        }
                        if mount_or_cwd_matched {
                            ev.push(format!(
                                "Bind mount/working directory '{}' matches session directory",
                                matched_path
                            ));
                        }
                        if shared_port_link {
                            ev.push(format!("Communicates on shared port {}", linked_port));
                        }
                        claims.push(CandidateClaim {
                            session_id: sess.id.clone(),
                            confidence: Confidence::Inferred,
                            evidence: ev,
                            creation_outcome: CreationOutcome::Succeeded,
                            attribution_basis: AttributionBasis::VerifiedSuccessfulCreation,
                        });
                    }
                    CreationOutcome::Unknown => {
                        // Creation operation outcome is unknown.
                        // Preserve appropriately qualified inferred attribution.
                        // Never elevate to Confirmed or HighConfidence in this read-only milestone.
                        let mut ev = vec![format!(
                            "Session process (PID {}) attempted container command (execution outcome is unknown): {}",
                            pid, cmd_info
                        )];
                        if created_during_session {
                            ev.push(format!(
                                "Container created during active session window ({})",
                                session_start.format("%H:%M:%S")
                            ));
                        }
                        if mount_or_cwd_matched {
                            ev.push(format!(
                                "Bind mount/working directory '{}' matches session directory",
                                matched_path
                            ));
                        }
                        if shared_port_link {
                            ev.push(format!("Communicates on shared port {}", linked_port));
                        }
                        claims.push(CandidateClaim {
                            session_id: sess.id.clone(),
                            confidence: Confidence::Inferred,
                            evidence: ev,
                            creation_outcome: CreationOutcome::Unknown,
                            attribution_basis: AttributionBasis::AttemptedCreation,
                        });
                    }
                }
            } else if created_during_session && mount_or_cwd_matched && shared_port_link {
                // Multi-signal non-command: creation window + mount/cwd + shared port -> Inferred
                claims.push(CandidateClaim {
                    session_id: sess.id.clone(),
                    confidence: Confidence::Inferred,
                    evidence: vec![
                        format!(
                            "Container created during active session window ({})",
                            session_start.format("%H:%M:%S")
                        ),
                        format!(
                            "Bind mount/working directory '{}' matches session directory",
                            matched_path
                        ),
                        format!("Communicates on shared port {}", linked_port),
                    ],
                    creation_outcome: CreationOutcome::Unknown,
                    attribution_basis: AttributionBasis::InferredSignals,
                });
            } else if created_during_session && shared_port_link {
                claims.push(CandidateClaim {
                    session_id: sess.id.clone(),
                    confidence: Confidence::Inferred,
                    evidence: vec![
                        format!(
                            "Created during active session window ({})",
                            session_start.format("%H:%M:%S")
                        ),
                        format!("Shares port {} with session process", linked_port),
                    ],
                    creation_outcome: CreationOutcome::Unknown,
                    attribution_basis: AttributionBasis::InferredSignals,
                });
            } else if created_during_session && mount_or_cwd_matched {
                claims.push(CandidateClaim {
                    session_id: sess.id.clone(),
                    confidence: Confidence::Inferred,
                    evidence: vec![
                        format!(
                            "Created during active session window ({})",
                            session_start.format("%H:%M:%S")
                        ),
                        format!(
                            "Bind mount or working directory '{}' matches session path",
                            matched_path
                        ),
                    ],
                    creation_outcome: CreationOutcome::Unknown,
                    attribution_basis: AttributionBasis::InferredSignals,
                });
            }
            // Note: Rule 3 strictly forbids mount_or_cwd_matched, shared_port_link,
            // or created_during_session from independently establishing ownership.
        }

        // RESOLVE CANDIDATE CLAIMS & DETECT CONFLICTS
        if claims.is_empty() {
            if let Some((sid, prev_conf)) = existing_attribution {
                // Rule: Preserve historical associations after containers exit or stop.
                // The container was created by this active session in an earlier cycle.
                container.session_id = Some(sid.clone());
                container.conflicting_sessions.clear();
                container.confidence = prev_conf
                    .min(Confidence::Inferred)
                    .max(Confidence::Inferred);
                container.attribution_basis = AttributionBasis::HistoricalInferred;
                let msg = format!("Preserved historical attribution to session {}", sid);
                if !container
                    .evidence
                    .iter()
                    .any(|e| e.contains("historical") || e.contains("Retained"))
                {
                    container.evidence.push(msg);
                }
                return;
            }

            container.session_id = None;
            container.conflicting_sessions.clear();
            container.confidence = Confidence::Unknown;
            if let Some((pid, ref cmd_info)) = failed_attempt_rejection {
                container.creation_outcome = CreationOutcome::Failed;
                container.attribution_basis = AttributionBasis::VerifiedFailedCreation;
                container.evidence = vec![format!(
                    "Session process (PID {}) creation operation verified failed; association rejected: {}",
                    pid, cmd_info
                )];
            } else {
                container.creation_outcome = CreationOutcome::Unknown;
                container.attribution_basis = AttributionBasis::None;
                container.evidence.clear();
            }
            return;
        }

        // Find highest confidence level among claims
        let highest_level = claims
            .iter()
            .map(|c| c.confidence)
            .max_by_key(|conf| match conf {
                Confidence::Confirmed => 3,
                Confidence::HighConfidence => 2,
                Confidence::Inferred => 1,
                Confidence::Unknown => 0,
            })
            .unwrap_or(Confidence::Unknown);

        // Filter to claims at highest confidence
        let mut top_claims: Vec<CandidateClaim> = claims
            .into_iter()
            .filter(|c| c.confidence == highest_level)
            .collect();

        // Deduplicate claims by session_id
        top_claims.sort_by(|a, b| a.session_id.cmp(&b.session_id));
        top_claims.dedup_by(|a, b| a.session_id == b.session_id);

        if top_claims.len() > 1 {
            // CONFLICT DETECTED: Multiple sessions claim the resource at the same confidence level!
            let conflict_ids: Vec<String> =
                top_claims.iter().map(|c| c.session_id.clone()).collect();
            container.session_id = None;
            container.conflicting_sessions = conflict_ids.clone();
            container.confidence = Confidence::Unknown;
            container.creation_outcome = CreationOutcome::Unknown;
            container.attribution_basis = AttributionBasis::None;
            container.evidence = vec![format!(
                "Conflicting session claims detected between sessions: {}",
                conflict_ids.join(", ")
            )];
        } else {
            // Exactly one session has the top claim
            let claim = top_claims.remove(0);
            container.session_id = Some(claim.session_id);
            container.conflicting_sessions.clear();
            container.confidence = claim.confidence;
            container.evidence = claim.evidence;
            container.creation_outcome = claim.creation_outcome;
            container.attribution_basis = claim.attribution_basis;
        }
    }
}
