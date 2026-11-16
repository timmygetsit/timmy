use crate::model::agent::Confidence;
use crate::model::process::ProcessInfo;
use crate::model::provenance::{normalize_path, IdentityMatchResult, ProvenanceSource};
use crate::model::service::{LaunchdPlistDetail, LaunchdRuntimeInfo, ServiceInfo, ServiceState};
use crate::model::session::{SessionInfo, SessionStatus};
use std::collections::HashMap;

/// Candidate session attribution claim for a launchd service.
#[derive(Debug)]
struct CandidateClaim<'a> {
    session_id: String,
    is_active: bool,
    is_verified_root: bool,
    is_unverified_root: bool,
    is_direct_tracked: bool,
    is_ancestry: bool,
    provenance_source: Option<ProvenanceSource>,
    reason: String,
    #[allow(dead_code)]
    session: &'a SessionInfo,
}

/// Coordinates service discovery, plist parsing, runtime state reconciliation,
/// and AI agent session attribution.
pub struct ServiceDiscoveryCoordinator;

impl ServiceDiscoveryCoordinator {
    /// Discovers background services using the platform's service collector.
    pub fn discover_services(
        collector: &dyn crate::platform::traits::ServiceCollector,
    ) -> Result<Vec<ServiceInfo>, crate::platform::traits::PlatformError> {
        collector.collect_services()
    }

    /// Reconciles on-disk launchd plist metadata with live runtime inspection.
    pub fn reconcile_service(
        plist_detail: Option<LaunchdPlistDetail>,
        runtime_info: Option<LaunchdRuntimeInfo>,
    ) -> (ServiceState, Option<u32>, Option<i32>) {
        match (plist_detail, runtime_info) {
            (Some(_plist), Some(runtime)) => {
                if runtime.is_loaded {
                    if let Some(pid) = runtime.pid {
                        (ServiceState::Running, Some(pid), runtime.last_exit_status)
                    } else if let Some(code) = runtime.last_exit_status {
                        (ServiceState::NotRunning, None, Some(code))
                    } else {
                        (ServiceState::Loaded, None, None)
                    }
                } else {
                    (ServiceState::DiscoveredOnDisk, None, None)
                }
            }
            (Some(_plist), None) => (ServiceState::DiscoveredOnDisk, None, None),
            (None, Some(runtime)) => {
                if runtime.is_loaded {
                    if let Some(pid) = runtime.pid {
                        (ServiceState::Running, Some(pid), runtime.last_exit_status)
                    } else {
                        (ServiceState::Loaded, None, runtime.last_exit_status)
                    }
                } else {
                    (ServiceState::Unknown, None, None)
                }
            }
            (None, None) => (ServiceState::Unknown, None, None),
        }
    }

    /// Correlates discovered launchd services with live system processes and active/historical AI sessions.
    ///
    /// CONSERVATIVE ATTRIBUTION & PROVENANCE POLICY:
    /// - `Confidence::Confirmed`: Permitted ONLY when structured, reliable evidence binds the exact
    ///   process identity (PID + non-null start time + process name + canonical executable) to the
    ///   session's explicitly selected root process (VerifiedSessionRootBinding).
    ///   Descendants, dev servers, or services spawned during the session NEVER receive Confirmed.
    /// - `Confidence::HighConfidence`: Permitted when unverified root process matches PID and binary with
    ///   non-null start time, OR multi-domain corroboration confirms ownership.
    ///   CRITICAL: Matching PPID plus executable similarity alone does NOT produce HighConfidence!
    /// - `Confidence::Inferred`: Permitted for ancestry alone (discovered descendant with matching PPID and
    ///   executable), heuristic associations (dev servers on ports), historical associations from
    ///   stopped sessions, or any process lacking a verified start time.
    /// - `Confidence::Unknown`: Required when multiple sessions conflict, when PID reuse is detected,
    ///   or when a process has an agent binary but no owning session.
    pub fn correlate_services(
        services: &mut [ServiceInfo],
        processes: &[ProcessInfo],
        sessions: &[SessionInfo],
    ) {
        let mut pid_to_proc: HashMap<u32, &ProcessInfo> = HashMap::new();
        for p in processes {
            pid_to_proc.insert(p.pid, p);
        }

        for service in services.iter_mut() {
            let mut evidence = Vec::new();
            let mut session_id = None;
            let mut confidence = Confidence::Unknown;

            // Descriptive keyword detection in service label or name
            let agent_keywords = [
                ("claude", "Claude Code"),
                ("cursor", "Cursor"),
                ("gemini", "Gemini CLI"),
                ("copilot", "GitHub Copilot"),
                ("codex", "OpenAI Codex"),
            ];
            for (kw, agent_name) in &agent_keywords {
                if service.label.to_lowercase().contains(kw)
                    || service.name.to_lowercase().contains(kw)
                {
                    evidence.push(format!(
                        "Descriptive evidence only: service name/label contains keyword '{}' (suggesting association with {}); does not establish active runtime session ownership",
                        kw, agent_name
                    ));
                    break;
                }
            }

            let matched_proc = service.pid.and_then(|pid| pid_to_proc.get(&pid).copied());

            if let Some(proc) = matched_proc {
                evidence.push(format!(
                    "Live process PID {} matched service runtime PID ({})",
                    proc.pid, proc.name
                ));
                evidence.push(format!(
                    "Process identity verified: PID {} ({}) matches launchd runtime job",
                    proc.pid, proc.name
                ));
            }

            if let Some(svc_exe) = service.executable_or_program() {
                let norm_svc = normalize_path(std::path::Path::new(svc_exe));
                let matches_any_proc = processes.iter().any(|p| {
                    if let Some(ref p_exe) = p.exe {
                        let norm_p = normalize_path(p_exe);
                        norm_p == norm_svc || p_exe.to_string_lossy() == svc_exe
                    } else {
                        p.name.eq_ignore_ascii_case(
                            std::path::Path::new(svc_exe)
                                .file_name()
                                .and_then(|f| f.to_str())
                                .unwrap_or(""),
                        )
                    }
                });
                if matches_any_proc {
                    evidence.push(format!(
                        "Supporting evidence: executable matches running process ('{}')",
                        svc_exe
                    ));
                    evidence.push("Supporting evidence: executable path match".to_string());
                }
            }

            let mut candidate_claims = Vec::new();

            for sess in sessions {
                let sess_start_secs = sess.start_time.timestamp().max(0) as u64;

                // Check temporal boundaries if process start time is known:
                // Guard against PID reuse and pre-existing daemons!
                if let Some(proc) = matched_proc {
                    if let Some(proc_start) = proc.start_time {
                        // Allow small clock skew (5 seconds)
                        if proc_start < sess_start_secs.saturating_sub(5) {
                            // Process existed BEFORE session was created!
                            evidence.push(format!(
                                "Temporal check: process start time ({}) predates session '{}' start time ({}); session claim rejected (PID reuse / pre-existing daemon)",
                                proc_start, sess.id, sess_start_secs
                            ));
                            continue;
                        }
                        if let Some(end_time) = sess.end_time {
                            let sess_end_secs = end_time.timestamp().max(0) as u64;
                            if proc_start > sess_end_secs.saturating_add(5) {
                                // Process started AFTER session was terminated!
                                evidence.push(format!(
                                    "Temporal check: process start time ({}) postdates session '{}' end time ({}); session claim rejected (PID reuse)",
                                    proc_start, sess.id, sess_end_secs
                                ));
                                continue;
                            }
                        }
                    }
                }

                let mut claims = false;
                let mut is_verified_root = false;
                let mut is_unverified_root = false;
                let mut is_direct_tracked = false;
                let mut is_ancestry = false;
                let mut provenance_source = None;
                let mut claim_reason = String::new();

                // 1. Root process claim
                if let Some(spid) = service.pid {
                    if sess.root_pid == Some(spid) {
                        if let Some(ref root_b) = sess.root_binding {
                            if let Some(proc) = matched_proc {
                                match root_b.verify_process_identity(proc) {
                                    IdentityMatchResult::ExactMatch => {
                                        claims = true;
                                        is_verified_root = true;
                                        provenance_source =
                                            Some(ProvenanceSource::VerifiedSessionRootBinding);
                                        claim_reason = format!(
                                            "Service PID {} matches verified session root binding",
                                            spid
                                        );
                                    }
                                    IdentityMatchResult::MissingStartTime => {
                                        claims = true;
                                        is_unverified_root = true;
                                        claim_reason = format!(
                                            "Service PID {} matches session root PID and executable, but lacks verified start time",
                                            spid
                                        );
                                        evidence.push(format!(
                                            "Identity limitation: service PID {} matches session root PID, but process start time is unavailable; cannot disprove PID recycling (capped at Inferred)",
                                            spid
                                        ));
                                    }
                                    IdentityMatchResult::StartTimeMismatch => {
                                        evidence.push(format!(
                                            "PID reuse check: service PID {} matches session root PID, but process start time ({:?} vs {:?}) differs from verified root binding; session claim rejected",
                                            spid, proc.start_time, root_b.process.start_time
                                        ));
                                        continue;
                                    }
                                    IdentityMatchResult::BinaryMismatch => {
                                        evidence.push(format!(
                                            "PID reuse check: service PID {} matches session root PID, but process binary ('{}' vs '{}') differs from verified root binding; session claim rejected",
                                            spid, proc.name, root_b.process.name
                                        ));
                                        continue;
                                    }
                                    IdentityMatchResult::PidMismatch => {
                                        continue;
                                    }
                                }
                            } else {
                                claims = true;
                                is_unverified_root = true;
                                claim_reason = format!(
                                    "Service PID {} claimed by session root PID (unverified process)",
                                    spid
                                );
                            }
                        } else {
                            claims = true;
                            is_unverified_root = true;
                            claim_reason = format!(
                                "Service PID {} claimed by session root PID (no structured root binding)",
                                spid
                            );
                        }
                    }
                }

                // 2. Direct tracked process claim
                if !claims {
                    if let Some(spid) = service.pid {
                        if sess.tracked_pids.contains(&spid) {
                            if let Some(proc) = matched_proc {
                                if let Some(ref prov) = proc.provenance {
                                    if prov.session_id == sess.id {
                                        match prov.verify_process_identity(proc) {
                                            IdentityMatchResult::ExactMatch
                                            | IdentityMatchResult::MissingStartTime => {
                                                claims = true;
                                                is_direct_tracked = true;
                                                provenance_source = Some(prov.source);
                                                claim_reason = format!(
                                                    "Service PID {} is tracked by session",
                                                    spid
                                                );
                                            }
                                            IdentityMatchResult::StartTimeMismatch
                                            | IdentityMatchResult::BinaryMismatch => {
                                                evidence.push(format!(
                                                    "PID reuse check: service PID {} was tracked by session '{}', but current process identity differs from recorded provenance; session claim rejected",
                                                    spid, sess.id
                                                ));
                                                continue;
                                            }
                                            IdentityMatchResult::PidMismatch => {}
                                        }
                                    }
                                }
                            }
                            if !claims {
                                claims = true;
                                is_direct_tracked = true;
                                claim_reason =
                                    format!("Service PID {} is tracked by session", spid);
                            }
                        }
                    }
                }

                // 3. Process tree ancestry claim
                if !claims {
                    if let Some(proc) = matched_proc {
                        if let Some(ppid) = proc.ppid {
                            if sess.root_pid == Some(ppid) {
                                claims = true;
                                is_ancestry = true;
                                claim_reason = format!(
                                    "Service process PID {} is child of session root PID {}",
                                    proc.pid, ppid
                                );
                                provenance_source = proc
                                    .provenance
                                    .as_ref()
                                    .map(|p| p.source)
                                    .or(Some(ProvenanceSource::DiscoveredDescendant));
                            } else if sess.tracked_pids.contains(&ppid) {
                                claims = true;
                                is_ancestry = true;
                                claim_reason = format!(
                                    "Service process PID {} is child of tracked session process PID {}",
                                    proc.pid, ppid
                                );
                                provenance_source = proc
                                    .provenance
                                    .as_ref()
                                    .map(|p| p.source)
                                    .or(Some(ProvenanceSource::DiscoveredDescendant));
                            }
                        }
                    }
                }

                if claims {
                    candidate_claims.push(CandidateClaim {
                        session_id: sess.id.clone(),
                        is_active: sess.status == SessionStatus::Active,
                        is_verified_root,
                        is_unverified_root,
                        is_direct_tracked,
                        is_ancestry,
                        provenance_source,
                        reason: claim_reason,
                        session: sess,
                    });
                }
            }

            // 5. Resolve attribution confidence and conflicting claims
            if candidate_claims.len() > 1 {
                let ids: Vec<String> = candidate_claims
                    .iter()
                    .map(|c| c.session_id.clone())
                    .collect();
                evidence.push(format!(
                    "Conflicting attribution: multiple sessions claim this service ({}); ownership unresolved",
                    ids.join(", ")
                ));
                // Multi-session conflict: ownership must remain unassigned and Unknown
                confidence = Confidence::Unknown;
                session_id = None;
            } else if candidate_claims.len() == 1 {
                let claim = &candidate_claims[0];
                evidence.push(format!(
                    "Session correlation: {} (Session '{}')",
                    claim.reason, claim.session_id
                ));
                session_id = Some(claim.session_id.clone());

                if !claim.is_active {
                    // Stale or stopped sessions can never produce Confirmed or HighConfidence ownership
                    confidence = Confidence::Inferred;
                    evidence.push("Historical association: session is stopped/completed; confidence capped at Inferred".to_string());
                } else {
                    let exe_matches = if let (Some(svc_exe), Some(proc)) =
                        (service.executable_or_program(), matched_proc)
                    {
                        proc.exe
                            .as_ref()
                            .map(|e| {
                                let norm_proc = normalize_path(e);
                                let norm_svc = normalize_path(std::path::Path::new(svc_exe));
                                norm_proc == norm_svc || e.to_string_lossy() == svc_exe
                            })
                            .unwrap_or_else(|| {
                                std::path::Path::new(svc_exe)
                                    .file_name()
                                    .and_then(|f| f.to_str())
                                    .map(|f| f.eq_ignore_ascii_case(&proc.name))
                                    .unwrap_or(false)
                            })
                    } else {
                        false
                    };

                    let proc_confidence = matched_proc
                        .map(|p| p.attribution.confidence)
                        .unwrap_or(Confidence::Unknown);

                    let has_proc_start_time = matched_proc.and_then(|p| p.start_time).is_some();

                    // Structured launch provenance check:
                    let has_observed_launch = matches!(
                        claim.provenance_source,
                        Some(ProvenanceSource::ObservedSpawn)
                            | Some(ProvenanceSource::ObservedExec)
                    );

                    let is_confirmed_candidate = (claim.is_verified_root || has_observed_launch)
                        && exe_matches
                        && proc_confidence == Confidence::Confirmed
                        && has_proc_start_time;

                    if is_confirmed_candidate {
                        // Confirmed: ONLY when structured, reliable evidence binds the exact root process identity
                        // (with verified non-null start time, matching executable, and confirmed agent signature)
                        // to the session's selected root process.
                        confidence = Confidence::Confirmed;
                        if claim.is_verified_root {
                            evidence.push("Confirmed ownership: service PID and executable match verified session root process identity".to_string());
                        } else {
                            evidence.push("Confirmed ownership: supervisor observed process launch event with confirmed agent identity".to_string());
                        }
                    } else if claim.provenance_source
                        == Some(ProvenanceSource::HeuristicAssociation)
                    {
                        // Heuristically tracked processes (e.g. dev servers on ports) must NEVER be Confirmed or HighConfidence
                        confidence = Confidence::Inferred;
                        evidence.push("Provenance guard: tracked process attribution basis is HeuristicAssociation; confidence capped at Inferred".to_string());
                    } else if !has_proc_start_time {
                        // Missing start time prevents disproving PID recycling
                        confidence = Confidence::Inferred;
                        evidence.push("Identity limitation: process start time is unavailable; cannot disprove PID recycling; confidence capped at Inferred".to_string());
                    } else if proc_confidence <= Confidence::Inferred && !claim.is_verified_root {
                        // Process attribution is weak/inferred; must be capped at Inferred
                        confidence = Confidence::Inferred;
                        evidence.push(format!(
                            "Provenance guard: process attribution basis is {:?}; confidence capped at Inferred",
                            proc_confidence
                        ));
                    } else if claim.is_unverified_root {
                        // Unverified root PID: Session has root PID without a structured VerifiedSessionRootBinding.
                        // Even if the live process has a non-null start time and confirmed agent attribution,
                        // the session stores no independently recorded root start time to compare against.
                        // Therefore, PID recycling cannot be disproven and ownership is not verified.
                        // Confidence is strictly capped at Inferred.
                        confidence = Confidence::Inferred;
                        if !has_proc_start_time {
                            if !evidence
                                .iter()
                                .any(|e| e.contains("process start time is unavailable"))
                            {
                                evidence.push("Identity limitation: process start time is unavailable; cannot disprove PID recycling; confidence capped at Inferred".to_string());
                            }
                            evidence.push("Unverified root binding: session has root PID without structured binding event; confidence capped at Inferred".to_string());
                        } else {
                            evidence.push("Unverified root binding: service PID matches session root PID, but session lacks an independently recorded root process identity or start time; confidence capped at Inferred (PID recycling cannot be disproven)".to_string());
                        }
                    } else if claim.is_ancestry || claim.is_direct_tracked {
                        // CRITICAL RULE: Matching PPID plus executable similarity alone does NOT constitute
                        // multiple independent evidence domains (the executable name and binary signature are
                        // the same artifact, and PPID is a single snapshot pointer). Capped at Inferred!
                        confidence = Confidence::Inferred;
                        evidence.push("Ancestry-only discovery: process tree ancestry (PPID) plus executable similarity alone does not constitute multi-domain independent evidence; confidence capped at Inferred".to_string());
                    } else {
                        confidence = Confidence::Inferred;
                    }
                }
            } else if let Some(proc) = matched_proc {
                // If not claimed by a recorded session, but running process has confirmed agent attribution
                if proc.attribution.confidence == Confidence::Confirmed {
                    confidence = Confidence::Unknown;
                    evidence.push(format!(
                        "Descriptive observation: running process PID {} ({}) attributed to agent binary, but no registered session owns this service; ownership remains unassigned",
                        proc.pid, proc.attribution.kind
                    ));
                }
            }

            service.session_id = session_id;
            service.confidence = confidence;
            service.evidence = evidence;
        }
    }
}
