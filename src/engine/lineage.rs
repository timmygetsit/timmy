use crate::model::lineage::{LineageChainResult, LineageStatus, ProcessLineageEdge};
use crate::model::process::{
    ProcessIncarnation, ProcessInfo, ProcessSnapshot, ProcessStartTime, SnapshotCompleteness,
};
use crate::model::provenance::LaunchProvenance;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use thiserror::Error;

/// Validation error preventing the establishment of a parent-child lineage edge.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LineageValidationError {
    #[error("Missing microsecond-precision start time for process PID {pid}")]
    MissingStartTime { pid: u32 },
    #[error("Parent process PID {parent_pid} (started {parent_st}) was born after child PID {child_pid} (started {child_st})")]
    ParentStartedAfterChild {
        parent_pid: u32,
        parent_st: ProcessStartTime,
        child_pid: u32,
        child_st: ProcessStartTime,
    },
    #[error("Child process PID {child_pid} PPID ({actual_ppid:?}) does not match parent PID {parent_pid}")]
    PpidMismatch {
        child_pid: u32,
        actual_ppid: Option<u32>,
        parent_pid: u32,
    },
    #[error("Invalid parent PID {parent_pid}: kernel and init processes (PID <= 1) cannot form lineage edges")]
    InvalidParentPid { parent_pid: u32 },
    #[error("Observation snapshot is not complete ({completeness:?})")]
    IncompleteSnapshot { completeness: SnapshotCompleteness },
}

/// Validates whether a parent-child process relationship meets all required integrity constraints.
pub fn validate_lineage_edge(
    parent: &ProcessInfo,
    child: &ProcessInfo,
    is_complete_snapshot: bool,
) -> Result<(), LineageValidationError> {
    if !is_complete_snapshot {
        return Err(LineageValidationError::IncompleteSnapshot {
            completeness: SnapshotCompleteness::Truncated {
                returned_count: 0,
                capacity: 0,
            },
        });
    }

    if parent.pid <= 1 {
        return Err(LineageValidationError::InvalidParentPid {
            parent_pid: parent.pid,
        });
    }

    if child.ppid != Some(parent.pid) {
        return Err(LineageValidationError::PpidMismatch {
            child_pid: child.pid,
            actual_ppid: child.ppid,
            parent_pid: parent.pid,
        });
    }

    let parent_st = parent
        .start_time_precise
        .ok_or(LineageValidationError::MissingStartTime { pid: parent.pid })?;

    let child_st = child
        .start_time_precise
        .ok_or(LineageValidationError::MissingStartTime { pid: child.pid })?;

    if parent_st > child_st {
        return Err(LineageValidationError::ParentStartedAfterChild {
            parent_pid: parent.pid,
            parent_st,
            child_pid: child.pid,
            child_st,
        });
    }

    Ok(())
}

/// Extracts verified parent-child lineage edges from a complete process snapshot.
///
/// Only complete, non-truncated snapshots are processed. Partial or truncated snapshots
/// return an empty vector, preventing false absence or premature edge creation.
pub fn extract_snapshot_lineage_edges(
    session_id: &str,
    session_root_pid: Option<u32>,
    session_root_binding: Option<&LaunchProvenance>,
    snapshot: &ProcessSnapshot,
    existing_edges: &[ProcessLineageEdge],
    snapshot_id: Option<i64>,
) -> Vec<ProcessLineageEdge> {
    if snapshot.completeness != SnapshotCompleteness::Complete {
        return Vec::new();
    }

    let current_pid = std::process::id();
    let now = Utc::now();
    let mut extracted = Vec::new();

    // Map live processes by PID
    let live_map: HashMap<u32, &ProcessInfo> =
        snapshot.processes.iter().map(|p| (p.pid, p)).collect();

    // Map parent PID to children
    let mut parent_to_children: HashMap<u32, Vec<&ProcessInfo>> = HashMap::new();
    for proc in &snapshot.processes {
        if let Some(ppid) = proc.ppid {
            if ppid > 1 {
                parent_to_children.entry(ppid).or_default().push(proc);
            }
        }
    }

    // Determine initial set of known session process incarnations
    let mut known_session_pids: HashSet<u32> = HashSet::new();

    // 1. Root PID
    if let Some(rpid) = session_root_pid {
        if let Some(root_proc) = live_map.get(&rpid) {
            let is_valid_root = if let Some(binding) = session_root_binding {
                binding.matches_process(root_proc)
            } else {
                true
            };
            if is_valid_root {
                known_session_pids.insert(rpid);
            }
        }
    }

    // 2. Existing edges (parents and children that are active with matching incarnation)
    for edge in existing_edges {
        if let Some(live_parent) = live_map.get(&edge.parent.pid) {
            if live_parent.start_time_precise == Some(edge.parent.start_time) {
                known_session_pids.insert(edge.parent.pid);
            }
        }
        if let Some(live_child) = live_map.get(&edge.child.pid) {
            if live_child.start_time_precise == Some(edge.child.start_time) {
                known_session_pids.insert(edge.child.pid);
            }
        }
    }

    // 3. BFS traversal to discover all descendant edges originating from known session processes
    let mut queue: Vec<u32> = known_session_pids.iter().copied().collect();
    let mut visited_edges: HashSet<(u32, u32)> = HashSet::new();

    while let Some(parent_pid) = queue.pop() {
        if let Some(parent_proc) = live_map.get(&parent_pid) {
            if parent_proc.pid == current_pid || parent_proc.name.eq_ignore_ascii_case("timmy") {
                continue;
            }

            if let Some(children) = parent_to_children.get(&parent_pid) {
                for child_proc in children {
                    if child_proc.pid == current_pid
                        || child_proc.name.eq_ignore_ascii_case("timmy")
                    {
                        continue;
                    }

                    if visited_edges.contains(&(parent_pid, child_proc.pid)) {
                        continue;
                    }
                    visited_edges.insert((parent_pid, child_proc.pid));

                    if validate_lineage_edge(parent_proc, child_proc, true).is_ok() {
                        let parent_inc = ProcessIncarnation::new(
                            parent_proc.pid,
                            parent_proc.start_time_precise.unwrap(),
                        );
                        let child_inc = ProcessIncarnation::new(
                            child_proc.pid,
                            child_proc.start_time_precise.unwrap(),
                        );

                        let edge = ProcessLineageEdge::new_snapshot_edge(
                            session_id.to_string(),
                            parent_inc,
                            child_inc,
                            Some(parent_proc.name.clone()),
                            parent_proc.exe.clone(),
                            child_proc.name.clone(),
                            child_proc.exe.clone(),
                            now,
                            snapshot_id,
                        );

                        extracted.push(edge);
                        queue.push(child_proc.pid);
                    }
                }
            }
        }
    }

    extracted
}

/// Evaluates and transitions the lifecycle statuses of existing recorded lineage edges.
///
/// If a parent has exited and the child is observed active under PPID 1, transitions the
/// edge status to `ReparentedToPid1`.
/// If the snapshot is partial or truncated, returns an empty vector without altering statuses.
pub fn update_edge_lifecycle_statuses(
    snapshot: &ProcessSnapshot,
    existing_edges: &[ProcessLineageEdge],
) -> Vec<ProcessLineageEdge> {
    if snapshot.completeness != SnapshotCompleteness::Complete {
        return Vec::new();
    }

    let live_map: HashMap<u32, &ProcessInfo> =
        snapshot.processes.iter().map(|p| (p.pid, p)).collect();

    let mut updated = Vec::new();

    for edge in existing_edges {
        let parent_active = live_map
            .get(&edge.parent.pid)
            .map(|p| p.start_time_precise == Some(edge.parent.start_time))
            .unwrap_or(false);

        let live_child = live_map.get(&edge.child.pid);
        let child_active = live_child
            .map(|c| c.start_time_precise == Some(edge.child.start_time))
            .unwrap_or(false);

        let new_status = if parent_active && child_active {
            LineageStatus::BothActive
        } else if !parent_active && child_active {
            if live_child.map(|c| c.ppid == Some(1)).unwrap_or(false) {
                LineageStatus::ReparentedToPid1
            } else {
                LineageStatus::ParentExited
            }
        } else {
            LineageStatus::BothExited
        };

        if edge.status != new_status {
            let mut edge_clone = edge.clone();
            edge_clone.status = new_status;
            edge_clone.last_observed_at = Utc::now();
            updated.push(edge_clone);
        }
    }

    updated
}

/// Walks recorded lineage edges backwards from a candidate process to the session root.
///
/// Resolves whether an unbroken chain exists and determines whether all intermediate
/// processes are active (`Confirmed`) or one or more have exited (`HighConfidence`).
pub fn resolve_lineage_chain(
    session_root_pid: Option<u32>,
    session_root_binding: Option<&LaunchProvenance>,
    candidate: &ProcessInfo,
    live_procs: &[ProcessInfo],
    lineage_edges: &[ProcessLineageEdge],
) -> LineageChainResult {
    // 1. Check if candidate is the session root itself
    let is_candidate_root = if let Some(rpid) = session_root_pid {
        candidate.pid == rpid
    } else if let Some(binding) = session_root_binding {
        candidate.pid == binding.process.pid
    } else {
        false
    };

    if is_candidate_root {
        if let Some(binding) = session_root_binding {
            let match_res = binding.verify_process_identity(candidate);
            if match_res.is_exact() {
                let precise = candidate
                    .start_time_precise
                    .unwrap_or_else(|| ProcessStartTime::new(candidate.start_time.unwrap_or(0), 0));
                return LineageChainResult::UnbrokenAllActive {
                    root: ProcessIncarnation::new(candidate.pid, precise),
                    chain: Vec::new(),
                };
            } else if match_res.is_recycled_or_mismatch() {
                return LineageChainResult::IdentityMismatch {
                    details: format!(
                        "Root candidate PID {} matches root PID but identity failed: {:?}",
                        candidate.pid, match_res
                    ),
                };
            } else {
                // Missing start time; cannot verify root binding
                return LineageChainResult::NoRecordedParentEdge {
                    target: ProcessIncarnation::new(
                        candidate.pid,
                        candidate.start_time_precise.unwrap_or_else(|| {
                            ProcessStartTime::new(candidate.start_time.unwrap_or(0), 0)
                        }),
                    ),
                };
            }
        } else {
            // Root PID exists but NO independent root binding was stored
            return LineageChainResult::NoRecordedParentEdge {
                target: ProcessIncarnation::new(
                    candidate.pid,
                    candidate.start_time_precise.unwrap_or_else(|| {
                        ProcessStartTime::new(candidate.start_time.unwrap_or(0), 0)
                    }),
                ),
            };
        }
    }

    // 2. Candidate must have microsecond-precision start time to establish verified incarnation
    let child_st = match candidate.start_time_precise {
        Some(st) => st,
        None => {
            return LineageChainResult::NoRecordedParentEdge {
                target: ProcessIncarnation::new(
                    candidate.pid,
                    ProcessStartTime::new(candidate.start_time.unwrap_or(0), 0),
                ),
            };
        }
    };

    let target_inc = ProcessIncarnation::new(candidate.pid, child_st);

    // Build live process map for quick incarnation verification
    let live_map: HashMap<u32, &ProcessInfo> = live_procs.iter().map(|p| (p.pid, p)).collect();

    // 3. Walk backwards through lineage edges
    let mut current_inc = target_inc;
    let mut chain = Vec::new();
    let mut visited = HashSet::new();
    visited.insert(current_inc);

    loop {
        // Find recorded parent edges for current_inc
        let parent_edges: Vec<&ProcessLineageEdge> = lineage_edges
            .iter()
            .filter(|e| e.child == current_inc)
            .collect();

        if parent_edges.is_empty() {
            if current_inc == target_inc {
                return LineageChainResult::NoRecordedParentEdge { target: target_inc };
            } else {
                return LineageChainResult::BrokenChain {
                    target: target_inc,
                    missing_parent_for: current_inc,
                };
            }
        }

        // Verify there is no conflicting parent evidence
        let first_parent = parent_edges[0].parent;
        for edge in &parent_edges[1..] {
            if edge.parent != first_parent {
                return LineageChainResult::ConflictingEvidence {
                    details: format!(
                        "Process {} has conflicting recorded parent incarnations: {} vs {}",
                        current_inc, first_parent, edge.parent
                    ),
                };
            }
        }

        let selected_edge = (*parent_edges[0]).clone();
        let parent_inc = selected_edge.parent;

        // Cycle detection
        if visited.contains(&parent_inc) {
            return LineageChainResult::ConflictingEvidence {
                details: format!("Cycle detected in process lineage involving {}", parent_inc),
            };
        }
        visited.insert(parent_inc);
        chain.push(selected_edge);

        // Check if parent_inc is the session root
        let is_root = if let Some(binding) = session_root_binding {
            if binding.process.pid == parent_inc.pid {
                if let Some(binding_precise) = binding.process.start_time_precise {
                    if binding_precise != parent_inc.start_time {
                        return LineageChainResult::IdentityMismatch {
                            details: format!(
                                "Parent PID {} has start time {} which differs from session root binding {}",
                                parent_inc.pid, parent_inc.start_time, binding_precise
                            ),
                        };
                    }
                    true
                } else if let Some(binding_st) = binding.process.start_time {
                    if binding_st != parent_inc.start_time.tv_sec {
                        return LineageChainResult::IdentityMismatch {
                            details: format!(
                                "Parent PID {} has coarse start time {} which differs from session root binding {}",
                                parent_inc.pid, parent_inc.start_time.tv_sec, binding_st
                            ),
                        };
                    }
                    true
                } else {
                    false
                }
            } else {
                false
            }
        } else if let Some(root_pid) = session_root_pid {
            parent_inc.pid == root_pid
        } else {
            false
        };

        if is_root {
            chain.reverse();

            // Check liveness of all ancestors along the chain
            let mut exited_ancestors = Vec::new();

            // Root liveness
            let root_alive = match live_map.get(&parent_inc.pid) {
                Some(p) => p.start_time_precise == Some(parent_inc.start_time),
                None => false,
            };
            if !root_alive {
                exited_ancestors.push(parent_inc);
            }

            // Intermediate ancestors liveness
            for edge in chain.iter().take(chain.len().saturating_sub(1)) {
                let ancestor = edge.child;
                let ancestor_alive = match live_map.get(&ancestor.pid) {
                    Some(p) => p.start_time_precise == Some(ancestor.start_time),
                    None => false,
                };
                if !ancestor_alive {
                    exited_ancestors.push(ancestor);
                }
            }

            if exited_ancestors.is_empty() {
                return LineageChainResult::UnbrokenAllActive {
                    root: parent_inc,
                    chain,
                };
            } else {
                return LineageChainResult::UnbrokenHistoricalWithExits {
                    root: parent_inc,
                    chain,
                    exited_ancestors,
                };
            }
        }

        current_inc = parent_inc;
    }
}

// ============================================================================
// Stage D: Hierarchical Lineage Tree Data Structures & Formatting
// ============================================================================

/// A node in the hierarchical process lineage tree for display in CLI and TUI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageTreeNode {
    pub pid: u32,
    pub start_time: ProcessStartTime,
    pub name: String,
    pub exe: Option<PathBuf>,
    pub status: LineageStatus,
    pub confidence: crate::model::Confidence,
    pub is_root: bool,
    pub is_detached: bool,
    pub ports: Vec<u16>,
    pub evidence: Vec<String>,
    pub is_active: bool,
    pub children: Vec<LineageTreeNode>,
}

/// Constructs a hierarchical process lineage tree from session records, tracked resources, and lineage edges.
pub fn build_session_lineage_tree(
    session: &crate::model::SessionInfo,
    resources: &[crate::model::TrackedResource],
    edges: &[ProcessLineageEdge],
    show_exited: bool,
) -> Vec<LineageTreeNode> {
    let mut res_by_pid: HashMap<u32, &crate::model::TrackedResource> = HashMap::new();
    for r in resources {
        if let Some(pid) = r.pid {
            res_by_pid.insert(pid, r);
        }
    }

    // Map of parent (pid, start_time) -> list of child edges
    let mut parent_to_edges: HashMap<(u32, ProcessStartTime), Vec<&ProcessLineageEdge>> =
        HashMap::new();
    for edge in edges {
        parent_to_edges
            .entry((edge.parent.pid, edge.parent.start_time))
            .or_default()
            .push(edge);
    }

    let mut included_pids: HashSet<u32> = HashSet::new();

    fn build_subtree(
        parent_inc: (u32, ProcessStartTime),
        parent_to_edges: &HashMap<(u32, ProcessStartTime), Vec<&ProcessLineageEdge>>,
        res_by_pid: &HashMap<u32, &crate::model::TrackedResource>,
        included_pids: &mut HashSet<u32>,
        show_exited: bool,
        visited_parents: &mut HashSet<(u32, ProcessStartTime)>,
    ) -> Vec<LineageTreeNode> {
        if visited_parents.contains(&parent_inc) {
            return Vec::new();
        }
        visited_parents.insert(parent_inc);

        let mut children_nodes = Vec::new();
        if let Some(child_edges) = parent_to_edges.get(&parent_inc) {
            for edge in child_edges {
                let child_pid = edge.child.pid;
                let child_st = edge.child.start_time;

                let live_res = res_by_pid.get(&child_pid).copied();
                let is_active = match live_res {
                    Some(r) => {
                        let res_st = r
                            .provenance
                            .as_ref()
                            .and_then(|p| p.process.start_time_precise);
                        match res_st {
                            Some(st) => st == child_st,
                            None => true,
                        }
                    }
                    None => false,
                };

                if is_active {
                    included_pids.insert(child_pid);
                }

                let sub_children = build_subtree(
                    (child_pid, child_st),
                    parent_to_edges,
                    res_by_pid,
                    included_pids,
                    show_exited,
                    visited_parents,
                );

                let has_active_descendant = is_active
                    || sub_children
                        .iter()
                        .any(|c| c.is_active || !c.children.is_empty());

                if !show_exited && !has_active_descendant {
                    continue;
                }

                let (name, exe, confidence, is_detached, ports, evidence) = match live_res {
                    Some(r) if is_active => (
                        r.name.clone(),
                        r.exe_path.as_ref().map(PathBuf::from),
                        r.confidence,
                        r.is_detached,
                        r.listening_ports.clone(),
                        r.evidence.clone(),
                    ),
                    _ => (
                        edge.child_name.clone(),
                        edge.child_exe.clone(),
                        crate::model::Confidence::HighConfidence,
                        false,
                        Vec::new(),
                        vec!["Historical intermediate process (exited)".to_string()],
                    ),
                };

                children_nodes.push(LineageTreeNode {
                    pid: child_pid,
                    start_time: child_st,
                    name,
                    exe,
                    status: edge.status,
                    confidence,
                    is_root: false,
                    is_detached,
                    ports,
                    evidence,
                    is_active,
                    children: sub_children,
                });
            }
        }

        children_nodes
    }

    let mut roots = Vec::new();
    let mut visited = HashSet::new();

    // 1. Root node if session has a root
    if let Some(r_pid) = session.root_pid {
        let root_st = session
            .root_binding
            .as_ref()
            .and_then(|b| b.process.start_time_precise)
            .or_else(|| {
                res_by_pid
                    .get(&r_pid)
                    .and_then(|r| r.provenance.as_ref())
                    .and_then(|p| p.process.start_time_precise)
            })
            .or_else(|| {
                edges
                    .iter()
                    .find(|e| e.parent.pid == r_pid)
                    .map(|e| e.parent.start_time)
            })
            .unwrap_or_else(|| ProcessStartTime::new(session.start_time.timestamp() as u64, 0));

        let live_root = res_by_pid.get(&r_pid).copied();
        let is_active = live_root.is_some();
        if is_active {
            included_pids.insert(r_pid);
        }

        let sub_children = build_subtree(
            (r_pid, root_st),
            &parent_to_edges,
            &res_by_pid,
            &mut included_pids,
            show_exited,
            &mut visited,
        );

        let (name, exe, confidence, ports, evidence) = match live_root {
            Some(r) => (
                r.name.clone(),
                r.exe_path.as_ref().map(PathBuf::from),
                r.confidence,
                r.listening_ports.clone(),
                r.evidence.clone(),
            ),
            None => (
                session
                    .root_process_name
                    .clone()
                    .unwrap_or_else(|| session.agent_kind.to_string()),
                session
                    .root_binding
                    .as_ref()
                    .and_then(|b| b.process.exe.clone()),
                session.confidence,
                Vec::new(),
                vec!["Session root agent process (exited)".to_string()],
            ),
        };

        if is_active || show_exited {
            roots.push(LineageTreeNode {
                pid: r_pid,
                start_time: root_st,
                name,
                exe,
                status: if is_active {
                    LineageStatus::BothActive
                } else {
                    LineageStatus::ParentExited
                },
                confidence,
                is_root: true,
                is_detached: false,
                ports,
                evidence,
                is_active,
                children: sub_children,
            });
        } else {
            for mut child in sub_children {
                child.is_detached = true;
                roots.push(child);
            }
        }
    }

    // 2. Any tracked resources not reached from root tree (e.g. unobserved orphans under PID 1)
    for r in resources {
        if let Some(pid) = r.pid {
            if !included_pids.contains(&pid) {
                let st = r
                    .provenance
                    .as_ref()
                    .and_then(|p| p.process.start_time_precise)
                    .unwrap_or_else(|| ProcessStartTime::new(r.process_start_time.unwrap_or(0), 0));

                let sub_children = build_subtree(
                    (pid, st),
                    &parent_to_edges,
                    &res_by_pid,
                    &mut included_pids,
                    show_exited,
                    &mut visited,
                );

                roots.push(LineageTreeNode {
                    pid,
                    start_time: st,
                    name: r.name.clone(),
                    exe: r.exe_path.as_ref().map(PathBuf::from),
                    status: if r.is_detached {
                        LineageStatus::ReparentedToPid1
                    } else {
                        LineageStatus::BothActive
                    },
                    confidence: r.confidence,
                    is_root: false,
                    is_detached: r.is_detached,
                    ports: r.listening_ports.clone(),
                    evidence: r.evidence.clone(),
                    is_active: true,
                    children: sub_children,
                });
            }
        }
    }

    roots
}

/// Formats the process lineage tree using standard Unicode box-drawing characters and secret masking.
pub fn format_lineage_tree_unicode(
    nodes: &[LineageTreeNode],
    secret_masker: &crate::safety::masker::SecretMasker,
) -> String {
    let mut out = String::new();

    fn render_nodes(
        nodes: &[LineageTreeNode],
        prefix: &str,
        secret_masker: &crate::safety::masker::SecretMasker,
        out: &mut String,
    ) {
        for (i, node) in nodes.iter().enumerate() {
            let is_last = i + 1 == nodes.len();
            let branch = if is_last { "└── " } else { "├── " };
            let child_prefix = if is_last { "    " } else { "│   " };

            let active_str = if node.is_active {
                "[ACTIVE]"
            } else {
                "[EXITED]"
            };

            let role_str = if node.is_root {
                " [ROOT]"
            } else if node.is_detached {
                " [Reparented to PID 1]"
            } else {
                ""
            };

            let masked_name = secret_masker.mask_sensitive_text(&node.name);
            out.push_str(&format!(
                "{}{}{} PID {} ({}){} - {}\n",
                prefix, branch, active_str, node.pid, masked_name, role_str, node.confidence
            ));

            let has_children = !node.children.is_empty();
            let ports_branch = if node.evidence.is_empty() && !has_children {
                "└── "
            } else {
                "├── "
            };

            if !node.ports.is_empty() {
                let ports_str = node
                    .ports
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                out.push_str(&format!(
                    "{}{}{}Ports: [{}]\n",
                    prefix, child_prefix, ports_branch, ports_str
                ));
            }

            if let Some(primary_ev) = node.evidence.first() {
                let ev_branch = if !has_children {
                    "└── "
                } else {
                    "├── "
                };
                let masked_ev = secret_masker.mask_sensitive_text(primary_ev);
                out.push_str(&format!(
                    "{}{}{}Evidence: {}\n",
                    prefix, child_prefix, ev_branch, masked_ev
                ));
            }

            let next_prefix = format!("{}{}", prefix, child_prefix);
            render_nodes(&node.children, &next_prefix, secret_masker, out);
        }
    }

    render_nodes(nodes, "", secret_masker, &mut out);
    out
}
