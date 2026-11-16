use crate::engine::{EngineOrchestrator, SystemSnapshot};
use crate::model::session::{CleanupRecommendation, SessionInfo, TrackedResource};
use crate::model::{
    ContainerDetail, ContainerInfo, ListeningPort, ProcessDetail, ProcessInfo, ServiceInfo,
};
use crate::ui::theme::Theme;
use crate::ui::views::{
    render_batch_confirm_modal, render_confirm_modal, render_detail_modal,
    render_docker_detail_modal, render_docker_table, render_port_table, render_process_table,
    render_service_detail_modal, render_service_table, render_session_modal, render_session_view,
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Sparkline, TableState, Tabs},
    Frame,
};
use std::collections::{HashSet, VecDeque};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveTab {
    Processes = 0,
    Ports = 1,
    Services = 2,
    Docker = 3,
    Sessions = 4,
}

#[derive(Debug, Clone)]
pub enum ActiveModal {
    None,
    Detail(Box<ProcessDetail>),
    ConfirmKill {
        process: Box<ProcessInfo>,
        force: bool,
    },
    ConfirmBatchKill {
        eligible: Vec<ProcessInfo>,
        blocked: Vec<(ProcessInfo, String)>,
        force: bool,
    },
    SessionInspect {
        session: Box<SessionInfo>,
        resources: Vec<TrackedResource>,
        recommendations: Vec<CleanupRecommendation>,
        lineage_tree: Vec<crate::engine::lineage::LineageTreeNode>,
        tree_text: String,
        active_tab: usize,
        scroll: usize,
    },
    DockerDetail(Box<ContainerDetail>),
    DockerDetailLoading {
        id: String,
        name: String,
    },
    ServiceDetail(Box<ServiceInfo>),
}

pub struct App {
    pub orchestrator: EngineOrchestrator,
    pub current_tab: ActiveTab,
    pub snapshot: SystemSnapshot,
    pub theme: Theme,
    pub process_table_state: TableState,
    pub port_table_state: TableState,
    pub service_table_state: TableState,
    pub docker_table_state: TableState,
    pub session_table_state: TableState,
    pub selected_session_resources: Vec<TrackedResource>,
    pub session_view_show_tree: bool,
    pub selected_session_tree: Option<String>,
    pub tagged_pids: HashSet<u32>,
    pub cpu_history: VecDeque<u64>,
    pub mem_history: VecDeque<u64>,
    pub modal: ActiveModal,
    pub filter_mode: bool,
    pub filter_query: String,
    pub status_message: Option<(String, bool)>, // (message, is_error)
    pub should_quit: bool,
    pub docker_worker: Option<std::sync::Arc<crate::platform::DockerBackgroundWorker>>,
    pub docker_generation: u64,
    pub service_worker: Option<std::sync::Arc<crate::platform::ServiceBackgroundWorker>>,
    pub service_generation: u64,
}

impl App {
    pub fn new(orchestrator: EngineOrchestrator) -> Self {
        let docker_worker = if orchestrator.is_docker_enabled() {
            Some(std::sync::Arc::new(
                crate::platform::DockerBackgroundWorker::new(
                    orchestrator.platform_docker_collector(),
                ),
            ))
        } else {
            None
        };

        let service_worker = Some(std::sync::Arc::new(
            crate::platform::ServiceBackgroundWorker::new(
                orchestrator.platform_service_collector(),
            ),
        ));

        let mut app = Self {
            orchestrator,
            current_tab: ActiveTab::Processes,
            snapshot: SystemSnapshot::default(),
            theme: Theme::default_dark(),
            process_table_state: TableState::default(),
            port_table_state: TableState::default(),
            service_table_state: TableState::default(),
            docker_table_state: TableState::default(),
            session_table_state: TableState::default(),
            selected_session_resources: Vec::new(),
            session_view_show_tree: false,
            selected_session_tree: None,
            tagged_pids: HashSet::new(),
            cpu_history: VecDeque::new(),
            mem_history: VecDeque::new(),
            modal: ActiveModal::None,
            filter_mode: false,
            filter_query: String::new(),
            status_message: Some(("Welcome to TIMMY. Ready.".to_string(), false)),
            should_quit: false,
            docker_worker,
            docker_generation: 0,
            service_worker,
            service_generation: 0,
        };

        app.refresh();
        app
    }

    /// Fetches a fresh snapshot without blocking the UI thread on Docker socket or launchctl I/O.
    pub fn refresh(&mut self) {
        match self.orchestrator.refresh_local_snapshot() {
            Ok(mut snap) => {
                if let Some(ref worker) = self.docker_worker {
                    self.docker_generation = self.docker_generation.saturating_add(1);
                    worker.trigger_refresh(
                        self.docker_generation,
                        snap.sessions.clone(),
                        snap.processes.clone(),
                    );
                    snap.containers = worker.get_cached_containers();
                }

                if let Some(ref worker) = self.service_worker {
                    self.service_generation = self.service_generation.saturating_add(1);
                    worker.trigger_refresh(
                        self.service_generation,
                        snap.sessions.clone(),
                        snap.processes.clone(),
                    );
                    snap.services = worker.get_cached_services();
                    match worker.snapshot_status() {
                        crate::platform::SnapshotStatus::Initial => {}
                        crate::platform::SnapshotStatus::Complete => {}
                        crate::platform::SnapshotStatus::Partial { ref reason } => {
                            self.status_message =
                                Some((format!("Partial services snapshot: {}", reason), false));
                        }
                        crate::platform::SnapshotStatus::Stale { ref error } => {
                            let age_str = worker.snapshot_age_str();
                            self.status_message = Some((
                                format!(
                                    "Service discovery failed: {} (displaying stale last-known-good snapshot from {})",
                                    error, age_str
                                ),
                                true,
                            ));
                        }
                        crate::platform::SnapshotStatus::Failed { ref error } => {
                            self.status_message = Some((
                                format!(
                                    "Service discovery failed: {} (no snapshot available)",
                                    error
                                ),
                                true,
                            ));
                        }
                    }
                }

                let cpu_sample = (snap.metrics.total_agent_cpu_usage.round() as u64).min(100);
                let mem_sample = snap.metrics.total_agent_memory_bytes / (1024 * 1024);
                self.cpu_history.push_back(cpu_sample);
                if self.cpu_history.len() > 35 {
                    self.cpu_history.pop_front();
                }
                self.mem_history.push_back(mem_sample);
                if self.mem_history.len() > 35 {
                    self.mem_history.pop_front();
                }

                self.snapshot = snap;
                self.ensure_table_selection();
                self.update_selected_session_resources();

                // If currently waiting for container inspection to load, check if it arrived
                if let ActiveModal::DockerDetailLoading { ref id, .. } = self.modal {
                    if let Some(ref worker) = self.docker_worker {
                        if let Some(detail) = worker.get_cached_detail(id) {
                            self.modal = ActiveModal::DockerDetail(Box::new(detail));
                        }
                    }
                }
            }
            Err(e) => {
                self.status_message = Some((format!("Refresh error: {}", e), true));
            }
        }
    }

    pub fn filtered_processes(&self) -> Vec<&ProcessInfo> {
        self.snapshot
            .processes
            .iter()
            .filter(|p| {
                let pid_str = p.pid.to_string();
                let kind_str = p.attribution.kind.to_string();
                let exe_str = p.exe.as_ref().and_then(|e| e.to_str()).unwrap_or("");
                let cmd_str = p.cmdline.join(" ");
                let cwd_str = p.cwd_status.as_ref().and_then(|c| c.to_str()).unwrap_or("");
                let user_str = p.user.as_deref().unwrap_or("");
                let fields = [
                    p.name.as_str(),
                    &pid_str,
                    &kind_str,
                    &p.attribution.reason,
                    exe_str,
                    &cmd_str,
                    cwd_str,
                    user_str,
                ];
                crate::ui::matches_filter_tokens(&fields, &self.filter_query)
            })
            .collect()
    }

    pub fn filtered_ports(&self) -> Vec<&ListeningPort> {
        self.snapshot
            .ports
            .iter()
            .filter(|p| {
                let port_str = p.port.to_string();
                let pid_str = p.pid.map(|pid| pid.to_string()).unwrap_or_default();
                let proc_str = p.process_name.as_deref().unwrap_or("");
                let proto_str = p.protocol.to_string();
                let fields = [&port_str, &pid_str, proc_str, &proto_str, &p.ip];
                crate::ui::matches_filter_tokens(&fields, &self.filter_query)
            })
            .collect()
    }

    pub fn filtered_services(&self) -> Vec<&ServiceInfo> {
        self.snapshot
            .services
            .iter()
            .filter(|s| {
                let pid_str = s.pid.map(|pid| pid.to_string()).unwrap_or_default();
                let domain_str = s.formatted_domain();
                let exe_str = s.executable_or_program().unwrap_or("");
                let session_str = s.session_id.as_deref().unwrap_or("");
                let status_str = s.status.to_string();
                let fields = [
                    s.name.as_str(),
                    s.label.as_str(),
                    &pid_str,
                    &domain_str,
                    exe_str,
                    session_str,
                    &status_str,
                ];
                crate::ui::matches_filter_tokens(&fields, &self.filter_query)
            })
            .collect()
    }

    pub fn filtered_containers(&self) -> Vec<&ContainerInfo> {
        self.snapshot
            .containers
            .iter()
            .filter(|c| {
                let sess_str = c.session_id.as_deref().unwrap_or("");
                let fields = [
                    c.name.as_str(),
                    c.image.as_str(),
                    c.id.as_str(),
                    c.short_id.as_str(),
                    sess_str,
                    c.status.as_str(),
                ];
                crate::ui::matches_filter_tokens(&fields, &self.filter_query)
            })
            .collect()
    }

    pub fn filtered_sessions(&self) -> Vec<&SessionInfo> {
        self.snapshot
            .sessions
            .iter()
            .filter(|s| {
                let kind_str = s.agent_kind.to_string();
                let status_str = s.status.to_string();
                let pid_str = s.root_pid.map(|p| p.to_string()).unwrap_or_default();
                let proc_name = s.root_process_name.as_deref().unwrap_or("");
                let fields = [s.id.as_str(), &kind_str, &status_str, &pid_str, proc_name];
                crate::ui::matches_filter_tokens(&fields, &self.filter_query)
            })
            .collect()
    }

    fn ensure_table_selection(&mut self) {
        let proc_count = self.filtered_processes().len();
        if proc_count > 0 {
            let sel = self
                .process_table_state
                .selected()
                .unwrap_or(0)
                .min(proc_count - 1);
            self.process_table_state.select(Some(sel));
        } else {
            self.process_table_state.select(None);
        }

        let port_count = self.filtered_ports().len();
        if port_count > 0 {
            let sel = self
                .port_table_state
                .selected()
                .unwrap_or(0)
                .min(port_count - 1);
            self.port_table_state.select(Some(sel));
        } else {
            self.port_table_state.select(None);
        }

        let srv_count = self.filtered_services().len();
        if srv_count > 0 {
            let sel = self
                .service_table_state
                .selected()
                .unwrap_or(0)
                .min(srv_count - 1);
            self.service_table_state.select(Some(sel));
        } else {
            self.service_table_state.select(None);
        }

        let cnt_count = self.filtered_containers().len();
        if cnt_count > 0 {
            let sel = self
                .docker_table_state
                .selected()
                .unwrap_or(0)
                .min(cnt_count - 1);
            self.docker_table_state.select(Some(sel));
        } else {
            self.docker_table_state.select(None);
        }

        let sess_count = self.filtered_sessions().len();
        if sess_count > 0 {
            let sel = self
                .session_table_state
                .selected()
                .unwrap_or(0)
                .min(sess_count - 1);
            self.session_table_state.select(Some(sel));
        } else {
            self.session_table_state.select(None);
        }
    }

    pub fn update_selected_session_resources(&mut self) {
        let selected_id = self
            .session_table_state
            .selected()
            .and_then(|idx| self.filtered_sessions().get(idx).map(|s| s.id.clone()));

        if let Some(id) = selected_id {
            if let Ok((_, res)) = self.orchestrator.get_session_resources(Some(&id)) {
                self.selected_session_resources = res;
                let lineage_tree = self
                    .orchestrator
                    .get_session_lineage_tree(&id, true)
                    .unwrap_or_default();
                self.selected_session_tree = if lineage_tree.is_empty() {
                    Some("No lineage edges recorded for this session.".to_string())
                } else {
                    let masker = crate::safety::masker::SecretMasker::new();
                    Some(crate::engine::lineage::format_lineage_tree_unicode(
                        &lineage_tree,
                        &masker,
                    ))
                };
                return;
            }
        }
        self.selected_session_resources.clear();
        self.selected_session_tree = None;
    }

    pub fn handle_key(&mut self, key: KeyEvent) {
        // Global quit check
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.should_quit = true;
            return;
        }

        // If filter mode is active, forward keystrokes to filter text
        if self.filter_mode {
            match key.code {
                KeyCode::Esc | KeyCode::Enter => {
                    self.filter_mode = false;
                }
                KeyCode::Backspace => {
                    self.filter_query.pop();
                    self.ensure_table_selection();
                    self.update_selected_session_resources();
                }
                KeyCode::Char(c) => {
                    self.filter_query.push(c);
                    self.ensure_table_selection();
                    self.update_selected_session_resources();
                }
                _ => {}
            }
            return;
        }

        // Modal handling
        match &mut self.modal {
            ActiveModal::SessionInspect {
                active_tab, scroll, ..
            } => {
                match key.code {
                    KeyCode::Char('1') => {
                        *active_tab = 0;
                        *scroll = 0;
                    }
                    KeyCode::Char('2') => {
                        *active_tab = 1;
                        *scroll = 0;
                    }
                    KeyCode::Char('3') => {
                        *active_tab = 2;
                        *scroll = 0;
                    }
                    KeyCode::Tab => {
                        *active_tab = (*active_tab + 1) % 3;
                        *scroll = 0;
                    }
                    KeyCode::BackTab => {
                        *active_tab = if *active_tab == 0 { 2 } else { *active_tab - 1 };
                        *scroll = 0;
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        *scroll = scroll.saturating_add(1);
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        *scroll = scroll.saturating_sub(1);
                    }
                    KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                        self.modal = ActiveModal::None;
                    }
                    _ => {}
                }
                return;
            }
            ActiveModal::Detail(_)
            | ActiveModal::DockerDetail(_)
            | ActiveModal::DockerDetailLoading { .. }
            | ActiveModal::ServiceDetail(_) => {
                if key.code == KeyCode::Esc
                    || key.code == KeyCode::Enter
                    || key.code == KeyCode::Char('q')
                {
                    self.modal = ActiveModal::None;
                }
                return;
            }
            ActiveModal::ConfirmKill { process, force } => {
                let proc_clone = process.clone();
                let force_val = *force;
                match key.code {
                    KeyCode::Char('y') | KeyCode::Char('Y') => {
                        let res = self.orchestrator.terminate_process(
                            proc_clone.pid,
                            &proc_clone.name,
                            proc_clone.start_time,
                            &proc_clone.attribution.kind.to_string(),
                            force_val,
                        );
                        match res {
                            Ok(_) => {
                                self.status_message = Some((
                                    format!(
                                        "Successfully sent {} to PID {}",
                                        if force_val { "SIGKILL" } else { "SIGTERM" },
                                        proc_clone.pid
                                    ),
                                    false,
                                ));
                                self.refresh();
                            }
                            Err(e) => {
                                self.status_message = Some((
                                    format!("Failed to kill PID {}: {}", proc_clone.pid, e),
                                    true,
                                ));
                            }
                        }
                        self.modal = ActiveModal::None;
                    }
                    KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                        self.status_message = Some(("Action canceled".to_string(), false));
                        self.modal = ActiveModal::None;
                    }
                    _ => {}
                }
                return;
            }
            ActiveModal::ConfirmBatchKill {
                eligible,
                blocked,
                force,
            } => {
                let force_val = *force;
                let eligible_procs = eligible.clone();
                let blocked_len = blocked.len();
                match key.code {
                    KeyCode::Char('y') | KeyCode::Char('Y') => {
                        let mut success_count = 0;
                        let mut fail_count = 0;
                        for proc in &eligible_procs {
                            match self.orchestrator.terminate_process(
                                proc.pid,
                                &proc.name,
                                proc.start_time,
                                &proc.attribution.kind.to_string(),
                                force_val,
                            ) {
                                Ok(_) => success_count += 1,
                                Err(_) => fail_count += 1,
                            }
                        }
                        self.tagged_pids.clear();
                        self.refresh();
                        self.status_message = Some((
                            format!(
                                "Batch terminated {} processes ({} failed, {} blocked by shield)",
                                success_count, fail_count, blocked_len
                            ),
                            fail_count > 0,
                        ));
                        self.modal = ActiveModal::None;
                    }
                    KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                        self.status_message = Some(("Action canceled".to_string(), false));
                        self.modal = ActiveModal::None;
                    }
                    _ => {}
                }
                return;
            }
            ActiveModal::None => {}
        }

        // Main view keyboard navigation
        match key.code {
            KeyCode::Char('q') => {
                self.should_quit = true;
            }
            KeyCode::Char('1') => {
                self.current_tab = ActiveTab::Processes;
                self.ensure_table_selection();
            }
            KeyCode::Char('2') => {
                self.current_tab = ActiveTab::Ports;
                self.ensure_table_selection();
            }
            KeyCode::Char('3') => {
                self.current_tab = ActiveTab::Services;
                self.ensure_table_selection();
            }
            KeyCode::Char('4') => {
                self.current_tab = ActiveTab::Docker;
                self.ensure_table_selection();
            }
            KeyCode::Char('5') | KeyCode::Char('s') => {
                self.current_tab = ActiveTab::Sessions;
                self.ensure_table_selection();
                self.update_selected_session_resources();
            }
            KeyCode::Tab => {
                self.current_tab = match self.current_tab {
                    ActiveTab::Processes => ActiveTab::Ports,
                    ActiveTab::Ports => ActiveTab::Services,
                    ActiveTab::Services => ActiveTab::Docker,
                    ActiveTab::Docker => ActiveTab::Sessions,
                    ActiveTab::Sessions => ActiveTab::Processes,
                };
                self.ensure_table_selection();
                self.update_selected_session_resources();
            }
            KeyCode::BackTab => {
                self.current_tab = match self.current_tab {
                    ActiveTab::Processes => ActiveTab::Sessions,
                    ActiveTab::Ports => ActiveTab::Processes,
                    ActiveTab::Services => ActiveTab::Ports,
                    ActiveTab::Docker => ActiveTab::Services,
                    ActiveTab::Sessions => ActiveTab::Docker,
                };
                self.ensure_table_selection();
                self.update_selected_session_resources();
            }
            KeyCode::Char('r') => {
                self.refresh();
                self.status_message = Some(("Refreshed state on demand".to_string(), false));
            }
            KeyCode::Char('t') => match self.current_tab {
                ActiveTab::Sessions => {
                    self.session_view_show_tree = !self.session_view_show_tree;
                    let mode = if self.session_view_show_tree {
                        "Lineage Tree"
                    } else {
                        "Flat Resources Table"
                    };
                    self.status_message =
                        Some((format!("Switched session bottom pane to {}", mode), false));
                }
                ActiveTab::Processes => {
                    let filtered = self.filtered_processes();
                    if let Some(idx) = self.process_table_state.selected() {
                        if let Some(proc) = filtered.get(idx) {
                            let pid = proc.pid;
                            let matching_session = self.snapshot.sessions.iter().find(|s| {
                                s.tracked_pids.contains(&pid)
                                    || s.root_pid == Some(pid)
                                    || (proc.attribution.root_agent_pid.is_some()
                                        && proc.attribution.root_agent_pid == s.root_pid)
                            });

                            if let Some(sess) = matching_session {
                                let sess_id = sess.id.clone();
                                let (session_info, resources, recs) =
                                    match self.orchestrator.inspect_session(Some(&sess_id)) {
                                        Ok(data) => data,
                                        Err(_) => (sess.clone(), Vec::new(), Vec::new()),
                                    };
                                let lineage_tree = self
                                    .orchestrator
                                    .get_session_lineage_tree(&sess_id, true)
                                    .unwrap_or_default();
                                let tree_text = if lineage_tree.is_empty() {
                                    "No lineage edges recorded for this session.".to_string()
                                } else {
                                    let masker = crate::safety::masker::SecretMasker::new();
                                    crate::engine::lineage::format_lineage_tree_unicode(
                                        &lineage_tree,
                                        &masker,
                                    )
                                };
                                self.modal = ActiveModal::SessionInspect {
                                    session: Box::new(session_info),
                                    resources,
                                    recommendations: recs,
                                    lineage_tree,
                                    tree_text,
                                    active_tab: 0,
                                    scroll: 0,
                                };
                                self.status_message = Some((
                                    format!("Opened session lineage tree for PID {}", pid),
                                    false,
                                ));
                            } else {
                                self.status_message = Some((
                                    format!(
                                        "No active or recorded session found for PID {} ({})",
                                        pid, proc.name
                                    ),
                                    false,
                                ));
                            }
                        }
                    }
                }
                _ => {}
            },
            KeyCode::Char('/') => {
                self.filter_mode = true;
            }
            KeyCode::Char(' ') => {
                if self.current_tab == ActiveTab::Processes {
                    let selected_pid = self
                        .process_table_state
                        .selected()
                        .and_then(|idx| self.filtered_processes().get(idx).map(|p| p.pid));
                    if let Some(pid) = selected_pid {
                        if self.tagged_pids.contains(&pid) {
                            self.tagged_pids.remove(&pid);
                        } else {
                            self.tagged_pids.insert(pid);
                        }
                    }
                }
            }
            KeyCode::Char('a') => {
                if self.current_tab == ActiveTab::Processes {
                    let pids: Vec<u32> = self.filtered_processes().iter().map(|p| p.pid).collect();
                    let all_tagged =
                        !pids.is_empty() && pids.iter().all(|pid| self.tagged_pids.contains(pid));
                    if all_tagged {
                        for pid in pids {
                            self.tagged_pids.remove(&pid);
                        }
                    } else {
                        for pid in pids {
                            self.tagged_pids.insert(pid);
                        }
                    }
                }
            }
            KeyCode::Esc => {
                if !self.filter_query.is_empty() {
                    self.filter_query.clear();
                    self.status_message = Some(("Filter cleared".to_string(), false));
                    self.ensure_table_selection();
                    self.update_selected_session_resources();
                } else if !self.tagged_pids.is_empty() {
                    self.tagged_pids.clear();
                    self.status_message = Some(("Cleared tagged processes".to_string(), false));
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_selection(1);
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_selection(-1);
            }
            KeyCode::Enter | KeyCode::Char('i') => {
                self.inspect_current_selection();
            }
            KeyCode::Char('x') => {
                self.prompt_termination(false);
            }
            KeyCode::Char('X') => {
                self.prompt_termination(true);
            }
            _ => {}
        }
    }

    fn move_selection(&mut self, delta: isize) {
        match self.current_tab {
            ActiveTab::Processes => {
                let count = self.filtered_processes().len();
                if count > 0 {
                    let current = self.process_table_state.selected().unwrap_or(0) as isize;
                    let next = (current + delta).clamp(0, count as isize - 1) as usize;
                    self.process_table_state.select(Some(next));
                } else {
                    self.process_table_state.select(None);
                }
            }
            ActiveTab::Ports => {
                let count = self.filtered_ports().len();
                if count > 0 {
                    let current = self.port_table_state.selected().unwrap_or(0) as isize;
                    let next = (current + delta).clamp(0, count as isize - 1) as usize;
                    self.port_table_state.select(Some(next));
                } else {
                    self.port_table_state.select(None);
                }
            }
            ActiveTab::Services => {
                let count = self.filtered_services().len();
                if count > 0 {
                    let current = self.service_table_state.selected().unwrap_or(0) as isize;
                    let next = (current + delta).clamp(0, count as isize - 1) as usize;
                    self.service_table_state.select(Some(next));
                } else {
                    self.service_table_state.select(None);
                }
            }
            ActiveTab::Docker => {
                let count = self.filtered_containers().len();
                if count > 0 {
                    let current = self.docker_table_state.selected().unwrap_or(0) as isize;
                    let next = (current + delta).clamp(0, count as isize - 1) as usize;
                    self.docker_table_state.select(Some(next));
                } else {
                    self.docker_table_state.select(None);
                }
            }
            ActiveTab::Sessions => {
                let count = self.filtered_sessions().len();
                if count > 0 {
                    let current = self.session_table_state.selected().unwrap_or(0) as isize;
                    let next = (current + delta).clamp(0, count as isize - 1) as usize;
                    self.session_table_state.select(Some(next));
                    self.update_selected_session_resources();
                } else {
                    self.session_table_state.select(None);
                }
            }
        }
    }

    fn inspect_current_selection(&mut self) {
        match self.current_tab {
            ActiveTab::Processes => {
                let filtered = self.filtered_processes();
                if let Some(idx) = self.process_table_state.selected() {
                    if let Some(proc) = filtered.get(idx) {
                        match self.orchestrator.inspect_process(proc.pid) {
                            Ok(detail) => {
                                self.modal = ActiveModal::Detail(Box::new(detail));
                            }
                            Err(e) => {
                                self.status_message =
                                    Some((format!("Inspection failed: {}", e), true));
                            }
                        }
                    }
                }
            }
            ActiveTab::Services => {
                let filtered = self.filtered_services();
                if let Some(idx) = self.service_table_state.selected() {
                    if let Some(svc) = filtered.get(idx) {
                        self.modal = ActiveModal::ServiceDetail(Box::new((*svc).clone()));
                    }
                }
            }
            ActiveTab::Docker => {
                let filtered = self.filtered_containers();
                if let Some(idx) = self.docker_table_state.selected() {
                    if let Some(c) = filtered.get(idx) {
                        if let Some(ref worker) = self.docker_worker {
                            if let Some(detail) = worker.get_cached_detail(&c.id) {
                                self.modal = ActiveModal::DockerDetail(Box::new(detail));
                            } else {
                                worker.trigger_inspect(
                                    c.id.clone(),
                                    self.snapshot.sessions.clone(),
                                    self.snapshot.processes.clone(),
                                );
                                self.modal = ActiveModal::DockerDetailLoading {
                                    id: c.id.clone(),
                                    name: c.name.clone(),
                                };
                            }
                        } else {
                            match self.orchestrator.inspect_container(&c.id) {
                                Ok(detail) => {
                                    self.modal = ActiveModal::DockerDetail(Box::new(detail));
                                }
                                Err(e) => {
                                    self.status_message =
                                        Some((format!("Container inspection failed: {}", e), true));
                                }
                            }
                        }
                    }
                }
            }
            ActiveTab::Sessions => {
                let filtered = self.filtered_sessions();
                if let Some(idx) = self.session_table_state.selected() {
                    if let Some(sess) = filtered.get(idx) {
                        let (session_info, resources, recs) =
                            match self.orchestrator.inspect_session(Some(&sess.id)) {
                                Ok(data) => data,
                                Err(_) => ((*sess).clone(), Vec::new(), Vec::new()),
                            };
                        let lineage_tree = self
                            .orchestrator
                            .get_session_lineage_tree(&sess.id, true)
                            .unwrap_or_default();
                        let tree_text = if lineage_tree.is_empty() {
                            "No lineage edges recorded for this session.".to_string()
                        } else {
                            let masker = crate::safety::masker::SecretMasker::new();
                            crate::engine::lineage::format_lineage_tree_unicode(
                                &lineage_tree,
                                &masker,
                            )
                        };
                        self.modal = ActiveModal::SessionInspect {
                            session: Box::new(session_info),
                            resources,
                            recommendations: recs,
                            lineage_tree,
                            tree_text,
                            active_tab: 0,
                            scroll: 0,
                        };
                    }
                }
            }
            _ => {}
        }
    }

    fn prompt_termination(&mut self, force: bool) {
        if self.current_tab == ActiveTab::Processes {
            if !self.tagged_pids.is_empty() {
                let shield = crate::safety::SafetyShield::new();
                let mut eligible = Vec::new();
                let mut blocked = Vec::new();
                for proc in &self.snapshot.processes {
                    if self.tagged_pids.contains(&proc.pid) {
                        match shield.validate_termination(proc.pid, &proc.name) {
                            Ok(()) => eligible.push(proc.clone()),
                            Err(violation) => blocked.push((proc.clone(), violation.to_string())),
                        }
                    }
                }
                self.modal = ActiveModal::ConfirmBatchKill {
                    eligible,
                    blocked,
                    force,
                };
            } else {
                let filtered = self.filtered_processes();
                if let Some(idx) = self.process_table_state.selected() {
                    if let Some(proc) = filtered.get(idx) {
                        self.modal = ActiveModal::ConfirmKill {
                            process: Box::new((*proc).clone()),
                            force,
                        };
                    }
                }
            }
        }
    }

    pub fn draw(&mut self, frame: &mut Frame) {
        let area = frame.area();

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Header & Tab navigation
                Constraint::Length(3), // Metrics & Sparklines trend bar
                Constraint::Min(5),    // Main Table View
                Constraint::Length(1), // Footer status bar
            ])
            .split(area);

        // 1. Header & Tabs
        let tab_titles = [
            "Processes [1]",
            "Ports [2]",
            "Services [3]",
            "Docker [4]",
            "Sessions [5]",
        ]
        .iter()
        .map(|t| Line::from(*t))
        .collect::<Vec<_>>();

        let tabs = Tabs::new(tab_titles)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" TIMMY: AI Agent Resource Manager ")
                    .title_style(self.theme.title_style()),
            )
            .highlight_style(self.theme.tab_active_style())
            .select(self.current_tab as usize);
        frame.render_widget(tabs, chunks[0]);

        // 2. Metrics summary & Sparklines bar
        let m = &self.snapshot.metrics;
        let active_sess_str = self
            .snapshot
            .active_session
            .as_ref()
            .map(|s| format!("{} ({})", s.agent_kind, s.duration_str()))
            .unwrap_or_else(|| "None".to_string());

        if chunks[1].width >= 90 {
            let metrics_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Min(42),
                    Constraint::Length(24),
                    Constraint::Length(24),
                ])
                .split(chunks[1]);

            let metrics_lines = vec![
                Line::from(vec![
                    Span::styled(
                        " Active Session: ",
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        active_sess_str,
                        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(" | "),
                    Span::styled(
                        "Processes: ",
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        m.total_agent_processes.to_string(),
                        Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(" | "),
                    Span::styled("Ports: ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::styled(
                        m.total_listening_ports.to_string(),
                        Style::default().fg(Color::Magenta),
                    ),
                ]),
                Line::from(vec![
                    Span::styled(
                        " [Tab/1-5] Switch | [↑/↓] Nav | [Space] Tag | [a] Tag All | [x] Kill | [/] Filter | [r] Refresh ",
                        Style::default().fg(Color::DarkGray),
                    ),
                ]),
            ];
            let metrics_para = Paragraph::new(metrics_lines);
            frame.render_widget(metrics_para, metrics_chunks[0]);

            let cpu_data: Vec<u64> = self.cpu_history.iter().copied().collect();
            let cpu_sparkline = Sparkline::default()
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(format!(" CPU: {:.0}% ", m.total_agent_cpu_usage))
                        .border_style(Style::default().fg(Color::DarkGray)),
                )
                .style(Style::default().fg(Color::Green))
                .data(&cpu_data)
                .max(100);
            frame.render_widget(cpu_sparkline, metrics_chunks[1]);

            let mem_data: Vec<u64> = self.mem_history.iter().copied().collect();
            let max_mem = self
                .mem_history
                .iter()
                .copied()
                .max()
                .unwrap_or(100)
                .max(50);
            let mem_sparkline = Sparkline::default()
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(format!(" RAM: {} ", m.formatted_memory()))
                        .border_style(Style::default().fg(Color::DarkGray)),
                )
                .style(Style::default().fg(Color::Cyan))
                .data(&mem_data)
                .max(max_mem);
            frame.render_widget(mem_sparkline, metrics_chunks[2]);
        } else {
            let metrics_lines = vec![
                Line::from(vec![
                    Span::styled(
                        " Active Session: ",
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        active_sess_str,
                        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(" | "),
                    Span::styled(
                        "Agent Processes: ",
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        m.total_agent_processes.to_string(),
                        Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(" | "),
                    Span::styled("RAM: ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::styled(m.formatted_memory(), Style::default().fg(Color::Green)),
                    Span::raw(" | "),
                    Span::styled("Ports: ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::styled(
                        m.total_listening_ports.to_string(),
                        Style::default().fg(Color::Magenta),
                    ),
                ]),
                Line::from(vec![
                    Span::styled(
                        " [Tab/1-5] Switch | [↑/↓] Nav | [Space] Tag | [a] Tag All | [x] Kill | [/] Filter | [r] Refresh ",
                        Style::default().fg(Color::DarkGray),
                    ),
                ]),
            ];
            let metrics_para = Paragraph::new(metrics_lines);
            frame.render_widget(metrics_para, chunks[1]);
        }

        // 3. Main Table View
        match self.current_tab {
            ActiveTab::Processes => {
                render_process_table(
                    frame,
                    chunks[2],
                    &self.snapshot.processes,
                    &mut self.process_table_state,
                    &self.theme,
                    &self.filter_query,
                    &self.tagged_pids,
                );
            }
            ActiveTab::Ports => {
                render_port_table(
                    frame,
                    chunks[2],
                    &self.snapshot.ports,
                    &mut self.port_table_state,
                    &self.theme,
                    &self.filter_query,
                );
            }
            ActiveTab::Services => {
                let (status, last_refresh) = if let Some(ref worker) = self.service_worker {
                    (worker.snapshot_status(), worker.last_refresh_time())
                } else {
                    (crate::platform::SnapshotStatus::Initial, None)
                };
                render_service_table(
                    frame,
                    chunks[2],
                    &self.snapshot.services,
                    &mut self.service_table_state,
                    &self.theme,
                    &self.filter_query,
                    &status,
                    last_refresh,
                );
            }
            ActiveTab::Docker => {
                render_docker_table(
                    frame,
                    chunks[2],
                    &self.snapshot.containers,
                    &mut self.docker_table_state,
                    &self.theme,
                    &self.filter_query,
                );
            }
            ActiveTab::Sessions => {
                render_session_view(
                    frame,
                    chunks[2],
                    &self.snapshot.sessions,
                    &self.selected_session_resources,
                    self.selected_session_tree.as_deref(),
                    self.session_view_show_tree,
                    &mut self.session_table_state,
                    &self.theme,
                    &self.filter_query,
                );
            }
        }

        // 4. Footer status bar
        let status_span = if self.filter_mode {
            Span::styled(
                format!(
                    "SEARCH / FILTER: {}█ (Press Enter to finish, Esc to cancel)",
                    self.filter_query
                ),
                Style::default()
                    .bg(Color::Blue)
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )
        } else if !self.filter_query.is_empty() {
            let base_msg = self
                .status_message
                .as_ref()
                .map(|(m, _)| m.as_str())
                .unwrap_or("Ready.");
            Span::styled(
                format!(
                    "ACTIVE FILTER: '{}' [Press / to edit, Esc to clear] | {}",
                    self.filter_query, base_msg
                ),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
        } else if let Some((msg, is_err)) = &self.status_message {
            Span::styled(
                msg.clone(),
                Style::default().fg(if *is_err { Color::Red } else { Color::Green }),
            )
        } else {
            Span::raw("Ready.")
        };
        let status_para = Paragraph::new(Line::from(status_span));
        frame.render_widget(status_para, chunks[3]);

        // 5. Active Modals overlay
        match &self.modal {
            ActiveModal::Detail(detail) => {
                render_detail_modal(frame, area, detail, &self.theme);
            }
            ActiveModal::ConfirmKill { process, force } => {
                render_confirm_modal(frame, area, process, *force, &self.theme);
            }
            ActiveModal::ConfirmBatchKill {
                eligible,
                blocked,
                force,
            } => {
                render_batch_confirm_modal(frame, area, eligible, blocked, *force, &self.theme);
            }
            ActiveModal::SessionInspect {
                session,
                resources,
                recommendations,
                tree_text,
                active_tab,
                scroll,
                ..
            } => {
                render_session_modal(
                    frame,
                    area,
                    session,
                    resources,
                    recommendations,
                    tree_text,
                    *active_tab,
                    *scroll,
                    &self.theme,
                );
            }
            ActiveModal::DockerDetail(detail) => {
                render_docker_detail_modal(frame, area, detail, &self.theme);
            }
            ActiveModal::DockerDetailLoading { id, name } => {
                use ratatui::layout::Rect;
                use ratatui::widgets::Clear;
                let modal_width = 64.min(area.width);
                let modal_height = 8.min(area.height);

                let modal_area = Rect {
                    x: area.x + (area.width - modal_width) / 2,
                    y: area.y + (area.height - modal_height) / 2,
                    width: modal_width,
                    height: modal_height,
                };

                frame.render_widget(Clear, modal_area);
                let block = Block::default()
                    .title(format!(" Inspecting Container: {} ", name))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan));
                let text = vec![
                    Line::from(""),
                    Line::from(vec![
                        Span::raw("  Connecting to Docker daemon to inspect container "),
                        Span::styled(id, Style::default().fg(Color::Yellow)),
                        Span::raw("..."),
                    ]),
                    Line::from(""),
                    Line::from(vec![
                        Span::styled("  [Esc] ", Style::default().fg(Color::DarkGray)),
                        Span::raw("Cancel inspection"),
                    ]),
                ];
                let p = Paragraph::new(text).block(block);
                frame.render_widget(p, modal_area);
            }
            ActiveModal::ServiceDetail(service) => {
                render_service_detail_modal(frame, area, service, &self.theme);
            }
            ActiveModal::None => {}
        }
    }
}
