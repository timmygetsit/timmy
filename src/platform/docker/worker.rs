use crate::engine::docker::DockerCoordinator;
use crate::model::session::SessionInfo;
use crate::model::{ContainerDetail, ContainerInfo, DockerStatus, ProcessInfo};
use crate::platform::traits::DockerCollector;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Maximum number of inspected container details to retain in memory.
pub const MAX_CACHED_INSPECTIONS: usize = 100;

/// Result of a Docker background worker shutdown attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerShutdownResult {
    /// Worker thread exited cleanly and its join handle was consumed.
    Terminated,
    /// Worker thread did not terminate within the specified timeout duration.
    /// The thread handle is preserved without leaking detached joiner threads.
    TimedOut,
    /// Worker thread was already stopped prior to this call.
    AlreadyStopped,
}

/// Shared thread-safe snapshot of Docker daemon state maintained by background worker.
#[derive(Debug, Default)]
pub struct DockerWorkerState {
    pub status: Option<DockerStatus>,
    pub containers: Vec<ContainerInfo>,
    pub inspected: HashMap<String, ContainerDetail>,
    pub inspected_keys: VecDeque<String>,
    pub is_refreshing: bool,
    pub last_refresh: Option<Instant>,
    pub last_error: Option<String>,
    pub generation: u64,
}

#[derive(Debug)]
pub enum WorkerRequest {
    Refresh {
        generation: u64,
        sessions: Vec<SessionInfo>,
        processes: Vec<ProcessInfo>,
    },
    Inspect {
        container_id: String,
        sessions: Vec<SessionInfo>,
        processes: Vec<ProcessInfo>,
    },
    Shutdown,
}

/// Genuine non-blocking background Docker worker.
///
/// Dispatches slow network/socket I/O off the TUI main thread onto a dedicated background worker.
/// Ensures the TUI event loop and keyboard input handlers remain 100% responsive at all times.
pub struct DockerBackgroundWorker {
    state: Arc<RwLock<DockerWorkerState>>,
    request_tx: SyncSender<WorkerRequest>,
    running: Arc<AtomicBool>,
    shutdown_requested: Arc<AtomicBool>,
    thread_exited: Arc<AtomicBool>,
    collector: Arc<dyn DockerCollector>,
    thread_handle: Option<JoinHandle<()>>,
}

impl DockerBackgroundWorker {
    pub fn new(collector: Arc<dyn DockerCollector>) -> Self {
        let state = Arc::new(RwLock::new(DockerWorkerState::default()));
        // Bounded channel to prevent request explosion
        let (request_tx, request_rx) = sync_channel::<WorkerRequest>(4);
        let running = Arc::new(AtomicBool::new(true));
        let shutdown_requested = Arc::new(AtomicBool::new(false));
        let thread_exited = Arc::new(AtomicBool::new(false));

        let state_clone = Arc::clone(&state);
        let running_clone = Arc::clone(&running);
        let shutdown_clone = Arc::clone(&shutdown_requested);
        let thread_exited_clone = Arc::clone(&thread_exited);
        let collector_clone = Arc::clone(&collector);

        let thread_handle = thread::Builder::new()
            .name("timmy-docker-worker".to_string())
            .spawn(move || {
                Self::worker_loop(
                    collector_clone,
                    state_clone,
                    request_rx,
                    running_clone,
                    shutdown_clone,
                    thread_exited_clone,
                );
            })
            .expect("Failed to spawn Docker background worker thread");

        Self {
            state,
            request_tx,
            running,
            shutdown_requested,
            thread_exited,
            collector,
            thread_handle: Some(thread_handle),
        }
    }

    fn worker_loop(
        collector: Arc<dyn DockerCollector>,
        state: Arc<RwLock<DockerWorkerState>>,
        rx: Receiver<WorkerRequest>,
        running: Arc<AtomicBool>,
        shutdown_requested: Arc<AtomicBool>,
        thread_exited: Arc<AtomicBool>,
    ) {
        // RAII guard guarantees thread_exited is marked true on ANY exit path
        // (normal exit, panic, error, or early return).
        struct ExitGuard {
            thread_exited: Arc<AtomicBool>,
            running: Arc<AtomicBool>,
        }
        impl Drop for ExitGuard {
            fn drop(&mut self) {
                self.running.store(false, Ordering::SeqCst);
                self.thread_exited.store(true, Ordering::SeqCst);
            }
        }
        let _guard = ExitGuard {
            thread_exited: Arc::clone(&thread_exited),
            running: Arc::clone(&running),
        };

        while running.load(Ordering::SeqCst) && !shutdown_requested.load(Ordering::SeqCst) {
            match rx.recv() {
                Ok(WorkerRequest::Shutdown) => break,
                Ok(WorkerRequest::Refresh {
                    generation,
                    sessions,
                    processes,
                }) => {
                    if !running.load(Ordering::SeqCst) || shutdown_requested.load(Ordering::SeqCst)
                    {
                        break;
                    }
                    {
                        if let Ok(mut st) = state.write() {
                            st.is_refreshing = true;
                        }
                    }

                    let status_res = collector.docker_status();
                    let (status, is_running, status_err) = match status_res {
                        Ok(st) => {
                            let r = st.running;
                            (Some(st), r, None)
                        }
                        Err(e) => (None, false, Some(e)),
                    };

                    let containers_res = if let Some(e) = status_err {
                        Err(e)
                    } else if is_running {
                        collector.collect_containers()
                    } else {
                        // Daemon reported cleanly not running
                        Ok(Vec::new())
                    };

                    if let Ok(mut st) = state.write() {
                        // Monotonic check: only commit if request is >= current state generation
                        if generation >= st.generation {
                            st.generation = generation;
                            if let Some(s) = status {
                                st.status = Some(s);
                            }
                            match containers_res {
                                Ok(mut containers) => {
                                    DockerCoordinator::correlate_containers(
                                        &mut containers,
                                        &sessions,
                                        &processes,
                                    );
                                    st.containers = containers;
                                    st.last_error = None;
                                    st.last_refresh = Some(Instant::now());
                                }
                                Err(e) => {
                                    // REFRESH FAILURE RESILIENCE: Retain last valid snapshot!
                                    // Never wipe cached containers on transient network/daemon errors.
                                    st.last_error = Some(e.to_string());
                                }
                            }
                        }
                        st.is_refreshing = false;
                    }
                }
                Ok(WorkerRequest::Inspect {
                    container_id,
                    sessions,
                    processes,
                }) => {
                    if !running.load(Ordering::SeqCst) || shutdown_requested.load(Ordering::SeqCst)
                    {
                        break;
                    }
                    let already_cached = {
                        state
                            .read()
                            .ok()
                            .map(|st| st.inspected.contains_key(&container_id))
                            .unwrap_or(false)
                    };

                    if !already_cached {
                        match collector.inspect_container(&container_id) {
                            Ok(mut detail) => {
                                DockerCoordinator::correlate_container_with_mounts(
                                    &mut detail.info,
                                    &detail.mounts,
                                    &sessions,
                                    &processes,
                                );
                                if let Ok(mut st) = state.write() {
                                    // Enforce bounded cache size
                                    while st.inspected_keys.len() >= MAX_CACHED_INSPECTIONS {
                                        if let Some(old_key) = st.inspected_keys.pop_front() {
                                            st.inspected.remove(&old_key);
                                        }
                                    }

                                    st.inspected.insert(container_id.clone(), detail.clone());
                                    st.inspected_keys.push_back(container_id.clone());
                                    if !detail.info.short_id.is_empty() {
                                        st.inspected
                                            .insert(detail.info.short_id.clone(), detail.clone());
                                    }
                                    if !detail.info.name.is_empty() {
                                        st.inspected.insert(
                                            detail.info.name.trim_start_matches('/').to_string(),
                                            detail,
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                if let Ok(mut st) = state.write() {
                                    st.last_error = Some(format!(
                                        "Inspection failed for {}: {}",
                                        container_id, e
                                    ));
                                }
                            }
                        }
                    }
                }
                Err(_) => break, // Channel disconnected
            }
        }
    }

    /// Triggers a non-blocking background refresh.
    /// Rate-limited: returns false and drops request if refresh is already in-flight,
    /// shutting down, worker thread exited, or queue is full.
    pub fn trigger_refresh(
        &self,
        generation: u64,
        sessions: Vec<SessionInfo>,
        processes: Vec<ProcessInfo>,
    ) -> bool {
        if self.is_shutting_down() || self.has_thread_exited() || self.is_refreshing() {
            return false;
        }

        let sent = self
            .request_tx
            .try_send(WorkerRequest::Refresh {
                generation,
                sessions,
                processes,
            })
            .is_ok();

        if sent {
            if let Ok(mut st) = self.state.write() {
                st.is_refreshing = true;
            }
        }
        sent
    }

    /// Triggers non-blocking background inspection of a container.
    pub fn trigger_inspect(
        &self,
        container_id: String,
        sessions: Vec<SessionInfo>,
        processes: Vec<ProcessInfo>,
    ) {
        if self.is_shutting_down() || self.has_thread_exited() {
            return;
        }
        let _ = self.request_tx.try_send(WorkerRequest::Inspect {
            container_id,
            sessions,
            processes,
        });
    }

    pub fn get_cached_containers(&self) -> Vec<ContainerInfo> {
        self.state
            .read()
            .map(|st| st.containers.clone())
            .unwrap_or_default()
    }

    pub fn get_cached_status(&self) -> Option<DockerStatus> {
        self.state.read().ok().and_then(|st| st.status.clone())
    }

    pub fn get_cached_detail(&self, id: &str) -> Option<ContainerDetail> {
        let clean_id = id.trim_start_matches('/');
        self.state
            .read()
            .ok()
            .and_then(|st| st.inspected.get(clean_id).cloned())
    }

    pub fn is_refreshing(&self) -> bool {
        self.state
            .read()
            .map(|st| st.is_refreshing)
            .unwrap_or(false)
    }

    pub fn last_refresh(&self) -> Option<Instant> {
        self.state.read().ok().and_then(|st| st.last_refresh)
    }

    pub fn snapshot_age(&self) -> Option<Duration> {
        self.last_refresh().map(|t| t.elapsed())
    }

    pub fn is_stale(&self, max_age: Duration) -> bool {
        match self.snapshot_age() {
            Some(age) => age > max_age,
            None => true,
        }
    }

    pub fn last_error(&self) -> Option<String> {
        self.state.read().ok().and_then(|st| st.last_error.clone())
    }

    pub fn is_error(&self) -> bool {
        self.last_error().is_some()
    }

    /// Checks if a shutdown has been initiated for this background worker.
    pub fn is_shutting_down(&self) -> bool {
        self.shutdown_requested.load(Ordering::SeqCst) || !self.running.load(Ordering::SeqCst)
    }

    /// Checks if the dedicated worker thread has terminated.
    pub fn has_thread_exited(&self) -> bool {
        self.thread_exited.load(Ordering::SeqCst)
    }

    /// Checks if the background worker is completely stopped.
    pub fn is_stopped(&self) -> bool {
        self.thread_handle.is_none() || self.has_thread_exited()
    }

    /// Requests shutdown of the worker thread and cancels any in-flight collector requests.
    pub fn request_shutdown(&self) {
        self.shutdown_requested.store(true, Ordering::SeqCst);
        self.running.store(false, Ordering::SeqCst);
        self.collector.cancel();
        let _ = self.request_tx.try_send(WorkerRequest::Shutdown);
    }

    /// Attempts to stop the background worker within the specified timeout.
    ///
    /// GUARANTEES:
    /// - Sets shutdown requested flag immediately to reject any new requests.
    /// - Signals cancellation to the underlying collector.
    /// - Never spawns detached joiner threads that leak resources when joins stall.
    /// - Polls the worker thread's exit flag up to `timeout`.
    /// - If the thread exits, consumes the join handle immediately.
    /// - If the timeout expires without exit, preserves the join handle and returns `TimedOut`.
    pub fn stop_with_timeout(&mut self, timeout: Duration) -> WorkerShutdownResult {
        if self.thread_handle.is_none() {
            return WorkerShutdownResult::AlreadyStopped;
        }

        // 1. Signal cancellation and shutdown
        self.request_shutdown();

        // 2. Bounded polling without spawning detached joiner threads
        let start = Instant::now();
        let poll_interval = Duration::from_millis(5);

        while !self.thread_exited.load(Ordering::SeqCst) {
            if start.elapsed() >= timeout {
                // Thread did not exit within timeout.
                // Do NOT discard or detach the join handle!
                return WorkerShutdownResult::TimedOut;
            }
            let remaining = timeout.saturating_sub(start.elapsed());
            thread::sleep(remaining.min(poll_interval));
        }

        // 3. Worker thread has confirmed exit; consume join handle with zero blocking
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }

        WorkerShutdownResult::Terminated
    }

    /// Stops the worker with a default 500ms bounded timeout.
    pub fn stop(&mut self) -> WorkerShutdownResult {
        self.stop_with_timeout(Duration::from_millis(500))
    }
}

impl Drop for DockerBackgroundWorker {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
