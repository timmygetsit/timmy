use crate::engine::services::ServiceDiscoveryCoordinator;
use crate::model::process::ProcessInfo;
use crate::model::service::ServiceInfo;
use crate::model::session::SessionInfo;
use crate::platform::docker::worker::WorkerShutdownResult;
use crate::platform::traits::ServiceCollector;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Status distinguishing complete, partial, stale, or failed snapshot collections.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SnapshotStatus {
    /// Initial state, no collection performed yet
    #[default]
    Initial,
    /// Fresh, complete inventory of services
    Complete,
    /// Partial inventory due to truncated output or bounded memory limits
    Partial { reason: String },
    /// Collection failed; retaining previous snapshot as stale last-known-good
    Stale { error: String },
    /// Collection failed with no previous snapshot available
    Failed { error: String },
}

/// Shared thread-safe snapshot of discovered services maintained by background worker.
#[derive(Debug, Default)]
pub struct ServiceWorkerState {
    pub services: Vec<ServiceInfo>,
    pub last_known_complete: Option<Vec<ServiceInfo>>,
    pub status: SnapshotStatus,
    pub is_refreshing: bool,
    pub last_refresh: Option<Instant>,
    pub last_error: Option<String>,
    pub is_partial: bool,
    pub warning: Option<String>,
    pub generation: u64,
}

#[derive(Debug)]
pub enum ServiceWorkerRequest {
    Refresh {
        generation: u64,
        sessions: Vec<SessionInfo>,
        processes: Vec<ProcessInfo>,
    },
    Shutdown,
}

/// Genuine non-blocking background background service worker.
///
/// Dispatches slow filesystem scanning and launchctl subprocess I/O off the TUI main thread
/// onto a dedicated worker thread. Ensures the TUI event loop, modal navigation, and keypress
/// handlers remain 100% responsive without dropping frames or stalling.
pub struct ServiceBackgroundWorker {
    state: Arc<RwLock<ServiceWorkerState>>,
    request_tx: SyncSender<ServiceWorkerRequest>,
    running: Arc<AtomicBool>,
    shutdown_requested: Arc<AtomicBool>,
    thread_exited: Arc<AtomicBool>,
    collector: Arc<dyn ServiceCollector>,
    thread_handle: Option<JoinHandle<()>>,
}

impl ServiceBackgroundWorker {
    pub fn new(collector: Arc<dyn ServiceCollector>) -> Self {
        let state = Arc::new(RwLock::new(ServiceWorkerState::default()));
        // Bounded channel to prevent request backlog
        let (request_tx, request_rx) = sync_channel::<ServiceWorkerRequest>(4);
        let running = Arc::new(AtomicBool::new(true));
        let shutdown_requested = Arc::new(AtomicBool::new(false));
        let thread_exited = Arc::new(AtomicBool::new(false));

        let state_clone = Arc::clone(&state);
        let running_clone = Arc::clone(&running);
        let shutdown_clone = Arc::clone(&shutdown_requested);
        let thread_exited_clone = Arc::clone(&thread_exited);
        let collector_clone = Arc::clone(&collector);

        let thread_handle = thread::Builder::new()
            .name("timmy-service-worker".to_string())
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
            .expect("Failed to spawn Service background worker thread");

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
        collector: Arc<dyn ServiceCollector>,
        state: Arc<RwLock<ServiceWorkerState>>,
        rx: Receiver<ServiceWorkerRequest>,
        running: Arc<AtomicBool>,
        shutdown_requested: Arc<AtomicBool>,
        thread_exited: Arc<AtomicBool>,
    ) {
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
                Ok(ServiceWorkerRequest::Shutdown) => break,
                Ok(ServiceWorkerRequest::Refresh {
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

                    // Perform service collection and session correlation
                    let result = collector.collect_services();

                    if !running.load(Ordering::SeqCst) || shutdown_requested.load(Ordering::SeqCst)
                    {
                        break;
                    }

                    if let Ok(mut st) = state.write() {
                        // Monotonic generation check: ensure slower older requests do not overwrite newer results
                        if generation >= st.generation {
                            st.generation = generation;
                            match result {
                                Ok(mut services) => {
                                    let has_partial = services.iter().any(|s| s.is_partial);
                                    st.is_partial = has_partial;
                                    ServiceDiscoveryCoordinator::correlate_services(
                                        &mut services,
                                        &processes,
                                        &sessions,
                                    );
                                    if has_partial {
                                        let reason = "launchctl output was truncated at memory limit (incomplete inventory)".to_string();
                                        st.status = SnapshotStatus::Partial {
                                            reason: reason.clone(),
                                        };
                                        st.warning = Some(format!("Partial snapshot: {}", reason));
                                    } else {
                                        st.status = SnapshotStatus::Complete;
                                        st.warning = None;
                                        st.last_known_complete = Some(services.clone());
                                    }
                                    st.services = services;
                                    st.last_error = None;
                                    st.last_refresh = Some(Instant::now());
                                }
                                Err(e) => {
                                    // PRESERVE SNAPSHOT: Do not blow away cached services on transient error!
                                    let err_str = format!("{}", e);
                                    st.last_error = Some(err_str.clone());
                                    if st.last_known_complete.is_some() || !st.services.is_empty() {
                                        let age_str = match st.last_refresh {
                                            Some(t) => {
                                                let secs = t.elapsed().as_secs();
                                                if secs < 60 {
                                                    format!("{}s ago", secs)
                                                } else if secs < 3600 {
                                                    format!("{}m ago", secs / 60)
                                                } else {
                                                    format!("{}h ago", secs / 3600)
                                                }
                                            }
                                            None => "never".to_string(),
                                        };
                                        st.status = SnapshotStatus::Stale {
                                            error: err_str.clone(),
                                        };
                                        st.warning = Some(format!(
                                            "Service discovery failed: {} (displaying stale last-known-good snapshot from {})",
                                            err_str, age_str
                                        ));
                                    } else {
                                        st.status = SnapshotStatus::Failed {
                                            error: err_str.clone(),
                                        };
                                        st.warning =
                                            Some(format!("Service discovery failed: {}", err_str));
                                    }
                                }
                            }
                        }
                        st.is_refreshing = false;
                    }
                }
                Err(_) => {
                    // Channel disconnected
                    break;
                }
            }
        }
    }

    /// Triggers an asynchronous service discovery refresh without blocking the caller.
    pub fn trigger_refresh(
        &self,
        generation: u64,
        sessions: Vec<SessionInfo>,
        processes: Vec<ProcessInfo>,
    ) {
        if !self.running.load(Ordering::SeqCst) || self.shutdown_requested.load(Ordering::SeqCst) {
            return;
        }

        let _ = self.request_tx.try_send(ServiceWorkerRequest::Refresh {
            generation,
            sessions,
            processes,
        });
    }

    /// Retrieves the most recent cached services snapshot without blocking.
    /// Resilient to lock poisoning (recovers inner state rather than failing or returning empty).
    pub fn get_cached_services(&self) -> Vec<ServiceInfo> {
        self.state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .services
            .clone()
    }

    /// Retrieves the last known complete services snapshot, preserved when the current
    /// snapshot is partial or failed.
    pub fn get_last_known_complete(&self) -> Option<Vec<ServiceInfo>> {
        self.state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .last_known_complete
            .clone()
    }

    /// Returns the current lifecycle status of the snapshot (Complete, Partial, Stale, or Failed).
    pub fn snapshot_status(&self) -> SnapshotStatus {
        self.state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .status
            .clone()
    }

    /// Returns whether a refresh is currently running in the background.
    pub fn is_refreshing(&self) -> bool {
        self.state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .is_refreshing
    }

    /// Returns whether the current snapshot was truncated or partial.
    pub fn is_partial(&self) -> bool {
        self.state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .is_partial
    }

    /// Returns any diagnostic warning from background collection.
    pub fn warning(&self) -> Option<String> {
        self.state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .warning
            .clone()
    }

    /// Returns the current generation number of cached service data.
    pub fn current_generation(&self) -> u64 {
        self.state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .generation
    }

    /// Returns the last error encountered during background collection, if any.
    pub fn last_error(&self) -> Option<String> {
        self.state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .last_error
            .clone()
    }

    /// Returns the timestamp of the last successful service refresh, if any.
    pub fn last_refresh_time(&self) -> Option<Instant> {
        self.state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .last_refresh
    }

    /// Returns the elapsed duration since the last successful service refresh.
    pub fn snapshot_age(&self) -> Option<Duration> {
        self.last_refresh_time().map(|t| t.elapsed())
    }

    /// Returns a human-readable string of the snapshot age (e.g., "5s ago", "2m ago").
    pub fn snapshot_age_str(&self) -> String {
        match self.snapshot_age() {
            Some(d) => {
                let secs = d.as_secs();
                if secs < 60 {
                    format!("{}s ago", secs)
                } else if secs < 3600 {
                    format!("{}m ago", secs / 60)
                } else {
                    format!("{}h ago", secs / 3600)
                }
            }
            None => "never".to_string(),
        }
    }

    /// Returns a reference to the underlying service collector.
    pub fn collector(&self) -> &Arc<dyn ServiceCollector> {
        &self.collector
    }

    /// Checks if worker is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst) && !self.shutdown_requested.load(Ordering::SeqCst)
    }

    /// Checks if worker thread has fully exited.
    pub fn is_terminated(&self) -> bool {
        self.thread_exited.load(Ordering::SeqCst)
    }

    /// Gracefully stops the worker within the given timeout.
    pub fn stop(&mut self, timeout: Duration) -> WorkerShutdownResult {
        if self.thread_exited.load(Ordering::SeqCst) {
            return WorkerShutdownResult::AlreadyStopped;
        }

        self.shutdown_requested.store(true, Ordering::SeqCst);
        self.running.store(false, Ordering::SeqCst);
        let _ = self.request_tx.try_send(ServiceWorkerRequest::Shutdown);

        let start = Instant::now();
        while !self.thread_exited.load(Ordering::SeqCst) {
            if start.elapsed() >= timeout {
                return WorkerShutdownResult::TimedOut;
            }
            thread::sleep(Duration::from_millis(10));
        }

        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }

        WorkerShutdownResult::Terminated
    }
}

impl Drop for ServiceBackgroundWorker {
    fn drop(&mut self) {
        if !self.thread_exited.load(Ordering::SeqCst) {
            let _ = self.stop(Duration::from_millis(500));
        }
    }
}
