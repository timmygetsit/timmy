use crate::model::{ContainerDetail, ContainerInfo, ContainerStats, DockerStatus};
use crate::platform::traits::{DockerCollector, PlatformError};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// A thread-safe, hermetic mock Docker collector for unit and integration testing.
#[derive(Clone)]
pub struct MockDockerCollector {
    pub status: Arc<Mutex<Result<DockerStatus, PlatformError>>>,
    pub containers: Arc<Mutex<Result<Vec<ContainerInfo>, PlatformError>>>,
    pub details: Arc<Mutex<HashMap<String, Result<ContainerDetail, PlatformError>>>>,
    pub stats: Arc<Mutex<HashMap<String, Result<ContainerStats, PlatformError>>>>,
    pub cancelled: Arc<std::sync::atomic::AtomicBool>,
}

impl Default for MockDockerCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl MockDockerCollector {
    pub fn new() -> Self {
        Self {
            status: Arc::new(Mutex::new(Ok(DockerStatus {
                installed: false,
                running: false,
                socket_path: "/var/run/docker.sock".to_string(),
                api_version: None,
                engine_version: None,
                os: None,
                arch: None,
                active_context: None,
                error_message: Some("Docker daemon not running".to_string()),
                error_category: Some(crate::model::DockerErrorCategory::DaemonStopped),
            }))),
            containers: Arc::new(Mutex::new(Ok(Vec::new()))),
            details: Arc::new(Mutex::new(HashMap::new())),
            stats: Arc::new(Mutex::new(HashMap::new())),
            cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    pub fn with_running_status(engine: &str, api: &str, socket: &str) -> Self {
        let mock = Self::new();
        *mock.status.lock().unwrap() = Ok(DockerStatus {
            installed: true,
            running: true,
            socket_path: socket.to_string(),
            api_version: Some(api.to_string()),
            engine_version: Some(engine.to_string()),
            os: Some("linux".to_string()),
            arch: Some("arm64".to_string()),
            active_context: Some("desktop-linux".to_string()),
            error_message: None,
            error_category: Some(crate::model::DockerErrorCategory::None),
        });
        mock
    }

    pub fn set_status(&self, status: Result<DockerStatus, PlatformError>) {
        *self.status.lock().unwrap() = status;
    }

    pub fn set_containers_result(&self, res: Result<Vec<ContainerInfo>, PlatformError>) {
        *self.containers.lock().unwrap() = res;
    }

    pub fn add_container(&self, container: ContainerInfo) {
        let mut list = self.containers.lock().unwrap();
        if let Ok(ref mut vec) = *list {
            vec.push(container);
        } else {
            *list = Ok(vec![container]);
        }
    }

    pub fn add_detail(&self, id: &str, detail: ContainerDetail) {
        self.details
            .lock()
            .unwrap()
            .insert(id.to_string(), Ok(detail));
    }

    pub fn set_detail_error(&self, id: &str, err: PlatformError) {
        self.details
            .lock()
            .unwrap()
            .insert(id.to_string(), Err(err));
    }

    pub fn add_stats(&self, id: &str, stats: ContainerStats) {
        self.stats.lock().unwrap().insert(id.to_string(), Ok(stats));
    }
}

impl DockerCollector for MockDockerCollector {
    fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn docker_status(&self) -> Result<DockerStatus, PlatformError> {
        self.status.lock().unwrap().clone()
    }

    fn collect_containers(&self) -> Result<Vec<ContainerInfo>, PlatformError> {
        self.containers.lock().unwrap().clone()
    }

    fn inspect_container(&self, id: &str) -> Result<ContainerDetail, PlatformError> {
        let details = self.details.lock().unwrap();
        if let Some(res) = details.get(id) {
            res.clone()
        } else {
            Err(PlatformError::ContainerNotFound(id.to_string()))
        }
    }

    fn collect_container_stats(&self, id: &str) -> Result<ContainerStats, PlatformError> {
        let stats = self.stats.lock().unwrap();
        if let Some(res) = stats.get(id) {
            res.clone()
        } else {
            Err(PlatformError::ContainerNotFound(id.to_string()))
        }
    }
}
