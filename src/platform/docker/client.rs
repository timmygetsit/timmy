use crate::model::{
    ContainerDetail, ContainerInfo, ContainerState, ContainerStats, DockerErrorCategory,
    DockerStatus, MountInfo, PortBinding,
};
use crate::platform::traits::{DockerCollector, PlatformError};
use crate::safety::masker::SecretMasker;
use bollard::query_parameters::{InspectContainerOptions, ListContainersOptions, StatsOptions};
use bollard::Docker;
use chrono::{DateTime, Utc};
use futures_util::stream::{self, StreamExt};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

/// Helper to execute async futures in a synchronous context without panicking.
pub struct TokioRunner {
    runtime: Mutex<tokio::runtime::Runtime>,
}

impl Default for TokioRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl TokioRunner {
    pub fn new() -> Self {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime for Docker client");
        Self {
            runtime: Mutex::new(runtime),
        }
    }

    pub fn block_on<F, R>(&self, future: F) -> R
    where
        F: std::future::Future<Output = R> + Send + 'static,
        R: Send + 'static,
    {
        if tokio::runtime::Handle::try_current().is_ok() {
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("Failed to create tokio runtime for Docker client");
                rt.block_on(future)
            })
            .join()
            .expect("Docker runner thread panicked")
        } else {
            let rt = self.runtime.lock().expect("Tokio runtime mutex poisoned");
            rt.block_on(future)
        }
    }
}

pub fn user_home_dir() -> Option<PathBuf> {
    directories::BaseDirs::new()
        .map(|b| b.home_dir().to_path_buf())
        .or_else(|| std::env::var("HOME").ok().map(PathBuf::from))
}

/// Resolves the Docker configuration directory respecting $DOCKER_CONFIG if set,
/// falling back to standard ~/.docker directory.
pub fn docker_config_dir() -> Option<PathBuf> {
    if let Ok(cfg_dir) = std::env::var("DOCKER_CONFIG") {
        let trimmed = cfg_dir.trim();
        if !trimmed.is_empty() {
            return Some(PathBuf::from(trimmed));
        }
    }
    user_home_dir().map(|h| h.join(".docker"))
}

/// Production Docker collector powered by `bollard` over strictly local UNIX domain sockets.
pub struct BollardDockerCollector {
    custom_socket: Option<String>,
    timeout: Duration,
    runner: TokioRunner,
    client_cache: Mutex<Option<(Docker, String)>>,
    cancelled: std::sync::atomic::AtomicBool,
}

impl BollardDockerCollector {
    pub fn new(custom_socket: Option<String>, timeout: Duration) -> Self {
        Self {
            custom_socket,
            timeout,
            runner: TokioRunner::new(),
            client_cache: Mutex::new(None),
            cancelled: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub fn reset_cancellation(&self) {
        self.cancelled
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// Resolves the Docker UNIX socket path in strict precedence order:
    /// 1. Explicit TIMMY configuration (`general.docker_socket`)
    /// 2. `DOCKER_CONTEXT` environment variable
    /// 3. `DOCKER_HOST` environment variable
    /// 4. Current context configured in `$DOCKER_CONFIG/config.json` (or `~/.docker/config.json`)
    /// 5. Standard default auto-discovery:
    ///    - macOS: Docker Desktop, OrbStack, Colima, or `/var/run/docker.sock`
    ///    - Linux: `/var/run/docker.sock` or rootless `$XDG_RUNTIME_DIR/docker.sock`
    ///
    /// GUARANTEES:
    /// - Strictly rejects all remote network schemes (`tcp://`, `http://`, `https://`, `ssh://`).
    /// - Never silently falls back to another socket when an explicit socket, host, or context was configured.
    pub fn resolve_endpoint(&self) -> Result<(String, Option<String>, bool), PlatformError> {
        let (installed, active_context) = Self::detect_installation();

        // 1. Explicit TIMMY config override (`general.docker_socket`)
        if let Some(ref custom) = self.custom_socket {
            let trimmed = custom.trim();
            if !trimmed.is_empty() {
                let sock_path = Self::parse_and_validate_local_endpoint(trimmed)?;
                Self::check_socket_accessible(Path::new(&sock_path))?;
                return Ok((sock_path, active_context, installed));
            }
        }

        // 2. DOCKER_CONTEXT environment variable (takes precedence over DOCKER_HOST per standard Docker CLI)
        if let Ok(ctx_env) = std::env::var("DOCKER_CONTEXT") {
            let trimmed = ctx_env.trim();
            if !trimmed.is_empty() && trimmed != "default" {
                let endpoint = Self::resolve_context_endpoint(trimmed)?;
                let sock_path = Self::parse_and_validate_local_endpoint(&endpoint)?;
                Self::check_socket_accessible(Path::new(&sock_path))?;
                return Ok((sock_path, Some(trimmed.to_string()), installed));
            }
        }

        // 3. DOCKER_HOST environment variable (takes precedence over config.json currentContext)
        if let Ok(env_host) = std::env::var("DOCKER_HOST") {
            let trimmed = env_host.trim();
            if !trimmed.is_empty() {
                let sock_path = Self::parse_and_validate_local_endpoint(trimmed)?;
                Self::check_socket_accessible(Path::new(&sock_path))?;
                return Ok((sock_path, active_context, installed));
            }
        }

        // 4. Current context from $DOCKER_CONFIG/config.json (or ~/.docker/config.json)
        if let Some(ref ctx) = active_context {
            if ctx != "default" {
                let endpoint = Self::resolve_context_endpoint(ctx)?;
                let sock_path = Self::parse_and_validate_local_endpoint(&endpoint)?;
                Self::check_socket_accessible(Path::new(&sock_path))?;
                return Ok((sock_path, Some(ctx.clone()), installed));
            }
        }

        // 5. Standard default auto-discovery (only when context is "default" or unset)
        let candidates = Self::standard_default_sockets();
        for candidate in candidates {
            if candidate.exists() {
                let sock_str = candidate.to_string_lossy().to_string();
                Self::check_socket_accessible(&candidate)?;
                return Ok((sock_str, active_context, installed));
            }
        }

        // If no candidate exists:
        if installed {
            let default_path = if cfg!(target_os = "macos") {
                user_home_dir()
                    .map(|h| {
                        h.join(".docker/run/docker.sock")
                            .to_string_lossy()
                            .to_string()
                    })
                    .unwrap_or_else(|| "/var/run/docker.sock".to_string())
            } else {
                "/var/run/docker.sock".to_string()
            };
            Err(PlatformError::DockerDaemonStopped(format!(
                "Docker socket not found at '{}'. Is Docker Desktop or the Docker daemon running?",
                default_path
            )))
        } else {
            Err(PlatformError::DockerNotInstalled)
        }
    }

    /// Validates that an endpoint string represents a local UNIX socket.
    /// Strictly rejects all remote protocols (tcp, http, https, ssh).
    pub fn parse_and_validate_local_endpoint(raw: &str) -> Result<String, PlatformError> {
        let trimmed = raw.trim();
        let lower = trimmed.to_lowercase();

        if lower.starts_with("tcp://")
            || lower.starts_with("http://")
            || lower.starts_with("https://")
            || lower.starts_with("ssh://")
        {
            return Err(PlatformError::DockerUnsupportedRemote(trimmed.to_string()));
        }

        // Also reject host:port format without scheme (e.g. "127.0.0.1:2375" or "localhost:2375")
        if let Some((host_part, port_part)) = trimmed.split_once(':') {
            if !host_part.is_empty()
                && !host_part.contains('/')
                && port_part.chars().all(|c| c.is_ascii_digit())
            {
                return Err(PlatformError::DockerUnsupportedRemote(trimmed.to_string()));
            }
        }

        if let Some(stripped) = trimmed.strip_prefix("unix://") {
            if stripped.is_empty() {
                return Err(PlatformError::DockerInvalidEndpoint(
                    "Empty unix socket path".to_string(),
                ));
            }
            Ok(stripped.to_string())
        } else if trimmed.starts_with('/') || trimmed.starts_with('.') || trimmed.starts_with('~') {
            let path_str = if let Some(stripped) = trimmed.strip_prefix("~/") {
                if let Some(h) = user_home_dir() {
                    h.join(stripped).to_string_lossy().to_string()
                } else {
                    trimmed.to_string()
                }
            } else {
                trimmed.to_string()
            };
            Ok(path_str)
        } else {
            Err(PlatformError::DockerInvalidEndpoint(format!(
                "Unrecognized local socket endpoint format: '{}'",
                trimmed
            )))
        }
    }

    /// Resolves context metadata from `<docker_config_dir>/contexts/meta/<hash>/meta.json`.
    pub fn resolve_context_endpoint(context_name: &str) -> Result<String, PlatformError> {
        if context_name == "default" {
            return Err(PlatformError::Other(
                "default context uses standard discovery".to_string(),
            ));
        }

        let cfg_dir = docker_config_dir().ok_or_else(|| {
            PlatformError::DockerSocketMissing(
                "Could not resolve Docker configuration directory for Docker contexts".to_string(),
            )
        })?;

        // 1. Direct SHA-256 hash lookup: Docker stores context metadata in <docker_config_dir>/contexts/meta/<sha256(name)>/meta.json
        let mut hasher = Sha256::new();
        hasher.update(context_name.as_bytes());
        let hash_hex = format!("{:x}", hasher.finalize());

        let meta_file = cfg_dir.join(format!("contexts/meta/{}/meta.json", hash_hex));
        if meta_file.exists() {
            if let Ok(content) = std::fs::read_to_string(&meta_file) {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(host) = val
                        .get("Endpoints")
                        .and_then(|e| e.get("docker"))
                        .and_then(|d| d.get("Host"))
                        .and_then(|h| h.as_str())
                    {
                        return Ok(host.to_string());
                    }
                }
            }
        }

        // 2. Directory scan fallback: search <docker_config_dir>/contexts/meta/*/meta.json by "Name" field
        let meta_dir = cfg_dir.join("contexts/meta");
        if meta_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(meta_dir) {
                for entry in entries.flatten() {
                    let candidate = entry.path().join("meta.json");
                    if candidate.exists() {
                        if let Ok(content) = std::fs::read_to_string(&candidate) {
                            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                                if val.get("Name").and_then(|n| n.as_str()) == Some(context_name) {
                                    if let Some(host) = val
                                        .get("Endpoints")
                                        .and_then(|e| e.get("docker"))
                                        .and_then(|d| d.get("Host"))
                                        .and_then(|h| h.as_str())
                                    {
                                        return Ok(host.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 3. Fallback for Docker Desktop desktop-linux context without meta.json
        if context_name == "desktop-linux" {
            let sock = cfg_dir.join("run/docker.sock");
            if sock.exists() {
                return Ok(format!("unix://{}", sock.to_string_lossy()));
            }
            if let Some(home) = user_home_dir() {
                let default_sock = home.join(".docker/run/docker.sock");
                if default_sock.exists() {
                    return Ok(format!("unix://{}", default_sock.to_string_lossy()));
                }
            }
        }

        Err(PlatformError::DockerInvalidEndpoint(format!(
            "Docker context '{}' was not found or contains no valid Docker endpoint",
            context_name
        )))
    }

    /// Returns candidate socket paths for default context auto-discovery.
    fn standard_default_sockets() -> Vec<PathBuf> {
        let mut candidates = Vec::new();
        let home = user_home_dir();

        #[cfg(target_os = "macos")]
        {
            if let Some(ref h) = home {
                // 1. Docker Desktop for macOS
                candidates.push(h.join(".docker/run/docker.sock"));
                // 2. OrbStack on macOS
                candidates.push(h.join(".orbstack/run/docker.sock"));
                // 3. Colima on macOS
                candidates.push(h.join(".colima/default/docker.sock"));
            }
            // 4. Standard legacy system socket
            candidates.push(PathBuf::from("/var/run/docker.sock"));
        }

        #[cfg(not(target_os = "macos"))]
        {
            // 1. Standard Unix socket on Linux
            candidates.push(PathBuf::from("/var/run/docker.sock"));
            // 2. Linux rootless Docker sockets
            if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
                candidates.push(PathBuf::from(runtime_dir).join("docker.sock"));
            }
            let uid = unsafe { libc::geteuid() };
            candidates.push(PathBuf::from(format!("/run/user/{}/docker.sock", uid)));
            if let Some(ref h) = home {
                candidates.push(h.join(".docker/run/docker.sock"));
            }
        }

        candidates
    }

    /// Checks if Docker CLI, Docker Desktop, or standard paths exist.
    pub fn detect_installation() -> (bool, Option<String>) {
        let app_exists = Path::new("/Applications/Docker.app").exists();
        let bin_paths = [
            "/usr/local/bin/docker",
            "/opt/homebrew/bin/docker",
            "/usr/bin/docker",
        ];
        let bin_exists = bin_paths.iter().any(|p| Path::new(p).exists());

        let home_bin_exists = user_home_dir()
            .map(|h| h.join(".docker/bin/docker").exists())
            .unwrap_or(false);

        let active_context = Self::read_docker_context();

        let installed = app_exists || bin_exists || home_bin_exists;
        (installed, active_context)
    }

    pub fn read_docker_context() -> Option<String> {
        if let Ok(ctx) = std::env::var("DOCKER_CONTEXT") {
            let trimmed = ctx.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }

        let cfg_dir = docker_config_dir()?;
        let config_file = cfg_dir.join("config.json");
        if !config_file.exists() {
            return None;
        }

        let content = std::fs::read_to_string(config_file).ok()?;
        let parsed: serde_json::Value = serde_json::from_str(&content).ok()?;
        parsed
            .get("currentContext")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    /// Invalidates any cached Bollard Docker client instance to force reconnection on next call.
    pub fn invalidate_client_cache(&self) {
        if let Ok(mut cache) = self.client_cache.lock() {
            *cache = None;
        }
    }

    /// Verifies that a Unix socket path exists and has accessible permissions.
    pub fn check_socket_accessible(path: &Path) -> Result<(), PlatformError> {
        let path_str = path.to_string_lossy().to_string();
        if !path.exists() {
            return Err(PlatformError::DockerSocketMissing(path_str));
        }

        match std::fs::metadata(path) {
            Ok(metadata) => {
                use std::os::unix::fs::PermissionsExt;
                let mode = metadata.permissions().mode();
                let is_root = unsafe { libc::geteuid() == 0 };
                // If socket has no read/write permissions for current user and user isn't root
                if !is_root && (mode & 0o666) == 0 {
                    return Err(PlatformError::DockerPermissionDenied(path_str));
                }
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                Err(PlatformError::DockerPermissionDenied(path_str))
            }
            Err(e) => Err(PlatformError::Io(e)),
        }
    }

    /// Internal connection helper that applies connection timeouts and reuses existing client.
    fn connect(&self) -> Result<(Docker, String), PlatformError> {
        if self.cancelled.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(PlatformError::DockerDaemonStopped(
                "Docker client operation cancelled".to_string(),
            ));
        }
        let (socket_path, _, _) = self.resolve_endpoint()?;
        Self::check_socket_accessible(Path::new(&socket_path))?;

        let mut cache = self
            .client_cache
            .lock()
            .map_err(|e| PlatformError::Other(e.to_string()))?;
        if let Some((ref docker, ref cached_path)) = *cache {
            if cached_path == &socket_path {
                return Ok((docker.clone(), socket_path));
            }
        }

        let docker = Docker::connect_with_unix(
            &socket_path,
            self.timeout.as_secs().max(1),
            bollard::API_DEFAULT_VERSION,
        )
        .map_err(|e| PlatformError::DockerApi(e.to_string()))?;

        *cache = Some((docker.clone(), socket_path.clone()));
        Ok((docker, socket_path))
    }

    async fn collect_stats_internal(
        docker: &Docker,
        id: &str,
        timeout: Duration,
    ) -> Result<ContainerStats, PlatformError> {
        let stats_opts = Some(StatsOptions {
            stream: false,
            one_shot: true,
        });

        let mut stream = docker.stats(id, stats_opts);
        let next_item = tokio::time::timeout(timeout, stream.next())
            .await
            .map_err(|_| {
                PlatformError::DockerApi(format!(
                    "Timed out after {}ms collecting stats for container {}",
                    timeout.as_millis(),
                    id
                ))
            })?;

        match next_item {
            Some(Ok(resp)) => parse_container_stats_response(&resp).ok_or_else(|| {
                PlatformError::DockerApi("Incomplete stats response from daemon".to_string())
            }),
            Some(Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404,
                ..
            })) => Err(PlatformError::ContainerNotFound(id.to_string())),
            Some(Err(e)) => Err(PlatformError::DockerApi(e.to_string())),
            None => Err(PlatformError::DockerApi("Empty stats stream".to_string())),
        }
    }
}

impl DockerCollector for BollardDockerCollector {
    fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.invalidate_client_cache();
    }

    fn docker_status(&self) -> Result<DockerStatus, PlatformError> {
        if self.cancelled.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(DockerStatus {
                installed: true,
                running: false,
                socket_path: String::new(),
                api_version: None,
                engine_version: None,
                os: None,
                arch: None,
                active_context: Self::read_docker_context(),
                error_message: Some("Docker collector cancelled".to_string()),
                error_category: Some(DockerErrorCategory::DaemonStopped),
            });
        }
        let endpoint_res = self.resolve_endpoint();
        let (socket_path, active_context, installed) = match endpoint_res {
            Ok(tuple) => tuple,
            Err(PlatformError::DockerNotInstalled) => {
                return Ok(DockerStatus {
                    installed: false,
                    running: false,
                    socket_path: String::new(),
                    api_version: None,
                    engine_version: None,
                    os: None,
                    arch: None,
                    active_context: None,
                    error_message: Some("Docker is not installed on this system.".to_string()),
                    error_category: Some(DockerErrorCategory::NotInstalled),
                });
            }
            Err(PlatformError::DockerDaemonStopped(msg)) => {
                let default_sock = if cfg!(target_os = "macos") {
                    user_home_dir()
                        .map(|h| {
                            h.join(".docker/run/docker.sock")
                                .to_string_lossy()
                                .to_string()
                        })
                        .unwrap_or_else(|| "/var/run/docker.sock".to_string())
                } else {
                    "/var/run/docker.sock".to_string()
                };
                return Ok(DockerStatus {
                    installed: true,
                    running: false,
                    socket_path: default_sock,
                    api_version: None,
                    engine_version: None,
                    os: None,
                    arch: None,
                    active_context: Self::read_docker_context(),
                    error_message: Some(msg),
                    error_category: Some(DockerErrorCategory::DaemonStopped),
                });
            }
            Err(PlatformError::DockerSocketMissing(path)) => {
                return Ok(DockerStatus {
                    installed: true,
                    running: false,
                    socket_path: path.clone(),
                    api_version: None,
                    engine_version: None,
                    os: None,
                    arch: None,
                    active_context: Self::read_docker_context(),
                    error_message: Some(format!(
                        "Configured Docker socket '{}' was not found. No fallback attempted because endpoint was explicitly requested.",
                        path
                    )),
                    error_category: Some(DockerErrorCategory::SocketMissing),
                });
            }
            Err(PlatformError::DockerPermissionDenied(path)) => {
                return Ok(DockerStatus {
                    installed: true,
                    running: false,
                    socket_path: path.clone(),
                    api_version: None,
                    engine_version: None,
                    os: None,
                    arch: None,
                    active_context: Self::read_docker_context(),
                    error_message: Some(format!(
                        "Permission denied accessing Docker socket at '{}'. Check user permissions or group membership.",
                        path
                    )),
                    error_category: Some(DockerErrorCategory::PermissionDenied),
                });
            }
            Err(PlatformError::DockerUnsupportedRemote(ep)) => {
                return Ok(DockerStatus {
                    installed: true,
                    running: false,
                    socket_path: ep.clone(),
                    api_version: None,
                    engine_version: None,
                    os: None,
                    arch: None,
                    active_context: Self::read_docker_context(),
                    error_message: Some(format!(
                        "Unsupported remote Docker endpoint '{}': TIMMY communicates strictly over local UNIX domain sockets in this milestone.",
                        ep
                    )),
                    error_category: Some(DockerErrorCategory::UnsupportedRemote),
                });
            }
            Err(PlatformError::DockerInvalidEndpoint(ep)) => {
                return Ok(DockerStatus {
                    installed: true,
                    running: false,
                    socket_path: ep.clone(),
                    api_version: None,
                    engine_version: None,
                    os: None,
                    arch: None,
                    active_context: Self::read_docker_context(),
                    error_message: Some(format!("Invalid Docker endpoint format: '{}'", ep)),
                    error_category: Some(DockerErrorCategory::InvalidEndpoint),
                });
            }
            Err(other) => {
                return Ok(DockerStatus {
                    installed: false,
                    running: false,
                    socket_path: String::new(),
                    api_version: None,
                    engine_version: None,
                    os: None,
                    arch: None,
                    active_context: Self::read_docker_context(),
                    error_message: Some(other.to_string()),
                    error_category: Some(DockerErrorCategory::Other),
                });
            }
        };

        let connect_timeout = self.timeout;
        let socket_for_run = socket_path.clone();

        let status_res = self.runner.block_on(async move {
            let docker = Docker::connect_with_unix(
                &socket_for_run,
                connect_timeout.as_secs().max(1),
                bollard::API_DEFAULT_VERSION,
            )
            .map_err(|e| PlatformError::DockerApi(e.to_string()))?;

            let version_fut = docker.version();
            tokio::time::timeout(connect_timeout, version_fut)
                .await
                .map_err(|_| {
                    PlatformError::DockerDaemonStopped(format!(
                        "Connection timed out after {}ms querying Docker version",
                        connect_timeout.as_millis()
                    ))
                })?
                .map_err(|e| PlatformError::DockerApi(e.to_string()))
        });

        match status_res {
            Ok(v) => Ok(DockerStatus {
                installed: true,
                running: true,
                socket_path,
                api_version: v.api_version,
                engine_version: v.version,
                os: v.os,
                arch: v.arch,
                active_context,
                error_message: None,
                error_category: Some(DockerErrorCategory::None),
            }),
            Err(e) => {
                self.invalidate_client_cache();
                Ok(DockerStatus {
                    installed,
                    running: false,
                    socket_path,
                    api_version: None,
                    engine_version: None,
                    os: None,
                    arch: None,
                    active_context,
                    error_message: Some(e.to_string()),
                    error_category: Some(DockerErrorCategory::DaemonStopped),
                })
            }
        }
    }

    fn collect_containers(&self) -> Result<Vec<ContainerInfo>, PlatformError> {
        if self.cancelled.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(PlatformError::DockerDaemonStopped(
                "Docker operation cancelled".to_string(),
            ));
        }
        let (docker, _) = self.connect()?;
        let timeout_dur = self.timeout;

        let res = self.runner.block_on(async move {
            let options = Some(ListContainersOptions {
                all: true,
                ..Default::default()
            });

            let list_fut = docker.list_containers(options);
            let summaries = tokio::time::timeout(timeout_dur, list_fut)
                .await
                .map_err(|_| {
                    PlatformError::DockerApi(format!(
                        "Timed out after {}ms listing containers",
                        timeout_dur.as_millis()
                    ))
                })?
                .map_err(|e| PlatformError::DockerApi(e.to_string()))?;

            // Gather running container IDs to collect live stats concurrently
            let running_ids: Vec<String> = summaries
                .iter()
                .filter(|s| {
                    s.state
                        .as_ref()
                        .map(|st| st.to_string().to_lowercase())
                        .as_deref()
                        == Some("running")
                })
                .filter_map(|s| s.id.clone())
                .collect();

            let mut stats_map: std::collections::HashMap<String, ContainerStats> = if !running_ids
                .is_empty()
            {
                let d = docker.clone();
                stream::iter(running_ids)
                    .map(|cid| {
                        let docker_ref = d.clone();
                        async move {
                            let stats_fut = async {
                                let mut stream = docker_ref.stats(
                                    &cid,
                                    Some(StatsOptions {
                                        stream: false,
                                        one_shot: true,
                                    }),
                                );
                                stream.next().await
                            };
                            match tokio::time::timeout(Duration::from_millis(150), stats_fut).await
                            {
                                Ok(Some(Ok(resp))) => {
                                    parse_container_stats_response(&resp).map(|st| (cid, st))
                                }
                                _ => None,
                            }
                        }
                    })
                    .buffer_unordered(4)
                    .filter_map(|res| async move { res })
                    .collect::<Vec<_>>()
                    .await
                    .into_iter()
                    .collect()
            } else {
                std::collections::HashMap::new()
            };

            let mut containers = Vec::with_capacity(summaries.len());

            for s in summaries {
                let id = s.id.unwrap_or_default();
                let short_id = if id.len() >= 12 {
                    id[..12].to_string()
                } else {
                    id.clone()
                };

                let name = s
                    .names
                    .and_then(|ns| ns.into_iter().next())
                    .map(|n| n.trim_start_matches('/').to_string())
                    .unwrap_or_else(|| "unnamed".to_string());

                let image = s.image.unwrap_or_default();
                let image_id = s.image_id;

                let state_str = s.state.map(|st| st.to_string()).unwrap_or_default();
                let state = state_str
                    .parse::<ContainerState>()
                    .unwrap_or(ContainerState::Unknown(state_str));

                let status = s.status.unwrap_or_default();

                let command = s.command.map(|cmd| {
                    let parts: Vec<String> =
                        cmd.split_whitespace().map(|p| p.to_string()).collect();
                    SecretMasker::mask_cmdline(&parts).join(" ")
                });

                let created_at = s
                    .created
                    .and_then(|secs| DateTime::<Utc>::from_timestamp(secs, 0))
                    .map(|dt| dt.to_rfc3339());

                let mut ports = Vec::new();
                if let Some(port_summaries) = s.ports {
                    for p in port_summaries {
                        if let Some(pub_port) = p.public_port {
                            ports.push(PortBinding {
                                host_ip: p.ip.unwrap_or_else(|| "0.0.0.0".to_string()),
                                host_port: pub_port,
                                container_port: p.private_port,
                                protocol: p
                                    .typ
                                    .as_ref()
                                    .map(|t| t.to_string())
                                    .unwrap_or_else(|| "tcp".to_string()),
                            });
                        }
                    }
                }

                // Mask sensitive values in labels
                let raw_labels = s.labels.unwrap_or_default();
                let labels = SecretMasker::mask_labels(&raw_labels);

                // Check declared session metadata label
                let declared_session_id = raw_labels
                    .get("timmy.session.id")
                    .or_else(|| raw_labels.get("com.timmy.session_id"))
                    .or_else(|| raw_labels.get("agent.session"))
                    .or_else(|| raw_labels.get("session_id"))
                    .or_else(|| raw_labels.get("timmy.session"))
                    .map(|s| s.trim().to_string());

                let mut networks = Vec::new();
                let mut ip_addresses = Vec::new();
                if let Some(ns) = s.network_settings.and_then(|n| n.networks) {
                    for (net_name, ep) in ns {
                        networks.push(net_name);
                        if let Some(ip) = ep.ip_address {
                            if !ip.is_empty() {
                                ip_addresses.push(ip);
                            }
                        }
                    }
                }

                let network_mode = s.host_config.and_then(|hc| hc.network_mode);
                let stats = stats_map.remove(&id);

                containers.push(ContainerInfo {
                    id,
                    short_id,
                    name,
                    image,
                    image_id,
                    state,
                    status,
                    created_at,
                    started_at: None,
                    ports,
                    exit_code: None,
                    health_status: None,
                    restart_count: None,
                    command,
                    entrypoint: None,
                    working_dir: None,
                    labels,
                    runtime: None,
                    networks,
                    ip_addresses,
                    network_mode,
                    stats,
                    session_id: None,
                    declared_session_id,
                    conflicting_sessions: Vec::new(),
                    confidence: crate::model::Confidence::Unknown,
                    evidence: Vec::new(),
                    creation_outcome: crate::model::CreationOutcome::Unknown,
                    attribution_basis: crate::model::AttributionBasis::None,
                });
            }

            Ok(containers)
        });
        if res.is_err() {
            self.invalidate_client_cache();
        }
        res
    }

    fn inspect_container(&self, id: &str) -> Result<ContainerDetail, PlatformError> {
        if self.cancelled.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(PlatformError::DockerDaemonStopped(
                "Docker operation cancelled".to_string(),
            ));
        }
        let (docker, _) = self.connect()?;
        let timeout_dur = self.timeout;
        let id_string = id.to_string();

        let res = self.runner.block_on(async move {
            let inspect_fut = docker.inspect_container(&id_string, None::<InspectContainerOptions>);
            let resp = tokio::time::timeout(timeout_dur, inspect_fut)
                .await
                .map_err(|_| {
                    PlatformError::DockerApi(format!(
                        "Timed out after {}ms inspecting container {}",
                        timeout_dur.as_millis(),
                        id_string
                    ))
                })?
                .map_err(|e| match e {
                    bollard::errors::Error::DockerResponseServerError {
                        status_code: 404, ..
                    } => PlatformError::ContainerNotFound(id_string.clone()),
                    other => PlatformError::DockerApi(other.to_string()),
                })?;

            let full_id = resp.id.unwrap_or_else(|| id_string.clone());
            let short_id = if full_id.len() >= 12 {
                full_id[..12].to_string()
            } else {
                full_id.clone()
            };

            let name = resp
                .name
                .map(|n| n.trim_start_matches('/').to_string())
                .unwrap_or_else(|| "unnamed".to_string());

            let (state, status, exit_code, health_status, started_at) = if let Some(st) = resp.state
            {
                let s_str = st
                    .status
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                let state = s_str
                    .parse::<ContainerState>()
                    .unwrap_or(ContainerState::Unknown(s_str.clone()));
                let exit = st.exit_code;
                let health = st.health.and_then(|h| h.status.map(|hs| hs.to_string()));
                let started = st
                    .started_at
                    .and_then(|t| DateTime::parse_from_rfc3339(&t).ok())
                    .map(|dt| dt.with_timezone(&Utc).to_rfc3339());
                (state, s_str, exit, health, started)
            } else {
                (
                    ContainerState::Unknown("unknown".to_string()),
                    "unknown".to_string(),
                    None,
                    None,
                    None,
                )
            };

            let restart_count = resp.restart_count.map(|c| c as u64);

            let created_at = resp
                .created
                .and_then(|t| DateTime::parse_from_rfc3339(&t).ok())
                .map(|dt| dt.with_timezone(&Utc).to_rfc3339());

            let config = resp.config;
            let raw_image = config
                .as_ref()
                .and_then(|c| c.image.clone())
                .unwrap_or_default();
            // Mask any embedded credentials in image URL
            let image = SecretMasker::mask_url_credentials(&raw_image).unwrap_or(raw_image);
            let image_id = resp.image;

            let command = config
                .as_ref()
                .and_then(|c| c.cmd.as_ref())
                .map(|args| SecretMasker::mask_cmdline(args).join(" "));

            let entrypoint = config
                .as_ref()
                .and_then(|c| c.entrypoint.as_ref())
                .map(|ep| SecretMasker::mask_cmdline(ep).join(" "));

            let working_dir = config.as_ref().and_then(|c| c.working_dir.clone());
            let raw_labels = config
                .as_ref()
                .and_then(|c| c.labels.clone())
                .unwrap_or_default();
            let labels = SecretMasker::mask_labels(&raw_labels);

            let declared_session_id = raw_labels
                .get("timmy.session.id")
                .or_else(|| raw_labels.get("com.timmy.session_id"))
                .or_else(|| raw_labels.get("agent.session"))
                .or_else(|| raw_labels.get("session_id"))
                .or_else(|| raw_labels.get("timmy.session"))
                .map(|s| s.trim().to_string());

            // SECURITY REQUIREMENT: Never persist or retrieve environment values. Extract variable names only.
            let env_keys: Vec<String> = config
                .as_ref()
                .and_then(|c| c.env.as_ref())
                .map(|list| {
                    list.iter()
                        .map(|kv| {
                            kv.split_once('=')
                                .map(|(k, _)| k.to_string())
                                .unwrap_or_else(|| kv.clone())
                        })
                        .collect()
                })
                .unwrap_or_default();

            let host_config = resp.host_config;
            let runtime = host_config.as_ref().and_then(|hc| hc.runtime.clone());
            let network_mode = host_config.as_ref().and_then(|hc| hc.network_mode.clone());
            let restart_policy = host_config
                .as_ref()
                .and_then(|hc| hc.restart_policy.as_ref())
                .and_then(|rp| rp.name.as_ref().map(|n| n.to_string()))
                .unwrap_or_else(|| "no".to_string());

            let mut mounts = Vec::new();
            if let Some(m_list) = resp.mounts {
                for m in m_list {
                    mounts.push(MountInfo {
                        source: m.source.unwrap_or_default(),
                        destination: m.destination.unwrap_or_default(),
                        mount_type: m.typ.map(|t| t.to_string()).unwrap_or_default(),
                        read_only: !m.rw.unwrap_or(true),
                    });
                }
            }

            let mut networks = Vec::new();
            let mut ip_addresses = Vec::new();
            let mut ports = Vec::new();

            if let Some(ns) = resp.network_settings {
                if let Some(net_map) = ns.networks {
                    for (net_name, ep) in net_map {
                        networks.push(net_name);
                        if let Some(ip) = ep.ip_address {
                            if !ip.is_empty() {
                                ip_addresses.push(ip);
                            }
                        }
                    }
                }

                if let Some(port_map) = ns.ports {
                    for (container_spec, bindings_opt) in port_map {
                        let (port_str, proto) = container_spec
                            .split_once('/')
                            .unwrap_or((&container_spec, "tcp"));
                        let container_port = port_str.parse::<u16>().unwrap_or(0);

                        if let Some(bindings) = bindings_opt {
                            for b in bindings {
                                if let Some(host_port_str) = b.host_port {
                                    if let Ok(host_port) = host_port_str.parse::<u16>() {
                                        ports.push(PortBinding {
                                            host_ip: b
                                                .host_ip
                                                .unwrap_or_else(|| "0.0.0.0".to_string()),
                                            host_port,
                                            container_port,
                                            protocol: proto.to_string(),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let stats = if state == ContainerState::Running {
                Self::collect_stats_internal(&docker, &full_id, timeout_dur)
                    .await
                    .ok()
            } else {
                None
            };

            let info = ContainerInfo {
                id: full_id,
                short_id,
                name,
                image,
                image_id,
                state,
                status,
                created_at,
                started_at,
                ports,
                exit_code,
                health_status,
                restart_count,
                command,
                entrypoint,
                working_dir,
                labels,
                runtime,
                networks,
                ip_addresses,
                network_mode,
                stats,
                session_id: None,
                declared_session_id,
                conflicting_sessions: Vec::new(),
                confidence: crate::model::Confidence::Unknown,
                evidence: Vec::new(),
                creation_outcome: crate::model::CreationOutcome::Unknown,
                attribution_basis: crate::model::AttributionBasis::None,
            };

            Ok(ContainerDetail {
                info,
                env_keys,
                mounts,
                restart_policy,
                platform: resp.platform,
            })
        });
        if res.is_err() {
            self.invalidate_client_cache();
        }
        res
    }

    fn collect_container_stats(&self, id: &str) -> Result<ContainerStats, PlatformError> {
        let (docker, _) = self.connect()?;
        let id_string = id.to_string();
        let timeout_dur = self.timeout;

        let res = self.runner.block_on(async move {
            Self::collect_stats_internal(&docker, &id_string, timeout_dur).await
        });
        if res.is_err() {
            self.invalidate_client_cache();
        }
        res
    }
}

/// Parses Docker stats response into a strongly typed `ContainerStats` instance.
pub fn parse_container_stats_response(
    resp: &bollard::models::ContainerStatsResponse,
) -> Option<ContainerStats> {
    let cpu_percentage = calculate_cpu_percentage(resp);
    let (memory_usage_bytes, memory_working_set_bytes, memory_limit_bytes, memory_percentage) =
        calculate_memory_stats(resp);
    let (network_rx_bytes, network_tx_bytes) = calculate_network_io(resp);
    let (block_read_bytes, block_write_bytes) = calculate_block_io(resp);
    let pids_count = resp
        .pids_stats
        .as_ref()
        .and_then(|p| p.current)
        .map(|c| c as u32);

    Some(ContainerStats {
        cpu_percentage,
        memory_usage_bytes,
        memory_working_set_bytes,
        memory_limit_bytes,
        memory_percentage,
        network_rx_bytes,
        network_tx_bytes,
        block_read_bytes,
        block_write_bytes,
        pids_count,
    })
}

/// Calculates container CPU utilization percentage following the official Docker calculation algorithm:
/// `(cpu_delta / system_delta) * online_cpus * 100.0`.
///
/// Returns:
/// - `Some(0.0)` for genuine idle states where container delta is 0 and system delta > 0.
/// - `None` when counters are missing, system delta <= 0, or counters are decreasing/invalid.
pub fn calculate_cpu_percentage(resp: &bollard::models::ContainerStatsResponse) -> Option<f32> {
    let cpu_stats = resp.cpu_stats.as_ref()?;
    let precpu_stats = resp.precpu_stats.as_ref()?;

    let total_usage = cpu_stats.cpu_usage.as_ref()?.total_usage?;
    let pre_total_usage = precpu_stats.cpu_usage.as_ref()?.total_usage?;

    // Decreasing counter indicates container reset or corrupt counters -> invalid metric
    if total_usage < pre_total_usage {
        return None;
    }
    let cpu_delta = total_usage as f64 - pre_total_usage as f64;

    let sys_usage = cpu_stats.system_cpu_usage?;
    let pre_sys_usage = precpu_stats.system_cpu_usage?;

    let system_delta = sys_usage as f64 - pre_sys_usage as f64;

    // System delta <= 0 means no elapsed host CPU ticks were recorded -> invalid metric
    if system_delta <= 0.0 {
        return None;
    }

    // Differentiate genuine 0.0% idle from missing or invalid counters
    if cpu_delta == 0.0 {
        return Some(0.0);
    }

    let online_cpus = cpu_stats.online_cpus.map(|c| c as f64).unwrap_or_else(|| {
        cpu_stats
            .cpu_usage
            .as_ref()
            .and_then(|u| u.percpu_usage.as_ref())
            .map(|p| p.len() as f64)
            .unwrap_or(1.0)
    });

    if online_cpus <= 0.0 {
        return None;
    }

    let pct = (cpu_delta / system_delta) * online_cpus * 100.0;
    if pct.is_finite() && pct >= 0.0 {
        Some(pct as f32)
    } else {
        None
    }
}

/// Calculates both raw memory consumption and adjusted working-set memory.
///
/// Memory working set excludes inactive page cache:
/// - Linux cgroups v2: `usage - inactive_file`
/// - Linux cgroups v1: `usage - cache` (or `usage - total_inactive_file`)
/// - Windows: `privateworkingset` or `commitbytes`
pub fn calculate_memory_stats(
    resp: &bollard::models::ContainerStatsResponse,
) -> (Option<u64>, Option<u64>, Option<u64>, Option<f32>) {
    if let Some(mem) = resp.memory_stats.as_ref() {
        let raw_usage = mem.usage.or(mem.privateworkingset).or(mem.commitbytes);
        let limit = mem.limit;

        let working_set = if let (Some(u), Some(stats)) = (raw_usage, mem.stats.as_ref()) {
            let inactive_file = stats
                .get("inactive_file")
                .or_else(|| stats.get("total_inactive_file"))
                .or_else(|| stats.get("cache"))
                .copied()
                .unwrap_or(0);
            Some(u.saturating_sub(inactive_file))
        } else {
            raw_usage
        };

        let pct = match (working_set.or(raw_usage), limit) {
            (Some(u), Some(l)) if l > 0 => {
                let p = (u as f64 / l as f64) * 100.0;
                if p.is_finite() && p >= 0.0 {
                    Some(p as f32)
                } else {
                    None
                }
            }
            _ => None,
        };
        (raw_usage, working_set, limit, pct)
    } else {
        (None, None, None, None)
    }
}

/// Aggregates network traffic (RX / TX) across all active container interfaces.
/// Returns `None` if the networks structure is missing or contains no active counters.
pub fn calculate_network_io(
    resp: &bollard::models::ContainerStatsResponse,
) -> (Option<u64>, Option<u64>) {
    if let Some(networks) = resp.networks.as_ref() {
        if networks.is_empty() {
            return (None, None);
        }
        let mut rx = 0u64;
        let mut tx = 0u64;
        let mut has_metrics = false;
        for net in networks.values() {
            if let Some(r) = net.rx_bytes {
                rx += r;
                has_metrics = true;
            }
            if let Some(t) = net.tx_bytes {
                tx += t;
                has_metrics = true;
            }
        }
        if has_metrics {
            (Some(rx), Some(tx))
        } else {
            (None, None)
        }
    } else {
        (None, None)
    }
}

/// Aggregates block I/O (read / write) across all devices.
/// Returns `None` if the blkio structure is missing or contains no device counters.
pub fn calculate_block_io(
    resp: &bollard::models::ContainerStatsResponse,
) -> (Option<u64>, Option<u64>) {
    if let Some(blkio) = resp.blkio_stats.as_ref() {
        if let Some(entries) = blkio.io_service_bytes_recursive.as_ref() {
            if entries.is_empty() {
                return (None, None);
            }
            let mut read = 0u64;
            let mut write = 0u64;
            let mut has_read = false;
            let mut has_write = false;
            for entry in entries {
                let op = entry.op.as_deref().unwrap_or("").to_lowercase();
                if let Some(bytes) = entry.value {
                    if op == "read" {
                        read += bytes;
                        has_read = true;
                    } else if op == "write" {
                        write += bytes;
                        has_write = true;
                    }
                }
            }
            let r = if has_read { Some(read) } else { None };
            let w = if has_write { Some(write) } else { None };
            (r, w)
        } else {
            (None, None)
        }
    } else {
        (None, None)
    }
}
