use crate::model::agent::Confidence;
use crate::model::service::{
    KeepAliveDetail, LaunchdDomain, LaunchdPlistDetail, LaunchdRuntimeInfo, PlistStatus,
    RuntimeStatus, ServiceInfo, ServiceKind, ServiceState, ServiceStatus,
};
use crate::platform::traits::PlatformError;
use crate::safety::masker::SecretMasker;
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// Maximum duration to wait for a launchctl subprocess to complete.
pub const LAUNCHCTL_TIMEOUT: Duration = Duration::from_millis(2000);

/// Maximum output size in bytes to read from a launchctl subprocess (2 MB).
pub const MAX_OUTPUT_BYTES: usize = 2 * 1024 * 1024;

/// Result of a bounded command execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedCommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub status: Option<i32>,
    pub timed_out: bool,
    pub truncated: bool,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

/// Executes a system command with a finite timeout and bounded output memory.
///
/// SAFETY:
/// - If the timeout is exceeded, the child process is immediately terminated via SIGKILL
///   and waited on to prevent zombie processes.
/// - Output reading is bounded to `max_bytes` to prevent unbounded memory growth.
pub fn run_command_bounded(
    cmd: &str,
    args: &[&str],
    timeout: Duration,
    max_bytes: usize,
) -> Result<BoundedCommandOutput, PlatformError> {
    run_command_bounded_ext(cmd, args, timeout, max_bytes, 64 * 1024)
}

/// Executes a system command with explicit independent bounds on stdout and stderr.
pub fn run_command_bounded_ext(
    cmd: &str,
    args: &[&str],
    timeout: Duration,
    max_stdout: usize,
    max_stderr: usize,
) -> Result<BoundedCommandOutput, PlatformError> {
    let mut child = Command::new(cmd)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| PlatformError::Other(format!("Failed to spawn {}: {}", cmd, e)))?;

    let mut stdout_pipe = child.stdout.take();
    let mut stderr_pipe = child.stderr.take();

    let (stdout_tx, stdout_rx) = mpsc::channel();
    let (stderr_tx, stderr_rx) = mpsc::channel();

    // Reader thread 1: stdout bounded chunk reading
    let stdout_handle = thread::Builder::new()
        .name(format!("{}-stdout-reader", cmd))
        .spawn(move || {
            let mut stdout_buf = Vec::new();
            let mut truncated = false;

            if let Some(mut pipe) = stdout_pipe.take() {
                let mut chunk = [0u8; 8192];
                while stdout_buf.len() < max_stdout {
                    let to_read = chunk.len().min(max_stdout - stdout_buf.len());
                    match pipe.read(&mut chunk[..to_read]) {
                        Ok(0) => break,
                        Ok(n) => stdout_buf.extend_from_slice(&chunk[..n]),
                        Err(_) => break,
                    }
                }
                // Check if there was additional data beyond max_stdout
                let mut extra = [0u8; 1];
                if let Ok(n) = pipe.read(&mut extra) {
                    if n > 0 {
                        truncated = true;
                    }
                }
            }

            let _ = stdout_tx.send((stdout_buf, truncated));
        })
        .map_err(|e| {
            PlatformError::Other(format!("Failed to spawn stdout reader thread: {}", e))
        })?;

    // Reader thread 2: stderr bounded chunk reading (parallel reading prevents OS pipe buffer deadlocks)
    let stderr_handle = thread::Builder::new()
        .name(format!("{}-stderr-reader", cmd))
        .spawn(move || {
            let mut stderr_buf = Vec::new();
            let mut truncated = false;

            if let Some(mut pipe) = stderr_pipe.take() {
                let mut chunk = [0u8; 4096];
                while stderr_buf.len() < max_stderr {
                    let to_read = chunk.len().min(max_stderr - stderr_buf.len());
                    match pipe.read(&mut chunk[..to_read]) {
                        Ok(0) => break,
                        Ok(n) => stderr_buf.extend_from_slice(&chunk[..n]),
                        Err(_) => break,
                    }
                }
                let mut extra = [0u8; 1];
                if let Ok(n) = pipe.read(&mut extra) {
                    if n > 0 {
                        truncated = true;
                    }
                }
            }

            let _ = stderr_tx.send((stderr_buf, truncated));
        })
        .map_err(|e| {
            PlatformError::Other(format!("Failed to spawn stderr reader thread: {}", e))
        })?;

    let start = Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let (stdout_bytes, stdout_trunc) = stdout_rx
                    .recv_timeout(timeout.saturating_sub(start.elapsed()))
                    .unwrap_or_else(|_| (Vec::new(), false));
                let (stderr_bytes, stderr_trunc) = stderr_rx
                    .recv_timeout(timeout.saturating_sub(start.elapsed()))
                    .unwrap_or_else(|_| (Vec::new(), false));

                let _ = stdout_handle.join();
                let _ = stderr_handle.join();

                return Ok(BoundedCommandOutput {
                    stdout: String::from_utf8_lossy(&stdout_bytes).to_string(),
                    stderr: String::from_utf8_lossy(&stderr_bytes).to_string(),
                    status: status.code(),
                    timed_out: false,
                    truncated: stdout_trunc || stderr_trunc,
                    stdout_truncated: stdout_trunc,
                    stderr_truncated: stderr_trunc,
                });
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    break;
                }
                thread::sleep(Duration::from_millis(15));
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_handle.join();
                let _ = stderr_handle.join();
                return Err(PlatformError::Other(format!(
                    "Error polling {}: {}",
                    cmd, e
                )));
            }
        }
    }

    // Process timed out: terminate child immediately and wait to prevent zombie
    let _ = child.kill();
    let _ = child.wait();
    let (stdout_bytes, stdout_trunc) = stdout_rx
        .recv_timeout(Duration::from_millis(50))
        .unwrap_or_else(|_| (Vec::new(), false));
    let (stderr_bytes, stderr_trunc) = stderr_rx
        .recv_timeout(Duration::from_millis(50))
        .unwrap_or_else(|_| (Vec::new(), false));
    let _ = stdout_handle.join();
    let _ = stderr_handle.join();

    Ok(BoundedCommandOutput {
        stdout: String::from_utf8_lossy(&stdout_bytes).to_string(),
        stderr: String::from_utf8_lossy(&stderr_bytes).to_string(),
        status: None,
        timed_out: true,
        truncated: stdout_trunc || stderr_trunc,
        stdout_truncated: stdout_trunc,
        stderr_truncated: stderr_trunc,
    })
}

/// Parsed runtime entry from launchctl list or launchctl print output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeJobEntry {
    pub label: String,
    pub pid: Option<u32>,
    pub last_exit_status: Option<i32>,
    pub domain: LaunchdDomain,
    pub process_state: Option<String>,
}

/// Parses standard `launchctl list` output:
/// Header: PID   Status  Label
/// Lines:  1234  0       com.example.service
///         -     0       com.example.idle
///         -     78      com.example.failed
pub fn parse_launchctl_list_output(stdout: &str, domain: LaunchdDomain) -> Vec<RuntimeJobEntry> {
    let mut entries = Vec::new();

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("PID\t") || trimmed.starts_with("PID ") {
            continue;
        }

        // Try tab-delimited first to preserve spaces within labels
        let tab_parts: Vec<&str> = trimmed.split('\t').collect();
        let (pid_str, status_str, label) = if tab_parts.len() >= 3 {
            let p = tab_parts[0].trim();
            let s = tab_parts[1].trim();
            let l = tab_parts[2..]
                .join("\t")
                .trim()
                .trim_matches('"')
                .to_string();
            (p, s, l)
        } else {
            let ws_parts: Vec<&str> = trimmed.split_whitespace().collect();
            if ws_parts.len() < 3 {
                continue;
            }
            let p = ws_parts[0];
            let s = ws_parts[1];
            let l = ws_parts[2..].join(" ").trim_matches('"').to_string();
            (p, s, l)
        };

        if label.is_empty() {
            continue;
        }

        let pid = if pid_str == "-" {
            None
        } else {
            pid_str.parse::<u32>().ok()
        };

        let last_exit_status = status_str.parse::<i32>().ok();

        entries.push(RuntimeJobEntry {
            label,
            pid,
            last_exit_status,
            domain: domain.clone(),
            process_state: if pid.is_some() {
                Some("running".to_string())
            } else {
                None
            },
        });
    }

    entries
}

/// Parses `launchctl print <domain>` output specifically for services in the `services = { ... }` block.
///
/// Format inside services block:
///        <pid_or_zero>   <status_or_dash>    <label>
/// Handles:
/// - Indented entries (tabs, spaces)
/// - Nested dictionaries and braces (depth tracking prevents premature break)
/// - Non-numeric status strings such as `(pe)` (pending-environment)
/// - Quoted labels and labels containing spaces
/// - Truncated or incomplete output
pub fn parse_launchctl_print_services_output(
    stdout: &str,
    default_domain: LaunchdDomain,
) -> Vec<RuntimeJobEntry> {
    let mut entries = Vec::new();
    let mut in_services_block = false;
    let mut brace_depth: i32 = 0;

    for line in stdout.lines() {
        let trimmed = line.trim();

        if !in_services_block {
            // Match exact "services = {" block (avoid "attractive services = {", "disabled services = {", etc.)
            if trimmed == "services = {" || trimmed.starts_with("services = {") {
                in_services_block = true;
                brace_depth = 1;
            }
            continue;
        }

        // Inside services block: track brace depth
        if trimmed.starts_with('{') {
            brace_depth += 1;
            continue;
        }
        if trimmed.starts_with('}') {
            brace_depth = brace_depth.saturating_sub(1);
            if brace_depth == 0 {
                break;
            }
            continue;
        }

        if trimmed.is_empty() {
            continue;
        }

        let mut tokens = trimmed.split_whitespace();
        let pid_str = match tokens.next() {
            Some(p) => p,
            None => continue,
        };
        let status_str = match tokens.next() {
            Some(s) => s,
            None => continue,
        };

        // Extract label as the remainder of the line following status_str
        let label = if let Some(idx) = line.find(status_str) {
            let after_status = &line[idx + status_str.len()..];
            after_status.trim().trim_matches('"').to_string()
        } else {
            tokens
                .collect::<Vec<_>>()
                .join(" ")
                .trim_matches('"')
                .to_string()
        };

        if label.is_empty() {
            continue;
        }

        let pid_num = pid_str.parse::<u32>().unwrap_or(0);
        let pid = if pid_num > 0 { Some(pid_num) } else { None };

        let (last_exit_status, process_state) = if status_str == "-" {
            (None, None)
        } else if let Ok(code) = status_str.parse::<i32>() {
            (Some(code), None)
        } else {
            // e.g. "(pe)" -> pending-environment
            let inner = status_str.trim_matches(|c| c == '(' || c == ')');
            let state_desc = match inner {
                "pe" => "pending-environment",
                other => other,
            };
            (None, Some(state_desc.to_string()))
        };

        let domain = match &default_domain {
            LaunchdDomain::User => LaunchdDomain::User,
            _ => {
                if label.starts_with("com.apple.") {
                    LaunchdDomain::SystemApple
                } else {
                    LaunchdDomain::SystemThirdParty
                }
            }
        };

        entries.push(RuntimeJobEntry {
            label,
            pid,
            last_exit_status,
            domain,
            process_state,
        });
    }

    entries
}

/// Parses `launchctl print system` output specifically for services in the `services = { ... }` block.
pub fn parse_launchctl_print_system_output(stdout: &str) -> Vec<RuntimeJobEntry> {
    parse_launchctl_print_services_output(stdout, LaunchdDomain::SystemThirdParty)
}

/// Safely parses a launchd property list from bytes.
///
/// Security constraints:
/// - Extracts variable names only for EnvironmentVariables (NEVER exposes values).
/// - Masks secrets in program arguments using SecretMasker.
/// - Masks sensitive tokens/passwords in Program and ExecutablePath.
/// - Sanitizes parse errors to prevent leaking raw file contents.
/// - Does not execute any program or follow arbitrary binary instructions.
/// - Handles malformed, partial, or missing keys without panicking.
pub fn parse_plist_content(bytes: &[u8], source_path: PathBuf) -> LaunchdPlistDetail {
    let reader = std::io::Cursor::new(bytes);
    let value = match plist::Value::from_reader(reader) {
        Ok(v) => v,
        Err(e) => {
            return LaunchdPlistDetail {
                source_path: source_path.clone(),
                label: source_path
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string()),
                program: None,
                program_arguments: Vec::new(),
                executable_path: None,
                working_directory: None,
                run_at_load: None,
                keep_alive: None,
                start_interval: None,
                start_calendar_interval: None,
                sockets: Vec::new(),
                mach_services: Vec::new(),
                standard_out_path: None,
                standard_error_path: None,
                environment_variable_names: Vec::new(),
                user_name: None,
                group_name: None,
                parse_error: Some(SecretMasker::mask_string(&format!(
                    "Failed to parse plist: {}",
                    e
                ))),
            };
        }
    };

    let dict = match value.as_dictionary() {
        Some(d) => d,
        None => {
            return LaunchdPlistDetail {
                source_path: source_path.clone(),
                label: source_path
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string()),
                program: None,
                program_arguments: Vec::new(),
                executable_path: None,
                working_directory: None,
                run_at_load: None,
                keep_alive: None,
                start_interval: None,
                start_calendar_interval: None,
                sockets: Vec::new(),
                mach_services: Vec::new(),
                standard_out_path: None,
                standard_error_path: None,
                environment_variable_names: Vec::new(),
                user_name: None,
                group_name: None,
                parse_error: Some("Plist root is not a dictionary".to_string()),
            };
        }
    };

    let label = dict
        .get("Label")
        .and_then(|v| v.as_string())
        .map(String::from)
        .or_else(|| {
            source_path
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
        });

    let program = dict
        .get("Program")
        .and_then(|v| v.as_string())
        .map(SecretMasker::mask_url);

    let mut raw_args = Vec::new();
    if let Some(arr) = dict.get("ProgramArguments").and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(s) = item.as_string() {
                raw_args.push(s.to_string());
            }
        }
    }

    let program_arguments = SecretMasker::mask_cmdline(&raw_args);

    let executable_path = program
        .clone()
        .or_else(|| raw_args.first().map(|s| SecretMasker::mask_url(s.as_str())));

    let working_directory = dict
        .get("WorkingDirectory")
        .and_then(|v| v.as_string())
        .map(String::from);

    let run_at_load = match dict.get("RunAtLoad") {
        Some(plist::Value::Boolean(b)) => Some(*b),
        Some(plist::Value::Dictionary(_)) => Some(true),
        _ => None,
    };

    let keep_alive = match dict.get("KeepAlive") {
        Some(plist::Value::Boolean(b)) => Some(KeepAliveDetail::Simple(*b)),
        Some(plist::Value::Dictionary(d)) => {
            let mut parts = Vec::new();
            for (k, v) in d {
                let v_str = match v {
                    plist::Value::Boolean(b) => b.to_string(),
                    plist::Value::String(s) => s.clone(),
                    plist::Value::Integer(i) => i.to_string(),
                    _ => "...".to_string(),
                };
                parts.push(format!("{}={}", k, v_str));
            }
            parts.sort();
            Some(KeepAliveDetail::Conditional(parts.join(", ")))
        }
        _ => None,
    };

    let start_interval = dict
        .get("StartInterval")
        .and_then(|v| v.as_unsigned_integer());

    let start_calendar_interval = match dict.get("StartCalendarInterval") {
        Some(plist::Value::Dictionary(d)) => {
            let mut parts = Vec::new();
            for (k, v) in d {
                if let Some(i) = v.as_signed_integer() {
                    parts.push(format!("{}={}", k, i));
                } else if let Some(s) = v.as_string() {
                    parts.push(format!("{}={}", k, s));
                }
            }
            parts.sort();
            Some(parts.join(", "))
        }
        Some(plist::Value::Array(arr)) => {
            let mut summaries = Vec::new();
            for item in arr {
                if let Some(d) = item.as_dictionary() {
                    let mut parts = Vec::new();
                    for (k, v) in d {
                        if let Some(i) = v.as_signed_integer() {
                            parts.push(format!("{}={}", k, i));
                        }
                    }
                    parts.sort();
                    summaries.push(format!("{{{}}}", parts.join(", ")));
                }
            }
            Some(summaries.join("; "))
        }
        _ => None,
    };

    let mut sockets = Vec::new();
    if let Some(sock_dict) = dict.get("Sockets").and_then(|v| v.as_dictionary()) {
        for k in sock_dict.keys() {
            sockets.push(SecretMasker::mask_string(k));
        }
        sockets.sort();
    }

    let mut mach_services = Vec::new();
    if let Some(mach_dict) = dict.get("MachServices").and_then(|v| v.as_dictionary()) {
        for k in mach_dict.keys() {
            mach_services.push(SecretMasker::mask_string(k));
        }
        mach_services.sort();
    }

    let standard_out_path = dict
        .get("StandardOutPath")
        .and_then(|v| v.as_string())
        .map(String::from);

    let standard_error_path = dict
        .get("StandardErrorPath")
        .and_then(|v| v.as_string())
        .map(String::from);

    // SECURITY MANDATE: Extract variable names ONLY. Never store or expose values!
    let mut environment_variable_names = Vec::new();
    if let Some(env_dict) = dict
        .get("EnvironmentVariables")
        .and_then(|v| v.as_dictionary())
    {
        for k in env_dict.keys() {
            environment_variable_names.push(k.clone());
        }
        environment_variable_names.sort();
    }

    let user_name = dict
        .get("UserName")
        .and_then(|v| v.as_string())
        .map(String::from);

    let group_name = dict
        .get("GroupName")
        .and_then(|v| v.as_string())
        .map(String::from);

    LaunchdPlistDetail {
        source_path,
        label,
        program,
        program_arguments,
        executable_path,
        working_directory,
        run_at_load,
        keep_alive,
        start_interval,
        start_calendar_interval,
        sockets,
        mach_services,
        standard_out_path,
        standard_error_path,
        environment_variable_names,
        user_name,
        group_name,
        parse_error: None,
    }
}

/// Pure reconciliation function: merges filesystem discoveries with launchctl runtime jobs.
///
/// Ensures that:
/// - On-disk plist status (`plist_status`) and launchd runtime status (`runtime_status`) are modeled independently.
/// - File parsing errors and runtime inspection errors are separate facts that never erase each other.
/// - Duplicate labels across different domains (User, SystemThirdParty, SystemApple) remain distinct records.
pub fn reconcile_services(
    plists: Vec<(LaunchdPlistDetail, LaunchdDomain, ServiceKind)>,
    runtime_jobs: Vec<RuntimeJobEntry>,
) -> Vec<ServiceInfo> {
    let mut map: HashMap<(String, String), ServiceInfo> = HashMap::new();

    // 1. Ingest plists discovered from disk
    for (detail, domain, kind) in plists {
        let label = detail.label.clone().unwrap_or_else(|| {
            detail
                .source_path
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "unknown".to_string())
        });

        let domain_key = domain.to_string();
        let key = (domain_key, label.clone());

        let plist_status = if let Some(ref err) = detail.parse_error {
            if err.contains("Could not read file") {
                PlistStatus::Unreadable {
                    path: detail.source_path.clone(),
                    error: err.clone(),
                }
            } else {
                PlistStatus::Malformed {
                    path: detail.source_path.clone(),
                    error: err.clone(),
                }
            }
        } else {
            PlistStatus::Valid {
                path: detail.source_path.clone(),
            }
        };

        let runtime_status = RuntimeStatus::NotLoaded;

        let state = if let Some(ref err) = detail.parse_error {
            ServiceState::Error(err.clone())
        } else {
            ServiceState::DiscoveredOnDisk
        };

        let status = ServiceStatus::from(&state);
        let name = label.split('.').next_back().unwrap_or(&label).to_string();
        let path = Some(detail.source_path.to_string_lossy().to_string());

        let service = ServiceInfo {
            name,
            kind,
            status,
            state,
            plist_status,
            runtime_status,
            pid: None,
            label,
            path,
            domain: Some(domain),
            last_exit_status: None,
            runtime: None,
            plist: Some(detail),
            session_id: None,
            confidence: Confidence::Unknown,
            evidence: Vec::new(),
            is_partial: false,
        };

        map.insert(key, service);
    }

    // 2. Correlate and merge runtime launchctl jobs
    for rjob in runtime_jobs {
        let domain_key = rjob.domain.to_string();
        let key = (domain_key.clone(), rjob.label.clone());

        let is_running = rjob.pid.is_some();
        let r_status = if let Some(pid) = rjob.pid {
            RuntimeStatus::Running { pid }
        } else if let Some(code) = rjob.last_exit_status {
            if code != 0 {
                RuntimeStatus::Failed { exit_code: code }
            } else {
                RuntimeStatus::Loaded
            }
        } else {
            RuntimeStatus::Loaded
        };

        let runtime_info = LaunchdRuntimeInfo {
            is_loaded: true,
            pid: rjob.pid,
            last_exit_status: rjob.last_exit_status,
            domain: Some(rjob.domain.clone()),
            process_state: rjob.process_state.clone().or_else(|| {
                if is_running {
                    Some("running".to_string())
                } else {
                    Some("loaded".to_string())
                }
            }),
            last_observed: chrono::Utc::now(),
        };

        if let Some(service) = map.get_mut(&key) {
            // PRESERVE plist_status: never overwrite on-disk errors
            service.runtime_status = r_status;
            service.pid = rjob.pid;
            service.last_exit_status = rjob.last_exit_status;
            service.runtime = Some(runtime_info);

            // Determine synthesized service.state:
            // If the service is actively executing, its operational state is Running.
            // If stopped with a non-zero exit code, NotRunning.
            // If idle and plist was malformed, surface the plist error in state.
            if service.runtime_status.is_running() {
                service.state = ServiceState::Running;
            } else if let Some(code) = rjob.last_exit_status {
                if code != 0 {
                    service.state = ServiceState::NotRunning;
                } else if service.plist_status.is_error() {
                    service.state = ServiceState::Error(
                        service
                            .plist_status
                            .error_message()
                            .unwrap_or("Plist error")
                            .to_string(),
                    );
                } else {
                    service.state = ServiceState::Loaded;
                }
            } else if service.plist_status.is_error() {
                service.state = ServiceState::Error(
                    service
                        .plist_status
                        .error_message()
                        .unwrap_or("Plist error")
                        .to_string(),
                );
            } else {
                service.state = ServiceState::Loaded;
            }
            service.status = ServiceStatus::from(&service.state);
        } else {
            // Service is loaded in launchd runtime but not present on disk
            let kind = match &rjob.domain {
                LaunchdDomain::User => ServiceKind::LaunchAgentUser,
                LaunchdDomain::SystemThirdParty => ServiceKind::LaunchDaemonSystem,
                LaunchdDomain::SystemApple => ServiceKind::LaunchDaemonApple,
                LaunchdDomain::Unknown(_) => ServiceKind::Other("LaunchdJob".to_string()),
            };

            let name = rjob
                .label
                .split('.')
                .next_back()
                .unwrap_or(&rjob.label)
                .to_string();

            let state = if is_running {
                ServiceState::Running
            } else if let Some(code) = rjob.last_exit_status {
                if code != 0 {
                    ServiceState::NotRunning
                } else {
                    ServiceState::Loaded
                }
            } else {
                ServiceState::Loaded
            };

            let service = ServiceInfo {
                name,
                kind,
                status: ServiceStatus::from(&state),
                state,
                plist_status: PlistStatus::NotDiscovered,
                runtime_status: r_status,
                pid: rjob.pid,
                label: rjob.label.clone(),
                path: None,
                domain: Some(rjob.domain),
                last_exit_status: rjob.last_exit_status,
                runtime: Some(runtime_info),
                plist: None,
                session_id: None,
                confidence: Confidence::Unknown,
                evidence: Vec::new(),
                is_partial: false,
            };

            map.insert(key, service);
        }
    }

    let mut results: Vec<ServiceInfo> = map.into_values().collect();
    results.sort_by_key(|a| a.name.to_lowercase());
    results
}

/// Discovers files in standard launchd directories.
pub fn scan_directory_for_plists(
    dir: &Path,
    domain: &LaunchdDomain,
    kind: &ServiceKind,
) -> Vec<(LaunchdPlistDetail, LaunchdDomain, ServiceKind)> {
    let mut results = Vec::new();

    let read_dir = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return results,
    };

    for entry in read_dir.flatten() {
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|ext| ext.to_str()) == Some("plist") {
            let bytes = match std::fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    let detail = LaunchdPlistDetail {
                        source_path: path.clone(),
                        label: path.file_stem().map(|s| s.to_string_lossy().to_string()),
                        program: None,
                        program_arguments: Vec::new(),
                        executable_path: None,
                        working_directory: None,
                        run_at_load: None,
                        keep_alive: None,
                        start_interval: None,
                        start_calendar_interval: None,
                        sockets: Vec::new(),
                        mach_services: Vec::new(),
                        standard_out_path: None,
                        standard_error_path: None,
                        environment_variable_names: Vec::new(),
                        user_name: None,
                        group_name: None,
                        parse_error: Some(SecretMasker::mask_string(&format!(
                            "Could not read file: {}",
                            e
                        ))),
                    };
                    results.push((detail, domain.clone(), kind.clone()));
                    continue;
                }
            };

            let detail = parse_plist_content(&bytes, path);
            results.push((detail, domain.clone(), kind.clone()));
        }
    }

    results
}

/// Resolves the user's home directory.
fn user_home_dir() -> Option<PathBuf> {
    directories::BaseDirs::new()
        .map(|b| b.home_dir().to_path_buf())
        .or_else(|| std::env::var("HOME").ok().map(PathBuf::from))
}

/// Discovers active macOS LaunchAgents and LaunchDaemons via read-only inspection.
///
/// SAFETY: This function is strictly observational. It NEVER modifies, unloads, loads,
/// or terminates any launchd service. Subprocesses are bounded in time and output memory.
pub fn discover_launchd_services() -> Result<Vec<ServiceInfo>, PlatformError> {
    let mut discovered_plists = Vec::new();

    // 1a. User LaunchAgents: ~/Library/LaunchAgents
    if let Some(home) = user_home_dir() {
        let user_agents = home.join("Library").join("LaunchAgents");
        discovered_plists.extend(scan_directory_for_plists(
            &user_agents,
            &LaunchdDomain::User,
            &ServiceKind::LaunchAgentUser,
        ));
    }

    // 1b. System-wide User LaunchAgents: /Library/LaunchAgents (runs in each user GUI login session)
    let sys_user_agents = Path::new("/Library/LaunchAgents");
    discovered_plists.extend(scan_directory_for_plists(
        sys_user_agents,
        &LaunchdDomain::User,
        &ServiceKind::LaunchAgentUser,
    ));

    // 2. System LaunchDaemons (Third-Party): /Library/LaunchDaemons
    let sys_daemons = Path::new("/Library/LaunchDaemons");
    discovered_plists.extend(scan_directory_for_plists(
        sys_daemons,
        &LaunchdDomain::SystemThirdParty,
        &ServiceKind::LaunchDaemonSystem,
    ));

    // 3. Apple System LaunchDaemons: /System/Library/LaunchDaemons
    let apple_daemons = Path::new("/System/Library/LaunchDaemons");
    discovered_plists.extend(scan_directory_for_plists(
        apple_daemons,
        &LaunchdDomain::SystemApple,
        &ServiceKind::LaunchDaemonApple,
    ));

    // 4. Read-only launchctl runtime inspection with bounded execution and timeout
    let mut runtime_jobs = Vec::new();
    let mut runtime_inspection_error = None;
    let mut is_snapshot_truncated = false;

    // 4a. User domain launchctl list
    match run_command_bounded("launchctl", &["list"], LAUNCHCTL_TIMEOUT, MAX_OUTPUT_BYTES) {
        Ok(out) => {
            if out.truncated {
                is_snapshot_truncated = true;
            }
            if out.timed_out {
                runtime_inspection_error =
                    Some("launchctl list timed out after 2000ms".to_string());
            } else if let Some(code) = out.status {
                if code == 0 {
                    runtime_jobs.extend(parse_launchctl_list_output(
                        &out.stdout,
                        LaunchdDomain::User,
                    ));
                } else {
                    runtime_inspection_error = Some(format!(
                        "launchctl list exited with code {}: {}",
                        code,
                        out.stderr.trim()
                    ));
                }
            }
        }
        Err(e) => {
            runtime_inspection_error = Some(format!("launchctl list failed: {}", e));
        }
    }

    // 4b. Explicit user GUI domain query: launchctl print gui/<uid>
    #[cfg(target_os = "macos")]
    {
        let uid = unsafe { libc::getuid() };
        let gui_target = format!("gui/{}", uid);
        if let Ok(out) = run_command_bounded(
            "launchctl",
            &["print", &gui_target],
            LAUNCHCTL_TIMEOUT,
            MAX_OUTPUT_BYTES,
        ) {
            if out.truncated {
                is_snapshot_truncated = true;
            }
            if out.timed_out {
                let msg = format!("launchctl print {} timed out after 2000ms", gui_target);
                runtime_inspection_error = Some(match runtime_inspection_error {
                    Some(prev) => format!("{}; {}", prev, msg),
                    None => msg,
                });
            } else if let Some(code) = out.status {
                if code == 0 {
                    runtime_jobs.extend(parse_launchctl_print_services_output(
                        &out.stdout,
                        LaunchdDomain::User,
                    ));
                }
            }
        }
    }

    // 4c. System domain launchctl print system
    if let Ok(out) = run_command_bounded(
        "launchctl",
        &["print", "system"],
        LAUNCHCTL_TIMEOUT,
        MAX_OUTPUT_BYTES,
    ) {
        if out.truncated {
            is_snapshot_truncated = true;
        }
        if out.timed_out {
            let msg = "launchctl print system timed out after 2000ms";
            runtime_inspection_error = Some(match runtime_inspection_error {
                Some(prev) => format!("{}; {}", prev, msg),
                None => msg.to_string(),
            });
        } else if let Some(code) = out.status {
            if code == 0 {
                runtime_jobs.extend(parse_launchctl_print_services_output(
                    &out.stdout,
                    LaunchdDomain::SystemThirdParty,
                ));
            }
        }
    }

    let mut services = reconcile_services(discovered_plists, runtime_jobs);

    // If runtime inspection failed, update uninspected services accordingly
    if let Some(ref err_msg) = runtime_inspection_error {
        for svc in services.iter_mut() {
            if svc.runtime.is_none() && svc.runtime_status == RuntimeStatus::NotLoaded {
                svc.runtime_status = RuntimeStatus::InspectionFailed(err_msg.clone());
            }
        }
    }

    // If output was truncated, mark all services and document in evidence
    if is_snapshot_truncated {
        for svc in services.iter_mut() {
            svc.is_partial = true;
            svc.evidence.push("Diagnostic warning: launchctl output was truncated at memory limit (partial snapshot)".to_string());
        }
    }

    Ok(services)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_launchctl_list_output() {
        let output = "PID\tStatus\tLabel\n1234\t0\tcom.example.service\n-\t0\tcom.example.idle\n-\t78\tcom.example.failed\n";
        let jobs = parse_launchctl_list_output(output, LaunchdDomain::User);
        assert_eq!(jobs.len(), 3);

        assert_eq!(jobs[0].label, "com.example.service");
        assert_eq!(jobs[0].pid, Some(1234));
        assert_eq!(jobs[0].last_exit_status, Some(0));

        assert_eq!(jobs[1].label, "com.example.idle");
        assert_eq!(jobs[1].pid, None);
        assert_eq!(jobs[1].last_exit_status, Some(0));

        assert_eq!(jobs[2].label, "com.example.failed");
        assert_eq!(jobs[2].pid, None);
        assert_eq!(jobs[2].last_exit_status, Some(78));
    }

    #[test]
    fn test_parse_launchctl_print_system_output() {
        let output = r#"
system = {
	services = {
		       0      - 	com.apple.relay.service
		    1857      0 	com.example.customdaemon
		     427      - 	com.apple.runningboardd
	}
}
"#;
        let jobs = parse_launchctl_print_system_output(output);
        assert_eq!(jobs.len(), 3);

        assert_eq!(jobs[0].label, "com.apple.relay.service");
        assert_eq!(jobs[0].pid, None);
        assert_eq!(jobs[0].last_exit_status, None);
        assert_eq!(jobs[0].domain, LaunchdDomain::SystemApple);

        assert_eq!(jobs[1].label, "com.example.customdaemon");
        assert_eq!(jobs[1].pid, Some(1857));
        assert_eq!(jobs[1].last_exit_status, Some(0));
        assert_eq!(jobs[1].domain, LaunchdDomain::SystemThirdParty);

        assert_eq!(jobs[2].label, "com.apple.runningboardd");
        assert_eq!(jobs[2].pid, Some(427));
        assert_eq!(jobs[2].domain, LaunchdDomain::SystemApple);
    }
}
