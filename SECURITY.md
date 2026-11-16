# TIMMY Security Policy & Safety Architecture

Security and operational safety are foundational tenets of **TIMMY**. Because TIMMY operates directly on active OS processes, network ports, and system resources, it enforces strict boundaries to prevent accidental system instability, data loss, privilege escalation, or credential leakage.

---

## 1. Core Safety Principles

### 1.1 Zero Unattended Termination
TIMMY **never** terminates, signals, or modifies any process or service automatically. Every state-altering action requires explicit human confirmation via keyboard or command-line confirmation flag.

### 1.2 The System Critical Shield
TIMMY enforces a hardcoded, non-configurable safety blocklist protecting critical macOS system processes. Any attempt to signal or terminate these processes immediately returns an error and is logged as a safety violation.

**Hard-Blocked Entities Include:**
- `PID 0` (kernel) and `PID 1` (`launchd`)
- Core Window & Login Daemons: `WindowServer`, `loginwindow`, `Dock`, `Finder`, `SystemUIServer`
- Security & Directory Services: `securityd`, `opendirectoryd`, `tccd`, `trustd`
- Core System Daemons: `kernel_task`, `syslogd`, `notifyd`, `diskarbitrationd`, `kextd`, `mds`, `mds_stores`
- Remote Access Daemons: `sshd`
- Terminal Host & Shell Ancestors: TIMMY detects its own PID, its parent shell, and the hosting terminal emulator (e.g., `Terminal.app`, `iTerm2`, `Ghostty`, `Alacritty`, `WezTerm`, `tmux`) to avoid accidental self-termination.

### 1.3 Strict Attribution Tiers
TIMMY never assumes an unknown process belongs to an AI agent. The system strictly separates:
- **Confirmed**: Matches verified agent binaries and verified execution paths.
- **HighConfidence**: Directly spawned in the process subtree of a confirmed agent.
- **Inferred**: Matches known development server signatures or port profiles, but not directly linked via ancestry.
- **Unknown**: Regular user or system processes. Marked in muted tones and excluded from batch agent actions.

### 1.4 Graceful-First Termination Lifecycle
When the user requests process termination:
1. **Stage 1 (Graceful)**: TIMMY sends a POSIX `SIGTERM` signal. This permits servers (Node.js, Python, databases) to execute cleanup hooks, release open ports, and flush database transactions.
2. **Stage 2 (Verification Window)**: TIMMY monitors the process table over a grace period (default: 3 seconds) to verify clean exit.
3. **Stage 3 (Escalation with Explicit Confirmation)**: Only if the process remains alive after the grace period does TIMMY present a dedicated Force-Kill (`SIGKILL`) modal requiring distinct, intentional user input (`y` / `Enter`).

### 1.5 Direct System Calls (No Shell Shortcuts)
TIMMY prohibits the execution of raw shell commands like `sh -c "kill -9 ..."` or invoking external utilities like `pkill` and `killall`. All signals are delivered strictly through type-checked POSIX system calls (`libc::kill(pid, signal)`) directly to validated, sanitized process IDs.

---

## 2. Privacy & Credential Masking

AI coding agents often carry sensitive API keys, database credentials, and authorization tokens in their environment variables. TIMMY guarantees privacy by default:

- **Sanitized Process Inspection**:
  When viewing environment variables in the TUI inspector, all values matching sensitive patterns are masked before rendering:
  - Any variable key containing substrings: `KEY`, `SECRET`, `TOKEN`, `AUTH`, `PASS`, `CREDENTIAL`, `PRIVATE`, `SIGNING`.
  - Values matching well-known token formats (e.g. `sk-ant-*`, `ghp_*`, `xoxb-*`, `AKIA*`, JWT formats).
- **Zero Network Egress**:
  TIMMY is 100% offline. It makes no external HTTP requests, sends no telemetry, and does not communicate with external cloud services or LLMs.
- **Local Persistence**:
  Local SQLite state is kept strictly on the user's workstation with standard user permissions (`0600` for SQLite file).

---

## 3. Privilege Model

- TIMMY is designed to run with **standard, unprivileged user permissions**.
- TIMMY will issue a prominent visual warning if executed with `sudo` or as `root`, advising the user to drop privileges unless strictly troubleshooting system-level daemons.
- When running as a standard user, TIMMY can only signal processes owned by the current user, providing natural kernel-level isolation.

---

## 4. Docker Integration Safety & Read-Only Policy

TIMMY provides local container visibility with strict read-only guarantees:

### 4.1 Zero Container Lifecycle Modification
- TIMMY **never** stops, starts, kills, restarts, removes, creates, or executes commands inside Docker containers.
- There are no code paths, CLI flags, or TUI keyboard shortcuts that send mutation requests (`POST /containers/{id}/stop`, `POST /containers/{id}/kill`, `DELETE /containers/{id}`, etc.) to the Docker daemon.
- Container management is strictly passive discovery and resource observation.

### 4.2 Local-Only UNIX Domain Sockets & Remote Rejection
- TIMMY interacts with Docker **exclusively** through local UNIX domain sockets (`~/.docker/run/docker.sock`, `/var/run/docker.sock`, OrbStack, Colima).
- All remote endpoint schemes (`tcp://`, `http://`, `https://`, `ssh://`, and unadorned `host:port` notations) are rejected immediately (`PlatformError::DockerUnsupportedRemote`). TIMMY will never open raw TCP connections to remote Docker daemons.
- TIMMY respects host filesystem permissions: if the current user lacks read/write access to the socket, TIMMY does not attempt privilege escalation. It reports a clean diagnostic message (`DockerPermissionDenied`) without failing or panicking.
- Connection and read timeouts (default: 2000ms) are enforced on all socket requests to ensure TIMMY never hangs or blocks if the daemon becomes unresponsive.
- **No Silent Fallback**: If an explicit socket, host, or context is configured and the target socket is missing, TIMMY returns `DockerSocketMissing` and will **never** silently connect to a different Docker daemon.

### 4.3 Environment Variable & Credential Defense-in-Depth
- **No Value Ingestion**: TIMMY **never** retrieves, stores, or logs environment variable values from container inspection. Only variable names (`env_keys`) are ingested and displayed. Variable values are suppressed at the source.
- **Secret Redaction**: Container command lines, entrypoints, sensitive labels (`*KEY*`, `*SECRET*`, `*TOKEN*`, `*AUTH*`, `*PASS*`), and embedded URLs with credentials are redacted via `SecretMasker` before CLI output, TUI rendering, or JSON serialization.

---

## 5. macOS LaunchAgent & LaunchDaemon Discovery Safety & Read-Only Policy

TIMMY provides observational discovery and inspection of macOS background services with strict safety guarantees:

### 5.1 Strictly Observational (Zero Service Lifecycle Operations)
- TIMMY **never** terminates, restarts, unloads, loads, boots out, enables, or disables any launchd service.
- The following commands are **explicitly prohibited** across all TIMMY binaries, modules, and commands:
  - `launchctl bootout`
  - `launchctl kickstart`
  - `launchctl disable`
  - `launchctl enable`
  - `launchctl unload`
  - `launchctl load`
- TIMMY will never modify, overwrite, delete, or create property list files in `~/Library/LaunchAgents`, `/Library/LaunchDaemons`, `/System/Library/LaunchDaemons`, or any other directory.

### 5.2 Environment Variable Value Defense-in-Depth
- Launchd property lists frequently contain database credentials, access tokens, and secret flags in their `EnvironmentVariables` dictionary.
- **Strict Prohibition on Value Extraction**: TIMMY parses **only** variable names (`environment_variable_names`). The values of environment variables are completely suppressed and never stored, logged, or exposed in any CLI output, TUI modal, or JSON export.

### 5.3 Command Line & Path Redaction
- Executable arguments defined in `ProgramArguments` are filtered through `SecretMasker::mask_cmdline` before storage or rendering. Tokens, passwords, API keys, and credentialed URLs are redacted automatically.

### 5.4 No Program Execution or Path Following
- TIMMY does **not** execute, spawn, test, or validate any binary path specified in a property list. Plist values are treated strictly as passive, untrusted metadata.

### 5.5 Platform Boundary Enforcement
- Launchd discovery logic is confined to macOS systems (`#[cfg(target_os = "macos")]`).
- On non-macOS systems, `PortableCollector::collect_services` cleanly returns an empty collection without executing external shell commands or falling back to inappropriate platform behaviors.

---

## 6. Reporting a Security Vulnerability

If you discover a security flaw or unintended safety bypass in TIMMY, please report it privately:

- **Email**: security@timmy-tools.local *(or open a private security advisory on GitHub)*
- Please include:
  1. Operating system version and architecture.
  2. Exact steps or code snippet reproducing the issue.
  3. The potential impact or bypass observed.

We strive to acknowledge reports within 48 hours and release fixes within 7 days.
