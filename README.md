# TIMMY (AI Agent Resource Manager)

> **TIMMY** is a lightweight, keyboard-driven, interactive terminal utility (`timmy`) designed for macOS (with cross-platform architecture) to discover, understand, monitor, and safely manage background processes, services, open ports, Docker containers, and orphan system resources left behind by AI coding agents and automated development environments.

[![Platform: macOS](https://img.shields.io/badge/Platform-macOS-black?logo=apple)](https://apple.com)
[![Language: Rust](https://img.shields.io/badge/Language-Rust-orange?logo=rust)](https://www.rust-lang.org)
[![TUI: Ratatui](https://img.shields.io/badge/TUI-Ratatui-blue)](https://ratatui.rs)
[![License: MIT/Apache-2.0](https://img.shields.io/badge/License-MIT%20%2F%20Apache--2.0-green)](#license)

---

## The Problem

Modern AI coding agents (such as Claude Code, Cursor, Windsurf, Aider, GitHub Copilot CLI, Devin, and custom autonomous agents) continuously run shell commands that spawn:
- Background development web servers (Vite, Next.js, Webpack, Astro, Express, FastAPI, Django, Rails)
- Embedded and standalone databases (PostgreSQL, Redis, MongoDB, MySQL, SQLite instances)
- Async task queues & workers (Celery, Sidekiq, BullMQ)
- Docker containers and Compose stacks
- Dangling network listeners holding ports like `3000`, `5432`, `6379`, `8000`, `8080`
- Background user services and orphaned child processes

When an agent crashes, gets interrupted, or completes its turn, these processes frequently linger indefinitely in the background. Developers are left with:
- Mysterious "Port already in use" errors (`EADDRINUSE`)
- Heavy CPU throttling and battery drain from runaway node/python loops
- High RAM consumption from forgotten microservices
- Unknown process lineage (Was this started by Cursor, Claude Code, or my own shell?)

---

## The Solution: TIMMY

`timmy` provides immediate, local, transparent visibility and safe control over these resources without requiring any background daemon, cloud account, or external LLM API.

### Core Capabilities

- 🔍 **Native macOS Kernel Process Discovery & Lineage Tree**: Zero-overhead process enumeration via `proc_listpids`, `sysctl KERN_PROCARGS2`, and `proc_pidpath`. Microsecond-precision `ProcessIncarnation` identities strictly prevent PID reuse errors.
- 🌳 **Persistent Process Lineage DAG**: Retains historical parent-child edges across observation intervals, intermediate parent exits, and macOS reparenting to PID 1 (`launchd`). Formatted Unicode lineage trees with `--tree` and `--show-exited`.
- 🤖 **AI-Agent Attribution Engine**: Heuristic and rule-based attribution engine that classifies processes into attribution confidence tiers (`Confirmed`, `HighConfidence`, `Inferred`, `Unknown`).
- 🌐 **Native Socket & Port Correlation**: In-memory inspection of open file descriptors via `PROC_PIDLISTFDS` and `PROC_PIDFDSOCKETINFO` without spawning child processes. Real-time correlation between listening TCP/UDP sockets and responsible processes.
- ⚙️ **Background Service & Launchd Visibility**: Inspect active macOS launchd user agents and daemons without wading through verbose `launchctl list` output.
- 🐳 **Docker Integration**: Surface containers and Compose stacks initiated during coding sessions, showing exposed ports and resource usage.
- 🛡️ **Safety-First Process Termination**:
  - **Zero automatic termination**: Never kills any process without explicit user authorization.
  - **Critical process shield**: Enforced blocklist protects macOS system daemons (`launchd`, `WindowServer`, `loginwindow`, `Dock`, `Finder`, `sshd`, etc.).
  - **Graceful degradation**: Prioritizes `SIGTERM` with configurable grace periods before escalating to `SIGKILL`.
  - **Confirmation modals**: Multi-step user confirmation for high-impact operations.
  - **Secret sanitization**: Redacts sensitive environment variables (`*_API_KEY`, `*TOKEN*`, `*SECRET*`, `*PASSWORD*`) when inspecting process details.
- ⚡ **Lightweight & Daemon-Free**: Executes on demand. No recurring background daemons running in the background. Minimal memory footprint.

---

## Installation & Requirements

### Prerequisites
- macOS 12+ (Apple Silicon & Intel supported)
- [Rust](https://rustup.rs) (1.75+ recommended)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/timmygetsit/timmy.git
cd timmy

# Compile in release mode
cargo build --release

# Install locally to your PATH
cargo install --path .
```

---

## Quickstart

Run TIMMY directly from your terminal:

```bash
timmy
```

### Interactive TUI Controls & Shortcuts

TIMMY provides an ergonomic terminal experience designed for fast triage, lineage navigation, and safe process management:

| Shortcut | Context | Action |
|:---|:---|:---|
| <kbd>1</kbd> – <kbd>5</kbd> | Global | Direct jump to tabs: `[1] Processes`, `[2] Ports`, `[3] Services`, `[4] Docker`, `[5] Sessions` |
| <kbd>Tab</kbd> / <kbd>Shift+Tab</kbd> | Global | Cycle forward / backward through tabs |
| <kbd>↑</kbd> / <kbd>↓</kbd> or <kbd>k</kbd> / <kbd>j</kbd> | Tables | Navigate table rows with automatic viewport scrolling |
| <kbd>/</kbd> | Global | Activate live multi-token filter mode (case-insensitive `AND` across all fields) |
| <kbd>Esc</kbd> | Global | Exit filter mode, clear active filter badge, or clear tagged processes |
| <kbd>Space</kbd> | Processes | Toggle multi-process selection tag `[x]` / `[ ]` on highlighted row |
| <kbd>a</kbd> | Processes | Toggle tag-all / untag-all for all currently filtered processes |
| <kbd>x</kbd> | Processes | Prompt graceful termination (`SIGTERM`) for selected or batch-tagged processes |
| <kbd>X</kbd> | Processes | Prompt forced termination (`SIGKILL`) for selected or batch-tagged processes |
| <kbd>t</kbd> | Processes | Jump directly into the parent AI agent session's Lineage Tree |
| <kbd>t</kbd> | Sessions | Toggle session bottom pane between Unicode Lineage Tree and flat Tracked Resources |
| <kbd>Enter</kbd> / <kbd>i</kbd> | Global | Deep inspection modal (process details, container inspect, service plist, session) |
| <kbd>1</kbd> – <kbd>3</kbd> | Session Modal | Switch modal inspector tabs: `[1] Lineage Tree`, `[2] Cleanup Plan`, `[3] Tracked Resources` |
| <kbd>r</kbd> | Global | Force immediate background refresh of processes, ports, and metrics |
| <kbd>q</kbd> / <kbd>Ctrl+C</kbd> | Global | Gracefully restore terminal screen and quit |

### Command Line Options

```text
Usage: timmy [OPTIONS] [COMMAND]

Commands:
  run      Launch the interactive TUI (default)
  scan     One-shot CLI snapshot of active AI agent processes [--agents-only] [--json]
  ports    List open listening ports and their associated agent/process [--json]
  services Discover and inspect macOS LaunchAgents and LaunchDaemons [--domain <name>] [--json]
  doctor   Verify system permissions and platform discovery capabilities [--json]
  session  Track and manage individual AI coding agent sessions
  help     Print help message

Session Subcommands:
  timmy session start [--agent <name>] [--watch] [--interval <sec>] [--replace]
                                        Start tracking an AI coding session
  timmy session watch [session_id] [--interval <sec>]
                                        Watch and periodically observe session in foreground
  timmy session list [--json]           List active and previous sessions
  timmy session inspect [session_id] [--tree] [--show-exited] [--json]
                                        Deep inspection, cleanup plan, or process lineage tree
  timmy session stop [session_id]       Stop tracking session (preserves processes)
  timmy session resources [session_id] [--tree] [--show-exited] [--json]
                                        Display resources and process lineage tree for session

Docker Subcommands:
  timmy docker status [--json]          Check Docker daemon connectivity, socket paths, and versions
  timmy docker list [--all] [--session <id>] [--json]
                                        List containers, port bindings, and AI session attributions
  timmy docker inspect <container-id> [--json]
                                        Deeply inspect container details, mounts, and masked env vars
  timmy docker stats [--json]           Show live CPU, memory, network, and block I/O resource metrics

Services Options:
  timmy services [--domain <user|system|apple>] [--json]
                                        Discover and inspect macOS launchd jobs, domains, and plists

Options:
  -c, --config <FILE>     Path to custom configuration file
  -r, --refresh <MS>      TUI refresh rate in milliseconds [default: 1000]
  -v, --verbose           Enable debug logging
  -h, --help              Print help
  -V, --version           Print version
```

---

## Docker Integration (Read-Only)

TIMMY includes deep, read-only Docker container discovery and inspection powered by `bollard`.

> **Read-Only Guarantee**: TIMMY will **never** stop, kill, restart, remove, create, or alter Docker containers or daemon settings. It is strictly a passive monitoring and diagnostic tool.

### Local-Only & Remote Rejection Policy
TIMMY communicates **exclusively** with local Docker Engine instances over local UNIX domain sockets.
All remote endpoint schemes (`tcp://`, `http://`, `https://`, `ssh://`, and unadorned `host:port` pairs) are strictly rejected with an immediate error (`DockerUnsupportedRemote`) to prevent unintended remote execution or network exposure.

### Socket Discovery & Exact Precedence Order
TIMMY resolves the Docker UNIX socket in strict precedence order:
1. **Explicit TIMMY configuration**: `general.docker_socket` in `config.toml` (or `--config`).
2. **`DOCKER_HOST` environment variable**: e.g. `unix:///path/to/custom.sock` (remote schemes rejected).
3. **`DOCKER_CONTEXT` environment variable**: reads context name and parses `~/.docker/contexts/meta/<hash>/meta.json`.
4. **Current context in `~/.docker/config.json`**: `currentContext` parsed via SHA-256 metadata lookup.
5. **Standard default auto-discovery** (only when context is `default` or unset):
   - **macOS**: Docker Desktop (`~/.docker/run/docker.sock`), OrbStack (`~/.orbstack/run/docker.sock`), Colima (`~/.colima/default/docker.sock`), or `/var/run/docker.sock`.
   - **Linux**: `/var/run/docker.sock` or rootless sockets (`$XDG_RUNTIME_DIR/docker.sock`, `/run/user/<UID>/docker.sock`).

> **No Silent Fallback**: If an explicit socket, host, or context is configured and the target socket is missing or unreachable, TIMMY reports `DockerSocketMissing` or `DockerDaemonStopped` and will **never** silently fall back to another socket or daemon.

### AI Agent Container Correlation & Ownership Semantics
TIMMY correlates containers with AI agent coding sessions using defensible evidence tiers:
- **`CONFIRMED`**: Reserved strictly for independently verifiable direct process execution provenance (e.g. an active session process with verified agent identity directly executed a `docker` command targeting the container).
- **`HIGH CONFIDENCE`**:
  - **Declared Session Metadata**: Container carries a session label (e.g., `timmy.session.id`, `com.timmy.session_id`, `agent.session`). An agent or developer can apply a label at container-creation time, but that label does not prove runtime ownership or prevent spoofing. TIMMY records this as declared metadata (`declared_session_id`) with high confidence.
  - **Multi-Signal Correlation**: Container created within the session active window, bind-mounted project directory matches the session directory, and container communicates over shared ports with a session process.
- **`INFERRED`**: Container created during the active session window sharing listening ports, or has a bind mount matching a session process path without temporal alignment.
- **`UNKNOWN`**: Insufficient evidence, or conflicting claims detected between multiple sessions.

### Conflict Detection & Retained Attribution
- **Conflicting Claims**: If multiple active sessions claim the same container at the same confidence level, TIMMY flags a conflict, records all candidate sessions in `conflicting_sessions`, and assigns `UNKNOWN` confidence with diagnostic evidence.
- **Surviving Containers**: When a session terminates, background containers survive. TIMMY retains their previous session attribution without falsely elevating confidence.

### Sensitive Data Handling
- **Environment Variables**: TIMMY **never** retrieves, stores, or logs environment variable values. Only environment variable names (`env_keys`) are parsed and displayed (`VALUE` is suppressed for security).
- **Redaction**: Container command lines, entrypoints, sensitive labels (`*KEY*`, `*SECRET*`, `*TOKEN*`, `*AUTH*`, `*PASS*`), and embedded URLs with credentials are automatically sanitized using `SecretMasker` before being displayed in the CLI, TUI, or JSON exports.

---

## macOS LaunchAgent and LaunchDaemon Discovery (Read-Only)

TIMMY provides native, strictly observational discovery and inspection of macOS background services, LaunchAgents, and LaunchDaemons.

> **Read-Only Guarantee**: TIMMY is purely observational. It will **never** execute service lifecycle operations (`launchctl bootout`, `launchctl kickstart`, `launchctl disable`, `launchctl enable`, `launchctl unload`, `launchctl load`), terminate service processes, or modify property list files on disk.

### What Launchd Information TIMMY Reads
TIMMY audits background services across three standard filesystem locations and active launchd runtime domains:
1. **User LaunchAgents (`~/Library/LaunchAgents`)**: Services configured specifically for the logged-in user, running in the user/GUI domain.
2. **Third-Party System LaunchDaemons (`/Library/LaunchDaemons`)**: System-level background daemons installed by developer tools, databases, and third-party software.
3. **Apple / System-Managed LaunchDaemons (`/System/Library/LaunchDaemons`)**: Core operating system daemons managed by Apple.
4. **Live Launchd Runtime Domains**: Queries `launchctl list` for the current user/GUI domain and `launchctl print system` for active system domain registrations.

### Orthogonal File Discovery and Runtime State
TIMMY explicitly separates filesystem discovery from launchd runtime registration using orthogonal, independent state tracking:
- **`PlistStatus`**: `Valid`, `Malformed { error }`, `Unreadable { error }`, `NotDiscovered`.
- **`RuntimeStatus`**: `NotLoaded`, `Loaded`, `Running { pid }`, `Failed { exit_code }`, `InspectionFailed(error)`, `Unknown`.
- **Non-destructive Reconciliation**: An on-disk plist parsing error never overwrites a live running process, and active runtime execution never conceals a malformed plist syntax error. Both axes are preserved and displayed.

### Permissions, Bounded I/O & Non-Blocking TUI
- **Unprivileged Operation**: TIMMY runs as a standard, non-root user. It inspects user agents and public system daemons without requiring `sudo`.
- **Bounded Execution**: `launchctl` commands run with a strict 2000 ms timeout and a 2 MB memory cap. Hung subprocesses are terminated immediately via `SIGKILL` and reaped to prevent zombie processes.
- **Non-Blocking TUI**: Service discovery is offloaded to a background thread (`ServiceBackgroundWorker`) with generation tracking. The TUI reads cached snapshots with zero latency.
- **Environment Variables**: TIMMY extracts variable names **only**. It **never** reads, stores, or logs raw environment variable values in memory, debug logs, or JSON output.
- **Secret Redaction**: Command-line arguments, executable paths, and parser error snippets are sanitized via `SecretMasker` before display and storage.

### AI Agent Attribution Confidence
Services are correlated with AI agent sessions based on defensible evidence:
- **`CONFIRMED`**: Active session explicitly tracks the process, verified binary identity matches the agent, process start time is within the session lifetime, and zero conflicting claims.
- **`HIGH CONFIDENCE`**: The running service process is a direct child of a confirmed active AI agent process.
- **`INFERRED`**: Historical association with a completed session, attributed running process without an active session, or conflicting claims.
- **`UNKNOWN`**: Standard user/system services, or services with insufficient provenance.
- **Temporal Boundary Checks**: If a process start time predates an AI session's creation, attribution is strictly rejected (guarding against PID reuse and pre-existing daemons).
- **Descriptive Evidence Only**: A service label containing words like `claude`, `cursor`, or `windsurf` is recorded as descriptive evidence only; it never unilaterally establishes agent ownership.
- **Unresolved Conflicts**: When multiple sessions claim the same background service, ownership is left unresolved (`session_id: None`, confidence downgraded to `INFERRED`).

---

## Keyboard Controls

| Key | Action |
|:---:|:---|
| <kbd>Tab</kbd> / <kbd>Shift+Tab</kbd> | Switch between views (**Processes**, **Ports**, **Services**, **Docker**, **Sessions**) |
| <kbd>1</kbd> - <kbd>5</kbd> / <kbd>s</kbd> | Jump directly to tab (<kbd>5</kbd> or <kbd>s</kbd> for Sessions) |
| <kbd>↑</kbd> / <kbd>k</kbd> | Move selection up |
| <kbd>↓</kbd> / <kbd>j</kbd> | Move selection down |
| <kbd>Enter</kbd> / <kbd>i</kbd> | Open detailed inspection modal (lineage/cmdline for processes, full inspection for Docker containers, or session cleanup plan) |
| <kbd>x</kbd> | Request graceful termination (`SIGTERM`) of selected process |
| <kbd>X</kbd> (Shift+X) | Request force kill (`SIGKILL`) of selected process (requires modal confirmation) |
| <kbd>/</kbd> | Filter / Search active list |
| <kbd>r</kbd> | Force immediate on-demand refresh |
| <kbd>Esc</kbd> | Close modal / Clear filter |
| <kbd>q</kbd> / <kbd>Ctrl+C</kbd> | Quit TIMMY safely (restores terminal state) |

---

## AI Agent Session Tracking

TIMMY tracks individual AI coding sessions across tools like Claude Code, Cursor, Windsurf, Aider, and Copilot CLI.

### Monitoring Modes: Snapshot vs. Continuous Watch

- **Point-in-Time Snapshot (`timmy session start`)**:
  Creates an active session record in local SQLite, snapshots currently running processes, ports, and agent lineage, and **immediately exits**. No background daemon or continuous polling process is spawned in the background.
- **Foreground Continuous Watch (`timmy session start --watch` or `timmy session watch`)**:
  Runs periodic observation in the foreground at a configurable interval (default: 2s). Captures new child processes as they spawn, detects when parent agents exit, tracks orphaned/detached background workers, and records historical snapshots. Pressing <kbd>Ctrl+C</kbd> cleanly stops monitoring without terminating any tracked processes.
- **Interactive TUI Monitoring**:
  While the interactive terminal UI (`timmy`) is open, it continuously monitors active session resources on its refresh loop. Exiting the TUI stops observation cleanly.

### Detached Process Attribution & Safety Rules

When AI coding agents launch servers (Vite, Next.js, FastAPI) and the agent CLI exits, the operating system re-parents those child processes to PID 1 (`launchd`). TIMMY attributes these accurately without false positives:
- **Previously Observed Children (`HighConfidence`)**:
  If TIMMY observed the process while its parent agent was running, it tracks the transition when the agent exits. The process is flagged as `is_detached = true` while retaining its `HighConfidence` attribution backed by verified lineage.
- **Unobserved Orphans (`Inferred` / `safe_to_terminate = false`)**:
  If a process under PID 1 was never observed under an agent tree, TIMMY will **never** assign it `Confirmed` or `HighConfidence`. It is classified strictly as `Inferred` with fail-safe `safe_to_terminate = false`.
- **PID Reuse Protection**:
  If an observed process exits and the OS recycles its PID for an unrelated process, TIMMY verifies process start times and executable names, automatically rejecting recycled PIDs from the session.
- **Fail-Safe Defaults**:
  All resources default to `safe_to_terminate = false`. Root agent executables, interactive shells, and terminal hosts are strictly protected. Session stopping (`timmy session stop`) never kills processes. Cleanup is strictly advisory.

---

## Architecture Overview

TIMMY is engineered with 12 strictly decoupled modular responsibilities:

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Entry (main)                 │
└──────────────────────────────┬──────────────────────────────┘
                               │
       ┌───────────────────────┼──────────────────────┐
       ▼                       ▼                      ▼
┌──────────────┐       ┌──────────────┐       ┌──────────────┐
│ Terminal UI  │       │ Domain Engine│       │ Configuration│
│  (Ratatui)   │       │(Orchestrator)│       │  & Storage   │
└──────┬───────┘       └───────┬──────┘       └──────────────┘
       │                       │
       │         ┌─────────────┴─────────────┐
       │         ▼                           ▼
       │  ┌──────────────┐            ┌──────────────┐
       │  │ Attribution  │            │ Safe Actions │
       │  │  & Heuristics│            │(Terminator)  │
       │  └──────────────┘            └──────┬───────┘
       │                                     │
       └─────────────────┬───────────────────┘
                         ▼
             ┌───────────────────────┐
             │  Platform Abstraction │
             │  (macOS / Portable)   │
             └───────────────────────┘
```

For in-depth architectural blueprints, trait contracts, and data flows, see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Safety Guarantees

TIMMY adheres to strict safety principles:
1. **No Unattended Kills**: Every termination is initiated by human keypress.
2. **Never Touch System Essentials**: System processes (`PID 0`, `PID 1`, kernel tasks, core window servers) are hard-blocked at the kernel ID and binary path level.
3. **No Credential Leaks**: Memory dumps and environment variable views mask known token formats and variable keys.
4. **No Destructive Shell Shortcuts**: Uses direct, type-checked POSIX system calls (`libc::kill`) rather than shell interpolation like `kill -9 $(pgrep ...)`.

Review the full policy in [SECURITY.md](SECURITY.md).

---

## Roadmap

See [ROADMAP.md](ROADMAP.md) for current progress and future milestones, including Linux/Windows platform layers, container deep-inspection, and custom agent signature plugins.

---

## Contributing

Contributions, bug reports, and agent signature additions are warmly welcomed! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for development workflows and coding standards.

---

## License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
