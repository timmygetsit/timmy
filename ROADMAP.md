# TIMMY Product Roadmap

This document outlines the evolutionary milestones for **TIMMY**, from foundational architecture to full macOS native integration, cross-platform expansion, and advanced agent telemetry.

---

## Milestone 0: Core Architecture & Foundation (Current Target)
> **Goal**: Establish a bulletproof, modular Rust foundation with all 12 responsibilities cleanly separated, domain models, safety guardrails, configuration parsing, persistence schema, and a working Ratatui TUI skeleton.

- [x] **Project Scaffolding**: Modular directory structure separating presentation, domain engine, platform adapters, storage, and safety.
- [x] **Core Domain Models**: Data models for `ProcessInfo`, `ListeningPort`, `ServiceInfo`, `ContainerInfo`, `AttributionResult`, and `Confidence`.
- [x] **Safety Engine Foundation**: Critical macOS system process shield (hardcoded kernel IDs and essential system binary names), graceful signal coordinator (`SIGTERM` -> timeout -> `SIGKILL`), and environment secret redactor.
- [x] **Platform Abstraction Layer**: Generic traits (`ProcessCollector`, `PortCollector`, `ServiceCollector`, `DockerCollector`) with initial portable implementations using `sysinfo`.
- [x] **Configuration Management**: TOML config loading with sensible defaults, XDG/macOS directory paths (`~/Library/Application Support/timmy`).
- [x] **Local Storage**: SQLite database schema setup (`timmy.db`) for tracking process history, kill audits, and custom agent signature rules.
- [x] **Interactive TUI Skeleton**: Ratatui + Crossterm terminal UI with navigation tabs (Processes, Ports, Services, Docker), safe modal dialogues, and terminal panic recovery hooks.
- [x] **Verification & Quality**: Zero compilation warnings, `cargo fmt --check`, `cargo check`, and automated unit tests.

---

## Milestone 1: Native macOS Discovery & Process Lineage (Completed & Production Ready)
> **Goal**: Elevate process discovery beyond basic `sysinfo` by tapping directly into macOS kernel APIs for deep lineage tracing and port-to-PID correlation.

- [x] **macOS `libproc` & `sysctl` Integration**:
  - Implement zero-overhead process enumeration using `proc_listpids` with dynamic buffer sizing and truncation detection.
  - Resolve exact command-line arguments using `sysctl KERN_PROCARGS2` with multi-null extraction and secret masking.
  - Extract true working directories and binary paths via `proc_pidinfo(PROC_PIDVNODEPATHINFO)` and `proc_pidpath`.
  - Capture microsecond-precision kernel start times (`pbi_start_tvsec`, `pbi_start_tvusec`) creating tamper-proof `ProcessIncarnation` identities.
- [x] **Process Tree & Persistent Lineage Reconstruction**:
  - Build persistent parent-to-child and child-to-parent process graph in SQLite Schema V7 (`process_lineage`).
  - Retain historical edges across observation intervals, intermediate process exits, and reparenting to PID 1 (`launchd`).
  - Strict PID reuse rejection: new processes recycling a PID with mismatched start times are strictly prevented from attaching to historical parent edges.
  - Formatted Unicode lineage tree visualization in CLI and TUI with `--tree` and `--show-exited` flags.
- [x] **Native Socket to PID Mapping**:
  - Scan open file descriptors for `PROX_FDTYPE_SOCKET` using `proc_pidinfo(PROC_PIDLISTFDS)`.
  - Inspect socket details and endpoints via `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)` directly in memory.
  - Zero-subprocess port discovery for TCP (`TSI_S_LISTEN`) and bound UDP sockets with graceful fallback to `lsof`.
- [x] **Expanded Agent Signatures**:
  - First-class support for Claude Code CLI, Cursor IDE / Cursor Server, Windsurf / Codeium, Aider, GitHub Copilot CLI, Devin, Continue.dev, Antigravity, and local Ollama/vLLM servers.

---

## Milestone 2: Background Services & Docker Deep Dive
> **Goal**: Expand visibility into persistent developer services, macOS launchd jobs, and container runtimes.

- [x] **Docker Engine UNIX Socket Integration (Read-Only Production Ready)**:
  - Asynchronous client over local UNIX sockets (`/var/run/docker.sock`, `~/.docker/run/docker.sock`, OrbStack, Colima) powered by `bollard`.
  - Strictly local-only: rejects remote endpoints (`tcp://`, `http://`, `https://`, `ssh://`, `host:port`) with `DockerUnsupportedRemote`.
  - Strict endpoint precedence with NO silent fallback: TIMMY config > `DOCKER_HOST` > `DOCKER_CONTEXT` > `currentContext` (`~/.docker/contexts/meta/<hash>/meta.json`) > standard auto-discovery.
  - Granular error diagnostics: `DockerNotInstalled`, `DockerDaemonStopped`, `DockerSocketMissing`, `DockerPermissionDenied`, `DockerInvalidEndpoint`, `DockerUnsupportedRemote`, `DockerApiIncompatible`.
  - Discovers running and non-running containers, live CPU/memory/network/block I/O metrics, and port mappings.
  - Connection caching and non-blocking bounded concurrent stats collection (`stream.buffer_unordered(4)` with 150ms timeout).
  - Deep inspection modal with secret-masked commands, entrypoints, sensitive labels, and environment variable names only (`env_keys`).
  - Evidence-based AI agent session correlation into 4 tiers (`CONFIRMED`, `HIGH CONFIDENCE`, `INFERRED`, `UNKNOWN`).
  - Distinguishes declared session metadata (`HighConfidence`) from verified process provenance (`Confirmed`).
  - Explicit multi-session conflict detection and representation (`conflicting_sessions`).
  - Retained attribution across session termination for surviving containers.
  - Read-only CLI commands: `timmy docker status`, `list`, `inspect`, `stats` with human-readable tables and `--json` support.
  - Comprehensive 29-scenario hermetic test suite running without external Docker daemon requirements.
- [x] **macOS LaunchAgent and LaunchDaemon Discovery & Inspection (Read-Only Production Ready)**:
  - Discovery across User LaunchAgents (`~/Library/LaunchAgents`), third-party System LaunchDaemons (`/Library/LaunchDaemons`), and Apple system daemons (`/System/Library/LaunchDaemons`).
  - Read-only runtime domain inspection via `launchctl list` and `launchctl print system`.
  - Distinguishes file discovery on disk from launchd runtime registration (6 explicit states: `DiscoveredOnDisk`, `Loaded`, `Running`, `NotRunning`, `Unknown`, `Error`).
  - Collision-free reconciliation keyed by `(domain, label)` to handle identical labels across different launchd domains.
  - Safe plist parsing with `plist` crate: extracts Label, Program, ProgramArguments, WorkingDirectory, RunAtLoad, KeepAlive (boolean & dictionary), StartInterval, StartCalendarInterval, Sockets, MachServices, StdOut/StdErr, User/Group.
  - Strict security controls: variable names only for `EnvironmentVariables` (raw values are never read, stored, or exposed), arguments masked with `SecretMasker`.
  - Process and session correlation: exact PID match, executable match, descriptive evidence, session ancestry, and multi-session conflict detection.
  - Interactive TUI Services table and detailed modal overlay (<kbd>Enter</kbd> / <kbd>i</kbd>).
  - CLI command `timmy services [--domain <name>] [--json]`.
  - Strictly observational: prohibits all lifecycle commands (`bootout`, `kickstart`, `disable`, `enable`, `unload`, `load`).
  - 19-scenario fixture and hermetic test suite with mock launchctl parser and macOS live integration.
- [ ] **Safe Service Lifecycle Management (Future Milestone)**:
  - Explicitly authorized, interactive service unload, stop, or disable operations with multi-step confirmation modals.

---

## Milestone 3: Interactive TUI Polish & Advanced Operations (Completed & Production Ready)
> **Goal**: Deliver a keyboard experience comparable to `htop`/`lazygit` tailored specifically for AI-generated workloads.

- [x] **Live Multi-Token Search & Interactive Filter Indicators**:
  - In-memory case-insensitive multi-token (AND) filtering across processes (PID, name, agent, reason, command line, working directory, executable), ports, services, containers, and sessions.
  - Active filter visual badge in footer with quick <kbd>/</kbd> to edit and <kbd>Esc</kbd> to clear.
- [x] **Tabbed Session Inspection Modal with Lineage Tree**:
  - Interactive modal with 3 switchable tabs: `[1] Lineage Tree`, `[2] Cleanup Plan`, `[3] Tracked Resources`.
  - Keyboard navigation with <kbd>1</kbd>-<kbd>3</kbd>, <kbd>Tab</kbd>, <kbd>BackTab</kbd>, <kbd>j</kbd>/<kbd>k</kbd> scrolling, and color-coded hierarchy syntax.
- [x] **Session View Lineage Toggle & Direct Process Jump**:
  - Toggle between flat Tracked Resources table and Unicode Lineage Tree in the session bottom pane via <kbd>t</kbd>.
  - Direct jump to a process's session lineage tree from the Processes tab via <kbd>t</kbd>.
- [x] **Multi-Process Tagging & Safety-Gated Batch Operations**:
  - Multi-process selection with <kbd>Space</kbd> tag toggle, <kbd>a</kbd> tag-all/untag-all toggle, and clear tag counter indicators.
  - Interactive batch termination confirmation modal (<kbd>x</kbd> for SIGTERM, <kbd>X</kbd> for SIGKILL).
  - Strict system `SafetyShield` audit partitioning candidates into eligible processes and protected/shielded processes (PID 0, PID 1, terminal emulators, TIMMY ancestor tree).
- [x] **Resource Sparks & Real-Time Telemetry Trends**:
  - Integrated 35-sample CPU and Memory sparkline widgets in the header dashboard with automatic fallback for compact terminals.
- [ ] **Custom Signature Editor (Future Roadmap)**:
  - Interactive UI to define new attribution rules and save them directly to SQLite / `config.toml`.

---

## Milestone 4: Cross-Platform Expansion
> **Goal**: Port platform collection traits to Linux and Windows.

- [ ] **Linux Platform Layer**:
  - `/proc` virtual filesystem reader for zero-overhead process and lineage tracing.
  - `/proc/net/tcp` and netlink socket correlation.
  - `systemd --user` unit discovery via D-Bus.
- [ ] **Windows Platform Layer**:
  - `CreateToolhelp32Snapshot` for process trees.
  - `GetExtendedTcpTable` for socket-to-PID correlation.
  - Windows Services API inspection.

---

## Milestone 5: Developer Workflows & Extensibility
> **Goal**: Seamless integration with CI, pre-commit hooks, and developer shell environments.

- [ ] **CLI Non-Interactive Mode**:
  - Output formats: JSON, Table, and Human-Readable summary for scripting (`timmy scan --json`).
  - Pre-commit / CI gate: `timmy scan --check-ports 3000,5432` to assert no leftover test servers remain running.
- [ ] **Shell Integrations**:
  - Prompt widget or zsh/fish plugin notifying when background agent servers are active.
