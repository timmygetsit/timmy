use clap::Parser;
use std::io::Write;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use timmy::cli::{Cli, Commands, DockerCommands, SessionCommands};
use timmy::config::ConfigManager;
use timmy::engine::EngineOrchestrator;
use timmy::model::Confidence;
use timmy::storage::{default_db_path, StorageManager};
use timmy::ui::{run_tui, App};

macro_rules! safe_println {
    ($($arg:tt)*) => {
        let _ = writeln!(std::io::stdout(), $($arg)*);
    };
}

fn run_foreground_watch(
    orchestrator: &EngineOrchestrator,
    session_id: &str,
    interval_secs: u64,
) -> anyhow::Result<()> {
    let stop_signal = Arc::new(AtomicBool::new(false));

    // Register async-signal-safe flags for SIGINT and SIGTERM with documented ordering:
    // 1st signal: requests graceful shutdown.
    // 2nd signal: triggers immediate default termination (SIG_DFL).
    timmy::engine::register_shutdown_signals(Arc::clone(&stop_signal))?;

    let interval_s = interval_secs.max(1);
    safe_println!("TIMMY: Active Foreground Observation Started");
    safe_println!("{:-<80}", "");
    safe_println!("Session ID:       {}", session_id);
    safe_println!("Observation Rate: Every {}s", interval_s);
    safe_println!("Press Ctrl+C to stop monitoring. Background processes will NOT be terminated.");
    safe_println!("{:-<80}", "");

    let watch_res = orchestrator.watch_session(
        session_id,
        std::time::Duration::from_secs(interval_s),
        stop_signal,
        |sess, resources| {
            let detached_count = resources.iter().filter(|r| r.is_detached).count();
            let eligible_count = resources.iter().filter(|r| r.safe_to_terminate).count();
            safe_println!(
                "[{}] Observing {} resources ({} detached, {} eligible) | RAM: {} | CPU: {} | Ports: [{}]",
                chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
                resources.len(),
                detached_count,
                eligible_count,
                sess.formatted_memory(),
                sess.formatted_cpu(),
                sess.ports_str()
            );
        },
    );

    match watch_res {
        Ok(final_sess) => {
            safe_println!("\n{:-<80}", "");
            if final_sess.status != timmy::model::SessionStatus::Active {
                safe_println!(
                    "NOTE: Session '{}' transitioned to status '{}' (stopped or replaced).",
                    final_sess.id,
                    final_sess.status
                );
            }
            safe_println!("TIMMY: Foreground monitoring stopped cleanly.");
            safe_println!(
                "Session remains recorded in SQLite. Run `timmy session stop` when ready to conclude tracking."
            );
            safe_println!("Background processes and ports were NOT terminated.");
        }
        Err(timmy::engine::SessionError::ObserverLeaseAlreadyHeld {
            session_id,
            owner_id,
            expires_at,
        }) => {
            eprintln!(
                "\n⚠️  Observation lease for session '{}' is currently held by '{}'.",
                session_id, owner_id
            );
            eprintln!(
                "    Another active observer is monitoring this session (lease expires at {}).",
                expires_at
            );
            eprintln!("    To inspect resources without competing for observation, run `timmy session inspect`.");
        }
        Err(e) => {
            eprintln!("\nForeground watch ended: {}", e);
        }
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Safety rule: Warn if running with elevated root privileges
    let is_root = unsafe { libc::geteuid() == 0 };
    if is_root {
        eprintln!("⚠️  WARNING: TIMMY is running with root/elevated privileges.");
        eprintln!("    It is strongly recommended to run TIMMY as a standard user to prevent accidental system changes.\n");
    }

    // 1. Load or initialize configuration
    let (config, config_path) = if let Some(custom_path) = &cli.config {
        let cfg = ConfigManager::load_from_path(custom_path)?;
        (cfg, custom_path.clone())
    } else {
        ConfigManager::load_or_create_default()
    };

    // 2. Initialize local SQLite storage
    let db_path = default_db_path();
    let storage = match StorageManager::open(&db_path) {
        Ok(s) => Some(Arc::new(s)),
        Err(e) => {
            if cli.verbose {
                eprintln!(
                    "Note: Could not open local database at {:?}: {}",
                    db_path, e
                );
            }
            None
        }
    };

    // 3. Initialize Domain Engine Orchestrator
    let orchestrator = EngineOrchestrator::new(config.clone(), storage.clone());

    // 4. Dispatch Command
    match cli.command.unwrap_or(Commands::Run) {
        Commands::Run => {
            let refresh_rate = if cli.refresh != 1000 {
                cli.refresh
            } else {
                config.general.refresh_interval_ms
            };

            let app = App::new(orchestrator);
            run_tui(app, refresh_rate)?;
        }
        Commands::Scan { agents_only, json } => {
            let snap = orchestrator.refresh_snapshot()?;
            if json {
                let procs: Vec<_> = if agents_only {
                    snap.processes
                        .into_iter()
                        .filter(|p| p.attribution.confidence != Confidence::Unknown)
                        .collect()
                } else {
                    snap.processes
                };
                let output_data = serde_json::json!({
                    "processes": procs,
                    "metrics": snap.metrics,
                });
                safe_println!("{}", serde_json::to_string_pretty(&output_data)?);
                return Ok(());
            }

            safe_println!("TIMMY: Active Process Scan");
            safe_println!("{:-<110}", "");
            safe_println!(
                "{:<8} {:<22} {:<16} {:<12} {:<14} {:<8} {:<10} {:<14}",
                "PID",
                "PROCESS",
                "ATTRIBUTION",
                "CONFIDENCE",
                "SAFE TO STOP",
                "CPU%",
                "RAM",
                "PORTS"
            );
            safe_println!("{:-<110}", "");

            for p in &snap.processes {
                if agents_only && p.attribution.confidence == Confidence::Unknown {
                    continue;
                }
                let ports_str = if p.listening_ports.is_empty() {
                    "-".to_string()
                } else {
                    p.listening_ports
                        .iter()
                        .map(|port| port.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                };

                let safe_str = if p.attribution.safe_to_terminate {
                    "YES"
                } else {
                    "NO (PROTECTED)"
                };

                safe_println!(
                    "{:<8} {:<22} {:<16} {:<12} {:<14} {:<8} {:<10} {:<14}",
                    p.pid,
                    truncate_str(&p.name, 20),
                    p.attribution.kind.to_string(),
                    p.attribution.confidence.to_string(),
                    safe_str,
                    p.formatted_cpu(),
                    p.formatted_memory(),
                    ports_str
                );
            }
            safe_println!("{:-<110}", "");
            safe_println!(
                "Total Processes: {} | Attributed Agents: {} | Open Ports: {}",
                snap.processes.len(),
                snap.metrics.total_agent_processes,
                snap.metrics.total_listening_ports
            );
        }
        Commands::Ports { json } => {
            let snap = orchestrator.refresh_snapshot()?;
            if json {
                safe_println!("{}", serde_json::to_string_pretty(&snap.ports)?);
                return Ok(());
            }

            safe_println!("TIMMY: Active Listening Network Ports");
            safe_println!("{:-<80}", "");
            safe_println!(
                "{:<8} {:<8} {:<18} {:<8} {:<28}",
                "PORT",
                "PROTO",
                "IP",
                "PID",
                "PROCESS"
            );
            safe_println!("{:-<80}", "");

            for port in &snap.ports {
                safe_println!(
                    "{:<8} {:<8} {:<18} {:<8} {:<28}",
                    port.port,
                    port.protocol.to_string(),
                    port.ip,
                    port.pid
                        .map(|id| id.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                    port.process_name.as_deref().unwrap_or("Unknown")
                );
            }
            safe_println!("{:-<80}", "");
            safe_println!("Total Listening Ports: {}", snap.ports.len());
        }
        Commands::Doctor { json } => {
            let shield = timmy::safety::SafetyShield::new();
            let shield_valid = shield.validate_termination(1, "launchd").is_err();
            let snap_res = orchestrator.refresh_snapshot();

            if json {
                let doc_data = serde_json::json!({
                    "os": std::env::consts::OS,
                    "arch": std::env::consts::ARCH,
                    "is_root": is_root,
                    "config_path": config_path,
                    "db_path": db_path,
                    "safety_shield_active": shield_valid,
                    "native_darwin_process_discovery": cfg!(target_os = "macos"),
                    "native_darwin_socket_discovery": cfg!(target_os = "macos"),
                    "persistent_lineage_schema_version": 7,
                    "snapshot": snap_res.as_ref().ok().map(|s| serde_json::json!({
                        "processes": s.processes.len(),
                        "ports": s.ports.len(),
                        "services": s.services.len(),
                        "containers": s.containers.len(),
                    })),
                });
                safe_println!("{}", serde_json::to_string_pretty(&doc_data)?);
                return Ok(());
            }
            safe_println!("TIMMY System Diagnostics & Health Check");
            safe_println!("========================================");
            safe_println!(
                "• Operating System: {} ({})",
                std::env::consts::OS,
                std::env::consts::ARCH
            );
            safe_println!(
                "• Process User: {}",
                if is_root {
                    "Root (WARNING)"
                } else {
                    "Unprivileged (Recommended)"
                }
            );
            safe_println!(
                "• Config Path: {:?} (Exists: {})",
                config_path,
                config_path.exists()
            );
            safe_println!(
                "• SQLite Path: {:?} (Writable: {})",
                db_path,
                db_path.exists() || db_path.parent().map(|p| p.exists()).unwrap_or(false)
            );

            let snap_res = orchestrator.refresh_snapshot();
            match snap_res {
                Ok(snap) => {
                    safe_println!(
                        "• Process Discovery: Operational (Found {} processes)",
                        snap.processes.len()
                    );
                    safe_println!(
                        "• Port Discovery: Operational (Found {} listening ports)",
                        snap.ports.len()
                    );
                    safe_println!(
                        "• Service Discovery: Operational (Found {} services)",
                        snap.services.len()
                    );
                    safe_println!(
                        "• Docker Daemon: {}",
                        if snap.containers.is_empty() {
                            "Not running or no containers"
                        } else {
                            "Active"
                        }
                    );
                }
                Err(e) => {
                    safe_println!("• Discovery Error: {}", e);
                }
            }

            let shield = timmy::safety::SafetyShield::new();
            safe_println!(
                "• Safety Shield: Active (Guards PID 0, PID 1, macOS WindowServer, launchd)"
            );
            assert!(shield.validate_termination(1, "launchd").is_err());
            safe_println!("• System Diagnostics Passed.");
        }
        Commands::Session { action } => match action {
            SessionCommands::Start {
                agent,
                watch,
                interval,
                replace,
            } => match orchestrator.start_session(agent, replace) {
                Ok(sess) => {
                    safe_println!("TIMMY: Started AI Agent Session Tracking");
                    safe_println!("{:-<80}", "");
                    safe_println!("Session ID:       {}", sess.id);
                    safe_println!("AI Agent:         {}", sess.agent_kind);
                    safe_println!("Status:           {}", sess.status);
                    safe_println!("Confidence:       {}", sess.confidence);
                    safe_println!(
                        "Started At:       {}",
                        sess.start_time.format("%Y-%m-%d %H:%M:%S UTC")
                    );
                    safe_println!(
                        "Root Process:     {}",
                        sess.root_pid
                            .map(|pid| format!(
                                "{} (PID {})",
                                sess.root_process_name.as_deref().unwrap_or("agent"),
                                pid
                            ))
                            .unwrap_or_else(|| "None identified (Uncertain)".to_string())
                    );
                    safe_println!("Evidence:         {}", sess.evidence.join("; "));
                    safe_println!("Tracked PIDs:     {:?}", sess.tracked_pids);
                    safe_println!("Listening Ports:  {}", sess.ports_str());
                    safe_println!("Memory Usage:     {}", sess.formatted_memory());
                    safe_println!("{:-<80}", "");

                    if watch {
                        run_foreground_watch(&orchestrator, &sess.id, interval)?;
                    } else {
                        safe_println!("NOTE: Session record created in SQLite.");
                        safe_println!(
                            "TIMMY does not run a background daemon; observation stops when this command returns."
                        );
                        safe_println!("To monitor this session in real time:");
                        safe_println!(
                            "  • Run with foreground watcher: timmy session start --watch"
                        );
                        safe_println!("  • Or attach watcher now:       timmy session watch");
                        safe_println!("  • Or open interactive TUI:     timmy");
                    }
                }
                Err(e) => {
                    eprintln!("Error starting session: {}", e);
                    std::process::exit(1);
                }
            },
            SessionCommands::Watch {
                session_id,
                interval,
            } => {
                let target_id = match session_id {
                    Some(id) => id,
                    None => match orchestrator.session_coordinator() {
                        Some(coord) => match coord.list_sessions() {
                            Ok(list) => match list
                                .iter()
                                .find(|s| s.status == timmy::model::SessionStatus::Active)
                            {
                                Some(s) => s.id.clone(),
                                None => {
                                    eprintln!("No active session found to watch. Start one with `timmy session start --watch`.");
                                    std::process::exit(1);
                                }
                            },
                            Err(e) => {
                                eprintln!("Error listing sessions: {}", e);
                                std::process::exit(1);
                            }
                        },
                        None => {
                            eprintln!("Storage manager not initialized.");
                            std::process::exit(1);
                        }
                    },
                };

                run_foreground_watch(&orchestrator, &target_id, interval)?;
            }
            SessionCommands::List { json } => match orchestrator.list_sessions() {
                Ok(sessions) => {
                    if json {
                        safe_println!("{}", serde_json::to_string_pretty(&sessions)?);
                        return Ok(());
                    }

                    if sessions.is_empty() {
                        safe_println!("No AI agent sessions recorded.");
                        safe_println!(
                            "Start tracking one with: timmy session start [--agent <name>]"
                        );
                        return Ok(());
                    }

                    safe_println!("TIMMY: AI Agent Coding Sessions");
                    safe_println!("{:-<105}", "");
                    safe_println!(
                        "{:<26} {:<16} {:<10} {:<19} {:<10} {:<10} {:<12}",
                        "SESSION ID",
                        "AGENT",
                        "STATUS",
                        "STARTED",
                        "DURATION",
                        "RESOURCES",
                        "RAM"
                    );
                    safe_println!("{:-<105}", "");

                    for s in &sessions {
                        safe_println!(
                            "{:<26} {:<16} {:<10} {:<19} {:<10} {:<10} {:<12}",
                            s.id,
                            s.agent_kind.to_string(),
                            s.status.to_string(),
                            s.start_time.format("%Y-%m-%d %H:%M").to_string(),
                            s.duration_str(),
                            s.resource_count,
                            s.formatted_memory()
                        );
                    }
                    safe_println!("{:-<105}", "");
                    safe_println!("Total Sessions: {}", sessions.len());
                }
                Err(e) => {
                    eprintln!("Error listing sessions: {}", e);
                    std::process::exit(1);
                }
            },
            SessionCommands::Inspect {
                session_id,
                tree,
                show_exited,
                json,
            } => match orchestrator.inspect_session(session_id.as_deref()) {
                Ok((sess, resources, recs)) => {
                    if json {
                        let lineage_tree = orchestrator
                            .get_session_lineage_tree(&sess.id, show_exited)
                            .ok();
                        let data = serde_json::json!({
                            "session": sess,
                            "resources": resources,
                            "recommendations": recs,
                            "lineage_tree": lineage_tree,
                        });
                        safe_println!("{}", serde_json::to_string_pretty(&data)?);
                        return Ok(());
                    }

                    if tree {
                        let lineage_tree = orchestrator
                            .get_session_lineage_tree(&sess.id, show_exited)
                            .unwrap_or_default();
                        safe_println!("TIMMY: AI Agent Session Lineage Tree");
                        safe_println!("{:-<80}", "");
                        safe_println!("Session ID:              {}", sess.id);
                        safe_println!("Declared Agent Identity: {}", sess.agent_kind);
                        safe_println!("Identity Confidence:     {}", sess.confidence);
                        safe_println!("Tracking Status:         {}", sess.status);
                        safe_println!("{:-<80}", "");
                        if lineage_tree.is_empty() {
                            safe_println!("No lineage edges recorded for this session.");
                        } else {
                            let masker = timmy::safety::masker::SecretMasker::new();
                            let tree_str = timmy::engine::lineage::format_lineage_tree_unicode(
                                &lineage_tree,
                                &masker,
                            );
                            safe_println!("{}", tree_str.trim_end());
                        }
                        safe_println!("{:-<80}", "");
                        return Ok(());
                    }

                    safe_println!("TIMMY: AI Agent Session Deep Inspection");
                    safe_println!("{:-<80}", "");
                    safe_println!("Session ID:              {}", sess.id);
                    safe_println!("Declared Agent Identity: {}", sess.agent_kind);
                    safe_println!(
                        "Identity Confidence:     {} (Declared/Identified Session Identity)",
                        sess.confidence
                    );
                    safe_println!("Tracking Status:         {}", sess.status);
                    if let Some(s) = &storage {
                        if let Ok(Some(lease)) = s.get_observer_lease(&sess.id) {
                            if !lease.is_expired() {
                                safe_println!(
                                            "Active Observer:         Owner '{}' (unexpired lease until {})",
                                            lease.owner_id,
                                            lease.expires_at.format("%Y-%m-%d %H:%M:%S UTC")
                                        );
                            }
                        }
                    }
                    safe_println!(
                        "Start Timestamp:         {}",
                        sess.start_time.format("%Y-%m-%d %H:%M:%S UTC")
                    );
                    if let Some(end) = sess.end_time {
                        safe_println!(
                            "End Timestamp:           {}",
                            end.format("%Y-%m-%d %H:%M:%S UTC")
                        );
                    }
                    safe_println!("Elapsed Duration:        {}", sess.duration_str());
                    safe_println!(
                        "Root Agent Process:      {}",
                        sess.root_pid
                            .map(|p| format!(
                                "{} (PID {})",
                                sess.root_process_name.as_deref().unwrap_or("agent"),
                                p
                            ))
                            .unwrap_or_else(|| "None identified / verified".to_string())
                    );
                    safe_println!("Session Evidence Log:");
                    for ev in &sess.evidence {
                        safe_println!("  • {}", ev);
                    }
                    safe_println!("{:-<80}", "");
                    safe_println!("Tracked Resources ({})", resources.len());
                    safe_println!(
                        "{:<8} {:<18} {:<16} {:<10} {:<16} {:<10} {:<12}",
                        "PID",
                        "PROCESS",
                        "OWNERSHIP CONF.",
                        "DETACHED",
                        "ELIGIBLE TO STOP",
                        "RAM",
                        "PORTS"
                    );
                    safe_println!("{:-<80}", "");

                    for r in &resources {
                        safe_println!(
                            "{:<8} {:<18} {:<16} {:<10} {:<16} {:<10} {:<12}",
                            r.pid
                                .map(|p| p.to_string())
                                .unwrap_or_else(|| "-".to_string()),
                            truncate_str(&r.name, 16),
                            r.confidence.to_string(),
                            if r.is_detached { "YES" } else { "no" },
                            if r.safe_to_terminate {
                                "YES"
                            } else {
                                "NO (SHIELD)"
                            },
                            r.formatted_memory(),
                            r.ports_str()
                        );
                    }

                    safe_println!("{:-<80}", "");
                    safe_println!(
                        "Session Cleanup Preparation (Advisory Only - No Automatic Termination)"
                    );
                    safe_println!("{:-<80}", "");
                    if recs.is_empty() {
                        safe_println!("No cleanup recommendations available for this session.");
                    } else {
                        for rec in &recs {
                            safe_println!(
                                        "• {:<16} (PID {:<6}) | Ownership: {:<12} | Eligible: {:<3} | User Auth: NO (Pending)",
                                        rec.resource_name,
                                        rec.pid_or_id,
                                        rec.ownership_confidence.to_string(),
                                        if rec.termination_eligible { "YES" } else { "NO" }
                                    );
                            safe_println!("    Ownership Evidence:    {}", rec.ownership_evidence);
                            safe_println!("    Eligibility Details:   {}", rec.eligibility_reason);
                            safe_println!("    Authorization Status:  NOT AUTHORIZED (Action required before any termination)");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error inspecting session: {}", e);
                    std::process::exit(1);
                }
            },
            SessionCommands::Stop { session_id } => {
                match orchestrator.stop_session(session_id.as_deref()) {
                    Ok(sess) => {
                        safe_println!("TIMMY: AI Agent Session Tracking Stopped");
                        safe_println!("{:-<80}", "");
                        safe_println!("Session ID:    {}", sess.id);
                        safe_println!("AI Agent:      {}", sess.agent_kind);
                        safe_println!("Status:        {}", sess.status);
                        safe_println!("Duration:      {}", sess.duration_str());
                        safe_println!("Resources:     {} tracked", sess.resource_count);
                        safe_println!("Total Memory:  {}", sess.formatted_memory());
                        safe_println!("{:-<80}", "");
                        safe_println!("NOTE: Session tracking is stopped. Background processes were NOT terminated.");
                    }
                    Err(e) => {
                        eprintln!("Error stopping session: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            SessionCommands::Resources {
                session_id,
                tree,
                show_exited,
                json,
            } => match orchestrator.get_session_resources(session_id.as_deref()) {
                Ok((sess, resources)) => {
                    if json {
                        let lineage_tree = orchestrator
                            .get_session_lineage_tree(&sess.id, show_exited)
                            .ok();
                        let data = serde_json::json!({
                            "session": sess,
                            "resources": resources,
                            "lineage_tree": lineage_tree,
                        });
                        safe_println!("{}", serde_json::to_string_pretty(&data)?);
                        return Ok(());
                    }

                    if tree {
                        let lineage_tree = orchestrator
                            .get_session_lineage_tree(&sess.id, show_exited)
                            .unwrap_or_default();
                        safe_println!(
                            "TIMMY: Process Lineage Tree for Session {} ({})",
                            sess.id,
                            sess.agent_kind
                        );
                        safe_println!("{:-<80}", "");
                        if lineage_tree.is_empty() {
                            safe_println!("No lineage edges recorded for this session.");
                        } else {
                            let masker = timmy::safety::masker::SecretMasker::new();
                            let tree_str = timmy::engine::lineage::format_lineage_tree_unicode(
                                &lineage_tree,
                                &masker,
                            );
                            safe_println!("{}", tree_str.trim_end());
                        }
                        safe_println!("{:-<80}", "");
                        return Ok(());
                    }

                    safe_println!(
                        "TIMMY: Tracked Resources for Session {} ({})",
                        sess.id,
                        sess.agent_kind
                    );
                    safe_println!("{:-<100}", "");
                    safe_println!(
                        "{:<8} {:<18} {:<16} {:<10} {:<16} {:<10} {:<14}",
                        "PID",
                        "PROCESS",
                        "OWNERSHIP CONF.",
                        "DETACHED",
                        "ELIGIBLE TO STOP",
                        "RAM",
                        "PORTS"
                    );
                    safe_println!("{:-<100}", "");

                    if resources.is_empty() {
                        safe_println!(
                            "No background resources currently associated with this session."
                        );
                    } else {
                        for r in &resources {
                            safe_println!(
                                "{:<8} {:<18} {:<16} {:<10} {:<16} {:<10} {:<14}",
                                r.pid
                                    .map(|p| p.to_string())
                                    .unwrap_or_else(|| "-".to_string()),
                                truncate_str(&r.name, 16),
                                r.confidence.to_string(),
                                if r.is_detached { "YES" } else { "no" },
                                if r.safe_to_terminate {
                                    "YES"
                                } else {
                                    "NO (SHIELD)"
                                },
                                r.formatted_memory(),
                                r.ports_str()
                            );
                        }
                    }
                    safe_println!("{:-<100}", "");
                    safe_println!(
                        "Total Resources: {} | Total Memory: {} | Open Ports: {}",
                        resources.len(),
                        sess.formatted_memory(),
                        sess.ports_str()
                    );
                }
                Err(e) => {
                    eprintln!("Error retrieving session resources: {}", e);
                    std::process::exit(1);
                }
            },
        },
        Commands::Docker { action } => match action {
            DockerCommands::Status { json } => {
                match orchestrator.docker_status() {
                    Ok(status) => {
                        if json {
                            safe_println!("{}", serde_json::to_string_pretty(&status)?);
                        } else {
                            safe_println!("TIMMY: Docker Engine Status");
                            safe_println!("{:-<80}", "");
                            safe_println!(
                                "Installed:        {}",
                                if status.installed { "YES" } else { "NO" }
                            );
                            safe_println!(
                                "Daemon Running:   {}",
                                if status.running { "YES" } else { "NO" }
                            );
                            safe_println!("Socket Path:      {}", status.socket_path);
                            safe_println!(
                                "Engine Version:   {}",
                                status.engine_version.as_deref().unwrap_or("N/A")
                            );
                            safe_println!(
                                "API Version:      {}",
                                status.api_version.as_deref().unwrap_or("N/A")
                            );
                            safe_println!(
                                "Active Context:   {}",
                                status.active_context.as_deref().unwrap_or("default")
                            );
                            safe_println!(
                                "OS / Arch:        {} / {}",
                                status.os.as_deref().unwrap_or("N/A"),
                                status.arch.as_deref().unwrap_or("N/A")
                            );
                            if let Some(ref cat) = status.error_category {
                                if *cat != timmy::model::DockerErrorCategory::None {
                                    safe_println!("Error Category:   {}", cat);
                                }
                            }
                            if let Some(ref err) = status.error_message {
                                safe_println!("Diagnostics:      {}", err);
                            }
                            safe_println!("{:-<80}", "");
                            safe_println!("Read-only guarantee: TIMMY never terminates or modifies containers.");
                        }
                    }
                    Err(e) => {
                        eprintln!("Error inspecting Docker status: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            DockerCommands::List { all, session, json } => {
                match orchestrator.list_containers(session.as_deref()) {
                    Ok(mut containers) => {
                        if !all {
                            containers.retain(|c| c.state == timmy::model::ContainerState::Running);
                        }

                        if json {
                            safe_println!("{}", serde_json::to_string_pretty(&containers)?);
                        } else {
                            safe_println!("TIMMY: Docker Containers");
                            safe_println!("{:-<110}", "");
                            safe_println!(
                                "{:<14} {:<20} {:<24} {:<12} {:<8} {:<12} {:<20}",
                                "ID",
                                "NAME",
                                "IMAGE",
                                "STATE",
                                "CPU%",
                                "MEMORY",
                                "SESSION"
                            );
                            safe_println!("{:-<110}", "");

                            if containers.is_empty() {
                                safe_println!("No containers found.");
                            } else {
                                for c in &containers {
                                    safe_println!(
                                        "{:<14} {:<20} {:<24} {:<12} {:<8} {:<12} {:<20}",
                                        c.short_id,
                                        truncate_str(&c.name, 18),
                                        truncate_str(&c.image, 22),
                                        c.state.to_string(),
                                        c.formatted_cpu(),
                                        c.formatted_memory(),
                                        c.formatted_session()
                                    );
                                }
                            }
                            safe_println!("{:-<110}", "");
                            safe_println!("Total Containers: {}", containers.len());
                        }
                    }
                    Err(timmy::platform::PlatformError::DockerNotRunning(msg)) => {
                        if json {
                            safe_println!("[]");
                        } else {
                            safe_println!("TIMMY: Docker Containers");
                            safe_println!("{:-<110}", "");
                            safe_println!("Docker daemon is not running ({}).", msg);
                            safe_println!("Run `timmy docker status` for connection diagnostics.");
                            safe_println!("{:-<110}", "");
                        }
                    }
                    Err(e) => {
                        eprintln!("Error listing Docker containers: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            DockerCommands::Inspect { container_id, json } => {
                match orchestrator.inspect_container(&container_id) {
                    Ok(detail) => {
                        if json {
                            safe_println!("{}", serde_json::to_string_pretty(&detail)?);
                        } else {
                            safe_println!("TIMMY: Container Inspection - {}", detail.info.name);
                            safe_println!("{:-<80}", "");
                            safe_println!("Full ID:         {}", detail.info.id);
                            safe_println!("Short ID:        {}", detail.info.short_id);
                            safe_println!("Name:            {}", detail.info.name);
                            safe_println!(
                                "Image:           {} (ID: {})",
                                detail.info.image,
                                detail.info.image_id.as_deref().unwrap_or("N/A")
                            );
                            safe_println!(
                                "State:           {} (Exit Code: {}, Restarts: {})",
                                detail.info.state,
                                detail
                                    .info
                                    .exit_code
                                    .map(|c| c.to_string())
                                    .unwrap_or_else(|| "N/A".to_string()),
                                detail
                                    .info
                                    .restart_count
                                    .map(|r| r.to_string())
                                    .unwrap_or_else(|| "0".to_string())
                            );
                            safe_println!(
                                "Health:          {}",
                                detail.info.health_status.as_deref().unwrap_or("none")
                            );
                            safe_println!(
                                "Created:         {}",
                                detail.info.created_at.as_deref().unwrap_or("N/A")
                            );
                            safe_println!(
                                "Started:         {}",
                                detail.info.started_at.as_deref().unwrap_or("N/A")
                            );
                            safe_println!(
                                "Working Dir:     {}",
                                detail.info.working_dir.as_deref().unwrap_or("N/A")
                            );
                            safe_println!(
                                "Runtime:         {}",
                                detail.info.runtime.as_deref().unwrap_or("runc")
                            );
                            safe_println!(
                                "Network Mode:    {}",
                                detail.info.network_mode.as_deref().unwrap_or("bridge")
                            );
                            safe_println!(
                                "IP Addresses:    {}",
                                if detail.info.ip_addresses.is_empty() {
                                    "-".to_string()
                                } else {
                                    detail.info.ip_addresses.join(", ")
                                }
                            );
                            safe_println!("Published Ports: {}", detail.info.formatted_ports());
                            safe_println!("Restart Policy:  {}", detail.restart_policy);
                            safe_println!(
                                "Platform:        {}",
                                detail.platform.as_deref().unwrap_or("N/A")
                            );

                            safe_println!("\nSession Attribution:");
                            safe_println!(
                                "  Session ID:    {}",
                                detail.info.session_id.as_deref().unwrap_or("None")
                            );
                            if let Some(ref decl) = detail.info.declared_session_id {
                                safe_println!("  Declared ID:   {} (Metadata label)", decl);
                            }
                            if !detail.info.conflicting_sessions.is_empty() {
                                safe_println!(
                                    "  Conflicts:     {}",
                                    detail.info.conflicting_sessions.join(", ")
                                );
                            }
                            safe_println!("  Confidence:    {}", detail.info.confidence);
                            if detail.info.evidence.is_empty() {
                                safe_println!("  Evidence:      None");
                            } else {
                                for ev in &detail.info.evidence {
                                    safe_println!("  • {}", ev);
                                }
                            }

                            safe_println!("\nExecution (Secret Masked):");
                            safe_println!(
                                "  Command:       {}",
                                detail.info.command.as_deref().unwrap_or("-")
                            );
                            safe_println!(
                                "  Entrypoint:    {}",
                                detail.info.entrypoint.as_deref().unwrap_or("-")
                            );

                            safe_println!(
                                "\nEnvironment Variables (Names Only, Values Suppressed):"
                            );
                            if detail.env_keys.is_empty() {
                                safe_println!("  (No environment variables recorded)");
                            } else {
                                for k in &detail.env_keys {
                                    safe_println!("  • {}", k);
                                }
                            }

                            safe_println!("\nStorage Mounts:");
                            if detail.mounts.is_empty() {
                                safe_println!("  (No mounts attached)");
                            } else {
                                for m in &detail.mounts {
                                    safe_println!(
                                        "  • {} -> {} [type={}, read_only={}]",
                                        m.source,
                                        m.destination,
                                        m.mount_type,
                                        m.read_only
                                    );
                                }
                            }

                            safe_println!("{:-<80}", "");
                            safe_println!("Read-only guarantee: TIMMY never terminates or modifies containers.");
                        }
                    }
                    Err(timmy::platform::PlatformError::DockerNotRunning(msg)) => {
                        if json {
                            safe_println!("null");
                        } else {
                            safe_println!("Docker daemon is not running ({}).", msg);
                            safe_println!("Run `timmy docker status` for connection diagnostics.");
                        }
                    }
                    Err(timmy::platform::PlatformError::ContainerNotFound(id)) => {
                        eprintln!("Container not found: '{}'", id);
                        std::process::exit(1);
                    }
                    Err(e) => {
                        eprintln!("Error inspecting container '{}': {}", container_id, e);
                        std::process::exit(1);
                    }
                }
            }
            DockerCommands::Stats { json } => match orchestrator.list_containers(None) {
                Ok(containers) => {
                    let running_containers: Vec<_> = containers
                        .into_iter()
                        .filter(|c| c.state == timmy::model::ContainerState::Running)
                        .collect();

                    let mut stats_list = Vec::new();
                    for c in &running_containers {
                        if let Ok(s) = orchestrator.collect_container_stats(&c.id) {
                            stats_list.push((c.clone(), s));
                        }
                    }

                    if json {
                        let json_stats: Vec<_> = stats_list
                            .iter()
                            .map(|(c, s)| {
                                serde_json::json!({
                                    "id": c.id,
                                    "short_id": c.short_id,
                                    "name": c.name,
                                    "stats": s,
                                })
                            })
                            .collect();
                        safe_println!("{}", serde_json::to_string_pretty(&json_stats)?);
                    } else {
                        safe_println!("TIMMY: Docker Live Resource Usage");
                        safe_println!("{:-<110}", "");
                        safe_println!(
                            "{:<14} {:<20} {:<8} {:<24} {:<8} {:<18} {:<6}",
                            "ID",
                            "NAME",
                            "CPU %",
                            "MEM USAGE / LIMIT",
                            "MEM %",
                            "NET I/O",
                            "PIDS"
                        );
                        safe_println!("{:-<110}", "");

                        if stats_list.is_empty() {
                            safe_println!(
                                "No running containers with active statistics available."
                            );
                        } else {
                            for (c, s) in &stats_list {
                                let cpu_str = s
                                    .cpu_percentage
                                    .map(|p| format!("{:.1}%", p))
                                    .unwrap_or_else(|| "N/A".to_string());
                                let mem_usage_str = s
                                    .memory_usage_bytes
                                    .map(format_bytes)
                                    .unwrap_or_else(|| "N/A".to_string());
                                let mem_limit_str = s
                                    .memory_limit_bytes
                                    .map(format_bytes)
                                    .unwrap_or_else(|| "N/A".to_string());
                                let mem_combo = format!("{} / {}", mem_usage_str, mem_limit_str);
                                let mem_pct_str = s
                                    .memory_percentage
                                    .map(|p| format!("{:.1}%", p))
                                    .unwrap_or_else(|| "N/A".to_string());
                                let net_rx_str = s
                                    .network_rx_bytes
                                    .map(format_bytes)
                                    .unwrap_or_else(|| "0 B".to_string());
                                let net_tx_str = s
                                    .network_tx_bytes
                                    .map(format_bytes)
                                    .unwrap_or_else(|| "0 B".to_string());
                                let net_combo = format!("{} / {}", net_rx_str, net_tx_str);
                                let pids_str = s
                                    .pids_count
                                    .map(|p| p.to_string())
                                    .unwrap_or_else(|| "N/A".to_string());

                                safe_println!(
                                    "{:<14} {:<20} {:<8} {:<24} {:<8} {:<18} {:<6}",
                                    c.short_id,
                                    truncate_str(&c.name, 18),
                                    cpu_str,
                                    mem_combo,
                                    mem_pct_str,
                                    net_combo,
                                    pids_str
                                );
                            }
                        }
                        safe_println!("{:-<110}", "");
                        safe_println!("Active Containers: {}", stats_list.len());
                    }
                }
                Err(timmy::platform::PlatformError::DockerNotRunning(msg)) => {
                    if json {
                        safe_println!("[]");
                    } else {
                        safe_println!("Docker daemon is not running ({}).", msg);
                        safe_println!("Run `timmy docker status` for connection diagnostics.");
                    }
                }
                Err(e) => {
                    eprintln!("Error collecting Docker stats: {}", e);
                    std::process::exit(1);
                }
            },
        },
        Commands::Services { domain, json } => {
            let snap = orchestrator.refresh_snapshot()?;
            let mut services = snap.services;
            if let Some(dom_filter) = domain {
                let lower = dom_filter.to_lowercase();
                services.retain(|s| s.formatted_domain().to_lowercase().contains(&lower));
            }

            if json {
                let serialized = serde_json::to_string_pretty(&services)?;
                safe_println!("{}", serialized);
            } else {
                safe_println!("TIMMY: macOS LaunchAgent and LaunchDaemon Discovery");
                safe_println!("{:-<120}", "");
                safe_println!(
                    "{:<25} {:<18} {:<16} {:<8} {:<24} {:<14} {:<12}",
                    "SERVICE NAME",
                    "DOMAIN",
                    "STATE",
                    "PID",
                    "PROGRAM / EXECUTABLE",
                    "SESSION",
                    "CONFIDENCE"
                );
                safe_println!("{:-<120}", "");

                for s in &services {
                    let exe = s.executable_or_program().unwrap_or("-");
                    safe_println!(
                        "{:<25} {:<18} {:<16} {:<8} {:<24} {:<14} {:<12}",
                        truncate_str(&s.name, 23),
                        truncate_str(&s.formatted_domain(), 16),
                        truncate_str(&s.formatted_state(), 15),
                        s.pid
                            .map(|p| p.to_string())
                            .unwrap_or_else(|| "-".to_string()),
                        truncate_str(exe, 22),
                        truncate_str(&s.formatted_session(), 12),
                        s.confidence.to_string()
                    );
                }
                safe_println!("{:-<120}", "");
                safe_println!("Total Services Discovered: {}", services.len());
            }
        }
    }

    Ok(())
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len - 3])
    } else {
        s.to_string()
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}
