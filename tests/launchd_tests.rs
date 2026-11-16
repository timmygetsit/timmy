use std::path::PathBuf;
use timmy::engine::services::ServiceDiscoveryCoordinator;
use timmy::model::agent::{AgentAttribution, AgentKind, Confidence};
use timmy::model::process::ProcessInfo;
use timmy::model::provenance::{LaunchProvenance, ProvenanceSource};
use timmy::model::service::{
    KeepAliveDetail, LaunchdDomain, LaunchdPlistDetail, PlistStatus, RuntimeStatus, ServiceInfo,
    ServiceKind, ServiceState, ServiceStatus,
};
use timmy::model::session::{SessionInfo, SessionStatus};
use timmy::platform::macos::launchd::{parse_plist_content, reconcile_services, RuntimeJobEntry};
use timmy::platform::portable::PortableCollector;
use timmy::platform::traits::ServiceCollector;

// =============================================================================
// 1. Valid User LaunchAgent Plist
// =============================================================================
#[test]
fn test_valid_user_launchagent_plist() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.anthropic.claudecode</string>
    <key>Program</key>
    <string>/usr/local/bin/claude</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/claude</string>
        <string>daemon</string>
        <string>--port</string>
        <string>8080</string>
    </array>
    <key>WorkingDirectory</key>
    <string>/Users/testuser/projects/agent</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StartInterval</key>
    <integer>300</integer>
    <key>Sockets</key>
    <dict>
        <key>Listeners</key>
        <dict>
            <key>SockServiceName</key>
            <string>8080</string>
        </dict>
    </dict>
    <key>MachServices</key>
    <dict>
        <key>com.anthropic.claudecode.mach</key>
        <true/>
    </dict>
    <key>StandardOutPath</key>
    <string>/tmp/claude.out</string>
    <key>StandardErrorPath</key>
    <string>/tmp/claude.err</string>
</dict>
</plist>"#;

    let path = PathBuf::from("/Users/testuser/Library/LaunchAgents/com.anthropic.claudecode.plist");
    let detail = parse_plist_content(xml.as_bytes(), path.clone());

    assert_eq!(detail.label.as_deref(), Some("com.anthropic.claudecode"));
    assert_eq!(detail.program.as_deref(), Some("/usr/local/bin/claude"));
    assert_eq!(
        detail.executable_path.as_deref(),
        Some("/usr/local/bin/claude")
    );
    assert_eq!(
        detail.program_arguments,
        vec!["/usr/local/bin/claude", "daemon", "--port", "8080"]
    );
    assert_eq!(
        detail.working_directory.as_deref(),
        Some("/Users/testuser/projects/agent")
    );
    assert_eq!(detail.run_at_load, Some(true));
    assert_eq!(detail.keep_alive, Some(KeepAliveDetail::Simple(true)));
    assert_eq!(detail.start_interval, Some(300));
    assert_eq!(detail.sockets, vec!["Listeners"]);
    assert_eq!(detail.mach_services, vec!["com.anthropic.claudecode.mach"]);
    assert_eq!(detail.standard_out_path.as_deref(), Some("/tmp/claude.out"));
    assert_eq!(
        detail.standard_error_path.as_deref(),
        Some("/tmp/claude.err")
    );
    assert!(detail.parse_error.is_none());
}

// =============================================================================
// 2. Valid Third-Party LaunchDaemon Plist
// =============================================================================
#[test]
fn test_valid_third_party_launchdaemon_plist() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.custom.helperdaemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Library/PrivilegedHelperTools/com.custom.helperdaemon</string>
        <string>--worker</string>
    </array>
    <key>UserName</key>
    <string>root</string>
    <key>GroupName</key>
    <string>wheel</string>
    <key>RunAtLoad</key>
    <false/>
</dict>
</plist>"#;

    let path = PathBuf::from("/Library/LaunchDaemons/com.custom.helperdaemon.plist");
    let detail = parse_plist_content(xml.as_bytes(), path);

    assert_eq!(detail.label.as_deref(), Some("com.custom.helperdaemon"));
    assert_eq!(
        detail.executable_path.as_deref(),
        Some("/Library/PrivilegedHelperTools/com.custom.helperdaemon")
    );
    assert_eq!(detail.user_name.as_deref(), Some("root"));
    assert_eq!(detail.group_name.as_deref(), Some("wheel"));
    assert_eq!(detail.run_at_load, Some(false));
    assert!(detail.parse_error.is_none());
}

// =============================================================================
// 3. Apple System Plist
// =============================================================================
#[test]
fn test_apple_system_plist() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.sysmond</string>
    <key>Program</key>
    <string>/usr/libexec/sysmond</string>
    <key>MachServices</key>
    <dict>
        <key>com.apple.sysmond</key>
        <true/>
    </dict>
</dict>
</plist>"#;

    let path = PathBuf::from("/System/Library/LaunchDaemons/com.apple.sysmond.plist");
    let detail = parse_plist_content(xml.as_bytes(), path);

    assert_eq!(detail.label.as_deref(), Some("com.apple.sysmond"));
    assert_eq!(detail.program.as_deref(), Some("/usr/libexec/sysmond"));
    assert!(detail
        .mach_services
        .contains(&"com.apple.sysmond".to_string()));

    let plists = vec![(
        detail,
        LaunchdDomain::SystemApple,
        ServiceKind::LaunchDaemonApple,
    )];
    let services = reconcile_services(plists, Vec::new());

    assert_eq!(services.len(), 1);
    assert_eq!(services[0].kind, ServiceKind::LaunchDaemonApple);
    assert_eq!(services[0].domain, Some(LaunchdDomain::SystemApple));
}

// =============================================================================
// 4. Malformed Plist (Handled safely without crash/panic)
// =============================================================================
#[test]
fn test_malformed_plist() {
    let malformed_xml = b"<plist><dict><key>Label</key><string>broken.plist";
    let path = PathBuf::from("/Users/test/Library/LaunchAgents/broken.plist");
    let detail = parse_plist_content(malformed_xml, path);

    assert_eq!(detail.label.as_deref(), Some("broken"));
    assert!(detail.parse_error.is_some());

    let plists = vec![(detail, LaunchdDomain::User, ServiceKind::LaunchAgentUser)];
    let services = reconcile_services(plists, Vec::new());

    assert_eq!(services.len(), 1);
    match &services[0].state {
        ServiceState::Error(err) => assert!(err.contains("Failed to parse plist")),
        other => panic!("Expected ServiceState::Error, got {:?}", other),
    }
    match &services[0].status {
        ServiceStatus::Failed(err) => assert!(err.contains("Failed to parse plist")),
        other => panic!("Expected ServiceStatus::Failed, got {:?}", other),
    }
}

// =============================================================================
// 5. Missing Optional Keys
// =============================================================================
#[test]
fn test_missing_optional_keys() {
    let minimal_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>minimal.service</string>
</dict>
</plist>"#;

    let path = PathBuf::from("/Users/test/Library/LaunchAgents/minimal.service.plist");
    let detail = parse_plist_content(minimal_xml.as_bytes(), path);

    assert_eq!(detail.label.as_deref(), Some("minimal.service"));
    assert!(detail.program.is_none());
    assert!(detail.program_arguments.is_empty());
    assert!(detail.executable_path.is_none());
    assert!(detail.working_directory.is_none());
    assert!(detail.run_at_load.is_none());
    assert!(detail.keep_alive.is_none());
    assert!(detail.start_interval.is_none());
    assert!(detail.sockets.is_empty());
    assert!(detail.mach_services.is_empty());
    assert!(detail.parse_error.is_none());
}

// =============================================================================
// 6. Multiple Program Arguments
// =============================================================================
#[test]
fn test_multiple_program_arguments() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>python.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/env</string>
        <string>python3</string>
        <string>-m</string>
        <string>my_agent</string>
        <string>--workers</string>
        <string>4</string>
        <string>--verbose</string>
    </array>
</dict>
</plist>"#;

    let path = PathBuf::from("/Users/test/Library/LaunchAgents/python.agent.plist");
    let detail = parse_plist_content(xml.as_bytes(), path);

    assert_eq!(detail.program_arguments.len(), 7);
    assert_eq!(
        detail.program_arguments,
        vec![
            "/usr/bin/env",
            "python3",
            "-m",
            "my_agent",
            "--workers",
            "4",
            "--verbose"
        ]
    );
    assert_eq!(detail.executable_path.as_deref(), Some("/usr/bin/env"));
}

// =============================================================================
// 7. KeepAlive as Both Boolean and Dictionary
// =============================================================================
#[test]
fn test_keep_alive_boolean_and_dictionary() {
    // 7a. Boolean KeepAlive
    let bool_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>bool.keepalive</string>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>"#;

    let detail_bool =
        parse_plist_content(bool_xml.as_bytes(), PathBuf::from("/Users/test/bool.plist"));
    assert_eq!(detail_bool.keep_alive, Some(KeepAliveDetail::Simple(true)));

    // 7b. Dictionary KeepAlive with conditional exit & network constraints
    let dict_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>dict.keepalive</string>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
        <key>NetworkState</key>
        <true/>
    </dict>
</dict>
</plist>"#;

    let detail_dict =
        parse_plist_content(dict_xml.as_bytes(), PathBuf::from("/Users/test/dict.plist"));
    match detail_dict.keep_alive {
        Some(KeepAliveDetail::Conditional(ref cond)) => {
            assert!(cond.contains("SuccessfulExit=false"));
            assert!(cond.contains("NetworkState=true"));
        }
        other => panic!("Expected KeepAliveDetail::Conditional, got {:?}", other),
    }
}

// =============================================================================
// 8. RunAtLoad Handling
// =============================================================================
#[test]
fn test_run_at_load_parsing() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>runatload.test</string>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>"#;

    let detail = parse_plist_content(xml.as_bytes(), PathBuf::from("/Users/test/run.plist"));
    assert_eq!(detail.run_at_load, Some(true));
}

// =============================================================================
// 9. Environment Variables: Names Only, NEVER Values
// =============================================================================
#[test]
fn test_environment_variables_names_without_values() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>env.test</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>ANTHROPIC_API_KEY</key>
        <string>sk-ant-api03-super-secret-key-123456789</string>
        <key>DATABASE_URL</key>
        <string>postgres://admin:superpassword@localhost:5432/db</string>
        <key>AGENT_PORT</key>
        <string>9000</string>
    </dict>
</dict>
</plist>"#;

    let detail = parse_plist_content(xml.as_bytes(), PathBuf::from("/Users/test/env.plist"));

    // Verify variable names are present and sorted
    assert_eq!(
        detail.environment_variable_names,
        vec!["AGENT_PORT", "ANTHROPIC_API_KEY", "DATABASE_URL"]
    );

    // Verify secret values are nowhere in the struct
    let debug_repr = format!("{:?}", detail);
    assert!(!debug_repr.contains("sk-ant-api03-super-secret-key-123456789"));
    assert!(!debug_repr.contains("superpassword"));
}

// =============================================================================
// 10. Secret Masking in Program Arguments
// =============================================================================
#[test]
fn test_secret_masking_in_program_arguments() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>secret.arg.test</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/agent</string>
        <string>--token</string>
        <string>secret-token-abcdef123456</string>
        <string>--api-key=sk-ant-secret987654</string>
        <string>postgres://alice:secretpass@db.local:5432/main</string>
    </array>
</dict>
</plist>"#;

    let detail = parse_plist_content(xml.as_bytes(), PathBuf::from("/Users/test/secret.plist"));

    assert_eq!(detail.program_arguments[0], "/usr/local/bin/agent");
    assert_eq!(detail.program_arguments[1], "--token");
    assert!(detail.program_arguments[2].contains("[REDACTED]"));
    assert!(detail.program_arguments[3].contains("[REDACTED]"));
    assert!(detail.program_arguments[4].contains("[REDACTED]"));
    assert!(!detail.program_arguments[2].contains("abcdef123456"));
    assert!(!detail.program_arguments[3].contains("secret987654"));
    assert!(!detail.program_arguments[4].contains("secretpass"));
}

// =============================================================================
// 11. Loaded but Not Running
// =============================================================================
#[test]
fn test_reconciliation_loaded_but_not_running() {
    let detail = LaunchdPlistDetail {
        source_path: PathBuf::from("/Users/test/Library/LaunchAgents/com.test.idle.plist"),
        label: Some("com.test.idle".to_string()),
        program: Some("/usr/bin/true".to_string()),
        program_arguments: vec!["/usr/bin/true".to_string()],
        executable_path: Some("/usr/bin/true".to_string()),
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
        parse_error: None,
    };

    let plists = vec![(detail, LaunchdDomain::User, ServiceKind::LaunchAgentUser)];
    let runtime = vec![RuntimeJobEntry {
        label: "com.test.idle".to_string(),
        pid: None,
        last_exit_status: Some(0),
        domain: LaunchdDomain::User,
        process_state: None,
    }];

    let services = reconcile_services(plists, runtime);
    assert_eq!(services.len(), 1);
    assert_eq!(services[0].state, ServiceState::Loaded);
    assert_eq!(services[0].status, ServiceStatus::Loaded);
    assert_eq!(services[0].pid, None);
    assert_eq!(services[0].last_exit_status, Some(0));
    assert!(services[0].runtime.as_ref().unwrap().is_loaded);
}

// =============================================================================
// 12. Running with PID
// =============================================================================
#[test]
fn test_reconciliation_running_with_pid() {
    let detail = LaunchdPlistDetail {
        source_path: PathBuf::from("/Users/test/Library/LaunchAgents/com.test.running.plist"),
        label: Some("com.test.running".to_string()),
        program: Some("/usr/bin/agent".to_string()),
        program_arguments: vec!["/usr/bin/agent".to_string()],
        executable_path: Some("/usr/bin/agent".to_string()),
        working_directory: None,
        run_at_load: Some(true),
        keep_alive: Some(KeepAliveDetail::Simple(true)),
        start_interval: None,
        start_calendar_interval: None,
        sockets: Vec::new(),
        mach_services: Vec::new(),
        standard_out_path: None,
        standard_error_path: None,
        environment_variable_names: Vec::new(),
        user_name: None,
        group_name: None,
        parse_error: None,
    };

    let plists = vec![(detail, LaunchdDomain::User, ServiceKind::LaunchAgentUser)];
    let runtime = vec![RuntimeJobEntry {
        label: "com.test.running".to_string(),
        pid: Some(9999),
        last_exit_status: Some(0),
        domain: LaunchdDomain::User,
        process_state: None,
    }];

    let services = reconcile_services(plists, runtime);
    assert_eq!(services.len(), 1);
    assert_eq!(services[0].state, ServiceState::Running);
    assert_eq!(services[0].status, ServiceStatus::Running);
    assert_eq!(services[0].pid, Some(9999));
}

// =============================================================================
// 13. Non-Zero Last Exit Status
// =============================================================================
#[test]
fn test_reconciliation_non_zero_last_exit_status() {
    let detail = LaunchdPlistDetail {
        source_path: PathBuf::from("/Library/LaunchDaemons/com.test.failing.plist"),
        label: Some("com.test.failing".to_string()),
        program: Some("/usr/bin/fail".to_string()),
        program_arguments: vec!["/usr/bin/fail".to_string()],
        executable_path: Some("/usr/bin/fail".to_string()),
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
        parse_error: None,
    };

    let plists = vec![(
        detail,
        LaunchdDomain::SystemThirdParty,
        ServiceKind::LaunchDaemonSystem,
    )];
    let runtime = vec![RuntimeJobEntry {
        label: "com.test.failing".to_string(),
        pid: None,
        last_exit_status: Some(78),
        domain: LaunchdDomain::SystemThirdParty,
        process_state: None,
    }];

    let services = reconcile_services(plists, runtime);
    assert_eq!(services.len(), 1);
    assert_eq!(services[0].state, ServiceState::NotRunning);
    assert_eq!(services[0].last_exit_status, Some(78));
}

// =============================================================================
// 14. Missing or Inaccessible Plist (Runtime job loaded without plist on disk)
// =============================================================================
#[test]
fn test_missing_or_inaccessible_plist() {
    let plists = Vec::new();
    let runtime = vec![RuntimeJobEntry {
        label: "com.apple.xpc.anonymous".to_string(),
        pid: Some(4012),
        last_exit_status: None,
        domain: LaunchdDomain::SystemApple,
        process_state: None,
    }];

    let services = reconcile_services(plists, runtime);
    assert_eq!(services.len(), 1);
    assert_eq!(services[0].label, "com.apple.xpc.anonymous");
    assert_eq!(services[0].pid, Some(4012));
    assert_eq!(services[0].state, ServiceState::Running);
    assert_eq!(services[0].path, None);
    assert!(services[0].plist.is_none());
}

// =============================================================================
// 15. Duplicate Labels Across Domains
// =============================================================================
#[test]
fn test_duplicate_labels_across_domains() {
    let user_detail = LaunchdPlistDetail {
        source_path: PathBuf::from("/Users/test/Library/LaunchAgents/com.shared.agent.plist"),
        label: Some("com.shared.agent".to_string()),
        program: Some("/usr/bin/user_agent".to_string()),
        program_arguments: vec!["/usr/bin/user_agent".to_string()],
        executable_path: Some("/usr/bin/user_agent".to_string()),
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
        parse_error: None,
    };

    let system_detail = LaunchdPlistDetail {
        source_path: PathBuf::from("/Library/LaunchDaemons/com.shared.agent.plist"),
        label: Some("com.shared.agent".to_string()),
        program: Some("/usr/bin/system_daemon".to_string()),
        program_arguments: vec!["/usr/bin/system_daemon".to_string()],
        executable_path: Some("/usr/bin/system_daemon".to_string()),
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
        parse_error: None,
    };

    let plists = vec![
        (
            user_detail,
            LaunchdDomain::User,
            ServiceKind::LaunchAgentUser,
        ),
        (
            system_detail,
            LaunchdDomain::SystemThirdParty,
            ServiceKind::LaunchDaemonSystem,
        ),
    ];

    let services = reconcile_services(plists, Vec::new());
    // Both must be preserved without collision
    assert_eq!(services.len(), 2);
    let user_svc = services
        .iter()
        .find(|s| s.domain == Some(LaunchdDomain::User))
        .expect("User service missing");
    let sys_svc = services
        .iter()
        .find(|s| s.domain == Some(LaunchdDomain::SystemThirdParty))
        .expect("System service missing");

    assert_eq!(user_svc.label, "com.shared.agent");
    assert_eq!(sys_svc.label, "com.shared.agent");
    assert_eq!(
        user_svc.executable_or_program(),
        Some("/usr/bin/user_agent")
    );
    assert_eq!(
        sys_svc.executable_or_program(),
        Some("/usr/bin/system_daemon")
    );
}

// =============================================================================
// 16. Process Correlation (Exact PID & Executable Match)
// =============================================================================
#[test]
fn test_process_correlation() {
    let now = chrono::Utc::now();
    let now_secs = now.timestamp().max(0) as u64;

    let mut services = vec![ServiceInfo {
        name: "claudecode".to_string(),
        kind: ServiceKind::LaunchAgentUser,
        status: ServiceStatus::Running,
        state: ServiceState::Running,
        plist_status: PlistStatus::Valid {
            path: PathBuf::from("/Users/test/Library/LaunchAgents/com.anthropic.claudecode.plist"),
        },
        runtime_status: RuntimeStatus::Running { pid: 4500 },
        pid: Some(4500),
        label: "com.anthropic.claudecode".to_string(),
        path: Some("/Users/test/Library/LaunchAgents/com.anthropic.claudecode.plist".to_string()),
        domain: Some(LaunchdDomain::User),
        last_exit_status: Some(0),
        runtime: None,
        plist: Some(LaunchdPlistDetail {
            source_path: PathBuf::from(
                "/Users/test/Library/LaunchAgents/com.anthropic.claudecode.plist",
            ),
            label: Some("com.anthropic.claudecode".to_string()),
            program: Some("/usr/local/bin/claude".to_string()),
            program_arguments: vec!["/usr/local/bin/claude".to_string(), "daemon".to_string()],
            executable_path: Some("/usr/local/bin/claude".to_string()),
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
            parse_error: None,
        }),
        session_id: None,
        confidence: Confidence::Unknown,
        evidence: Vec::new(),
        is_partial: false,
    }];

    let processes = vec![ProcessInfo {
        pid: 4500,
        ppid: Some(1),
        name: "claude".to_string(),
        exe: Some(PathBuf::from("/usr/local/bin/claude")),
        cpu_usage: Some(1.5),
        memory_bytes: Some(50 * 1024 * 1024),
        run_time_secs: 100,
        start_time: Some(now_secs),
        user: Some("testuser".to_string()),
        attribution: AgentAttribution {
            kind: AgentKind::ClaudeCode,
            confidence: Confidence::Confirmed,
            reason: "Direct binary match".to_string(),
            evidence: "Binary: claude".to_string(),
            parent_pid: Some(1),
            parent_name: None,
            root_agent_pid: Some(4500),
            root_agent_name: Some("claude".to_string()),
            is_confirmed: true,
            safe_to_terminate: false,
        },
        listening_ports: vec![8080],
        cmdline: vec!["/usr/local/bin/claude".to_string(), "daemon".to_string()],
        command_outcome: None,
        provenance: None,
        ..Default::default()
    }];

    let sessions = vec![SessionInfo {
        id: "sess-claude-01".to_string(),
        agent_kind: AgentKind::ClaudeCode,
        status: SessionStatus::Active,
        start_time: now,
        end_time: None,
        root_pid: Some(4500),
        root_process_name: Some("claude".to_string()),
        confidence: Confidence::Confirmed,
        evidence: vec!["Created session".to_string()],
        tracked_pids: vec![4500],
        total_memory_bytes: 50 * 1024 * 1024,
        total_cpu_usage: 1.5,
        open_ports: vec![8080],
        resource_count: 1,
        root_binding: Some(LaunchProvenance::root_binding(
            "sess-claude-01".to_string(),
            4500,
            Some(now_secs),
            "claude".to_string(),
            Some(PathBuf::from("/usr/local/bin/claude")),
            Some(1),
            "Verified root binding".to_string(),
        )),
    }];

    ServiceDiscoveryCoordinator::correlate_services(&mut services, &processes, &sessions);

    assert_eq!(services[0].session_id.as_deref(), Some("sess-claude-01"));
    assert_eq!(services[0].confidence, Confidence::Confirmed);
    assert!(services[0]
        .evidence
        .iter()
        .any(|e| e.contains("Process identity verified")));
    assert!(services[0]
        .evidence
        .iter()
        .any(|e| e.contains("Supporting evidence: executable path match")));
    assert!(services[0]
        .evidence
        .iter()
        .any(|e| e.contains("Session correlation")));
}

// =============================================================================
// 17. Conflicting Session Attribution
// =============================================================================
#[test]
fn test_conflicting_session_attribution() {
    let mut services = vec![ServiceInfo {
        name: "shared-daemon".to_string(),
        kind: ServiceKind::LaunchAgentUser,
        status: ServiceStatus::Running,
        state: ServiceState::Running,
        plist_status: PlistStatus::NotDiscovered,
        runtime_status: RuntimeStatus::Running { pid: 7777 },
        pid: Some(7777),
        label: "com.shared.daemon".to_string(),
        path: None,
        domain: Some(LaunchdDomain::User),
        last_exit_status: Some(0),
        runtime: None,
        plist: None,
        session_id: None,
        confidence: Confidence::Unknown,
        evidence: Vec::new(),
        is_partial: false,
    }];

    let processes = vec![ProcessInfo {
        pid: 7777,
        ppid: Some(1),
        name: "shared".to_string(),
        exe: None,
        cpu_usage: None,
        memory_bytes: None,
        run_time_secs: 50,
        start_time: None,
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: Vec::new(),
        cmdline: Vec::new(),
        command_outcome: None,
        provenance: None,
        ..Default::default()
    }];

    let sessions = vec![
        SessionInfo {
            id: "sess-alpha".to_string(),
            agent_kind: AgentKind::ClaudeCode,
            status: SessionStatus::Active,
            start_time: chrono::Utc::now(),
            end_time: None,
            root_pid: Some(7777),
            root_process_name: Some("shared".to_string()),
            confidence: Confidence::HighConfidence,
            evidence: Vec::new(),
            tracked_pids: vec![7777],
            total_memory_bytes: 0,
            total_cpu_usage: 0.0,
            open_ports: Vec::new(),
            resource_count: 1,
            root_binding: None,
        },
        SessionInfo {
            id: "sess-beta".to_string(),
            agent_kind: AgentKind::Cursor,
            status: SessionStatus::Active,
            start_time: chrono::Utc::now(),
            end_time: None,
            root_pid: Some(7777),
            root_process_name: Some("shared".to_string()),
            confidence: Confidence::HighConfidence,
            evidence: Vec::new(),
            tracked_pids: vec![7777],
            total_memory_bytes: 0,
            total_cpu_usage: 0.0,
            open_ports: Vec::new(),
            resource_count: 1,
            root_binding: None,
        },
    ];

    ServiceDiscoveryCoordinator::correlate_services(&mut services, &processes, &sessions);

    // With conflicting claims, session_id is None, confidence remains Unknown, and conflict logged in evidence
    assert_eq!(services[0].session_id, None);
    assert_eq!(services[0].confidence, Confidence::Unknown);
    assert!(services[0]
        .evidence
        .iter()
        .any(|e| e.contains("Conflicting attribution")));
}

// =============================================================================
// 18. Non-macOS Unsupported Behaviour
// =============================================================================
#[test]
fn test_non_macos_unsupported_behaviour() {
    let collector = PortableCollector::new();
    let res = collector.collect_services();
    assert!(res.is_ok());
    let list = res.unwrap();
    // PortableCollector must cleanly return empty list without executing macOS launchctl
    assert!(list.is_empty());
}

// =============================================================================
// 19. macOS Live Integration: Strictly Read-Only Discovery
// =============================================================================
#[cfg(target_os = "macos")]
#[test]
fn test_macos_live_read_only_discovery() {
    use std::path::Path;
    use std::time::Duration;
    use timmy::platform::macos::launchd::{
        discover_launchd_services, parse_launchctl_list_output,
        parse_launchctl_print_services_output, run_command_bounded, scan_directory_for_plists,
    };

    // 1. Live launchd discovery of all domains
    let res = discover_launchd_services();
    assert!(
        res.is_ok(),
        "Live launchd discovery must succeed: {:?}",
        res.err()
    );
    let services = res.unwrap();

    // On any standard macOS machine, there will be multiple launchd services
    assert!(
        !services.is_empty(),
        "Expected at least one macOS launchd service"
    );

    // 2. Verify domain discrimination across discovered inventory
    let has_user = services
        .iter()
        .any(|s| s.domain == Some(LaunchdDomain::User));
    let has_apple = services
        .iter()
        .any(|s| s.domain == Some(LaunchdDomain::SystemApple));
    assert!(
        has_user || has_apple,
        "Expected user or apple domain services"
    );

    // Verify read-only nature: no services had their state corrupted
    for s in &services {
        assert!(!s.name.is_empty());
        assert!(!s.label.is_empty());
    }

    // 3. Verify directory traversal on standard Apple domain directory
    let apple_dir = Path::new("/System/Library/LaunchDaemons");
    if apple_dir.is_dir() {
        let scanned = scan_directory_for_plists(
            apple_dir,
            &LaunchdDomain::SystemApple,
            &ServiceKind::LaunchDaemonApple,
        );
        assert!(
            !scanned.is_empty(),
            "Expected Apple system LaunchDaemons in /System/Library/LaunchDaemons"
        );
    }

    // 4. Verify live GUI domain query and runtime output parsing
    let uid = unsafe { libc::getuid() };
    let gui_target = format!("gui/{}", uid);
    let gui_res = run_command_bounded(
        "launchctl",
        &["print", &gui_target],
        Duration::from_millis(2000),
        2 * 1024 * 1024,
    );
    if let Ok(out) = gui_res {
        if out.status == Some(0) {
            let parsed_gui_jobs =
                parse_launchctl_print_services_output(&out.stdout, LaunchdDomain::User);
            assert!(
                !parsed_gui_jobs.is_empty(),
                "Expected at least one live service in gui domain"
            );
        }
    }

    // 5. Verify live launchctl list parsing
    let list_res = run_command_bounded(
        "launchctl",
        &["list"],
        Duration::from_millis(2000),
        2 * 1024 * 1024,
    );
    assert!(list_res.is_ok());
    let list_out = list_res.unwrap();
    assert_eq!(list_out.status, Some(0));
    let parsed_list_jobs = parse_launchctl_list_output(&list_out.stdout, LaunchdDomain::User);
    assert!(
        !parsed_list_jobs.is_empty(),
        "Expected at least one service from launchctl list"
    );

    // 6. Verify distinction between empty domain vs inspection failure without third-party dependencies:
    // Querying an invalid / nonexistent domain MUST return non-zero exit status, NOT be treated as empty.
    let fail_res = run_command_bounded(
        "launchctl",
        &["print", "domain_that_does_not_exist_99999"],
        Duration::from_millis(2000),
        64 * 1024,
    );
    assert!(fail_res.is_ok());
    let fail_out = fail_res.unwrap();
    assert_ne!(
        fail_out.status,
        Some(0),
        "Invalid launchctl domain query should return non-zero status"
    );
    assert!(
        !fail_out.stderr.is_empty() || !fail_out.stdout.is_empty(),
        "Invalid domain should produce error diagnostic output"
    );
}

// =============================================================================
// 20. Bounded Subprocess Timeout & Output Limits
// =============================================================================
#[test]
fn test_bounded_subprocess_timeout() {
    use std::time::{Duration, Instant};
    use timmy::platform::macos::launchd::run_command_bounded;

    let start = Instant::now();
    // sleep for 5 seconds with a 150ms timeout
    let res = run_command_bounded("sleep", &["5"], Duration::from_millis(150), 1024);
    assert!(
        res.is_ok(),
        "run_command_bounded returned error: {:?}",
        res.err()
    );
    let out = res.unwrap();
    assert!(out.timed_out, "Command should have timed out");
    assert!(out.status.is_none(), "Status should be None on timeout");
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "Timeout did not abort promptly: took {:?}",
        start.elapsed()
    );
}

#[test]
fn test_bounded_subprocess_output_truncation() {
    use std::time::Duration;
    use timmy::platform::macos::launchd::run_command_bounded;

    // Output 20,000 bytes with limit of 1000 bytes
    let script = "for i in $(seq 1 2000); do echo '0123456789'; done";
    let res = run_command_bounded("sh", &["-c", script], Duration::from_millis(2000), 1000);
    assert!(res.is_ok());
    let out = res.unwrap();
    assert!(
        out.stdout.len() <= 1500,
        "Output length was not bounded: {}",
        out.stdout.len()
    );
    assert!(out.truncated, "Truncation flag should be set");
}

// =============================================================================
// 21. Realistic macOS launchctl Output with Nested Braces and (pe) Status
// =============================================================================
#[test]
fn test_realistic_launchctl_print_system_output_parsing() {
    use timmy::platform::macos::launchd::parse_launchctl_print_system_output;

    let realistic_output = r#"
system = {
	type = system
	handle = 0
	active count = 1086
	service count = 428
	services = {
		       0      - 	com.apple.backgroundassets.managed.relay.service
		    1857      - 	com.apple.lskdd
		       0   (pe) 	com.apple.kernelmanager_helper
		     427      0 	com.apple.runningboardd
		       0      1 	com.apple.wifiFirmwareLoader
		       0     78 	com.apple.custom.failed
		    3312      - 	"com.thirdparty.quoted daemon with spaces"
		       0      0 	com.apple.Kerberos.digest-service
	}

	task-special ports = {
			   0x903 4       bootstrap  com.apple.xpc.launchd.domain.system
			  0x3a0b 9          access  com.apple.taskgated
	}

	disabled services = {
		"com.malwarebytes.mbam.rtprotection.daemon" => enabled
		"postgresql-18" => enabled
	}
}
"#;

    let entries = parse_launchctl_print_system_output(realistic_output);
    assert_eq!(entries.len(), 8);

    let relay = entries
        .iter()
        .find(|e| e.label == "com.apple.backgroundassets.managed.relay.service")
        .unwrap();
    assert_eq!(relay.pid, None);
    assert_eq!(relay.last_exit_status, None);
    assert_eq!(relay.domain, LaunchdDomain::SystemApple);

    let lskdd = entries
        .iter()
        .find(|e| e.label == "com.apple.lskdd")
        .unwrap();
    assert_eq!(lskdd.pid, Some(1857));
    assert_eq!(lskdd.last_exit_status, None);

    let helper = entries
        .iter()
        .find(|e| e.label == "com.apple.kernelmanager_helper")
        .unwrap();
    assert_eq!(helper.pid, None);
    assert_eq!(helper.last_exit_status, None);
    assert_eq!(helper.process_state.as_deref(), Some("pending-environment"));

    let runningboardd = entries
        .iter()
        .find(|e| e.label == "com.apple.runningboardd")
        .unwrap();
    assert_eq!(runningboardd.pid, Some(427));
    assert_eq!(runningboardd.last_exit_status, Some(0));

    let wifi = entries
        .iter()
        .find(|e| e.label == "com.apple.wifiFirmwareLoader")
        .unwrap();
    assert_eq!(wifi.pid, None);
    assert_eq!(wifi.last_exit_status, Some(1));

    let failed = entries
        .iter()
        .find(|e| e.label == "com.apple.custom.failed")
        .unwrap();
    assert_eq!(failed.pid, None);
    assert_eq!(failed.last_exit_status, Some(78));

    let quoted = entries
        .iter()
        .find(|e| e.label == "com.thirdparty.quoted daemon with spaces")
        .unwrap();
    assert_eq!(quoted.pid, Some(3312));
    assert_eq!(quoted.domain, LaunchdDomain::SystemThirdParty);

    // Verify disabled services outside the block were NOT parsed as jobs
    assert!(entries.iter().all(|e| !e.label.contains("postgresql-18")));
    assert!(entries.iter().all(|e| !e.label.contains("malwarebytes")));
}

#[test]
fn test_truncated_launchctl_output() {
    use timmy::platform::macos::launchd::parse_launchctl_print_system_output;

    // Truncated before the block closes
    let truncated_output = r#"
system = {
	services = {
		       0      - 	com.apple.first
		    1234      0 	com.apple.second
"#;
    let entries = parse_launchctl_print_system_output(truncated_output);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].label, "com.apple.first");
    assert_eq!(entries[1].label, "com.apple.second");
    assert_eq!(entries[1].pid, Some(1234));
}

// =============================================================================
// 22. Verification of 8 Distinct Service State Reconciliation Conditions
// =============================================================================

#[test]
fn test_condition_1_plist_exists_job_not_loaded() {
    let detail = LaunchdPlistDetail {
        source_path: PathBuf::from("/Users/test/Library/LaunchAgents/com.test.c1.plist"),
        label: Some("com.test.c1".to_string()),
        program: Some("/bin/true".to_string()),
        program_arguments: vec!["/bin/true".to_string()],
        executable_path: Some("/bin/true".to_string()),
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
        parse_error: None,
    };
    let plists = vec![(detail, LaunchdDomain::User, ServiceKind::LaunchAgentUser)];
    let services = reconcile_services(plists, Vec::new());

    assert_eq!(services.len(), 1);
    assert_eq!(services[0].state, ServiceState::DiscoveredOnDisk);
    assert_eq!(
        services[0].plist_status,
        PlistStatus::Valid {
            path: PathBuf::from("/Users/test/Library/LaunchAgents/com.test.c1.plist")
        }
    );
    assert_eq!(services[0].runtime_status, RuntimeStatus::NotLoaded);
    assert_eq!(services[0].formatted_state(), "ON DISK");
}

#[test]
fn test_condition_2_job_loaded_process_not_running() {
    let detail = LaunchdPlistDetail {
        source_path: PathBuf::from("/Users/test/Library/LaunchAgents/com.test.c2.plist"),
        label: Some("com.test.c2".to_string()),
        program: Some("/bin/true".to_string()),
        program_arguments: vec!["/bin/true".to_string()],
        executable_path: Some("/bin/true".to_string()),
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
        parse_error: None,
    };
    let plists = vec![(detail, LaunchdDomain::User, ServiceKind::LaunchAgentUser)];
    let runtime = vec![RuntimeJobEntry {
        label: "com.test.c2".to_string(),
        pid: None,
        last_exit_status: Some(0),
        domain: LaunchdDomain::User,
        process_state: Some("loaded".to_string()),
    }];
    let services = reconcile_services(plists, runtime);

    assert_eq!(services.len(), 1);
    assert_eq!(services[0].state, ServiceState::Loaded);
    assert_eq!(services[0].runtime_status, RuntimeStatus::Loaded);
    assert_eq!(services[0].formatted_state(), "LOADED (Exit: 0)");
}

#[test]
fn test_condition_3_job_loaded_process_running_with_pid() {
    let detail = LaunchdPlistDetail {
        source_path: PathBuf::from("/Users/test/Library/LaunchAgents/com.test.c3.plist"),
        label: Some("com.test.c3".to_string()),
        program: Some("/usr/bin/daemon".to_string()),
        program_arguments: vec!["/usr/bin/daemon".to_string()],
        executable_path: Some("/usr/bin/daemon".to_string()),
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
        parse_error: None,
    };
    let plists = vec![(detail, LaunchdDomain::User, ServiceKind::LaunchAgentUser)];
    let runtime = vec![RuntimeJobEntry {
        label: "com.test.c3".to_string(),
        pid: Some(5432),
        last_exit_status: None,
        domain: LaunchdDomain::User,
        process_state: Some("running".to_string()),
    }];
    let services = reconcile_services(plists, runtime);

    assert_eq!(services.len(), 1);
    assert_eq!(services[0].state, ServiceState::Running);
    assert_eq!(
        services[0].runtime_status,
        RuntimeStatus::Running { pid: 5432 }
    );
    assert_eq!(services[0].formatted_state(), "RUNNING (5432)");
}

#[test]
fn test_condition_4_job_loaded_last_exit_status_non_zero() {
    let detail = LaunchdPlistDetail {
        source_path: PathBuf::from("/Users/test/Library/LaunchAgents/com.test.c4.plist"),
        label: Some("com.test.c4".to_string()),
        program: Some("/bin/fail".to_string()),
        program_arguments: vec!["/bin/fail".to_string()],
        executable_path: Some("/bin/fail".to_string()),
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
        parse_error: None,
    };
    let plists = vec![(detail, LaunchdDomain::User, ServiceKind::LaunchAgentUser)];
    let runtime = vec![RuntimeJobEntry {
        label: "com.test.c4".to_string(),
        pid: None,
        last_exit_status: Some(78),
        domain: LaunchdDomain::User,
        process_state: None,
    }];
    let services = reconcile_services(plists, runtime);

    assert_eq!(services.len(), 1);
    assert_eq!(services[0].state, ServiceState::NotRunning);
    assert_eq!(
        services[0].runtime_status,
        RuntimeStatus::Failed { exit_code: 78 }
    );
    assert_eq!(services[0].formatted_state(), "STOPPED (Exit: 78)");
}

#[test]
fn test_condition_5_job_visible_at_runtime_plist_unavailable() {
    let plists = Vec::new();
    let runtime = vec![RuntimeJobEntry {
        label: "com.apple.virtual.service".to_string(),
        pid: Some(9876),
        last_exit_status: None,
        domain: LaunchdDomain::SystemApple,
        process_state: Some("running".to_string()),
    }];
    let services = reconcile_services(plists, runtime);

    assert_eq!(services.len(), 1);
    assert_eq!(services[0].state, ServiceState::Running);
    assert_eq!(services[0].plist_status, PlistStatus::NotDiscovered);
    assert_eq!(
        services[0].runtime_status,
        RuntimeStatus::Running { pid: 9876 }
    );
    assert!(services[0].path.is_none());
}

#[test]
fn test_condition_6_plist_malformed_and_job_running_in_runtime() {
    // CRITICAL RECONCILIATION TEST:
    // Plist is malformed on disk, but the service is currently executing in runtime!
    // The plist error must NOT erase the runtime Running state,
    // and the runtime Running state must NOT erase the on-disk PlistError!
    let malformed_detail = LaunchdPlistDetail {
        source_path: PathBuf::from("/Users/test/Library/LaunchAgents/com.test.broken.plist"),
        label: Some("com.test.broken".to_string()),
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
        parse_error: Some("Failed to parse plist: XML syntax error at byte 42".to_string()),
    };

    let plists = vec![(
        malformed_detail,
        LaunchdDomain::User,
        ServiceKind::LaunchAgentUser,
    )];
    let runtime = vec![RuntimeJobEntry {
        label: "com.test.broken".to_string(),
        pid: Some(6543),
        last_exit_status: None,
        domain: LaunchdDomain::User,
        process_state: Some("running".to_string()),
    }];

    let services = reconcile_services(plists, runtime);
    assert_eq!(services.len(), 1);

    // Operational state is Running
    assert_eq!(services[0].state, ServiceState::Running);
    assert_eq!(services[0].pid, Some(6543));
    assert_eq!(
        services[0].runtime_status,
        RuntimeStatus::Running { pid: 6543 }
    );

    // Independent plist status preserves the malformed error!
    assert!(services[0].plist_status.is_error());
    match &services[0].plist_status {
        PlistStatus::Malformed { error, .. } => assert!(error.contains("XML syntax error")),
        other => panic!("Expected PlistStatus::Malformed, got {:?}", other),
    }

    // Formatted state indicates both Running and Plist Error!
    assert_eq!(
        services[0].formatted_state(),
        "RUNNING (6543) [Plist Error]"
    );
}

#[test]
fn test_condition_7_runtime_inspection_failed_preserves_plist() {
    let service = ServiceInfo {
        name: "agent".to_string(),
        kind: ServiceKind::LaunchAgentUser,
        status: ServiceStatus::Loaded,
        state: ServiceState::DiscoveredOnDisk,
        plist_status: PlistStatus::Valid {
            path: PathBuf::from("/Users/test/agent.plist"),
        },
        runtime_status: RuntimeStatus::InspectionFailed(
            "launchctl list timed out after 2000ms".to_string(),
        ),
        pid: None,
        label: "com.test.agent".to_string(),
        path: Some("/Users/test/agent.plist".to_string()),
        domain: Some(LaunchdDomain::User),
        last_exit_status: None,
        runtime: None,
        plist: None,
        session_id: None,
        confidence: Confidence::Unknown,
        evidence: Vec::new(),
        is_partial: false,
    };

    assert_eq!(service.state, ServiceState::DiscoveredOnDisk);
    assert!(matches!(
        service.runtime_status,
        RuntimeStatus::InspectionFailed(_)
    ));
    assert_eq!(service.formatted_state(), "ON DISK [Inspect Failed]");
}

#[test]
fn test_condition_8_service_state_genuinely_unknown() {
    let service = ServiceInfo {
        name: "unknown-job".to_string(),
        kind: ServiceKind::Other("Custom".to_string()),
        status: ServiceStatus::Unknown,
        state: ServiceState::Unknown,
        plist_status: PlistStatus::NotDiscovered,
        runtime_status: RuntimeStatus::Unknown,
        pid: None,
        label: "custom.unknown".to_string(),
        path: None,
        domain: None,
        last_exit_status: None,
        runtime: None,
        plist: None,
        session_id: None,
        confidence: Confidence::Unknown,
        evidence: Vec::new(),
        is_partial: false,
    };

    assert_eq!(service.state, ServiceState::Unknown);
    assert_eq!(service.formatted_state(), "UNKNOWN");
}

// =============================================================================
// 23. Attribution Adversarial Tests
// =============================================================================

#[test]
fn test_adversarial_attribution_unrelated_process() {
    // Service process is a system utility with no agent attribution
    let mut services = vec![ServiceInfo {
        name: "sysmond".to_string(),
        kind: ServiceKind::LaunchDaemonApple,
        status: ServiceStatus::Running,
        state: ServiceState::Running,
        plist_status: PlistStatus::NotDiscovered,
        runtime_status: RuntimeStatus::Running { pid: 300 },
        pid: Some(300),
        label: "com.apple.sysmond".to_string(),
        path: None,
        domain: Some(LaunchdDomain::SystemApple),
        last_exit_status: None,
        runtime: None,
        plist: None,
        session_id: None,
        confidence: Confidence::Unknown,
        evidence: Vec::new(),
        is_partial: false,
    }];

    let processes = vec![ProcessInfo {
        pid: 300,
        ppid: Some(1),
        name: "sysmond".to_string(),
        exe: Some(PathBuf::from("/usr/libexec/sysmond")),
        cpu_usage: None,
        memory_bytes: None,
        run_time_secs: 1000,
        start_time: Some(100),
        user: Some("root".to_string()),
        attribution: AgentAttribution::default(),
        listening_ports: Vec::new(),
        cmdline: vec!["/usr/libexec/sysmond".to_string()],
        command_outcome: None,
        provenance: None,
        ..Default::default()
    }];

    let sessions = vec![SessionInfo {
        id: "sess-user-01".to_string(),
        agent_kind: AgentKind::ClaudeCode,
        status: SessionStatus::Active,
        start_time: chrono::Utc::now(),
        end_time: None,
        root_pid: Some(5000),
        root_process_name: Some("claude".to_string()),
        confidence: Confidence::Confirmed,
        evidence: Vec::new(),
        tracked_pids: vec![5000],
        total_memory_bytes: 0,
        total_cpu_usage: 0.0,
        open_ports: Vec::new(),
        resource_count: 0,
        root_binding: None,
    }];

    ServiceDiscoveryCoordinator::correlate_services(&mut services, &processes, &sessions);

    assert_eq!(services[0].session_id, None);
    assert_eq!(services[0].confidence, Confidence::Unknown);
}

#[test]
fn test_adversarial_attribution_pid_reuse_rejected() {
    // Process started at t=100. Session created at t=500.
    // PID matches session.tracked_pids, but process predated the session!
    let now = chrono::Utc::now();
    let sess_start_secs = now.timestamp().max(0) as u64;
    let proc_pre_existing_secs = sess_start_secs.saturating_sub(100);

    let mut services = vec![ServiceInfo {
        name: "recycled".to_string(),
        kind: ServiceKind::LaunchAgentUser,
        status: ServiceStatus::Running,
        state: ServiceState::Running,
        plist_status: PlistStatus::NotDiscovered,
        runtime_status: RuntimeStatus::Running { pid: 4444 },
        pid: Some(4444),
        label: "com.test.recycled".to_string(),
        path: None,
        domain: Some(LaunchdDomain::User),
        last_exit_status: None,
        runtime: None,
        plist: None,
        session_id: None,
        confidence: Confidence::Unknown,
        evidence: Vec::new(),
        is_partial: false,
    }];

    let processes = vec![ProcessInfo {
        pid: 4444,
        ppid: Some(1),
        name: "recycled".to_string(),
        exe: Some(PathBuf::from("/usr/bin/recycled")),
        cpu_usage: None,
        memory_bytes: None,
        run_time_secs: 500,
        start_time: Some(proc_pre_existing_secs),
        user: Some("testuser".to_string()),
        attribution: AgentAttribution::default(),
        listening_ports: Vec::new(),
        cmdline: vec!["/usr/bin/recycled".to_string()],
        command_outcome: None,
        provenance: None,
        ..Default::default()
    }];

    let sessions = vec![SessionInfo {
        id: "sess-late-01".to_string(),
        agent_kind: AgentKind::ClaudeCode,
        status: SessionStatus::Active,
        start_time: now,
        end_time: None,
        root_pid: Some(1111),
        root_process_name: Some("claude".to_string()),
        confidence: Confidence::Confirmed,
        evidence: Vec::new(),
        tracked_pids: vec![1111, 4444],
        total_memory_bytes: 0,
        total_cpu_usage: 0.0,
        open_ports: Vec::new(),
        resource_count: 2,
        root_binding: None,
    }];

    ServiceDiscoveryCoordinator::correlate_services(&mut services, &processes, &sessions);

    assert_eq!(services[0].session_id, None);
    assert_eq!(services[0].confidence, Confidence::Unknown);
    assert!(services[0]
        .evidence
        .iter()
        .any(|e| e.contains("predates session")));
}

#[test]
fn test_adversarial_attribution_stale_session_capped_at_inferred() {
    let now = chrono::Utc::now();
    let now_secs = now.timestamp().max(0) as u64;

    let mut services = vec![ServiceInfo {
        name: "stale-service".to_string(),
        kind: ServiceKind::LaunchAgentUser,
        status: ServiceStatus::Running,
        state: ServiceState::Running,
        plist_status: PlistStatus::NotDiscovered,
        runtime_status: RuntimeStatus::Running { pid: 5555 },
        pid: Some(5555),
        label: "com.test.stale".to_string(),
        path: None,
        domain: Some(LaunchdDomain::User),
        last_exit_status: None,
        runtime: None,
        plist: None,
        session_id: None,
        confidence: Confidence::Unknown,
        evidence: Vec::new(),
        is_partial: false,
    }];

    let processes = vec![ProcessInfo {
        pid: 5555,
        ppid: Some(1),
        name: "stale".to_string(),
        exe: None,
        cpu_usage: None,
        memory_bytes: None,
        run_time_secs: 100,
        start_time: Some(now_secs),
        user: Some("testuser".to_string()),
        attribution: AgentAttribution::default(),
        listening_ports: Vec::new(),
        cmdline: Vec::new(),
        command_outcome: None,
        provenance: None,
        ..Default::default()
    }];

    let sessions = vec![SessionInfo {
        id: "sess-stopped-01".to_string(),
        agent_kind: AgentKind::ClaudeCode,
        status: SessionStatus::Completed, // SESSION HAS TERMINATED
        start_time: now,
        end_time: Some(now),
        root_pid: Some(5555),
        root_process_name: Some("claude".to_string()),
        confidence: Confidence::Confirmed,
        evidence: Vec::new(),
        tracked_pids: vec![5555],
        total_memory_bytes: 0,
        total_cpu_usage: 0.0,
        open_ports: Vec::new(),
        resource_count: 1,
        root_binding: None,
    }];

    ServiceDiscoveryCoordinator::correlate_services(&mut services, &processes, &sessions);

    assert_eq!(services[0].session_id.as_deref(), Some("sess-stopped-01"));
    // Must be capped at Inferred because the session is no longer active!
    assert_eq!(services[0].confidence, Confidence::Inferred);
    assert!(services[0]
        .evidence
        .iter()
        .any(|e| e.contains("Historical association")));
}

#[test]
fn test_adversarial_attribution_shared_executable_supporting_only() {
    let mut services = vec![ServiceInfo {
        name: "python-svc".to_string(),
        kind: ServiceKind::LaunchAgentUser,
        status: ServiceStatus::Loaded,
        state: ServiceState::Loaded,
        plist_status: PlistStatus::Valid {
            path: PathBuf::from("/Users/test/py.plist"),
        },
        runtime_status: RuntimeStatus::Loaded,
        pid: None, // No running PID
        label: "com.test.python".to_string(),
        path: Some("/Users/test/py.plist".to_string()),
        domain: Some(LaunchdDomain::User),
        last_exit_status: Some(0),
        runtime: None,
        plist: Some(LaunchdPlistDetail {
            source_path: PathBuf::from("/Users/test/py.plist"),
            label: Some("com.test.python".to_string()),
            program: Some("/usr/bin/python3".to_string()),
            program_arguments: vec!["/usr/bin/python3".to_string()],
            executable_path: Some("/usr/bin/python3".to_string()),
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
            parse_error: None,
        }),
        session_id: None,
        confidence: Confidence::Unknown,
        evidence: Vec::new(),
        is_partial: false,
    }];

    let processes = vec![ProcessInfo {
        pid: 9191,
        ppid: Some(1),
        name: "python3".to_string(),
        exe: Some(PathBuf::from("/usr/bin/python3")),
        cpu_usage: None,
        memory_bytes: None,
        run_time_secs: 50,
        start_time: None,
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: Vec::new(),
        cmdline: vec!["/usr/bin/python3".to_string()],
        command_outcome: None,
        provenance: None,
        ..Default::default()
    }];

    let sessions = vec![SessionInfo {
        id: "sess-py-01".to_string(),
        agent_kind: AgentKind::GenericLlmAgent("PythonAgent".to_string()),
        status: SessionStatus::Active,
        start_time: chrono::Utc::now(),
        end_time: None,
        root_pid: Some(9191),
        root_process_name: Some("python3".to_string()),
        confidence: Confidence::HighConfidence,
        evidence: Vec::new(),
        tracked_pids: vec![9191],
        total_memory_bytes: 0,
        total_cpu_usage: 0.0,
        open_ports: Vec::new(),
        resource_count: 1,
        root_binding: None,
    }];

    ServiceDiscoveryCoordinator::correlate_services(&mut services, &processes, &sessions);

    // Matching shared binary alone does NOT assign ownership to the service!
    assert_eq!(services[0].session_id, None);
    assert_eq!(services[0].confidence, Confidence::Unknown);
    assert!(services[0]
        .evidence
        .iter()
        .any(|e| e.contains("Supporting evidence: executable matches running process")));
}

#[test]
fn test_adversarial_attribution_descriptive_keyword_only() {
    let mut services = vec![ServiceInfo {
        name: "claudecode".to_string(),
        kind: ServiceKind::LaunchAgentUser,
        status: ServiceStatus::Stopped,
        state: ServiceState::DiscoveredOnDisk,
        plist_status: PlistStatus::Valid {
            path: PathBuf::from("/Users/test/claude.plist"),
        },
        runtime_status: RuntimeStatus::NotLoaded,
        pid: None,
        label: "com.anthropic.claudecode".to_string(),
        path: Some("/Users/test/claude.plist".to_string()),
        domain: Some(LaunchdDomain::User),
        last_exit_status: None,
        runtime: None,
        plist: None,
        session_id: None,
        confidence: Confidence::Unknown,
        evidence: Vec::new(),
        is_partial: false,
    }];

    // No running processes or sessions
    ServiceDiscoveryCoordinator::correlate_services(&mut services, &[], &[]);

    assert_eq!(services[0].session_id, None);
    assert_eq!(services[0].confidence, Confidence::Unknown);
    assert!(services[0]
        .evidence
        .iter()
        .any(|e| e.contains("Descriptive evidence only")));
}

// =============================================================================
// 24. Secret Handling, Serialized JSON & Debug Representation Audits
// =============================================================================

#[test]
fn test_secret_safety_in_serialized_json_and_debug() {
    let secret_key = "sk-ant-api03-ultra-secret-test-token-987654321";
    let db_pass = "supersecretpassword123";
    let url_secret = "postgres://admin:supersecretpassword123@localhost:5432/main";
    let arg_secret = "secret-token-abcdef123456";

    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.secret.agent</string>
    <key>Program</key>
    <string>{}</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/agent</string>
        <string>--token</string>
        <string>{}</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>ANTHROPIC_API_KEY</key>
        <string>{}</string>
        <key>DATABASE_URL</key>
        <string>{}</string>
    </dict>
</dict>
</plist>"#,
        url_secret, arg_secret, secret_key, url_secret
    );

    let path = PathBuf::from("/Users/test/secret.plist");
    let detail = parse_plist_content(xml.as_bytes(), path);

    // Verify EnvironmentVariables values were NEVER stored
    assert_eq!(
        detail.environment_variable_names,
        vec!["ANTHROPIC_API_KEY", "DATABASE_URL"]
    );

    let plists = vec![(detail, LaunchdDomain::User, ServiceKind::LaunchAgentUser)];
    let services = reconcile_services(plists, Vec::new());
    assert_eq!(services.len(), 1);

    // 1. In-memory verification
    let debug_repr = format!("{:?}", services[0]);
    assert!(
        !debug_repr.contains(secret_key),
        "Debug output leaked secret key!"
    );
    assert!(
        !debug_repr.contains(db_pass),
        "Debug output leaked db password!"
    );
    assert!(
        !debug_repr.contains(arg_secret),
        "Debug output leaked arg secret!"
    );

    // 2. Serialized JSON verification
    let json_output = serde_json::to_string_pretty(&services[0]).unwrap();
    assert!(
        !json_output.contains(secret_key),
        "Serialized JSON leaked secret key!"
    );
    assert!(
        !json_output.contains(db_pass),
        "Serialized JSON leaked db password!"
    );
    assert!(
        !json_output.contains(arg_secret),
        "Serialized JSON leaked arg secret!"
    );

    // Verify redaction markers are present
    assert!(json_output.contains("[REDACTED]"));
}

#[test]
fn test_secret_sanitization_in_plist_parse_error() {
    let secret = "sk-ant-sensitive-error-token-112233";
    let malformed_with_secret = format!(
        "<plist><dict><key>Token</key><string>{}</string><key>Bad<",
        secret
    );

    let path = PathBuf::from("/Users/test/broken_secret.plist");
    let detail = parse_plist_content(malformed_with_secret.as_bytes(), path);

    assert!(detail.parse_error.is_some());
    let err_msg = detail.parse_error.unwrap();
    assert!(
        !err_msg.contains(secret),
        "Parse error exposed raw secret token!"
    );
}

// =============================================================================
// 25. ServiceBackgroundWorker Non-blocking, Generation & Fallback Tests
// =============================================================================

#[test]
fn test_service_background_worker_lifecycle_and_non_blocking_read() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use timmy::model::service::{
        PlistStatus, RuntimeStatus, ServiceInfo, ServiceKind, ServiceState, ServiceStatus,
    };
    use timmy::platform::traits::{PlatformError, ServiceCollector};
    use timmy::platform::ServiceBackgroundWorker;

    struct MockServiceCollector {
        call_count: AtomicUsize,
    }
    impl ServiceCollector for MockServiceCollector {
        fn collect_services(&self) -> Result<Vec<ServiceInfo>, PlatformError> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Ok(vec![ServiceInfo {
                name: "mock-worker-svc".to_string(),
                kind: ServiceKind::LaunchAgentUser,
                status: ServiceStatus::Running,
                state: ServiceState::Running,
                plist_status: PlistStatus::NotDiscovered,
                runtime_status: RuntimeStatus::Running { pid: 1010 },
                pid: Some(1010),
                label: "com.mock.worker".to_string(),
                path: None,
                domain: None,
                last_exit_status: None,
                runtime: None,
                plist: None,
                session_id: None,
                confidence: Confidence::Unknown,
                evidence: Vec::new(),
                is_partial: false,
            }])
        }
    }

    let collector = Arc::new(MockServiceCollector {
        call_count: AtomicUsize::new(0),
    });
    let mut worker = ServiceBackgroundWorker::new(collector.clone());

    // 1. Initial read before refresh is empty and instantaneous
    let initial = worker.get_cached_services();
    assert!(initial.is_empty());

    // 2. Trigger non-blocking refresh
    worker.trigger_refresh(1, Vec::new(), Vec::new());

    // Wait briefly for worker thread to process
    let start = std::time::Instant::now();
    while worker.get_cached_services().is_empty() && start.elapsed() < Duration::from_secs(1) {
        std::thread::sleep(Duration::from_millis(10));
    }

    let cached = worker.get_cached_services();
    assert_eq!(cached.len(), 1);
    assert_eq!(cached[0].label, "com.mock.worker");
    assert_eq!(worker.current_generation(), 1);

    // 3. Graceful shutdown
    let shutdown_res = worker.stop(Duration::from_millis(500));
    assert_eq!(
        shutdown_res,
        timmy::platform::WorkerShutdownResult::Terminated
    );
    assert!(worker.is_terminated());
}

#[test]
fn test_service_background_worker_preserves_snapshot_on_failure() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use timmy::model::service::{
        PlistStatus, RuntimeStatus, ServiceInfo, ServiceKind, ServiceState, ServiceStatus,
    };
    use timmy::platform::traits::{PlatformError, ServiceCollector};
    use timmy::platform::ServiceBackgroundWorker;

    struct FailingServiceCollector {
        should_fail: AtomicBool,
    }
    impl ServiceCollector for FailingServiceCollector {
        fn collect_services(&self) -> Result<Vec<ServiceInfo>, PlatformError> {
            if self.should_fail.load(Ordering::SeqCst) {
                Err(PlatformError::Other("Simulated daemon failure".to_string()))
            } else {
                Ok(vec![ServiceInfo {
                    name: "persisted-svc".to_string(),
                    kind: ServiceKind::LaunchAgentUser,
                    status: ServiceStatus::Running,
                    state: ServiceState::Running,
                    plist_status: PlistStatus::NotDiscovered,
                    runtime_status: RuntimeStatus::Running { pid: 2020 },
                    pid: Some(2020),
                    label: "com.mock.persisted".to_string(),
                    path: None,
                    domain: None,
                    last_exit_status: None,
                    runtime: None,
                    plist: None,
                    session_id: None,
                    confidence: Confidence::Unknown,
                    evidence: Vec::new(),
                    is_partial: false,
                }])
            }
        }
    }

    let collector = Arc::new(FailingServiceCollector {
        should_fail: AtomicBool::new(false),
    });
    let mut worker = ServiceBackgroundWorker::new(collector.clone());

    // Gen 1: Succeeds
    worker.trigger_refresh(1, Vec::new(), Vec::new());
    let start = std::time::Instant::now();
    while worker.get_cached_services().is_empty() && start.elapsed() < Duration::from_secs(1) {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(worker.get_cached_services().len(), 1);

    // Gen 2: Collector fails
    collector.should_fail.store(true, Ordering::SeqCst);
    worker.trigger_refresh(2, Vec::new(), Vec::new());

    let start = std::time::Instant::now();
    while worker.last_error().is_none() && start.elapsed() < Duration::from_secs(1) {
        std::thread::sleep(Duration::from_millis(10));
    }

    assert!(worker
        .last_error()
        .unwrap()
        .contains("Simulated daemon failure"));
    // CRITICAL REQUIREMENT: Cached services must NOT be replaced with empty list!
    let preserved = worker.get_cached_services();
    assert_eq!(
        preserved.len(),
        1,
        "Cached services were wiped out on failure!"
    );
    assert_eq!(preserved[0].label, "com.mock.persisted");

    let _ = worker.stop(Duration::from_millis(500));
}

#[test]
fn test_service_background_worker_monotonic_generation_guard() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use timmy::model::service::{
        PlistStatus, RuntimeStatus, ServiceInfo, ServiceKind, ServiceState, ServiceStatus,
    };
    use timmy::platform::traits::{PlatformError, ServiceCollector};
    use timmy::platform::ServiceBackgroundWorker;

    struct DelayedServiceCollector {
        is_second_call: AtomicBool,
    }
    impl ServiceCollector for DelayedServiceCollector {
        fn collect_services(&self) -> Result<Vec<ServiceInfo>, PlatformError> {
            let is_second = self.is_second_call.swap(true, Ordering::SeqCst);
            if !is_second {
                // First call (older generation): slow
                std::thread::sleep(Duration::from_millis(100));
                Ok(vec![ServiceInfo {
                    name: "old-gen".to_string(),
                    kind: ServiceKind::LaunchAgentUser,
                    status: ServiceStatus::Loaded,
                    state: ServiceState::Loaded,
                    plist_status: PlistStatus::NotDiscovered,
                    runtime_status: RuntimeStatus::Loaded,
                    pid: None,
                    label: "com.mock.old".to_string(),
                    path: None,
                    domain: None,
                    last_exit_status: None,
                    runtime: None,
                    plist: None,
                    session_id: None,
                    confidence: Confidence::Unknown,
                    evidence: Vec::new(),
                    is_partial: false,
                }])
            } else {
                // Second call (newer generation): fast
                Ok(vec![ServiceInfo {
                    name: "new-gen".to_string(),
                    kind: ServiceKind::LaunchAgentUser,
                    status: ServiceStatus::Running,
                    state: ServiceState::Running,
                    plist_status: PlistStatus::NotDiscovered,
                    runtime_status: RuntimeStatus::Running { pid: 3030 },
                    pid: Some(3030),
                    label: "com.mock.new".to_string(),
                    path: None,
                    domain: None,
                    last_exit_status: None,
                    runtime: None,
                    plist: None,
                    session_id: None,
                    confidence: Confidence::Unknown,
                    evidence: Vec::new(),
                    is_partial: false,
                }])
            }
        }
    }

    let collector = Arc::new(DelayedServiceCollector {
        is_second_call: AtomicBool::new(false),
    });
    let mut worker = ServiceBackgroundWorker::new(collector);

    // Refresh generation 1 (slow)
    worker.trigger_refresh(1, Vec::new(), Vec::new());
    // Immediately trigger generation 2 (newer)
    worker.trigger_refresh(2, Vec::new(), Vec::new());

    let start = std::time::Instant::now();
    while worker.current_generation() < 2 && start.elapsed() < Duration::from_secs(2) {
        std::thread::sleep(Duration::from_millis(20));
    }

    assert_eq!(worker.current_generation(), 2);
    let cached = worker.get_cached_services();
    assert_eq!(cached.len(), 1);
    assert_eq!(
        cached[0].label, "com.mock.new",
        "Older generation overwrote newer generation!"
    );

    let _ = worker.stop(Duration::from_millis(500));
}

// =============================================================================
// 26. Final Audit: Seven Adversarial Attribution Tests
// =============================================================================

#[test]
fn test_adversarial_attribution_preexisting_daemon_rejected() {
    // 1. A pre-existing daemon with a matching executable name.
    // Process started before session creation: must be rejected by temporal check.
    let now = chrono::Utc::now();
    let sess_start = now;
    let proc_start = (sess_start.timestamp().max(0) as u64).saturating_sub(60); // 60 seconds BEFORE session!

    let mut services = vec![ServiceInfo {
        name: "claude-daemon".to_string(),
        kind: ServiceKind::LaunchAgentUser,
        status: ServiceStatus::Running,
        state: ServiceState::Running,
        plist_status: PlistStatus::Valid {
            path: PathBuf::from("/Users/test/Library/LaunchAgents/com.anthropic.claudecode.plist"),
        },
        runtime_status: RuntimeStatus::Running { pid: 8888 },
        pid: Some(8888),
        label: "com.anthropic.claudecode".to_string(),
        path: Some("/Users/test/Library/LaunchAgents/com.anthropic.claudecode.plist".to_string()),
        domain: Some(LaunchdDomain::User),
        last_exit_status: Some(0),
        runtime: None,
        plist: Some(LaunchdPlistDetail {
            source_path: PathBuf::from(
                "/Users/test/Library/LaunchAgents/com.anthropic.claudecode.plist",
            ),
            label: Some("com.anthropic.claudecode".to_string()),
            program: Some("/usr/local/bin/claude".to_string()),
            program_arguments: vec!["/usr/local/bin/claude".to_string()],
            executable_path: Some("/usr/local/bin/claude".to_string()),
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
            parse_error: None,
        }),
        session_id: None,
        confidence: Confidence::Unknown,
        evidence: Vec::new(),
        is_partial: false,
    }];

    let processes = vec![ProcessInfo {
        pid: 8888,
        ppid: Some(1),
        name: "claude".to_string(),
        exe: Some(PathBuf::from("/usr/local/bin/claude")),
        cpu_usage: Some(0.5),
        memory_bytes: Some(40 * 1024 * 1024),
        run_time_secs: 120,
        start_time: Some(proc_start), // Predates session!
        user: Some("testuser".to_string()),
        attribution: AgentAttribution {
            kind: AgentKind::ClaudeCode,
            confidence: Confidence::Confirmed,
            reason: "Binary match".to_string(),
            evidence: "claude".to_string(),
            parent_pid: Some(1),
            parent_name: None,
            root_agent_pid: Some(8888),
            root_agent_name: Some("claude".to_string()),
            is_confirmed: true,
            safe_to_terminate: false,
        },
        listening_ports: Vec::new(),
        cmdline: vec!["/usr/local/bin/claude".to_string()],
        command_outcome: None,
        provenance: None,
        ..Default::default()
    }];

    let sessions = vec![SessionInfo {
        id: "sess-new-active".to_string(),
        agent_kind: AgentKind::ClaudeCode,
        status: SessionStatus::Active,
        start_time: sess_start,
        end_time: None,
        root_pid: Some(8888), // Claiming PID 8888
        root_process_name: Some("claude".to_string()),
        confidence: Confidence::Confirmed,
        evidence: Vec::new(),
        tracked_pids: vec![8888],
        total_memory_bytes: 0,
        total_cpu_usage: 0.0,
        open_ports: Vec::new(),
        resource_count: 1,
        root_binding: None,
    }];

    ServiceDiscoveryCoordinator::correlate_services(&mut services, &processes, &sessions);

    // JUSTIFICATION: Pre-existing process was running before the session started.
    // Must NOT be attributed to the new session. Confidence remains Unknown, session_id is None.
    assert_eq!(services[0].session_id, None);
    assert_eq!(services[0].confidence, Confidence::Unknown);
    assert!(services[0]
        .evidence
        .iter()
        .any(|e| e.contains("predates session") && e.contains("rejected")));
}

#[test]
fn test_adversarial_attribution_daemon_started_by_launchd_during_session() {
    // 2. A daemon started by launchd during an active AI session.
    // Started during session, but PPID is 1 (launchd) and not in session's tracked process tree.
    let now = chrono::Utc::now();
    let sess_start = now;
    let proc_start = (sess_start.timestamp().max(0) as u64).saturating_add(5);

    let mut services = vec![ServiceInfo {
        name: "ollama-service".to_string(),
        kind: ServiceKind::LaunchAgentUser,
        status: ServiceStatus::Running,
        state: ServiceState::Running,
        plist_status: PlistStatus::Valid {
            path: PathBuf::from("/Users/test/Library/LaunchAgents/com.ollama.service.plist"),
        },
        runtime_status: RuntimeStatus::Running { pid: 9191 },
        pid: Some(9191),
        label: "com.ollama.service".to_string(),
        path: Some("/Users/test/Library/LaunchAgents/com.ollama.service.plist".to_string()),
        domain: Some(LaunchdDomain::User),
        last_exit_status: Some(0),
        runtime: None,
        plist: Some(LaunchdPlistDetail {
            source_path: PathBuf::from("/Users/test/Library/LaunchAgents/com.ollama.service.plist"),
            label: Some("com.ollama.service".to_string()),
            program: Some("/usr/local/bin/ollama".to_string()),
            program_arguments: vec!["/usr/local/bin/ollama".to_string(), "serve".to_string()],
            executable_path: Some("/usr/local/bin/ollama".to_string()),
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
            parse_error: None,
        }),
        session_id: None,
        confidence: Confidence::Unknown,
        evidence: Vec::new(),
        is_partial: false,
    }];

    let processes = vec![ProcessInfo {
        pid: 9191,
        ppid: Some(1), // PPID 1 = launched directly by launchd, NOT by the AI agent!
        name: "ollama".to_string(),
        exe: Some(PathBuf::from("/usr/local/bin/ollama")),
        cpu_usage: Some(2.0),
        memory_bytes: Some(128 * 1024 * 1024),
        run_time_secs: 10,
        start_time: Some(proc_start),
        user: Some("testuser".to_string()),
        attribution: AgentAttribution {
            kind: AgentKind::GenericLlmAgent("ollama".to_string()),
            confidence: Confidence::Confirmed,
            reason: "Binary match".to_string(),
            evidence: "ollama".to_string(),
            parent_pid: Some(1),
            parent_name: None,
            root_agent_pid: Some(9191),
            root_agent_name: Some("ollama".to_string()),
            is_confirmed: true,
            safe_to_terminate: false,
        },
        listening_ports: vec![11434],
        cmdline: vec!["/usr/local/bin/ollama".to_string(), "serve".to_string()],
        command_outcome: None,
        provenance: None,
        ..Default::default()
    }];

    let sessions = vec![SessionInfo {
        id: "sess-cursor-active".to_string(),
        agent_kind: AgentKind::Cursor,
        status: SessionStatus::Active,
        start_time: sess_start,
        end_time: None,
        root_pid: Some(5000), // Cursor session root PID is 5000
        root_process_name: Some("cursor".to_string()),
        confidence: Confidence::Confirmed,
        evidence: Vec::new(),
        tracked_pids: vec![5000, 5001], // 9191 is NOT tracked by Cursor!
        total_memory_bytes: 0,
        total_cpu_usage: 0.0,
        open_ports: Vec::new(),
        resource_count: 2,
        root_binding: None,
    }];

    ServiceDiscoveryCoordinator::correlate_services(&mut services, &processes, &sessions);

    // JUSTIFICATION: The daemon was started by launchd (PPID 1) independently of the session.
    // It is not in the session's tracked process tree. Ownership remains unassigned (session_id: None, Unknown).
    assert_eq!(services[0].session_id, None);
    assert_eq!(services[0].confidence, Confidence::Unknown);
    assert!(services[0]
        .evidence
        .iter()
        .any(|e| e.contains("no registered session")));
}

#[test]
fn test_adversarial_attribution_pid_reuse_after_session_end_rejected() {
    // 3. A process whose PID has been reused after a session ended.
    // Session ran from T=0 to T=100. New process spawned at T=200 with the same PID.
    let base_time = chrono::Utc::now();
    let sess_start = base_time;
    let sess_end = base_time + chrono::Duration::seconds(100);
    let proc_start = (sess_end.timestamp().max(0) as u64).saturating_add(50); // Started 50s AFTER session ended!

    let mut services = vec![ServiceInfo {
        name: "reused-pid-svc".to_string(),
        kind: ServiceKind::LaunchAgentUser,
        status: ServiceStatus::Running,
        state: ServiceState::Running,
        plist_status: PlistStatus::NotDiscovered,
        runtime_status: RuntimeStatus::Running { pid: 4444 },
        pid: Some(4444),
        label: "com.unrelated.worker".to_string(),
        path: None,
        domain: Some(LaunchdDomain::User),
        last_exit_status: Some(0),
        runtime: None,
        plist: None,
        session_id: None,
        confidence: Confidence::Unknown,
        evidence: Vec::new(),
        is_partial: false,
    }];

    let processes = vec![ProcessInfo {
        pid: 4444,
        ppid: Some(1),
        name: "worker".to_string(),
        exe: Some(PathBuf::from("/usr/bin/worker")),
        cpu_usage: None,
        memory_bytes: None,
        run_time_secs: 10,
        start_time: Some(proc_start),
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: Vec::new(),
        cmdline: Vec::new(),
        command_outcome: None,
        provenance: None,
        ..Default::default()
    }];

    let sessions = vec![SessionInfo {
        id: "sess-ended-history".to_string(),
        agent_kind: AgentKind::ClaudeCode,
        status: SessionStatus::Stopped,
        start_time: sess_start,
        end_time: Some(sess_end),
        root_pid: Some(4444), // Historical session used PID 4444
        root_process_name: Some("claude".to_string()),
        confidence: Confidence::Confirmed,
        evidence: Vec::new(),
        tracked_pids: vec![4444],
        total_memory_bytes: 0,
        total_cpu_usage: 0.0,
        open_ports: Vec::new(),
        resource_count: 1,
        root_binding: None,
    }];

    ServiceDiscoveryCoordinator::correlate_services(&mut services, &processes, &sessions);

    // JUSTIFICATION: Process start time postdates session end time.
    // PID reuse detected and rejected. Ownership remains None and Unknown.
    assert_eq!(services[0].session_id, None);
    assert_eq!(services[0].confidence, Confidence::Unknown);
    assert!(services[0]
        .evidence
        .iter()
        .any(|e| e.contains("postdates session") && e.contains("PID reuse")));
}

#[test]
fn test_adversarial_attribution_direct_child_process_demonstrably_launched() {
    // 4. A direct child process that is demonstrably launched by the session.
    // Parent PID is the session root PID, process started during active session,
    // and executable matches agent or service definition.
    let now = chrono::Utc::now();
    let sess_start = now;
    let proc_start = (sess_start.timestamp().max(0) as u64).saturating_add(2);

    let mut services = vec![ServiceInfo {
        name: "agent-helper".to_string(),
        kind: ServiceKind::LaunchAgentUser,
        status: ServiceStatus::Running,
        state: ServiceState::Running,
        plist_status: PlistStatus::Valid {
            path: PathBuf::from("/Users/test/Library/LaunchAgents/com.agent.helper.plist"),
        },
        runtime_status: RuntimeStatus::Running { pid: 6100 },
        pid: Some(6100),
        label: "com.agent.helper".to_string(),
        path: Some("/Users/test/Library/LaunchAgents/com.agent.helper.plist".to_string()),
        domain: Some(LaunchdDomain::User),
        last_exit_status: Some(0),
        runtime: None,
        plist: Some(LaunchdPlistDetail {
            source_path: PathBuf::from("/Users/test/Library/LaunchAgents/com.agent.helper.plist"),
            label: Some("com.agent.helper".to_string()),
            program: Some("/usr/local/bin/agent-helper".to_string()),
            program_arguments: vec!["/usr/local/bin/agent-helper".to_string()],
            executable_path: Some("/usr/local/bin/agent-helper".to_string()),
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
            parse_error: None,
        }),
        session_id: None,
        confidence: Confidence::Unknown,
        evidence: Vec::new(),
        is_partial: false,
    }];

    let processes = vec![
        ProcessInfo {
            pid: 6000,
            ppid: Some(1),
            name: "claude".to_string(),
            exe: Some(PathBuf::from("/usr/local/bin/claude")),
            cpu_usage: Some(1.0),
            memory_bytes: Some(50 * 1024 * 1024),
            run_time_secs: 20,
            start_time: Some(sess_start.timestamp().max(0) as u64),
            user: Some("testuser".to_string()),
            attribution: AgentAttribution {
                kind: AgentKind::ClaudeCode,
                confidence: Confidence::Confirmed,
                reason: "Direct binary".to_string(),
                evidence: "claude".to_string(),
                parent_pid: Some(1),
                parent_name: None,
                root_agent_pid: Some(6000),
                root_agent_name: Some("claude".to_string()),
                is_confirmed: true,
                safe_to_terminate: false,
            },
            listening_ports: Vec::new(),
            cmdline: vec!["/usr/local/bin/claude".to_string()],
            command_outcome: None,
            provenance: None,
            ..Default::default()
        },
        ProcessInfo {
            pid: 6100,
            ppid: Some(6000), // Direct child of session root process 6000!
            name: "agent-helper".to_string(),
            exe: Some(PathBuf::from("/usr/local/bin/agent-helper")),
            cpu_usage: Some(0.8),
            memory_bytes: Some(25 * 1024 * 1024),
            run_time_secs: 15,
            start_time: Some(proc_start),
            user: Some("testuser".to_string()),
            attribution: AgentAttribution {
                kind: AgentKind::ClaudeCode,
                confidence: Confidence::Confirmed,
                reason: "Direct child of claude".to_string(),
                evidence: "claude".to_string(),
                parent_pid: Some(6000),
                parent_name: Some("claude".to_string()),
                root_agent_pid: Some(6000),
                root_agent_name: Some("claude".to_string()),
                is_confirmed: true,
                safe_to_terminate: false,
            },
            listening_ports: Vec::new(),
            cmdline: vec!["/usr/local/bin/agent-helper".to_string()],
            command_outcome: None,
            provenance: None,
            ..Default::default()
        },
    ];

    let sessions = vec![SessionInfo {
        id: "sess-claude-parent".to_string(),
        agent_kind: AgentKind::ClaudeCode,
        status: SessionStatus::Active,
        start_time: sess_start,
        end_time: None,
        root_pid: Some(6000),
        root_process_name: Some("claude".to_string()),
        confidence: Confidence::Confirmed,
        evidence: Vec::new(),
        tracked_pids: vec![6000, 6100], // Directly tracked child process
        total_memory_bytes: 75 * 1024 * 1024,
        total_cpu_usage: 1.8,
        open_ports: Vec::new(),
        resource_count: 2,
        root_binding: None,
    }];

    ServiceDiscoveryCoordinator::correlate_services(&mut services, &processes, &sessions);

    // JUSTIFICATION: Direct child ancestry verified, executable matches service definition,
    // start time within active session, tracked by session.
    // Invariant: Matching PPID plus executable similarity alone does NOT constitute multi-domain
    // independent evidence; confidence is strictly capped at Inferred.
    assert_eq!(
        services[0].session_id.as_deref(),
        Some("sess-claude-parent")
    );
    assert_eq!(
        services[0].confidence,
        Confidence::Inferred,
        "Direct child discovered via process tree must be capped at Inferred"
    );
    assert!(services[0]
        .evidence
        .iter()
        .any(|e| e.contains("tracked by session") || e.contains("child of session root")));
}

#[test]
fn test_adversarial_attribution_plist_label_match_no_process_relationship() {
    // 5. A service with a matching plist label but no process relationship.
    // Label contains "claude" or "copilot", but PID is None, not running, no process ancestry.
    let now = chrono::Utc::now();

    let mut services = vec![ServiceInfo {
        name: "claude-idle-plist".to_string(),
        kind: ServiceKind::LaunchAgentUser,
        status: ServiceStatus::Loaded,
        state: ServiceState::DiscoveredOnDisk,
        plist_status: PlistStatus::Valid {
            path: PathBuf::from("/Users/test/Library/LaunchAgents/com.anthropic.claude.idle.plist"),
        },
        runtime_status: RuntimeStatus::NotLoaded,
        pid: None, // No running process!
        label: "com.anthropic.claude.idle".to_string(),
        path: Some("/Users/test/Library/LaunchAgents/com.anthropic.claude.idle.plist".to_string()),
        domain: Some(LaunchdDomain::User),
        last_exit_status: None,
        runtime: None,
        plist: Some(LaunchdPlistDetail {
            source_path: PathBuf::from(
                "/Users/test/Library/LaunchAgents/com.anthropic.claude.idle.plist",
            ),
            label: Some("com.anthropic.claude.idle".to_string()),
            program: Some("/usr/local/bin/claude".to_string()),
            program_arguments: vec!["/usr/local/bin/claude".to_string()],
            executable_path: Some("/usr/local/bin/claude".to_string()),
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
            parse_error: None,
        }),
        session_id: None,
        confidence: Confidence::Unknown,
        evidence: Vec::new(),
        is_partial: false,
    }];

    let sessions = vec![SessionInfo {
        id: "sess-active-claude".to_string(),
        agent_kind: AgentKind::ClaudeCode,
        status: SessionStatus::Active,
        start_time: now,
        end_time: None,
        root_pid: Some(9900),
        root_process_name: Some("claude".to_string()),
        confidence: Confidence::Confirmed,
        evidence: Vec::new(),
        tracked_pids: vec![9900],
        total_memory_bytes: 0,
        total_cpu_usage: 0.0,
        open_ports: Vec::new(),
        resource_count: 1,
        root_binding: None,
    }];

    // Discovered services with matching keyword in label
    ServiceDiscoveryCoordinator::correlate_services(&mut services, &[], &sessions);

    // JUSTIFICATION: A matching keyword in plist label or filename is descriptive evidence only.
    // It must NEVER elevate confidence to Confirmed or HighConfidence, and without process relationship,
    // session_id must remain None and confidence remains Unknown!
    assert_eq!(services[0].session_id, None);
    assert_eq!(services[0].confidence, Confidence::Unknown);
    assert!(services[0]
        .evidence
        .iter()
        .any(|e| e.contains("Descriptive evidence only")));
}

#[test]
fn test_adversarial_attribution_competing_claims_remain_unresolved() {
    // 6. Two sessions claiming the same service.
    // Competing ownership must remain unassigned (session_id: None) and Unknown.
    let now = chrono::Utc::now();

    let mut services = vec![ServiceInfo {
        name: "shared-ipc-daemon".to_string(),
        kind: ServiceKind::LaunchAgentUser,
        status: ServiceStatus::Running,
        state: ServiceState::Running,
        plist_status: PlistStatus::NotDiscovered,
        runtime_status: RuntimeStatus::Running { pid: 7171 },
        pid: Some(7171),
        label: "com.shared.ipc.daemon".to_string(),
        path: None,
        domain: Some(LaunchdDomain::User),
        last_exit_status: Some(0),
        runtime: None,
        plist: None,
        session_id: None,
        confidence: Confidence::Unknown,
        evidence: Vec::new(),
        is_partial: false,
    }];

    let processes = vec![ProcessInfo {
        pid: 7171,
        ppid: Some(1),
        name: "ipc-daemon".to_string(),
        exe: None,
        cpu_usage: None,
        memory_bytes: None,
        run_time_secs: 10,
        start_time: Some(now.timestamp().max(0) as u64),
        user: None,
        attribution: AgentAttribution::default(),
        listening_ports: Vec::new(),
        cmdline: Vec::new(),
        command_outcome: None,
        provenance: None,
        ..Default::default()
    }];

    let sessions = vec![
        SessionInfo {
            id: "session-1".to_string(),
            agent_kind: AgentKind::ClaudeCode,
            status: SessionStatus::Active,
            start_time: now,
            end_time: None,
            root_pid: Some(7171),
            root_process_name: Some("ipc-daemon".to_string()),
            confidence: Confidence::Confirmed,
            evidence: Vec::new(),
            tracked_pids: vec![7171],
            total_memory_bytes: 0,
            total_cpu_usage: 0.0,
            open_ports: Vec::new(),
            resource_count: 1,
            root_binding: None,
        },
        SessionInfo {
            id: "session-2".to_string(),
            agent_kind: AgentKind::Cursor,
            status: SessionStatus::Active,
            start_time: now,
            end_time: None,
            root_pid: Some(7171),
            root_process_name: Some("ipc-daemon".to_string()),
            confidence: Confidence::Confirmed,
            evidence: Vec::new(),
            tracked_pids: vec![7171],
            total_memory_bytes: 0,
            total_cpu_usage: 0.0,
            open_ports: Vec::new(),
            resource_count: 1,
            root_binding: None,
        },
    ];

    ServiceDiscoveryCoordinator::correlate_services(&mut services, &processes, &sessions);

    // JUSTIFICATION: Multiple active sessions assert competing claims.
    // The conflict cannot be resolved automatically; ownership must remain unassigned
    // (session_id: None, confidence: Unknown) and all conflicting session IDs documented in evidence.
    assert_eq!(services[0].session_id, None);
    assert_eq!(services[0].confidence, Confidence::Unknown);
    assert!(services[0]
        .evidence
        .iter()
        .any(|e| e.contains("Conflicting attribution") && e.contains("ownership unresolved")));
}

#[test]
fn test_adversarial_attribution_stopped_session_retains_historical_association() {
    // 7. A stopped session whose associated service remains running.
    // Completed sessions retain historical association without appearing to actively own currently running services.
    let now = chrono::Utc::now();
    let sess_start = now - chrono::Duration::hours(1);
    let sess_end = now - chrono::Duration::minutes(10);
    let proc_start = (sess_start.timestamp().max(0) as u64).saturating_add(60);

    let mut services = vec![ServiceInfo {
        name: "persisted-agent".to_string(),
        kind: ServiceKind::LaunchAgentUser,
        status: ServiceStatus::Running,
        state: ServiceState::Running,
        plist_status: PlistStatus::Valid {
            path: PathBuf::from("/Users/test/Library/LaunchAgents/com.persisted.agent.plist"),
        },
        runtime_status: RuntimeStatus::Running { pid: 3232 },
        pid: Some(3232),
        label: "com.persisted.agent".to_string(),
        path: Some("/Users/test/Library/LaunchAgents/com.persisted.agent.plist".to_string()),
        domain: Some(LaunchdDomain::User),
        last_exit_status: Some(0),
        runtime: None,
        plist: Some(LaunchdPlistDetail {
            source_path: PathBuf::from(
                "/Users/test/Library/LaunchAgents/com.persisted.agent.plist",
            ),
            label: Some("com.persisted.agent".to_string()),
            program: Some("/usr/local/bin/agent".to_string()),
            program_arguments: vec!["/usr/local/bin/agent".to_string()],
            executable_path: Some("/usr/local/bin/agent".to_string()),
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
            parse_error: None,
        }),
        session_id: None,
        confidence: Confidence::Unknown,
        evidence: Vec::new(),
        is_partial: false,
    }];

    let processes = vec![ProcessInfo {
        pid: 3232,
        ppid: Some(1),
        name: "agent".to_string(),
        exe: Some(PathBuf::from("/usr/local/bin/agent")),
        cpu_usage: Some(0.1),
        memory_bytes: Some(30 * 1024 * 1024),
        run_time_secs: 3000,
        start_time: Some(proc_start),
        user: Some("testuser".to_string()),
        attribution: AgentAttribution {
            kind: AgentKind::ClaudeCode,
            confidence: Confidence::Confirmed,
            reason: "Binary".to_string(),
            evidence: "agent".to_string(),
            parent_pid: Some(1),
            parent_name: None,
            root_agent_pid: Some(3232),
            root_agent_name: Some("agent".to_string()),
            is_confirmed: true,
            safe_to_terminate: false,
        },
        listening_ports: Vec::new(),
        cmdline: vec!["/usr/local/bin/agent".to_string()],
        command_outcome: None,
        provenance: None,
        ..Default::default()
    }];

    let sessions = vec![SessionInfo {
        id: "sess-historical-stop".to_string(),
        agent_kind: AgentKind::ClaudeCode,
        status: SessionStatus::Stopped, // Session is STOPPED / Completed
        start_time: sess_start,
        end_time: Some(sess_end),
        root_pid: Some(3232),
        root_process_name: Some("agent".to_string()),
        confidence: Confidence::Confirmed,
        evidence: Vec::new(),
        tracked_pids: vec![3232],
        total_memory_bytes: 0,
        total_cpu_usage: 0.0,
        open_ports: Vec::new(),
        resource_count: 1,
        root_binding: None,
    }];

    ServiceDiscoveryCoordinator::correlate_services(&mut services, &processes, &sessions);

    // JUSTIFICATION: Session is stopped. While historical association is preserved (session_id is recorded),
    // confidence must be capped at Inferred so it does not appear as active confirmed ownership of running resources.
    assert_eq!(
        services[0].session_id.as_deref(),
        Some("sess-historical-stop")
    );
    assert_eq!(services[0].confidence, Confidence::Inferred);
    assert!(services[0]
        .evidence
        .iter()
        .any(|e| e.contains("Historical association") && e.contains("capped at Inferred")));
}

// =============================================================================
// 27. Launchd Domain Coverage & Explicit GUI Query Tests
// =============================================================================

#[test]
fn test_domain_user_gui_explicit_query_parsing() {
    use timmy::platform::macos::launchd::parse_launchctl_print_services_output;

    let sample_gui_output = r#"
gui/501 = {
	type = login
	handle = 100020
	active count = 10
	service count = 10

	services = {
		    1568      - 	application.com.google.antigravity.72680814.72680820
		   46704   (pe) 	com.apple.syncdefaultsd
		   10572   (jt) 	com.apple.assistantd
		       0      - 	com.apple.DataDetectorsLocalSources
		       0      - 	com.apple.unmountassistant.useragent
		   46662   (pe) 	com.apple.mlhostd
		    9999      0 	com.thirdparty.useragent
	}
}
"#;

    let jobs = parse_launchctl_print_services_output(sample_gui_output, LaunchdDomain::User);
    assert_eq!(jobs.len(), 7);

    // Verify all jobs parsed from user GUI domain have LaunchdDomain::User
    for job in &jobs {
        assert_eq!(job.domain, LaunchdDomain::User);
    }

    let antigravity = jobs
        .iter()
        .find(|j| j.label.contains("antigravity"))
        .unwrap();
    assert_eq!(antigravity.pid, Some(1568));

    let thirdparty = jobs
        .iter()
        .find(|j| j.label == "com.thirdparty.useragent")
        .unwrap();
    assert_eq!(thirdparty.pid, Some(9999));
    assert_eq!(thirdparty.last_exit_status, Some(0));

    let idle = jobs
        .iter()
        .find(|j| j.label == "com.apple.DataDetectorsLocalSources")
        .unwrap();
    assert_eq!(idle.pid, None);
}

// =============================================================================
// 28. Partial and Truncated Snapshots Tests
// =============================================================================

#[test]
fn test_partial_snapshot_marked_when_output_truncated() {
    let service = ServiceInfo {
        name: "test-truncated-svc".to_string(),
        kind: ServiceKind::LaunchAgentUser,
        status: ServiceStatus::Running,
        state: ServiceState::Running,
        plist_status: PlistStatus::Valid {
            path: PathBuf::from("/Users/test/test.plist"),
        },
        runtime_status: RuntimeStatus::Running { pid: 1234 },
        pid: Some(1234),
        label: "com.test.truncated".to_string(),
        path: Some("/Users/test/test.plist".to_string()),
        domain: Some(LaunchdDomain::User),
        last_exit_status: Some(0),
        runtime: None,
        plist: None,
        session_id: None,
        confidence: Confidence::Unknown,
        evidence: Vec::new(),
        is_partial: true, // Marked partial due to truncation!
    };

    assert!(service.is_partial);
    assert_eq!(service.formatted_state(), "RUNNING (1234) [Partial]");
}

#[test]
fn test_snapshot_recovery_on_next_successful_collection() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use timmy::platform::traits::{PlatformError, ServiceCollector};
    use timmy::platform::ServiceBackgroundWorker;

    struct RecoveringCollector {
        is_first: AtomicBool,
    }
    impl ServiceCollector for RecoveringCollector {
        fn collect_services(&self) -> Result<Vec<ServiceInfo>, PlatformError> {
            if self.is_first.swap(false, Ordering::SeqCst) {
                // First call: Truncated partial result
                Ok(vec![ServiceInfo {
                    name: "partial-svc".to_string(),
                    kind: ServiceKind::LaunchAgentUser,
                    status: ServiceStatus::Running,
                    state: ServiceState::Running,
                    plist_status: PlistStatus::NotDiscovered,
                    runtime_status: RuntimeStatus::Running { pid: 1111 },
                    pid: Some(1111),
                    label: "com.test.partial".to_string(),
                    path: None,
                    domain: None,
                    last_exit_status: None,
                    runtime: None,
                    plist: None,
                    session_id: None,
                    confidence: Confidence::Unknown,
                    evidence: vec!["Diagnostic warning: launchctl output was truncated at memory limit (partial snapshot)".to_string()],
                    is_partial: true,
                }])
            } else {
                // Second call: Complete successful collection
                Ok(vec![ServiceInfo {
                    name: "complete-svc".to_string(),
                    kind: ServiceKind::LaunchAgentUser,
                    status: ServiceStatus::Running,
                    state: ServiceState::Running,
                    plist_status: PlistStatus::NotDiscovered,
                    runtime_status: RuntimeStatus::Running { pid: 1111 },
                    pid: Some(1111),
                    label: "com.test.complete".to_string(),
                    path: None,
                    domain: None,
                    last_exit_status: None,
                    runtime: None,
                    plist: None,
                    session_id: None,
                    confidence: Confidence::Unknown,
                    evidence: Vec::new(),
                    is_partial: false,
                }])
            }
        }
    }

    let collector = Arc::new(RecoveringCollector {
        is_first: AtomicBool::new(true),
    });
    let mut worker = ServiceBackgroundWorker::new(collector);

    // Gen 1: partial snapshot
    worker.trigger_refresh(1, Vec::new(), Vec::new());
    let start = std::time::Instant::now();
    while !worker.is_partial() && start.elapsed() < Duration::from_secs(1) {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(worker.is_partial());
    assert!(worker.warning().unwrap().contains("Partial snapshot"));

    // Gen 2: complete recovery
    worker.trigger_refresh(2, Vec::new(), Vec::new());
    let start = std::time::Instant::now();
    while (worker.is_partial() || worker.current_generation() < 2)
        && start.elapsed() < Duration::from_secs(1)
    {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !worker.is_partial(),
        "Snapshot should have recovered from partial to complete"
    );
    assert!(
        worker.warning().is_none(),
        "Warning should clear on complete collection"
    );
    let cached = worker.get_cached_services();
    assert_eq!(cached[0].label, "com.test.complete");

    let _ = worker.stop(Duration::from_millis(500));
}

// =============================================================================
// 29. Background Worker Lifecycle & Lock Poisoning Tests
// =============================================================================

#[test]
fn test_service_background_worker_lock_poisoning_recovery() {
    use std::sync::Arc;
    use std::time::Duration;
    use timmy::platform::traits::{PlatformError, ServiceCollector};
    use timmy::platform::ServiceBackgroundWorker;

    struct DummyCollector;
    impl ServiceCollector for DummyCollector {
        fn collect_services(&self) -> Result<Vec<ServiceInfo>, PlatformError> {
            Ok(vec![ServiceInfo {
                name: "dummy".to_string(),
                kind: ServiceKind::LaunchAgentUser,
                status: ServiceStatus::Running,
                state: ServiceState::Running,
                plist_status: PlistStatus::NotDiscovered,
                runtime_status: RuntimeStatus::Running { pid: 99 },
                pid: Some(99),
                label: "com.dummy".to_string(),
                path: None,
                domain: None,
                last_exit_status: None,
                runtime: None,
                plist: None,
                session_id: None,
                confidence: Confidence::Unknown,
                evidence: Vec::new(),
                is_partial: false,
            }])
        }
    }

    let collector = Arc::new(DummyCollector);
    let mut worker = ServiceBackgroundWorker::new(collector);

    worker.trigger_refresh(1, Vec::new(), Vec::new());
    let start = std::time::Instant::now();
    while worker.get_cached_services().is_empty() && start.elapsed() < Duration::from_secs(1) {
        std::thread::sleep(Duration::from_millis(10));
    }

    let cached = worker.get_cached_services();
    assert_eq!(cached.len(), 1);
    assert_eq!(cached[0].name, "dummy");
    assert!(!worker.is_refreshing());
    assert!(!worker.is_partial());

    let _ = worker.stop(Duration::from_millis(500));
}

// =============================================================================
// 30. End-to-End Secret Sanitization Across All Surfaces Tests
// =============================================================================

#[test]
fn test_secret_sanitization_end_to_end_all_surfaces() {
    let secret_token = "sk-ant-topsecret-live-credential-xyz987";
    let db_auth = "postgres://rootuser:supersecretpass999@internal.db:5432/secrets";
    let socket_secret = "sk-proj-socket-credential-4321";
    let error_token = "ghp_PersonalAccessTokenLeak123456";

    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.anthropic.agent</string>
    <key>Program</key>
    <string>/usr/local/bin/agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/agent</string>
        <string>--api-key</string>
        <string>{}</string>
        <string>--db</string>
        <string>{}</string>
    </array>
    <key>Sockets</key>
    <dict>
        <key>Listeners</key>
        <dict>
            <key>SockServiceName</key>
            <string>{}</string>
        </dict>
    </dict>
    <key>EnvironmentVariables</key>
    <dict>
        <key>OPENAI_API_KEY</key>
        <string>SUPER_CONFIDENTIAL_VALUE_NEVER_STORED</string>
    </dict>
</dict>
</plist>"#,
        secret_token, db_auth, socket_secret
    );

    let path = PathBuf::from("/Users/test/all_surfaces.plist");
    let detail = parse_plist_content(xml.as_bytes(), path);

    // 1. Verify EnvironmentVariables values were never read or stored
    assert_eq!(detail.environment_variable_names, vec!["OPENAI_API_KEY"]);

    let plists = vec![(detail, LaunchdDomain::User, ServiceKind::LaunchAgentUser)];
    let services = reconcile_services(plists, Vec::new());
    assert_eq!(services.len(), 1);

    // 2. In-memory checks: ProgramArguments, executable, and sockets
    let svc = &services[0];
    assert!(!svc.plist.as_ref().unwrap().program_arguments[2].contains(secret_token));
    assert!(svc.plist.as_ref().unwrap().program_arguments[2].contains("[REDACTED]"));
    assert!(!svc.plist.as_ref().unwrap().program_arguments[4].contains("supersecretpass999"));
    assert!(svc.plist.as_ref().unwrap().program_arguments[4].contains("[REDACTED]"));

    // 3. Debug formatting test: format!("{:?}", svc) must not contain any sensitive values
    let debug_str = format!("{:?}", svc);
    assert!(
        !debug_str.contains(secret_token),
        "Debug representation leaked secret_token"
    );
    assert!(
        !debug_str.contains("supersecretpass999"),
        "Debug representation leaked db password"
    );
    assert!(
        !debug_str.contains("SUPER_CONFIDENTIAL_VALUE_NEVER_STORED"),
        "Debug representation leaked env value"
    );

    // 4. JSON serialization test: serde_json::to_string(svc) must not contain sensitive values
    let json_str = serde_json::to_string(svc).unwrap();
    assert!(!json_str.contains(secret_token), "JSON leaked secret_token");
    assert!(
        !json_str.contains("supersecretpass999"),
        "JSON leaked db password"
    );
    assert!(
        !json_str.contains("SUPER_CONFIDENTIAL_VALUE_NEVER_STORED"),
        "JSON leaked env value"
    );

    // 5. Useful identities are preserved
    assert_eq!(svc.name, "agent");
    assert_eq!(svc.label, "com.anthropic.agent");
    assert_eq!(svc.executable_or_program(), Some("/usr/local/bin/agent"));

    // 6. Verify error sanitization with error_token
    let broken_xml = format!(
        "<plist><dict><key>Token</key><string>{}</string><key>Broken<",
        error_token
    );
    let broken_detail = parse_plist_content(
        broken_xml.as_bytes(),
        PathBuf::from("/Users/test/err.plist"),
    );
    assert!(broken_detail.parse_error.is_some());
    let err_str = broken_detail.parse_error.unwrap();
    assert!(
        !err_str.contains(error_token),
        "Parse error exposed raw token"
    );
}

// =============================================================================
// 31. Output-Limit Boundary Behavior Verification
// =============================================================================

#[test]
fn test_bounded_subprocess_stdout_boundary_zero_bytes() {
    use std::time::Duration;
    use timmy::platform::macos::launchd::run_command_bounded_ext;

    // 0 bytes output with limit of 100
    let res = run_command_bounded_ext("sh", &["-c", ""], Duration::from_millis(1000), 100, 100);
    assert!(res.is_ok());
    let out = res.unwrap();
    assert_eq!(out.stdout.len(), 0);
    assert!(!out.stdout_truncated);
    assert!(!out.stderr_truncated);
    assert!(!out.truncated);
    assert!(!out.timed_out);
    assert_eq!(out.status, Some(0));
}

#[test]
fn test_bounded_subprocess_stdout_boundary_limit_minus_one() {
    use std::time::Duration;
    use timmy::platform::macos::launchd::run_command_bounded_ext;

    // Exactly 99 bytes with limit of 100
    let res = run_command_bounded_ext(
        "sh",
        &["-c", "printf '%099d' 0"],
        Duration::from_millis(1000),
        100,
        100,
    );
    assert!(res.is_ok());
    let out = res.unwrap();
    assert_eq!(out.stdout.len(), 99);
    assert!(!out.stdout_truncated);
    assert!(!out.stderr_truncated);
    assert!(!out.truncated);
}

#[test]
fn test_bounded_subprocess_stdout_boundary_exact_limit() {
    use std::time::Duration;
    use timmy::platform::macos::launchd::run_command_bounded_ext;

    // Exactly 100 bytes with limit of 100
    // Crucial: Reaching the exact limit without subsequent data is NOT truncation!
    let res = run_command_bounded_ext(
        "sh",
        &["-c", "printf '%0100d' 0"],
        Duration::from_millis(1000),
        100,
        100,
    );
    assert!(res.is_ok());
    let out = res.unwrap();
    assert_eq!(out.stdout.len(), 100);
    assert!(
        !out.stdout_truncated,
        "Exact limit reached at EOF must not be marked truncated"
    );
    assert!(!out.truncated);
}

#[test]
fn test_bounded_subprocess_stdout_boundary_limit_plus_one() {
    use std::time::Duration;
    use timmy::platform::macos::launchd::run_command_bounded_ext;

    // Exactly 101 bytes with limit of 100 (1 byte beyond limit)
    let res = run_command_bounded_ext(
        "sh",
        &["-c", "printf '%0101d' 0"],
        Duration::from_millis(1000),
        100,
        100,
    );
    assert!(res.is_ok());
    let out = res.unwrap();
    assert_eq!(out.stdout.len(), 100);
    assert!(
        out.stdout_truncated,
        "Output exceeding limit by 1 byte must be marked truncated"
    );
    assert!(out.truncated);
}

#[test]
fn test_bounded_subprocess_stdout_boundary_several_times_limit() {
    use std::time::Duration;
    use timmy::platform::macos::launchd::run_command_bounded_ext;

    // 500 bytes with limit of 100 (5x limit)
    let res = run_command_bounded_ext(
        "sh",
        &["-c", "printf '%0500d' 0"],
        Duration::from_millis(1000),
        100,
        100,
    );
    assert!(res.is_ok());
    let out = res.unwrap();
    assert_eq!(out.stdout.len(), 100);
    assert!(out.stdout_truncated);
    assert!(out.truncated);
}

#[test]
fn test_bounded_subprocess_stderr_boundary_conditions() {
    use std::time::Duration;
    use timmy::platform::macos::launchd::run_command_bounded_ext;

    // 1. 0 bytes on stderr
    let res0 = run_command_bounded_ext("sh", &["-c", ""], Duration::from_millis(1000), 1000, 100);
    let out0 = res0.unwrap();
    assert_eq!(out0.stderr.len(), 0);
    assert!(!out0.stderr_truncated);

    // 2. 99 bytes on stderr
    let res99 = run_command_bounded_ext(
        "sh",
        &["-c", "printf '%099d' 0 >&2"],
        Duration::from_millis(1000),
        1000,
        100,
    );
    let out99 = res99.unwrap();
    assert_eq!(out99.stderr.len(), 99);
    assert!(!out99.stderr_truncated);
    assert!(!out99.truncated);

    // 3. Exactly 100 bytes on stderr
    let res100 = run_command_bounded_ext(
        "sh",
        &["-c", "printf '%0100d' 0 >&2"],
        Duration::from_millis(1000),
        1000,
        100,
    );
    let out100 = res100.unwrap();
    assert_eq!(out100.stderr.len(), 100);
    assert!(
        !out100.stderr_truncated,
        "Exact stderr limit reached at EOF must not be marked truncated"
    );
    assert!(!out100.truncated);

    // 4. Exactly 101 bytes on stderr (1 byte beyond limit)
    let res101 = run_command_bounded_ext(
        "sh",
        &["-c", "printf '%0101d' 0 >&2"],
        Duration::from_millis(1000),
        1000,
        100,
    );
    let out101 = res101.unwrap();
    assert_eq!(out101.stderr.len(), 100);
    assert!(
        out101.stderr_truncated,
        "Stderr exceeding limit by 1 byte must be marked truncated"
    );
    assert!(out101.truncated);

    // 5. 500 bytes on stderr (5x limit)
    let res500 = run_command_bounded_ext(
        "sh",
        &["-c", "printf '%0500d' 0 >&2"],
        Duration::from_millis(1000),
        1000,
        100,
    );
    let out500 = res500.unwrap();
    assert_eq!(out500.stderr.len(), 100);
    assert!(out500.stderr_truncated);
    assert!(out500.truncated);
}

// =============================================================================
// 32. Session-Tracked Process Provenance Verification (6 Scenarios)
// =============================================================================

fn make_test_service(spid: u32, label: &str, exe: &str) -> ServiceInfo {
    ServiceInfo {
        name: label.to_string(),
        kind: ServiceKind::LaunchAgentUser,
        status: ServiceStatus::Running,
        state: ServiceState::Running,
        plist_status: PlistStatus::Valid {
            path: PathBuf::from(format!("/Users/test/{}.plist", label)),
        },
        runtime_status: RuntimeStatus::Running { pid: spid },
        pid: Some(spid),
        label: label.to_string(),
        path: Some(format!("/Users/test/{}.plist", label)),
        domain: Some(LaunchdDomain::User),
        last_exit_status: Some(0),
        runtime: None,
        plist: Some(LaunchdPlistDetail {
            source_path: PathBuf::from(format!("/Users/test/{}.plist", label)),
            label: Some(label.to_string()),
            program: Some(exe.to_string()),
            program_arguments: vec![exe.to_string()],
            executable_path: Some(exe.to_string()),
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
            parse_error: None,
        }),
        session_id: None,
        confidence: Confidence::Unknown,
        evidence: Vec::new(),
        is_partial: false,
    }
}

fn make_test_process(
    pid: u32,
    ppid: Option<u32>,
    name: &str,
    exe_str: &str,
    start_time: u64,
    attr_kind: AgentKind,
    attr_confidence: Confidence,
) -> ProcessInfo {
    ProcessInfo {
        pid,
        ppid,
        name: name.to_string(),
        exe: Some(PathBuf::from(exe_str)),
        cpu_usage: Some(1.0),
        memory_bytes: Some(64 * 1024 * 1024),
        run_time_secs: 10,
        start_time: Some(start_time),
        user: Some("testuser".to_string()),
        attribution: AgentAttribution {
            kind: attr_kind,
            confidence: attr_confidence,
            reason: "Process inspection".to_string(),
            evidence: exe_str.to_string(),
            parent_pid: ppid,
            parent_name: None,
            root_agent_pid: ppid,
            root_agent_name: None,
            is_confirmed: attr_confidence == Confidence::Confirmed,
            safe_to_terminate: false,
        },
        listening_ports: Vec::new(),
        cmdline: vec![exe_str.to_string()],
        command_outcome: None,
        provenance: None,
        ..Default::default()
    }
}

fn make_test_session(
    id: &str,
    agent_kind: AgentKind,
    status: SessionStatus,
    start_time: chrono::DateTime<chrono::Utc>,
    root_pid: Option<u32>,
    tracked_pids: Vec<u32>,
) -> SessionInfo {
    SessionInfo {
        id: id.to_string(),
        agent_kind,
        status,
        start_time,
        end_time: None,
        root_pid,
        root_process_name: Some("agent-cli".to_string()),
        confidence: Confidence::Confirmed,
        evidence: Vec::new(),
        tracked_pids,
        total_memory_bytes: 0,
        total_cpu_usage: 0.0,
        open_ports: Vec::new(),
        resource_count: 1,
        root_binding: None,
    }
}

// =============================================================================
// 32. Structured Launch Provenance & Adversarial Regression Tests
// =============================================================================

#[test]
fn test_adversarial_scenario_01_genuine_structured_root_binding() {
    // Scenario 1: A genuine structured root-binding event for the exact root process identity.
    let now = chrono::Utc::now();
    let now_secs = now.timestamp().max(0) as u64;

    let mut services = vec![make_test_service(
        1000,
        "com.anthropic.claude",
        "/usr/local/bin/claude",
    )];
    let processes = vec![make_test_process(
        1000,
        Some(1),
        "claude",
        "/usr/local/bin/claude",
        now_secs,
        AgentKind::ClaudeCode,
        Confidence::Confirmed,
    )];
    let mut session = make_test_session(
        "sess-root-1",
        AgentKind::ClaudeCode,
        SessionStatus::Active,
        now,
        Some(1000),
        vec![1000],
    );
    session.root_binding = Some(LaunchProvenance::root_binding(
        "sess-root-1".to_string(),
        1000,
        Some(now_secs),
        "claude".to_string(),
        Some(PathBuf::from("/usr/local/bin/claude")),
        Some(1),
        "Verified live root agent binding".to_string(),
    ));
    let sessions = vec![session];

    ServiceDiscoveryCoordinator::correlate_services(&mut services, &processes, &sessions);

    assert_eq!(services[0].session_id, Some("sess-root-1".to_string()));
    assert_eq!(
        services[0].confidence,
        Confidence::Confirmed,
        "Exact structured root-binding match with confirmed attribution must be Confirmed"
    );
    assert!(services[0].evidence.iter().any(|e| e.contains(
        "Confirmed ownership: service PID and executable match verified session root process identity"
    )));
}

#[test]
fn test_adversarial_scenario_02_root_pid_no_structured_binding() {
    // Scenario 2: A root PID with no structured binding event.
    // Demonstrates removal of the automatic root bypass: A matching PID alone is insufficient.
    let now = chrono::Utc::now();
    let now_secs = now.timestamp().max(0) as u64;

    let mut services = vec![make_test_service(
        1000,
        "com.anthropic.claude",
        "/usr/local/bin/claude",
    )];
    let processes = vec![make_test_process(
        1000,
        Some(1),
        "claude",
        "/usr/local/bin/claude",
        now_secs,
        AgentKind::ClaudeCode,
        Confidence::Confirmed,
    )];
    let mut session = make_test_session(
        "sess-root-2",
        AgentKind::ClaudeCode,
        SessionStatus::Active,
        now,
        Some(1000),
        vec![1000],
    );
    session.root_binding = None; // NO STRUCTURED BINDING!
    let sessions = vec![session];

    ServiceDiscoveryCoordinator::correlate_services(&mut services, &processes, &sessions);

    assert_eq!(services[0].session_id, Some("sess-root-2".to_string()));
    assert_eq!(
        services[0].confidence,
        Confidence::Inferred,
        "Root PID without structured binding event must NEVER receive HighConfidence or Confirmed; capped at Inferred"
    );
    assert!(services[0]
        .evidence
        .iter()
        .any(|e| e.contains("Unverified root binding")
            && e.contains("lacks an independently recorded root process identity or start time")));
}

// =============================================================================
// Dedicated Tests for Root PID Attribution Matrix
// =============================================================================

#[test]
fn test_unverified_root_case_01_no_recorded_start_time() {
    // 1. Unverified root PID with no recorded start time:
    // Session has root_pid: Some(1000), root_binding: None.
    // Live process has start_time: None.
    let now = chrono::Utc::now();
    let mut services = vec![make_test_service(
        1000,
        "com.anthropic.claude",
        "/usr/local/bin/claude",
    )];
    let mut proc = make_test_process(
        1000,
        Some(1),
        "claude",
        "/usr/local/bin/claude",
        0,
        AgentKind::ClaudeCode,
        Confidence::Confirmed,
    );
    proc.start_time = None; // No start time in process snapshot
    let processes = vec![proc];
    let mut session = make_test_session(
        "sess-case-01",
        AgentKind::ClaudeCode,
        SessionStatus::Active,
        now,
        Some(1000),
        vec![1000],
    );
    session.root_binding = None;
    let sessions = vec![session];

    ServiceDiscoveryCoordinator::correlate_services(&mut services, &processes, &sessions);

    assert_eq!(services[0].session_id, Some("sess-case-01".to_string()));
    assert_eq!(
        services[0].confidence,
        Confidence::Inferred,
        "Unverified root PID with missing start time must be capped at Inferred"
    );
    assert!(services[0]
        .evidence
        .iter()
        .any(|e| e.contains("cannot disprove PID recycling")
            || e.contains("process start time is unavailable")));
}

#[test]
fn test_unverified_root_case_02_live_start_time_no_stored_identity() {
    // 2. Unverified root PID with live non-null start time but no stored comparison identity:
    // Session has root_pid: Some(1000), root_binding: None.
    // Live process has start_time: Some(now_secs).
    // Agent attribution: Confirmed.
    // Invariant: Must NEVER receive HighConfidence or Confirmed; capped strictly at Inferred.
    let now = chrono::Utc::now();
    let now_secs = now.timestamp().max(0) as u64;
    let mut services = vec![make_test_service(
        1000,
        "com.anthropic.claude",
        "/usr/local/bin/claude",
    )];
    let processes = vec![make_test_process(
        1000,
        Some(1),
        "claude",
        "/usr/local/bin/claude",
        now_secs,
        AgentKind::ClaudeCode,
        Confidence::Confirmed,
    )];
    let mut session = make_test_session(
        "sess-case-02",
        AgentKind::ClaudeCode,
        SessionStatus::Active,
        now,
        Some(1000),
        vec![1000],
    );
    session.root_binding = None;
    let sessions = vec![session];

    ServiceDiscoveryCoordinator::correlate_services(&mut services, &processes, &sessions);

    assert_eq!(services[0].session_id, Some("sess-case-02".to_string()));
    assert_eq!(
        services[0].confidence,
        Confidence::Inferred,
        "Unverified root PID without stored comparison identity must NEVER receive HighConfidence; strictly capped at Inferred"
    );
    assert!(services[0]
        .evidence
        .iter()
        .any(|e| e.contains("Unverified root binding")
            && e.contains("lacks an independently recorded root process identity or start time")));
}

#[test]
fn test_unverified_root_case_03_verified_root_matching_identity() {
    // 3. Verified root binding with matching identity:
    // Session has structured VerifiedSessionRootBinding matching live process PID, start_time, exe, and confirmed agent attribution.
    let now = chrono::Utc::now();
    let now_secs = now.timestamp().max(0) as u64;
    let mut services = vec![make_test_service(
        1000,
        "com.anthropic.claude",
        "/usr/local/bin/claude",
    )];
    let processes = vec![make_test_process(
        1000,
        Some(1),
        "claude",
        "/usr/local/bin/claude",
        now_secs,
        AgentKind::ClaudeCode,
        Confidence::Confirmed,
    )];
    let mut session = make_test_session(
        "sess-case-03",
        AgentKind::ClaudeCode,
        SessionStatus::Active,
        now,
        Some(1000),
        vec![1000],
    );
    session.root_binding = Some(LaunchProvenance::verified_session_root_binding(
        "sess-case-03".to_string(),
        1000,
        Some(now_secs),
        "claude".to_string(),
        Some(std::path::PathBuf::from("/usr/local/bin/claude")),
        Some(1),
        "Verified live root agent binding".to_string(),
    ));
    let sessions = vec![session];

    ServiceDiscoveryCoordinator::correlate_services(&mut services, &processes, &sessions);

    assert_eq!(services[0].session_id, Some("sess-case-03".to_string()));
    assert_eq!(
        services[0].confidence,
        Confidence::Confirmed,
        "Verified root binding with exact identity and confirmed agent attribution must be Confirmed"
    );
    assert!(services[0].evidence.iter().any(|e| e.contains(
        "Confirmed ownership: service PID and executable match verified session root process identity"
    )));
}

#[test]
fn test_unverified_root_case_04_verified_root_mismatching_start_time() {
    // 4. Verified root binding with mismatching start time:
    // Session has structured root binding with start_time = 1000.
    // Live process with PID 1000 has start_time = 2000 (PID recycling!).
    // Invariant: Claim must be rejected, service unassigned (Unknown).
    let sess_time = chrono::DateTime::from_timestamp(1000, 0).unwrap();
    let mut services = vec![make_test_service(
        1000,
        "com.anthropic.claude",
        "/usr/local/bin/claude",
    )];
    let processes = vec![make_test_process(
        1000,
        Some(1),
        "claude",
        "/usr/local/bin/claude",
        2000,
        AgentKind::ClaudeCode,
        Confidence::Confirmed,
    )];
    let mut session = make_test_session(
        "sess-case-04",
        AgentKind::ClaudeCode,
        SessionStatus::Active,
        sess_time,
        Some(1000),
        vec![1000],
    );
    session.root_binding = Some(LaunchProvenance::verified_session_root_binding(
        "sess-case-04".to_string(),
        1000,
        Some(1000), // Different start time!
        "claude".to_string(),
        Some(std::path::PathBuf::from("/usr/local/bin/claude")),
        Some(1),
        "Verified root binding".to_string(),
    ));
    let sessions = vec![session];

    ServiceDiscoveryCoordinator::correlate_services(&mut services, &processes, &sessions);

    assert_eq!(
        services[0].session_id, None,
        "Mismatched start time must reject session ownership"
    );
    assert_eq!(services[0].confidence, Confidence::Unknown);
    assert!(services[0]
        .evidence
        .iter()
        .any(|e| e.contains("PID reuse check")
            && e.contains("differs from verified root binding; session claim rejected")));
}

#[test]
fn test_unverified_root_case_05_verified_root_missing_start_time() {
    // 5. Verified root binding where either identity has missing start time:
    // Case 5a: Live process has start_time: None.
    let now = chrono::Utc::now();
    let now_secs = now.timestamp().max(0) as u64;
    let mut services = vec![make_test_service(
        1000,
        "com.anthropic.claude",
        "/usr/local/bin/claude",
    )];
    let mut proc = make_test_process(
        1000,
        Some(1),
        "claude",
        "/usr/local/bin/claude",
        0,
        AgentKind::ClaudeCode,
        Confidence::Confirmed,
    );
    proc.start_time = None; // Live process missing start time
    let processes = vec![proc];
    let mut session = make_test_session(
        "sess-case-05",
        AgentKind::ClaudeCode,
        SessionStatus::Active,
        now,
        Some(1000),
        vec![1000],
    );
    session.root_binding = Some(LaunchProvenance::verified_session_root_binding(
        "sess-case-05".to_string(),
        1000,
        Some(now_secs),
        "claude".to_string(),
        Some(std::path::PathBuf::from("/usr/local/bin/claude")),
        Some(1),
        "Verified root binding".to_string(),
    ));
    let sessions = vec![session];

    ServiceDiscoveryCoordinator::correlate_services(&mut services, &processes, &sessions);

    assert_eq!(services[0].session_id, Some("sess-case-05".to_string()));
    assert_eq!(
        services[0].confidence,
        Confidence::Inferred,
        "Missing start time cannot verify identity; must be capped at Inferred"
    );
    assert!(services[0]
        .evidence
        .iter()
        .any(|e| e.contains("Identity limitation") || e.contains("cannot disprove PID recycling")));
}

#[test]
fn test_unverified_root_case_06_recycled_root_pid_different_executable() {
    // 6. Recycled root PID with a different executable:
    // Session recorded root binding with executable "claude".
    // Current live process with PID 1000 is "nginx" (/usr/sbin/nginx).
    // Invariant: Claim must be rejected due to binary mismatch, ownership unassigned (Unknown).
    let now = chrono::Utc::now();
    let now_secs = now.timestamp().max(0) as u64;
    let mut services = vec![make_test_service(
        1000,
        "com.nginx.webserver",
        "/usr/sbin/nginx",
    )];
    let processes = vec![make_test_process(
        1000,
        Some(1),
        "nginx",
        "/usr/sbin/nginx",
        now_secs,
        AgentKind::Unknown,
        Confidence::Unknown,
    )];
    let mut session = make_test_session(
        "sess-case-06",
        AgentKind::ClaudeCode,
        SessionStatus::Active,
        now,
        Some(1000),
        vec![1000],
    );
    session.root_binding = Some(LaunchProvenance::verified_session_root_binding(
        "sess-case-06".to_string(),
        1000,
        Some(now_secs),
        "claude".to_string(),
        Some(std::path::PathBuf::from("/usr/local/bin/claude")),
        Some(1),
        "Verified root binding".to_string(),
    ));
    let sessions = vec![session];

    ServiceDiscoveryCoordinator::correlate_services(&mut services, &processes, &sessions);

    assert_eq!(
        services[0].session_id, None,
        "Binary mismatch on recycled PID must reject session claim"
    );
    assert_eq!(services[0].confidence, Confidence::Unknown);
    assert!(services[0]
        .evidence
        .iter()
        .any(|e| e.contains("PID reuse check")
            && e.contains("differs from verified root binding; session claim rejected")));
}

#[test]
fn test_adversarial_scenario_03_direct_child_discovered_during_later_scan() {
    // Scenario 3: A direct child discovered during a later process-tree scan.
    // INVARIANT: Matching PPID plus executable similarity alone does NOT constitute multi-domain
    // independent evidence; confidence is strictly capped at Inferred.
    let now = chrono::Utc::now();
    let sess_start = (now.timestamp().max(0) as u64).saturating_sub(60);
    let proc_start = sess_start + 45;

    let mut services = vec![make_test_service(
        2001,
        "com.anthropic.claude.worker",
        "/usr/local/bin/claude",
    )];
    let mut proc = make_test_process(
        2001,
        Some(2000), // Child of root PID 2000
        "claude",
        "/usr/local/bin/claude",
        proc_start,
        AgentKind::ClaudeCode,
        Confidence::Confirmed,
    );
    proc.provenance = Some(LaunchProvenance::discovered_descendant(
        "sess-scan-3".to_string(),
        2001,
        Some(proc_start),
        "claude".to_string(),
        Some(PathBuf::from("/usr/local/bin/claude")),
        2000,
        "Descendant discovered during scan pass".to_string(),
    ));
    let processes = vec![proc];
    let sessions = vec![make_test_session(
        "sess-scan-3",
        AgentKind::ClaudeCode,
        SessionStatus::Active,
        chrono::DateTime::from_timestamp(sess_start as i64, 0).unwrap_or(now),
        Some(2000),
        vec![2000, 2001],
    )];

    ServiceDiscoveryCoordinator::correlate_services(&mut services, &processes, &sessions);

    assert_eq!(services[0].session_id, Some("sess-scan-3".to_string()));
    assert_eq!(
        services[0].confidence,
        Confidence::Inferred,
        "Matching PPID plus executable similarity alone must be capped at Inferred"
    );
    assert!(services[0]
        .evidence
        .iter()
        .any(|e| e.contains("Ancestry-only discovery")
            && e.contains("confidence capped at Inferred")));
}

#[test]
fn test_adversarial_scenario_04_matching_ppid_parent_never_observed_at_launch() {
    // Scenario 4: A process whose current PPID matches the session root but whose parent relationship
    // was never observed at launch.
    // INVARIANT: Current PPID matching root without independent corroboration must be capped at Inferred.
    let now = chrono::Utc::now();
    let sess_start = (now.timestamp().max(0) as u64).saturating_sub(30);
    let proc_start = sess_start + 10;

    let mut services = vec![make_test_service(
        3001,
        "com.anthropic.claude",
        "/usr/local/bin/claude",
    )];
    let processes = vec![make_test_process(
        3001,
        Some(3000), // PPID matches session root 3000 in snapshot
        "claude",
        "/usr/local/bin/claude",
        proc_start,
        AgentKind::ClaudeCode,
        Confidence::Confirmed,
    )];
    let sessions = vec![make_test_session(
        "sess-claude-4",
        AgentKind::ClaudeCode,
        SessionStatus::Active,
        chrono::DateTime::from_timestamp(sess_start as i64, 0).unwrap_or(now),
        Some(3000),
        vec![3000, 3001],
    )];

    ServiceDiscoveryCoordinator::correlate_services(&mut services, &processes, &sessions);

    assert_eq!(services[0].session_id, Some("sess-claude-4".to_string()));
    assert_eq!(
        services[0].confidence,
        Confidence::Inferred,
        "Current PPID matching root without independent corroboration must be capped at Inferred"
    );
    assert!(services[0]
        .evidence
        .iter()
        .any(|e| e.contains("confidence capped at Inferred")));
}

#[test]
fn test_adversarial_scenario_05_matching_executable_no_launch_provenance() {
    // Scenario 5: A process with a matching executable but no launch provenance or PID linkage.
    let now = chrono::Utc::now();
    let sess_start = (now.timestamp().max(0) as u64).saturating_sub(10);
    let proc_start = sess_start + 1;

    let mut services = vec![make_test_service(
        4000,
        "com.ollama.daemon",
        "/usr/local/bin/ollama",
    )];
    let processes = vec![make_test_process(
        4000,
        Some(1),
        "ollama",
        "/usr/local/bin/ollama",
        proc_start,
        AgentKind::GenericLlmAgent("ollama".to_string()),
        Confidence::Confirmed,
    )];
    let sessions = vec![make_test_session(
        "sess-unrelated-cursor",
        AgentKind::Cursor,
        SessionStatus::Active,
        chrono::DateTime::from_timestamp(sess_start as i64, 0).unwrap_or(now),
        Some(5000),
        vec![5000, 5001],
    )];

    ServiceDiscoveryCoordinator::correlate_services(&mut services, &processes, &sessions);

    assert_eq!(services[0].session_id, None);
    assert_eq!(services[0].confidence, Confidence::Unknown);
}

#[test]
fn test_adversarial_scenario_06_heuristic_process_added_to_tracked_pids() {
    // Scenario 6: A heuristic process added to tracked_pids.
    let now = chrono::Utc::now();
    let sess_start = (now.timestamp().max(0) as u64).saturating_sub(10);
    let proc_start = sess_start + 2;

    let mut services = vec![make_test_service(
        4100,
        "com.dev.server",
        "/usr/local/bin/node",
    )];
    let mut proc = make_test_process(
        4100,
        Some(1),
        "node",
        "/usr/local/bin/node",
        proc_start,
        AgentKind::GenericLlmAgent("node".to_string()),
        Confidence::Inferred,
    );
    proc.provenance = Some(LaunchProvenance::heuristic_association(
        "sess-windsurf-6".to_string(),
        4100,
        Some(proc_start),
        "node".to_string(),
        Some(PathBuf::from("/usr/local/bin/node")),
        "Heuristic port-holder association".to_string(),
    ));
    let processes = vec![proc];
    let sessions = vec![make_test_session(
        "sess-windsurf-6",
        AgentKind::Windsurf,
        SessionStatus::Active,
        chrono::DateTime::from_timestamp(sess_start as i64, 0).unwrap_or(now),
        Some(4000),
        vec![4000, 4100],
    )];

    ServiceDiscoveryCoordinator::correlate_services(&mut services, &processes, &sessions);

    assert_eq!(services[0].session_id, Some("sess-windsurf-6".to_string()));
    assert_eq!(
        services[0].confidence,
        Confidence::Inferred,
        "Heuristic association must strictly be capped at Inferred"
    );
    assert!(services[0]
        .evidence
        .iter()
        .any(|e| e.contains("Provenance guard: tracked process attribution basis is HeuristicAssociation; confidence capped at Inferred")));
}

#[test]
fn test_adversarial_scenario_07_pid_reused_by_different_process() {
    // Scenario 7: A PID reused by a different process with a different start time.
    let sess_time = chrono::DateTime::from_timestamp(1000, 0).unwrap();

    let mut services = vec![make_test_service(
        5000,
        "com.reused.service",
        "/usr/local/bin/claude",
    )];
    // Live process occupying PID 5000 was started at timestamp 2000
    let processes = vec![make_test_process(
        5000,
        Some(1),
        "claude",
        "/usr/local/bin/claude",
        2000,
        AgentKind::ClaudeCode,
        Confidence::Confirmed,
    )];
    let mut session = make_test_session(
        "sess-reused-7",
        AgentKind::ClaudeCode,
        SessionStatus::Active,
        sess_time,
        Some(5000),
        vec![5000],
    );
    // Root binding was recorded for PID 5000 at timestamp 1000!
    session.root_binding = Some(LaunchProvenance::root_binding(
        "sess-reused-7".to_string(),
        5000,
        Some(1000),
        "claude".to_string(),
        Some(PathBuf::from("/usr/local/bin/claude")),
        Some(1),
        "Original session root".to_string(),
    ));
    let sessions = vec![session];

    ServiceDiscoveryCoordinator::correlate_services(&mut services, &processes, &sessions);

    assert_eq!(
        services[0].session_id, None,
        "Recycled PID with different start time must be rejected"
    );
    assert_eq!(services[0].confidence, Confidence::Unknown);
    assert!(services[0]
        .evidence
        .iter()
        .any(|e| e.contains("PID reuse check")
            && e.contains("differs from verified root binding; session claim rejected")));
}

#[test]
fn test_adversarial_scenario_08_fabricated_session_evidence_string_ignored() {
    // Scenario 8: A fabricated session evidence string containing 'observed launch PID 2001'.
    // Invariant: Substring matching in display strings is forbidden and cannot grant Confirmed.
    let now = chrono::Utc::now();
    let sess_start = (now.timestamp().max(0) as u64).saturating_sub(20);
    let proc_start = sess_start + 5;

    let mut services = vec![make_test_service(
        2001,
        "com.anthropic.claude",
        "/usr/local/bin/claude",
    )];
    let processes = vec![make_test_process(
        2001,
        Some(2000),
        "claude",
        "/usr/local/bin/claude",
        proc_start,
        AgentKind::ClaudeCode,
        Confidence::Confirmed,
    )];
    let mut session = make_test_session(
        "sess-fake-text-8",
        AgentKind::ClaudeCode,
        SessionStatus::Active,
        chrono::DateTime::from_timestamp(sess_start as i64, 0).unwrap_or(now),
        Some(2000),
        vec![2000, 2001],
    );
    // Inject attacker/bug text in free-text evidence
    session
        .evidence
        .push("observed launch PID 2001 by AI agent".to_string());
    session
        .evidence
        .push("explicit session launch PID 2001".to_string());
    session.root_binding = None;
    let sessions = vec![session];

    ServiceDiscoveryCoordinator::correlate_services(&mut services, &processes, &sessions);

    assert_eq!(services[0].session_id, Some("sess-fake-text-8".to_string()));
    assert_ne!(
        services[0].confidence,
        Confidence::Confirmed,
        "Fabricated substring in session evidence must NOT grant Confirmed attribution!"
    );
    assert_eq!(services[0].confidence, Confidence::Inferred);
}

#[test]
fn test_adversarial_scenario_09_fabricated_attribution_reason_string_ignored() {
    // Scenario 9: A fabricated attribution reason containing 'explicit session launch'.
    let now = chrono::Utc::now();
    let sess_start = (now.timestamp().max(0) as u64).saturating_sub(20);
    let proc_start = sess_start + 5;

    let mut services = vec![make_test_service(
        2001,
        "com.anthropic.claude",
        "/usr/local/bin/claude",
    )];
    let mut proc = make_test_process(
        2001,
        Some(2000),
        "claude",
        "/usr/local/bin/claude",
        proc_start,
        AgentKind::ClaudeCode,
        Confidence::Confirmed,
    );
    // Inject fabricated strings in attribution fields
    proc.attribution.reason = "explicit session launch of container/process".to_string();
    proc.attribution.evidence = "observed at launch in session envelope".to_string();
    proc.provenance = None;
    let processes = vec![proc];

    let session = make_test_session(
        "sess-fake-reason-9",
        AgentKind::ClaudeCode,
        SessionStatus::Active,
        chrono::DateTime::from_timestamp(sess_start as i64, 0).unwrap_or(now),
        Some(2000),
        vec![2000, 2001],
    );
    let sessions = vec![session];

    ServiceDiscoveryCoordinator::correlate_services(&mut services, &processes, &sessions);

    assert_eq!(
        services[0].session_id,
        Some("sess-fake-reason-9".to_string())
    );
    assert_ne!(
        services[0].confidence,
        Confidence::Confirmed,
        "Fabricated string in attribution reason must NOT grant Confirmed attribution!"
    );
    assert_eq!(services[0].confidence, Confidence::Inferred);
}

#[test]
fn test_adversarial_scenario_10_conflicting_session_claims_unresolved_unknown() {
    // Scenario 10: Two active sessions claiming the same process.
    let now = chrono::Utc::now();
    let sess_start = (now.timestamp().max(0) as u64).saturating_sub(10);
    let proc_start = sess_start + 2;

    let mut services = vec![make_test_service(
        6000,
        "com.shared.daemon",
        "/usr/local/bin/agent",
    )];
    let processes = vec![make_test_process(
        6000,
        Some(1000),
        "agent",
        "/usr/local/bin/agent",
        proc_start,
        AgentKind::ClaudeCode,
        Confidence::Confirmed,
    )];
    let sessions = vec![
        make_test_session(
            "sess-alpha",
            AgentKind::ClaudeCode,
            SessionStatus::Active,
            chrono::DateTime::from_timestamp(sess_start as i64, 0).unwrap_or(now),
            Some(1000),
            vec![1000, 6000],
        ),
        make_test_session(
            "sess-beta",
            AgentKind::Cursor,
            SessionStatus::Active,
            chrono::DateTime::from_timestamp(sess_start as i64, 0).unwrap_or(now),
            Some(2000),
            vec![2000, 6000],
        ),
    ];

    ServiceDiscoveryCoordinator::correlate_services(&mut services, &processes, &sessions);

    assert_eq!(
        services[0].session_id, None,
        "Ownership must remain unresolved when multiple sessions claim it"
    );
    assert_eq!(services[0].confidence, Confidence::Unknown);
    assert!(services[0].evidence.iter().any(|e| e
        .contains("Conflicting attribution: multiple sessions claim this service")
        && e.contains("sess-alpha")
        && e.contains("sess-beta")));
}

#[test]
fn test_adversarial_scenario_11_structured_provenance_persists_and_reloads_in_db() {
    // Scenario 11: Structured provenance surviving database persistence and reload.
    use timmy::model::session::TrackedResource;
    use timmy::storage::StorageManager;

    let storage = StorageManager::open_in_memory().expect("Should open memory db");
    let now = chrono::Utc::now();
    let now_secs = now.timestamp().max(0) as u64;

    let root_prov = LaunchProvenance::verified_session_root_binding(
        "sess-db-11".to_string(),
        8000,
        Some(now_secs),
        "claude".to_string(),
        Some(PathBuf::from("/usr/local/bin/claude")),
        Some(1),
        "Verified root binding event".to_string(),
    );

    let session = SessionInfo {
        id: "sess-db-11".to_string(),
        agent_kind: AgentKind::ClaudeCode,
        status: SessionStatus::Active,
        start_time: now,
        end_time: None,
        root_pid: Some(8000),
        root_process_name: Some("claude".to_string()),
        confidence: Confidence::Confirmed,
        evidence: vec!["DB persistence test".to_string()],
        tracked_pids: vec![8000, 8001],
        total_memory_bytes: 1024 * 1024 * 10,
        total_cpu_usage: 0.5,
        open_ports: vec![9090],
        resource_count: 2,
        root_binding: Some(root_prov.clone()),
    };

    storage.save_session(&session).expect("Must save session");

    let child_prov = LaunchProvenance::discovered_descendant(
        "sess-db-11".to_string(),
        8001,
        Some(now_secs + 1),
        "node".to_string(),
        Some(PathBuf::from("/usr/local/bin/node")),
        8000,
        "Child worker discovered in process tree".to_string(),
    );

    let res = TrackedResource {
        session_id: "sess-db-11".to_string(),
        pid: Some(8001),
        name: "node".to_string(),
        exe_path: Some("/usr/local/bin/node".to_string()),
        memory_bytes: Some(1024 * 1024 * 20),
        cpu_usage: Some(0.8),
        listening_ports: vec![9090],
        confidence: Confidence::HighConfidence,
        evidence: vec!["Tree scan".to_string()],
        is_detached: false,
        is_protected: false,
        safe_to_terminate: true,
        first_seen: now,
        last_seen: now,
        process_start_time: Some(now_secs + 1),
        provenance: Some(child_prov.clone()),
    };

    storage
        .save_session_resources("sess-db-11", &[res])
        .expect("Must save resources");

    // Reload from SQLite database
    let reloaded_session = storage
        .get_session("sess-db-11")
        .expect("Query must succeed")
        .expect("Session must exist");
    assert!(reloaded_session.root_binding.is_some());
    let reloaded_root_b = reloaded_session.root_binding.unwrap();
    assert_eq!(reloaded_root_b.session_id, "sess-db-11");
    assert_eq!(
        reloaded_root_b.source,
        ProvenanceSource::VerifiedSessionRootBinding
    );
    assert_eq!(reloaded_root_b.process.pid, 8000);
    assert_eq!(reloaded_root_b.process.start_time, Some(now_secs));
    assert_eq!(reloaded_root_b.process.name, "claude");

    let reloaded_resources = storage
        .get_session_resources("sess-db-11")
        .expect("Resource query must succeed");
    assert_eq!(reloaded_resources.len(), 1);
    assert!(reloaded_resources[0].provenance.is_some());
    let reloaded_res_prov = reloaded_resources[0].provenance.as_ref().unwrap();
    assert_eq!(reloaded_res_prov.session_id, "sess-db-11");
    assert_eq!(
        reloaded_res_prov.source,
        ProvenanceSource::DiscoveredDescendant
    );
    assert_eq!(reloaded_res_prov.process.pid, 8001);
    assert_eq!(reloaded_res_prov.process.start_time, Some(now_secs + 1));
    assert_eq!(reloaded_res_prov.process.name, "node");
    assert_eq!(
        reloaded_res_prov.parent.as_ref().map(|p| p.ppid),
        Some(8000)
    );
}

#[test]
fn test_adversarial_scenario_12_reparented_to_pid1_retains_historical_association() {
    // Scenario 12: A process whose parent exits and which is subsequently reparented to PID 1.
    // INVARIANT: Reparenting preserves session linkage at Inferred (with is_detached = true), never Unknown.
    let now = chrono::Utc::now();
    let sess_start = (now.timestamp().max(0) as u64).saturating_sub(60);
    let proc_start = sess_start + 10;

    let mut services = vec![make_test_service(
        7001,
        "com.anthropic.claude.daemon",
        "/usr/local/bin/claude",
    )];
    // Process is now under PID 1 (launchd) due to parent termination reparenting
    let mut proc = make_test_process(
        7001,
        Some(1), // REPARENTED TO PID 1!
        "claude",
        "/usr/local/bin/claude",
        proc_start,
        AgentKind::ClaudeCode,
        Confidence::Confirmed,
    );
    // Historical provenance records that it was originally discovered as a descendant of session root 7000
    proc.provenance = Some(LaunchProvenance::discovered_descendant(
        "sess-reparent-12".to_string(),
        7001,
        Some(proc_start),
        "claude".to_string(),
        Some(PathBuf::from("/usr/local/bin/claude")),
        7000,
        "Originally discovered under agent tree before parent exit".to_string(),
    ));
    let processes = vec![proc];
    let sessions = vec![make_test_session(
        "sess-reparent-12",
        AgentKind::ClaudeCode,
        SessionStatus::Active,
        chrono::DateTime::from_timestamp(sess_start as i64, 0).unwrap_or(now),
        Some(7000),
        vec![7000, 7001], // Retained in session's tracked_pids
    )];

    ServiceDiscoveryCoordinator::correlate_services(&mut services, &processes, &sessions);

    assert_eq!(services[0].session_id, Some("sess-reparent-12".to_string()));
    assert_eq!(
        services[0].confidence,
        Confidence::Inferred,
        "Reparented process with historical association retains session linkage at Inferred, not Unknown"
    );
    assert!(services[0]
        .evidence
        .iter()
        .any(|e| e.contains("Ancestry-only discovery")
            && e.contains("confidence capped at Inferred")));
}

#[test]
fn test_adversarial_scenario_13_missing_start_time_cannot_confirm_identity() {
    // Scenario 13: Start time is missing (None) in candidate process or root binding.
    // INVARIANT: None == None NEVER validates identity! Missing start time makes PID recycling
    // impossible to disprove, strictly forbidding Confirmed and capping at Inferred.
    let now = chrono::Utc::now();

    let mut services = vec![make_test_service(
        8050,
        "com.anthropic.claude",
        "/usr/local/bin/claude",
    )];
    // Process has start_time: None!
    let mut proc = make_test_process(
        8050,
        Some(1),
        "claude",
        "/usr/local/bin/claude",
        0,
        AgentKind::ClaudeCode,
        Confidence::Confirmed,
    );
    proc.start_time = None;
    let processes = vec![proc];

    let mut session = make_test_session(
        "sess-missing-st-13",
        AgentKind::ClaudeCode,
        SessionStatus::Active,
        now,
        Some(8050),
        vec![8050],
    );
    // Root binding also has start_time: None!
    session.root_binding = Some(LaunchProvenance::verified_session_root_binding(
        "sess-missing-st-13".to_string(),
        8050,
        None, // MISSING START TIME!
        "claude".to_string(),
        Some(PathBuf::from("/usr/local/bin/claude")),
        Some(1),
        "Root binding lacking start time".to_string(),
    ));
    let sessions = vec![session];

    ServiceDiscoveryCoordinator::correlate_services(&mut services, &processes, &sessions);

    assert_eq!(
        services[0].session_id,
        Some("sess-missing-st-13".to_string())
    );
    assert_ne!(
        services[0].confidence,
        Confidence::Confirmed,
        "Missing start time MUST NEVER result in Confirmed attribution!"
    );
    assert_eq!(
        services[0].confidence,
        Confidence::Inferred,
        "Missing start time must cap confidence at Inferred due to PID recycling uncertainty"
    );
    assert!(services[0]
        .evidence
        .iter()
        .any(|e| e.contains("cannot disprove PID recycling")));
}

#[test]
fn test_adversarial_scenario_14_lexical_path_normalization_matches_process() {
    // Scenario 14: Executable paths differ syntactically (e.g. '.' or '..') but normalize to identical path.
    // INVARIANT: Lexical path normalization matches semantically identical executable paths.
    let now = chrono::Utc::now();
    let now_secs = now.timestamp().max(0) as u64;

    let mut services = vec![make_test_service(
        8100,
        "com.anthropic.claude",
        "/usr/local/bin/../bin/claude", // Non-canonical path in plist
    )];
    let processes = vec![make_test_process(
        8100,
        Some(1),
        "claude",
        "/usr/local/bin/claude", // Canonical path in process table
        now_secs,
        AgentKind::ClaudeCode,
        Confidence::Confirmed,
    )];
    let mut session = make_test_session(
        "sess-norm-14",
        AgentKind::ClaudeCode,
        SessionStatus::Active,
        now,
        Some(8100),
        vec![8100],
    );
    session.root_binding = Some(LaunchProvenance::verified_session_root_binding(
        "sess-norm-14".to_string(),
        8100,
        Some(now_secs),
        "claude".to_string(),
        Some(PathBuf::from("/usr/local/bin/claude")),
        Some(1),
        "Root binding with canonical path".to_string(),
    ));
    let sessions = vec![session];

    ServiceDiscoveryCoordinator::correlate_services(&mut services, &processes, &sessions);

    assert_eq!(services[0].session_id, Some("sess-norm-14".to_string()));
    assert_eq!(
        services[0].confidence,
        Confidence::Confirmed,
        "Lexically normalized path must match canonical root executable"
    );
}

// =============================================================================
// 33. Snapshot Replacement Lifecycle Sequence (Complete -> Truncated -> Failed -> Complete)
// =============================================================================

#[test]
fn test_service_snapshot_replacement_lifecycle_sequence() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use timmy::platform::traits::{PlatformError, ServiceCollector};
    use timmy::platform::{ServiceBackgroundWorker, SnapshotStatus};

    struct SequenceMockCollector {
        step: AtomicUsize,
    }

    impl ServiceCollector for SequenceMockCollector {
        fn collect_services(&self) -> Result<Vec<ServiceInfo>, PlatformError> {
            let current = self.step.fetch_add(1, Ordering::SeqCst);
            match current {
                0 => {
                    // Stage 1: Complete snapshot with 2 services
                    Ok(vec![
                        make_test_service(101, "com.test.complete1", "/bin/echo"),
                        make_test_service(102, "com.test.complete2", "/bin/echo"),
                    ])
                }
                1 => {
                    // Stage 2: Truncated partial snapshot (marked partial due to output limit)
                    let mut partial_svc = make_test_service(103, "com.test.partial", "/bin/echo");
                    partial_svc.is_partial = true;
                    Ok(vec![partial_svc])
                }
                2 => {
                    // Stage 3: Collection failure (e.g. launchctl timeout or permission error)
                    Err(PlatformError::Other("launchctl timeout 2000ms".to_string()))
                }
                _ => {
                    // Stage 4: Recovered fresh complete snapshot with 3 services
                    Ok(vec![
                        make_test_service(104, "com.test.recovered1", "/bin/echo"),
                        make_test_service(105, "com.test.recovered2", "/bin/echo"),
                        make_test_service(106, "com.test.recovered3", "/bin/echo"),
                    ])
                }
            }
        }
    }

    let collector = Arc::new(SequenceMockCollector {
        step: AtomicUsize::new(0),
    });
    let mut worker = ServiceBackgroundWorker::new(collector);

    // Initial state check
    assert_eq!(worker.snapshot_status(), SnapshotStatus::Initial);
    assert!(worker.get_last_known_complete().is_none());

    // -------------------------------------------------------------------------
    // Stage 1: Initial Complete Snapshot
    // -------------------------------------------------------------------------
    worker.trigger_refresh(1, Vec::new(), Vec::new());
    let start = std::time::Instant::now();
    while (worker.snapshot_status() != SnapshotStatus::Complete || worker.current_generation() < 1)
        && start.elapsed() < Duration::from_secs(2)
    {
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(worker.snapshot_status(), SnapshotStatus::Complete);
    assert!(!worker.is_partial());
    assert!(worker.warning().is_none());
    assert_eq!(worker.get_cached_services().len(), 2);
    let complete_v1 = worker
        .get_last_known_complete()
        .expect("Must have last known complete");
    assert_eq!(complete_v1.len(), 2);
    assert_eq!(complete_v1[0].name, "com.test.complete1");

    // -------------------------------------------------------------------------
    // Stage 2: Truncated / Partial Snapshot
    // -------------------------------------------------------------------------
    worker.trigger_refresh(2, Vec::new(), Vec::new());
    let start = std::time::Instant::now();
    while (!worker.is_partial() || worker.current_generation() < 2)
        && start.elapsed() < Duration::from_secs(2)
    {
        std::thread::sleep(Duration::from_millis(10));
    }

    assert!(matches!(
        worker.snapshot_status(),
        SnapshotStatus::Partial { .. }
    ));
    assert!(worker.is_partial());
    assert!(worker.warning().unwrap().contains("Partial snapshot"));
    assert_eq!(worker.get_cached_services().len(), 1);
    assert_eq!(worker.get_cached_services()[0].name, "com.test.partial");

    // CRITICAL: last_known_complete MUST NOT be replaced by the partial snapshot!
    let complete_preserved_v1 = worker
        .get_last_known_complete()
        .expect("Must retain last known complete");
    assert_eq!(complete_preserved_v1.len(), 2);
    assert_eq!(complete_preserved_v1[0].name, "com.test.complete1");

    // -------------------------------------------------------------------------
    // Stage 3: Collection Failure -> Stale Last-Known-Good Snapshot
    // -------------------------------------------------------------------------
    worker.trigger_refresh(3, Vec::new(), Vec::new());
    let start = std::time::Instant::now();
    while (!matches!(worker.snapshot_status(), SnapshotStatus::Stale { .. })
        || worker.current_generation() < 3)
        && start.elapsed() < Duration::from_secs(2)
    {
        std::thread::sleep(Duration::from_millis(10));
    }

    assert!(matches!(
        worker.snapshot_status(),
        SnapshotStatus::Stale { .. }
    ));
    assert!(worker
        .warning()
        .unwrap()
        .contains("stale last-known-good snapshot"));
    // Services cache is preserved, not cleared to empty!
    assert!(!worker.get_cached_services().is_empty());
    // last_known_complete is STILL preserved from Stage 1!
    let complete_preserved_v2 = worker
        .get_last_known_complete()
        .expect("Must retain last known complete");
    assert_eq!(complete_preserved_v2.len(), 2);
    assert_eq!(complete_preserved_v2[0].name, "com.test.complete1");

    // -------------------------------------------------------------------------
    // Stage 4: Recovery with Fresh Complete Snapshot
    // -------------------------------------------------------------------------
    worker.trigger_refresh(4, Vec::new(), Vec::new());
    let start = std::time::Instant::now();
    while (worker.snapshot_status() != SnapshotStatus::Complete || worker.current_generation() < 4)
        && start.elapsed() < Duration::from_secs(2)
    {
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(worker.snapshot_status(), SnapshotStatus::Complete);
    assert!(!worker.is_partial());
    assert!(worker.warning().is_none());
    assert_eq!(worker.get_cached_services().len(), 3);
    let complete_v2 = worker
        .get_last_known_complete()
        .expect("Must have updated last known complete");
    assert_eq!(complete_v2.len(), 3);
    assert_eq!(complete_v2[0].name, "com.test.recovered1");

    let _ = worker.stop(Duration::from_millis(500));
}

// =============================================================================
// 34. UI Presentation & Status-Message Propagation Verification
// =============================================================================

#[test]
fn test_ui_presentation_distinguishes_complete_snapshot() {
    use ratatui::backend::TestBackend;
    use ratatui::widgets::TableState;
    use ratatui::Terminal;
    use timmy::platform::SnapshotStatus;
    use timmy::ui::theme::Theme;
    use timmy::ui::views::render_service_table;

    let services = vec![
        make_test_service(101, "com.apple.syslogd", "/usr/libexec/syslogd"),
        make_test_service(102, "com.anthropic.claude", "/usr/local/bin/claude"),
    ];

    let backend = TestBackend::new(140, 20);
    let mut terminal = Terminal::new(backend).expect("terminal creation");
    let theme = Theme::default_dark();
    let mut state = TableState::default();
    let status = SnapshotStatus::Complete;

    terminal
        .draw(|f| {
            render_service_table(
                f,
                f.area(),
                &services,
                &mut state,
                &theme,
                "",
                &status,
                Some(std::time::Instant::now()),
            );
        })
        .expect("draw table");

    let buffer = terminal.backend().buffer();
    let mut rendered = String::new();
    for y in 0..buffer.area.height {
        for x in 0..buffer.area.width {
            rendered.push_str(buffer[(x, y)].symbol());
        }
        rendered.push('\n');
    }

    assert!(
        rendered.contains("Background Services (2)"),
        "Complete snapshot must show total count without warnings"
    );
    assert!(
        !rendered.contains("STALE"),
        "Complete snapshot must not be flagged as stale"
    );
    assert!(
        !rendered.contains("PARTIAL"),
        "Complete snapshot must not be flagged as partial"
    );
    assert!(
        !rendered.contains("INITIALIZING"),
        "Complete snapshot must not be flagged as initializing"
    );
}

#[test]
fn test_ui_presentation_distinguishes_partial_snapshot() {
    use ratatui::backend::TestBackend;
    use ratatui::widgets::TableState;
    use ratatui::Terminal;
    use timmy::platform::SnapshotStatus;
    use timmy::ui::theme::Theme;
    use timmy::ui::views::render_service_table;

    let mut partial_svc = make_test_service(101, "com.apple.partial", "/usr/libexec/partial");
    partial_svc.is_partial = true;
    let services = vec![partial_svc];

    let backend = TestBackend::new(160, 20);
    let mut terminal = Terminal::new(backend).expect("terminal creation");
    let theme = Theme::default_dark();
    let mut state = TableState::default();
    let status = SnapshotStatus::Partial {
        reason: "launchctl output truncated at 2MB".to_string(),
    };

    terminal
        .draw(|f| {
            render_service_table(
                f,
                f.area(),
                &services,
                &mut state,
                &theme,
                "",
                &status,
                Some(std::time::Instant::now()),
            );
        })
        .expect("draw table");

    let buffer = terminal.backend().buffer();
    let mut rendered = String::new();
    for y in 0..buffer.area.height {
        for x in 0..buffer.area.width {
            rendered.push_str(buffer[(x, y)].symbol());
        }
        rendered.push('\n');
    }

    assert!(
        rendered.contains("[PARTIAL SNAPSHOT - INCOMPLETE: launchctl output truncated at 2MB]"),
        "Partial snapshot must prominently display the partial badge and truncation reason"
    );
}

#[test]
fn test_ui_presentation_distinguishes_stale_snapshot_with_failure_reason_and_age() {
    use ratatui::backend::TestBackend;
    use ratatui::widgets::TableState;
    use ratatui::Terminal;
    use std::time::{Duration, Instant};
    use timmy::platform::SnapshotStatus;
    use timmy::ui::theme::Theme;
    use timmy::ui::views::render_service_table;

    let services = vec![
        make_test_service(101, "com.apple.syslogd", "/usr/libexec/syslogd"),
        make_test_service(102, "com.anthropic.claude", "/usr/local/bin/claude"),
    ];

    let backend = TestBackend::new(160, 20);
    let mut terminal = Terminal::new(backend).expect("terminal creation");
    let theme = Theme::default_dark();
    let mut state = TableState::default();
    let status = SnapshotStatus::Stale {
        error: "launchctl timed out after 2000ms".to_string(),
    };
    // Last successful refresh occurred 45 seconds ago
    let last_refresh = Some(Instant::now() - Duration::from_secs(45));

    terminal
        .draw(|f| {
            render_service_table(
                f,
                f.area(),
                &services,
                &mut state,
                &theme,
                "",
                &status,
                last_refresh,
            );
        })
        .expect("draw table");

    let buffer = terminal.backend().buffer();
    let mut rendered = String::new();
    for y in 0..buffer.area.height {
        for x in 0..buffer.area.width {
            rendered.push_str(buffer[(x, y)].symbol());
        }
        rendered.push('\n');
    }

    assert!(
        rendered.contains("[STALE SNAPSHOT - LAST GOOD 45s ago]"),
        "Stale snapshot title must display prominent stale badge and exact elapsed age"
    );
    assert!(
        rendered.contains("[ERROR: launchctl timed out after 2000ms]"),
        "Stale snapshot title must display the exact collection failure reason"
    );
}

#[test]
fn test_ui_presentation_distinguishes_initial_uncollected_state() {
    use ratatui::backend::TestBackend;
    use ratatui::widgets::TableState;
    use ratatui::Terminal;
    use timmy::platform::SnapshotStatus;
    use timmy::ui::theme::Theme;
    use timmy::ui::views::render_service_table;

    let services: Vec<ServiceInfo> = Vec::new();

    let backend = TestBackend::new(140, 20);
    let mut terminal = Terminal::new(backend).expect("terminal creation");
    let theme = Theme::default_dark();
    let mut state = TableState::default();
    let status = SnapshotStatus::Initial;

    terminal
        .draw(|f| {
            render_service_table(
                f,
                f.area(),
                &services,
                &mut state,
                &theme,
                "",
                &status,
                None,
            );
        })
        .expect("draw table");

    let buffer = terminal.backend().buffer();
    let mut rendered = String::new();
    for y in 0..buffer.area.height {
        for x in 0..buffer.area.width {
            rendered.push_str(buffer[(x, y)].symbol());
        }
        rendered.push('\n');
    }

    assert!(
        rendered.contains("[INITIALIZING - NO SNAPSHOT]"),
        "Initial state with no prior collections must display initializing badge"
    );
    assert!(
        rendered.contains("0 services discovered"),
        "Initial state must report 0 services discovered"
    );
}

#[test]
fn test_app_status_message_propagation_across_snapshot_states() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use timmy::config::TimmyConfig;
    use timmy::engine::EngineOrchestrator;
    use timmy::model::ListeningPort;
    use timmy::platform::traits::{
        DockerCollector, PlatformError, PortCollector, ProcessCollector, ServiceCollector,
    };
    use timmy::platform::SnapshotStatus;
    use timmy::storage::StorageManager;
    use timmy::ui::App;

    struct MultiStageCollector {
        stage: AtomicUsize,
    }

    impl ProcessCollector for MultiStageCollector {
        fn collect_processes(&self) -> Result<Vec<ProcessInfo>, PlatformError> {
            Ok(Vec::new())
        }
        fn inspect_process(&self, pid: u32) -> Result<timmy::model::ProcessDetail, PlatformError> {
            Err(PlatformError::ProcessNotFound(pid))
        }
    }
    impl PortCollector for MultiStageCollector {
        fn collect_listening_ports(&self) -> Result<Vec<ListeningPort>, PlatformError> {
            Ok(Vec::new())
        }
    }
    impl DockerCollector for MultiStageCollector {
        fn collect_containers(&self) -> Result<Vec<timmy::model::ContainerInfo>, PlatformError> {
            Ok(Vec::new())
        }
        fn inspect_container(
            &self,
            _id: &str,
        ) -> Result<timmy::model::ContainerDetail, PlatformError> {
            Err(PlatformError::Other("Not docker".to_string()))
        }
        fn docker_status(&self) -> Result<timmy::model::DockerStatus, PlatformError> {
            Ok(timmy::model::DockerStatus::default())
        }
        fn collect_container_stats(
            &self,
            _id: &str,
        ) -> Result<timmy::model::ContainerStats, PlatformError> {
            Err(PlatformError::Other("Not docker".to_string()))
        }
    }
    impl ServiceCollector for MultiStageCollector {
        fn collect_services(&self) -> Result<Vec<ServiceInfo>, PlatformError> {
            let s = self.stage.load(Ordering::SeqCst);
            match s {
                0 => {
                    // Complete
                    Ok(vec![make_test_service(
                        101,
                        "com.complete.svc",
                        "/bin/echo",
                    )])
                }
                1 => {
                    // Stale (failure following complete)
                    Err(PlatformError::Other(
                        "launchctl socket timeout 2000ms".to_string(),
                    ))
                }
                _ => {
                    // Partial
                    let mut partial = make_test_service(102, "com.partial.svc", "/bin/echo");
                    partial.is_partial = true;
                    Ok(vec![partial])
                }
            }
        }
    }

    let collector = Arc::new(MultiStageCollector {
        stage: AtomicUsize::new(0),
    });
    let storage = Arc::new(StorageManager::open_in_memory().expect("in-memory db"));
    let mut config = TimmyConfig::default();
    config.general.enable_docker = false;
    let orchestrator = EngineOrchestrator::with_collector(config, Some(storage), collector.clone());
    let mut app = App::new(orchestrator);

    // Initial state check
    let worker = app.service_worker.as_ref().unwrap().clone();
    // Allow initial collection to run
    let start = std::time::Instant::now();
    while worker.current_generation() < 1 && start.elapsed() < Duration::from_secs(2) {
        std::thread::sleep(Duration::from_millis(10));
    }
    app.refresh();

    assert_eq!(worker.snapshot_status(), SnapshotStatus::Complete);

    // Transition to Stage 1: Failure (Stale snapshot)
    collector.stage.store(1, Ordering::SeqCst);
    app.refresh(); // triggers refresh with new generation
    let start = std::time::Instant::now();
    while !matches!(worker.snapshot_status(), SnapshotStatus::Stale { .. })
        && start.elapsed() < Duration::from_secs(2)
    {
        std::thread::sleep(Duration::from_millis(10));
    }
    app.refresh(); // propagates worker state into app.status_message

    assert!(matches!(
        worker.snapshot_status(),
        SnapshotStatus::Stale { .. }
    ));
    let status_msg = app
        .status_message
        .as_ref()
        .expect("status_message must be set");
    assert!(
        status_msg.1,
        "Stale snapshot error status must be flagged as error (true)"
    );
    assert!(
        status_msg.0.contains("Service discovery failed:")
            && status_msg.0.contains("launchctl socket timeout 2000ms"),
        "Status message must contain the exact collection failure reason: got '{}'",
        status_msg.0
    );
    assert!(
        status_msg
            .0
            .contains("displaying stale last-known-good snapshot"),
        "Status message must explicitly notify the user that data is stale: got '{}'",
        status_msg.0
    );

    // Transition to Stage 2: Partial snapshot
    collector.stage.store(2, Ordering::SeqCst);
    app.refresh();
    let start = std::time::Instant::now();
    while !matches!(worker.snapshot_status(), SnapshotStatus::Partial { .. })
        && start.elapsed() < Duration::from_secs(2)
    {
        std::thread::sleep(Duration::from_millis(10));
    }
    app.refresh();

    assert!(matches!(
        worker.snapshot_status(),
        SnapshotStatus::Partial { .. }
    ));
    let partial_msg = app
        .status_message
        .as_ref()
        .expect("status_message must be set");
    assert!(
        !partial_msg.1,
        "Partial snapshot warning is informational (false)"
    );
    assert!(
        partial_msg.0.contains("Partial services snapshot"),
        "Status message must indicate partial snapshot: got '{}'",
        partial_msg.0
    );
}
