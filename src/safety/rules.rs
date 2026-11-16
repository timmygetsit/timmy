use std::collections::HashSet;
use std::path::Path;

/// Set of protected macOS and Unix system process names that should never be terminated.
pub fn get_system_protected_names() -> HashSet<&'static str> {
    let mut names = HashSet::new();

    // macOS Window Server & Display Server
    names.insert("WindowServer");
    names.insert("loginwindow");
    names.insert("Dock");
    names.insert("Finder");
    names.insert("SystemUIServer");

    // macOS Core System Daemons & Security
    names.insert("launchd");
    names.insert("kernel_task");
    names.insert("syslogd");
    names.insert("notifyd");
    names.insert("securityd");
    names.insert("trustd");
    names.insert("tccd");
    names.insert("opendirectoryd");
    names.insert("diskarbitrationd");
    names.insert("kextd");
    names.insert("configd");
    names.insert("coreauthd");
    names.insert("powerd");
    names.insert("distnoted");
    names.insert("cfprefsd");

    // Remote access & shell infrastructure
    names.insert("sshd");
    names.insert("init");
    names.insert("systemd");

    names
}

/// Known terminal emulator and multiplexer process names.
pub fn get_terminal_emulator_names() -> HashSet<&'static str> {
    let mut names = HashSet::new();
    names.insert("Terminal");
    names.insert("iTerm2");
    names.insert("Ghostty");
    names.insert("Alacritty");
    names.insert("kitty");
    names.insert("WezTerm");
    names.insert("Hyper");
    names.insert("tmux");
    names.insert("screen");
    names
}

/// Known interactive shells that should not be terminated as orphan resources.
pub fn get_interactive_shells() -> HashSet<&'static str> {
    let mut names = HashSet::new();
    names.insert("zsh");
    names.insert("bash");
    names.insert("fish");
    names.insert("sh");
    names.insert("csh");
    names.insert("tcsh");
    names
}

/// Checks whether a PID represents a protected low-level OS kernel/init process.
pub fn is_protected_pid(pid: u32) -> bool {
    // PID 0 = kernel, PID 1 = launchd / init
    pid <= 1
}

/// Checks whether a process name matches an immutably protected critical system process.
pub fn is_critical_system_process(name: &str) -> bool {
    let protected = get_system_protected_names();
    protected.contains(name)
}

/// Checks whether a process name matches a terminal host or multiplexer.
pub fn is_terminal_host(name: &str) -> bool {
    let terminals = get_terminal_emulator_names();
    terminals.contains(name)
}

/// Checks whether a process is an interactive user shell.
pub fn is_interactive_shell(name: &str) -> bool {
    let shells = get_interactive_shells();
    shells.contains(name)
}

/// Checks whether an executable path is an essential OS system binary.
pub fn is_system_binary_path<P: AsRef<Path>>(path: P) -> bool {
    let p = path.as_ref();
    let s = p.to_string_lossy();
    s.starts_with("/System/")
        || s.starts_with("/usr/libexec/")
        || s.starts_with("/usr/sbin/")
        || s.starts_with("/System/Library/")
}
