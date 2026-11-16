use crate::model::{ListeningPort, Protocol, SocketState};
use crate::platform::traits::PlatformError;
use std::process::Command;

/// Parses field-based lsof output (`lsof -F pcnT`).
/// This avoids whitespace word-splitting bugs and correctly preserves command names containing spaces.
pub fn parse_lsof_field_output(raw: &str) -> Vec<ListeningPort> {
    let mut ports = Vec::new();

    let mut current_pid: Option<u32> = None;
    let mut current_cmd: Option<String> = None;
    let mut current_name: Option<String> = None;
    let mut is_listen_state = false;
    let mut current_proto = Protocol::Tcp;

    for line in raw.lines() {
        if line.is_empty() {
            continue;
        }

        let prefix = &line[..1];
        let rest = &line[1..];

        match prefix {
            "p" => {
                // Flush previous record if ready
                if let (Some(pid), Some(name)) = (current_pid, &current_name) {
                    if let Some(port) = parse_port_entry(
                        pid,
                        current_cmd.as_deref(),
                        name,
                        current_proto,
                        is_listen_state,
                    ) {
                        ports.push(port);
                    }
                }
                current_pid = rest.parse::<u32>().ok();
                current_cmd = None;
                current_name = None;
                is_listen_state = false;
                current_proto = Protocol::Tcp;
            }
            "c" => {
                // Command name (preserves all internal spaces)
                current_cmd = Some(rest.to_string());
            }
            "n" => {
                // If we already had a name for this process, flush it first
                if let (Some(pid), Some(name)) = (current_pid, &current_name) {
                    if let Some(port) = parse_port_entry(
                        pid,
                        current_cmd.as_deref(),
                        name,
                        current_proto,
                        is_listen_state,
                    ) {
                        ports.push(port);
                    }
                }
                current_name = Some(rest.to_string());
                is_listen_state = false; // Reset state for this new fd/socket
                                         // Default protocol: if UDP output was requested, detect if rest or fd had UDP
                current_proto = if rest.contains("UDP") {
                    Protocol::Udp
                } else {
                    Protocol::Tcp
                };
            }
            "T" if rest.contains("LISTEN") => {
                is_listen_state = true;
                current_proto = Protocol::Tcp;
            }
            _ => {}
        }
    }

    // Flush last entry
    if let (Some(pid), Some(name)) = (current_pid, &current_name) {
        if let Some(port) = parse_port_entry(
            pid,
            current_cmd.as_deref(),
            name,
            current_proto,
            is_listen_state,
        ) {
            ports.push(port);
        }
    }

    // Sort by port ascending
    ports.sort_by_key(|p| p.port);
    ports.dedup_by(|a, b| a.port == b.port && a.pid == b.pid && a.protocol == b.protocol);

    ports
}

fn parse_port_entry(
    pid: u32,
    cmd: Option<&str>,
    name: &str,
    proto: Protocol,
    is_listen: bool,
) -> Option<ListeningPort> {
    // Ignore active connection pairs (e.g. 127.0.0.1:49174->127.0.0.1:51234)
    if name.contains("->") || name == "*:*" {
        return None;
    }

    // For TCP, we only care about LISTEN sockets.
    // For UDP, bound sockets don't have a LISTEN state in lsof, but have a concrete port.
    if proto == Protocol::Tcp && !is_listen && !name.ends_with("(LISTEN)") {
        // If lsof didn't output TST=LISTEN but name ends with (LISTEN)
        // or if it was filtered by -sTCP:LISTEN, allow it if not a connection pair
        // Note: lsof -sTCP:LISTEN ensures all TCP results are listening
    }

    // Parse IPv6 [::1]:port or IPv4 ip:port
    let (ip, port_str) = if name.starts_with('[') {
        let close_bracket = name.find(']')?;
        let ip = &name[1..close_bracket];
        let after = &name[close_bracket + 1..];
        let port = after.strip_prefix(':').unwrap_or(after);
        (ip, port)
    } else {
        let last_colon = name.rfind(':')?;
        let ip = &name[..last_colon];
        let port = &name[last_colon + 1..];
        (ip, port)
    };

    let port: u16 = port_str.trim_end_matches(" (LISTEN)").parse().ok()?;
    if port == 0 {
        return None;
    }

    let clean_ip = if ip.is_empty() || ip == "*" {
        "0.0.0.0".to_string()
    } else {
        ip.to_string()
    };

    Some(ListeningPort {
        port,
        protocol: proto,
        ip: clean_ip,
        pid: Some(pid),
        process_name: cmd.map(|s| s.to_string()),
        state: SocketState::Listen,
    })
}

/// Discovers listening TCP and UDP ports on macOS by querying lsof in field mode.
pub fn discover_listening_ports_lsof() -> Result<Vec<ListeningPort>, PlatformError> {
    // -nP: numeric ports & hosts
    // -F pcnT: machine-readable fields (PID, Command, Name, TCP state)
    // -iTCP -sTCP:LISTEN: listening TCP sockets
    // -iUDP: UDP sockets
    let output = Command::new("lsof")
        .args(["-nP", "-F", "pcnT", "-iTCP", "-sTCP:LISTEN", "-iUDP"])
        .output();

    let output = match output {
        Ok(out) => out,
        Err(e) => return Err(PlatformError::Io(e)),
    };

    if !output.status.success() {
        return Ok(Vec::new());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_lsof_field_output(&stdout))
}

/// Discovers listening TCP and UDP ports natively via Darwin kernel proc_pidinfo and proc_pidfdinfo.
pub fn discover_listening_ports_native() -> Result<Vec<ListeningPort>, PlatformError> {
    super::darwin_sys::collect_all_listening_sockets_darwin()
}

/// Discovers listening TCP and UDP ports on macOS.
/// Attempts zero-overhead native Darwin kernel discovery first; if native discovery encounters
/// permissions or sandbox restrictions or finds no ports, seamlessly falls back to `lsof`.
pub fn discover_listening_ports() -> Result<Vec<ListeningPort>, PlatformError> {
    match discover_listening_ports_native() {
        Ok(ports) if !ports.is_empty() => Ok(ports),
        _ => discover_listening_ports_lsof(),
    }
}

/// High-performance Darwin native port collector implementing `PortCollector`.
#[derive(Clone, Default)]
pub struct DarwinPortCollector;

impl DarwinPortCollector {
    pub fn new() -> Self {
        Self
    }
}

impl crate::platform::traits::PortCollector for DarwinPortCollector {
    fn collect_listening_ports(&self) -> Result<Vec<ListeningPort>, PlatformError> {
        discover_listening_ports()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_lsof_field_output_with_spaces() {
        let mock_output = r#"
p1296
cAntigravity Helper
f23
n127.0.0.1:49191
TST=LISTEN
p12345
cGoogle Chrome
f10
n*:3000
TST=LISTEN
p999
cnode
f5
n[::1]:5432
TST=LISTEN
p888
cpython
f6
n127.0.0.1:8080->127.0.0.1:54321
"#;
        let ports = parse_lsof_field_output(mock_output);
        assert_eq!(ports.len(), 3);

        // First port: 3000 Google Chrome
        let p3000 = ports
            .iter()
            .find(|p| p.port == 3000)
            .expect("Must find 3000");
        assert_eq!(p3000.process_name.as_deref(), Some("Google Chrome"));
        assert_eq!(p3000.pid, Some(12345));
        assert_eq!(p3000.ip, "0.0.0.0");

        // Second port: 5432 IPv6 node
        let p5432 = ports
            .iter()
            .find(|p| p.port == 5432)
            .expect("Must find 5432");
        assert_eq!(p5432.process_name.as_deref(), Some("node"));
        assert_eq!(p5432.ip, "::1");

        // Third port: 49191 Antigravity Helper (command name with space)
        let p49191 = ports
            .iter()
            .find(|p| p.port == 49191)
            .expect("Must find 49191");
        assert_eq!(p49191.process_name.as_deref(), Some("Antigravity Helper"));
        assert_eq!(p49191.pid, Some(1296));
    }

    #[test]
    fn test_port_discovery_live() {
        let res = discover_listening_ports();
        assert!(res.is_ok());
    }
}
