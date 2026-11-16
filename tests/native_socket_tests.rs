use std::net::{TcpListener, UdpSocket};
use timmy::model::{Protocol, SocketState};
use timmy::platform::macos::darwin_sys::{collect_process_listening_sockets, list_process_fds};
use timmy::platform::macos::ports::{
    discover_listening_ports_lsof, discover_listening_ports_native, DarwinPortCollector,
};
use timmy::platform::PortCollector;

#[test]
fn test_native_socket_tcp_listen_state() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral TCP port");
    let local_port = listener.local_addr().expect("local addr").port();
    let current_pid = std::process::id();

    let ports = collect_process_listening_sockets(current_pid, Some("test_runner"))
        .expect("collect process sockets");

    let found = ports.iter().find(|p| p.port == local_port);
    assert!(
        found.is_some(),
        "Native socket discovery must discover bound TCP listener port {}",
        local_port
    );

    let p = found.unwrap();
    assert_eq!(p.protocol, Protocol::Tcp);
    assert_eq!(p.state, SocketState::Listen);
    assert_eq!(p.ip, "127.0.0.1");
    assert_eq!(p.pid, Some(current_pid));
    assert_eq!(p.process_name.as_deref(), Some("test_runner"));
}

#[test]
fn test_native_socket_dual_stack_ipv6() {
    let listener = match TcpListener::bind("[::1]:0") {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "IPv6 loopback bind not supported in this environment: {}",
                e
            );
            return;
        }
    };
    let local_port = listener.local_addr().expect("local addr").port();
    let current_pid = std::process::id();

    let ports = collect_process_listening_sockets(current_pid, Some("test_runner_ipv6"))
        .expect("collect process sockets");

    let found = ports.iter().find(|p| p.port == local_port);
    assert!(
        found.is_some(),
        "Native socket discovery must discover bound IPv6 listener port {}",
        local_port
    );

    let p = found.unwrap();
    assert_eq!(p.protocol, Protocol::Tcp);
    assert_eq!(p.state, SocketState::Listen);
    assert_eq!(p.ip, "::1");
    assert_eq!(p.pid, Some(current_pid));
}

#[test]
fn test_native_socket_udp_bound() {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral UDP socket");
    let local_port = socket.local_addr().expect("local addr").port();
    let current_pid = std::process::id();

    let ports = collect_process_listening_sockets(current_pid, Some("test_runner_udp"))
        .expect("collect process sockets");

    let found = ports.iter().find(|p| p.port == local_port);
    assert!(
        found.is_some(),
        "Native socket discovery must discover bound UDP port {}",
        local_port
    );

    let p = found.unwrap();
    assert_eq!(p.protocol, Protocol::Udp);
    assert_eq!(p.state, SocketState::Listen);
    assert_eq!(p.ip, "127.0.0.1");
    assert_eq!(p.pid, Some(current_pid));
}

#[test]
fn test_native_socket_query_nonexistent_pid() {
    let res = collect_process_listening_sockets(999_999_999, None);
    assert!(
        res.is_ok(),
        "Querying nonexistent PID must return Ok(empty) without panicking"
    );
    assert!(res.unwrap().is_empty());
}

#[test]
fn test_native_socket_permission_boundary_pid_1() {
    // PID 1 is launchd (root-owned). Unprivileged inspection must handle EPERM gracefully.
    let res = collect_process_listening_sockets(1, Some("launchd"));
    assert!(
        res.is_ok(),
        "Unprivileged inspection on PID 1 must handle EPERM cleanly and return Ok"
    );
}

#[test]
fn test_native_socket_fds_listing_on_self() {
    let current_pid = std::process::id();
    let fds = list_process_fds(current_pid).expect("list self FDs");
    assert!(
        !fds.is_empty(),
        "Current test process must have open file descriptors"
    );
}

#[test]
fn test_native_socket_parity_with_lsof() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind TCP listener for parity");
    let test_port = listener.local_addr().expect("local addr").port();

    let native_ports = discover_listening_ports_native().expect("discover_listening_ports_native");
    let lsof_ports = discover_listening_ports_lsof().expect("discover_listening_ports_lsof");

    let found_native = native_ports.iter().any(|p| p.port == test_port);
    let found_lsof = lsof_ports.iter().any(|p| p.port == test_port);

    assert!(
        found_native,
        "Native discovery must find test port {}",
        test_port
    );
    assert!(
        found_lsof,
        "lsof discovery must find test port {}",
        test_port
    );

    // Verify collector interface
    let collector = DarwinPortCollector::new();
    let combined_ports = collector
        .collect_listening_ports()
        .expect("DarwinPortCollector");
    assert!(combined_ports.iter().any(|p| p.port == test_port));
}
