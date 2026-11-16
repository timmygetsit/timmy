use serde::{Deserialize, Serialize};
use std::fmt;

/// Transport network protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
        }
    }
}

/// Listening socket state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SocketState {
    Listen,
    Established,
    Other(String),
}

impl fmt::Display for SocketState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SocketState::Listen => write!(f, "LISTEN"),
            SocketState::Established => write!(f, "ESTABLISHED"),
            SocketState::Other(s) => write!(f, "{}", s),
        }
    }
}

/// Representation of an open listening network port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListeningPort {
    pub port: u16,
    pub protocol: Protocol,
    pub ip: String,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub state: SocketState,
}
