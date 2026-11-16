use serde::{Deserialize, Serialize};
use std::fmt;

/// Attribution confidence grade for an identified process or resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Confidence {
    /// Regular user or system process not attributed to any AI agent.
    Unknown = 0,
    /// Inferred based on port profile, working directory, or runtime parameters.
    Inferred = 1,
    /// High confidence; spawned directly within an AI agent's process tree.
    HighConfidence = 2,
    /// Confirmed; process binary or launch signature definitively belongs to an AI agent.
    Confirmed = 3,
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Confidence::Confirmed => write!(f, "CONFIRMED"),
            Confidence::HighConfidence => write!(f, "HIGH"),
            Confidence::Inferred => write!(f, "INFERRED"),
            Confidence::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

impl Confidence {
    pub fn to_code(&self) -> i32 {
        *self as i32
    }

    pub fn from_code(code: i32) -> Self {
        match code {
            3 => Confidence::Confirmed,
            2 => Confidence::HighConfidence,
            1 => Confidence::Inferred,
            _ => Confidence::Unknown,
        }
    }
}

/// Category or brand of AI coding agent.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AgentKind {
    ClaudeCode,
    Cursor,
    Windsurf,
    Aider,
    GitHubCopilot,
    Devin,
    OllamaLocal,
    Antigravity,
    GenericLlmAgent(String),
    Unknown,
}

impl fmt::Display for AgentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AgentKind::ClaudeCode => write!(f, "Claude Code"),
            AgentKind::Cursor => write!(f, "Cursor"),
            AgentKind::Windsurf => write!(f, "Windsurf"),
            AgentKind::Aider => write!(f, "Aider"),
            AgentKind::GitHubCopilot => write!(f, "GitHub Copilot"),
            AgentKind::Devin => write!(f, "Devin"),
            AgentKind::OllamaLocal => write!(f, "Ollama"),
            AgentKind::Antigravity => write!(f, "Antigravity"),
            AgentKind::GenericLlmAgent(name) => write!(f, "{}", name),
            AgentKind::Unknown => write!(f, "None"),
        }
    }
}

impl AgentKind {
    pub fn from_str_name(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "claudecode" | "claude code" | "claude" | "claude-code" => AgentKind::ClaudeCode,
            "cursor" | "cursor-server" => AgentKind::Cursor,
            "windsurf" | "codeium" => AgentKind::Windsurf,
            "aider" | "aider-chat" => AgentKind::Aider,
            "githubcopilot" | "github copilot" | "copilot" => AgentKind::GitHubCopilot,
            "devin" | "opendevin" => AgentKind::Devin,
            "ollamalocal" | "ollama" => AgentKind::OllamaLocal,
            "antigravity" => AgentKind::Antigravity,
            "none" | "unknown" => AgentKind::Unknown,
            other => AgentKind::GenericLlmAgent(other.to_string()),
        }
    }
}

/// Attribution metadata for a process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAttribution {
    pub kind: AgentKind,
    pub confidence: Confidence,
    pub reason: String,
    pub evidence: String,
    pub parent_pid: Option<u32>,
    pub parent_name: Option<String>,
    pub root_agent_pid: Option<u32>,
    pub root_agent_name: Option<String>,
    pub is_confirmed: bool,
    pub safe_to_terminate: bool,
}

impl AgentAttribution {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: AgentKind,
        confidence: Confidence,
        reason: String,
        evidence: String,
        parent_pid: Option<u32>,
        parent_name: Option<String>,
        root_agent_pid: Option<u32>,
        root_agent_name: Option<String>,
        safe_to_terminate: bool,
    ) -> Self {
        let is_confirmed = confidence == Confidence::Confirmed;
        Self {
            kind,
            confidence,
            reason,
            evidence,
            parent_pid,
            parent_name,
            root_agent_pid,
            root_agent_name,
            is_confirmed,
            safe_to_terminate,
        }
    }
}

impl Default for AgentAttribution {
    fn default() -> Self {
        Self {
            kind: AgentKind::Unknown,
            confidence: Confidence::Unknown,
            reason: "No AI agent association detected".to_string(),
            evidence: "None".to_string(),
            parent_pid: None,
            parent_name: None,
            root_agent_pid: None,
            root_agent_name: None,
            is_confirmed: false,
            safe_to_terminate: false,
        }
    }
}
