use crate::config::model::CustomAgentRule;
use crate::model::agent::{AgentAttribution, AgentKind, Confidence};
use crate::model::process::ProcessInfo;
use crate::safety::rules;
use std::collections::HashMap;

/// Pre-configured agent signature.
#[derive(Debug, Clone)]
pub struct AgentSignature {
    pub kind: AgentKind,
    pub binary_names: Vec<&'static str>,
    pub cmdline_patterns: Vec<&'static str>,
    pub env_var_markers: Vec<&'static str>,
}

/// AI-agent attribution heuristics and signature catalog.
pub struct AttributionEngine {
    signatures: Vec<AgentSignature>,
    custom_rules: Vec<CustomAgentRule>,
}

impl AttributionEngine {
    pub fn new(custom_rules: Vec<CustomAgentRule>) -> Self {
        let signatures = vec![
            AgentSignature {
                kind: AgentKind::ClaudeCode,
                binary_names: vec!["claude", "claude-code"],
                cmdline_patterns: vec!["@anthropic-ai/claude-code", "claude", "claude-code"],
                env_var_markers: vec!["CLAUDE_CODE", "ANTHROPIC_API_KEY"],
            },
            AgentSignature {
                kind: AgentKind::Cursor,
                binary_names: vec!["Cursor", "cursor-server", "cursor"],
                cmdline_patterns: vec!["cursor-server", ".cursor-tutor", "Cursor.app"],
                env_var_markers: vec!["CURSOR_AGENT", "CURSOR_SERVER"],
            },
            AgentSignature {
                kind: AgentKind::Windsurf,
                binary_names: vec!["windsurf", "codeium-server"],
                cmdline_patterns: vec!["windsurf", "codeium"],
                env_var_markers: vec!["WINDSURF_AGENT"],
            },
            AgentSignature {
                kind: AgentKind::Aider,
                binary_names: vec!["aider", "aider-chat"],
                cmdline_patterns: vec!["aider", "aider.main"],
                env_var_markers: vec!["AIDER_ANALYTICS"],
            },
            AgentSignature {
                kind: AgentKind::GitHubCopilot,
                binary_names: vec!["copilot", "github-copilot-cli"],
                cmdline_patterns: vec!["copilot", "github-copilot"],
                env_var_markers: vec!["GITHUB_COPILOT"],
            },
            AgentSignature {
                kind: AgentKind::Devin,
                binary_names: vec!["devin", "opendevin"],
                cmdline_patterns: vec!["devin", "opendevin"],
                env_var_markers: vec!["DEVIN_SESSION_ID"],
            },
            AgentSignature {
                kind: AgentKind::OllamaLocal,
                binary_names: vec!["ollama", "ollama_llama_server"],
                cmdline_patterns: vec!["ollama serve", "ollama_llama_server"],
                env_var_markers: vec!["OLLAMA_HOST", "OLLAMA_MODELS"],
            },
            AgentSignature {
                kind: AgentKind::Antigravity,
                binary_names: vec![
                    "Antigravity",
                    "antigravity",
                    "antigravity_agent",
                    "Antigravi",
                ],
                cmdline_patterns: vec!["Antigravity", "antigravity", "antigravity_agent"],
                env_var_markers: vec!["ANTIGRAVITY", "GEMINI_API_KEY"],
            },
        ];

        Self {
            signatures,
            custom_rules,
        }
    }

    /// Evaluates direct process signature matching.
    pub fn attribute_process(&self, proc: &ProcessInfo) -> AgentAttribution {
        let current_pid = std::process::id();

        // 1. TIMMY Self-Protection: TIMMY must never attribute itself as an AI agent or background resource.
        if proc.pid == current_pid || proc.name.eq_ignore_ascii_case("timmy") {
            return AgentAttribution {
                kind: AgentKind::Unknown,
                confidence: Confidence::Unknown,
                reason: "TIMMY utility process (self)".to_string(),
                evidence: "Current executable".to_string(),
                parent_pid: proc.ppid,
                parent_name: None,
                root_agent_pid: None,
                root_agent_name: None,
                is_confirmed: false,
                safe_to_terminate: false,
            };
        }

        // 2. Interactive shells & terminals should never be classified as agent targets
        if rules::is_interactive_shell(&proc.name) || rules::is_terminal_host(&proc.name) {
            return AgentAttribution {
                kind: AgentKind::Unknown,
                confidence: Confidence::Unknown,
                reason: format!("Interactive developer environment ({})", proc.name),
                evidence: "Interactive shell/terminal".to_string(),
                parent_pid: proc.ppid,
                parent_name: None,
                root_agent_pid: None,
                root_agent_name: None,
                is_confirmed: false,
                safe_to_terminate: false,
            };
        }

        let name_lower = proc.name.to_lowercase();

        // 3. Check built-in agent signatures for direct binary match (Confirmed)
        for sig in &self.signatures {
            for bin in &sig.binary_names {
                if name_lower == bin.to_lowercase() {
                    return AgentAttribution {
                        kind: sig.kind.clone(),
                        confidence: Confidence::Confirmed,
                        reason: format!("Direct binary match with '{}'", bin),
                        evidence: format!(
                            "Executable binary name '{}' matches known agent signature",
                            bin
                        ),
                        parent_pid: proc.ppid,
                        parent_name: None,
                        root_agent_pid: Some(proc.pid),
                        root_agent_name: Some(proc.name.clone()),
                        is_confirmed: true,
                        safe_to_terminate: true,
                    };
                }
            }
        }

        // 4. Check custom user rules
        for rule in &self.custom_rules {
            for pattern in &rule.binary_patterns {
                if name_lower.contains(&pattern.to_lowercase()) {
                    return AgentAttribution {
                        kind: AgentKind::GenericLlmAgent(rule.name.clone()),
                        confidence: Confidence::Confirmed,
                        reason: format!("Custom rule binary match '{}'", pattern),
                        evidence: format!("Matched user-defined rule '{}'", rule.name),
                        parent_pid: proc.ppid,
                        parent_name: None,
                        root_agent_pid: Some(proc.pid),
                        root_agent_name: Some(proc.name.clone()),
                        is_confirmed: true,
                        safe_to_terminate: true,
                    };
                }
            }
        }

        // 5. Check for common development servers/tools often spawned by agents (Inferred)
        let common_dev_servers = [
            "node", "python", "python3", "ruby", "vite", "next", "uvicorn", "cargo", "docker",
        ];
        if common_dev_servers.contains(&name_lower.as_str()) && !proc.listening_ports.is_empty() {
            return AgentAttribution {
                kind: AgentKind::Unknown,
                confidence: Confidence::Inferred,
                reason: format!(
                    "Active development server holding ports: {:?}",
                    proc.listening_ports
                ),
                evidence: format!("Process '{}' actively listening on network ports without direct agent parentage", proc.name),
                parent_pid: proc.ppid,
                parent_name: None,
                root_agent_pid: None,
                root_agent_name: None,
                is_confirmed: false,
                safe_to_terminate: true,
            };
        }

        AgentAttribution::default()
    }

    /// Correlates process tree to attribute children spawned by AI agents (HighConfidence).
    /// Distinguishes between background worker servers vs interactive developer tools.
    pub fn propagate_tree_attribution(&self, processes: &mut [ProcessInfo]) {
        let current_pid = std::process::id();

        // Build maps of PID -> Process info and attribution
        let mut pid_to_attribution: HashMap<u32, AgentAttribution> = HashMap::new();
        let pid_to_name: HashMap<u32, String> =
            processes.iter().map(|p| (p.pid, p.name.clone())).collect();

        // First pass: Direct signatures
        for proc in processes.iter_mut() {
            let attr = self.attribute_process(proc);
            if attr.confidence == Confidence::Confirmed {
                proc.attribution = attr.clone();
                pid_to_attribution.insert(proc.pid, attr);
            }
        }

        // Known interactive developer tools that shouldn't be tagged as disposable background servers
        let interactive_dev_tools = [
            "vim", "nvim", "nano", "emacs", "less", "more", "man", "top", "htop", "git", "ssh",
        ];

        // Second pass: Multi-generation descendant tree propagation
        let mut changed = true;
        let mut rounds = 0;
        while changed && rounds < 10 {
            changed = false;
            rounds += 1;

            for proc in processes.iter_mut() {
                // Rule: TIMMY itself must NEVER be attributed to an AI agent
                if proc.pid == current_pid || proc.name.eq_ignore_ascii_case("timmy") {
                    continue;
                }

                if proc.attribution.confidence != Confidence::Confirmed {
                    if let Some(ppid) = proc.ppid {
                        if let Some(parent_attr) = pid_to_attribution.get(&ppid) {
                            if parent_attr.confidence >= Confidence::HighConfidence {
                                let proc_name_lower = proc.name.to_lowercase();
                                let parent_name = pid_to_name.get(&ppid).cloned();

                                // Check if this child is an interactive shell or developer editor
                                let is_shell = rules::is_interactive_shell(&proc.name);
                                let is_editor =
                                    interactive_dev_tools.contains(&proc_name_lower.as_str());

                                let (reason, evidence, safe_to_terminate) = if is_shell {
                                    (
                                        format!("Interactive terminal shell spawned under agent (PID {})", ppid),
                                        format!("Descendant of {} (PID {}), but protected as interactive session", parent_attr.kind, ppid),
                                        false,
                                    )
                                } else if is_editor {
                                    (
                                        format!("Interactive editor/tool launched in agent environment (PID {})", ppid),
                                        format!("User application '{}' active in session", proc.name),
                                        false,
                                    )
                                } else {
                                    (
                                        format!(
                                            "Background task spawned by agent tree (parent PID {})",
                                            ppid
                                        ),
                                        format!(
                                            "Direct child/descendant of {} (PID {})",
                                            parent_attr.kind, ppid
                                        ),
                                        true,
                                    )
                                };

                                let new_attr = AgentAttribution {
                                    kind: parent_attr.kind.clone(),
                                    confidence: Confidence::HighConfidence,
                                    reason,
                                    evidence,
                                    parent_pid: Some(ppid),
                                    parent_name,
                                    root_agent_pid: parent_attr.root_agent_pid.or(Some(ppid)),
                                    root_agent_name: parent_attr.root_agent_name.clone(),
                                    is_confirmed: false,
                                    safe_to_terminate,
                                };

                                if proc.attribution != new_attr {
                                    proc.attribution = new_attr.clone();
                                    pid_to_attribution.insert(proc.pid, new_attr);
                                    changed = true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

impl Default for AttributionEngine {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_direct_binary_attribution() {
        let engine = AttributionEngine::default();
        let proc = ProcessInfo {
            pid: 100,
            ppid: Some(1),
            name: "claude".to_string(),
            memory_bytes: Some(1024),
            run_time_secs: 10,
            start_time: Some(1000),
            ..Default::default()
        };

        let attr = engine.attribute_process(&proc);
        assert_eq!(attr.kind, AgentKind::ClaudeCode);
        assert_eq!(attr.confidence, Confidence::Confirmed);
        assert!(attr.is_confirmed);
        assert!(attr.safe_to_terminate);
    }

    #[test]
    fn test_timmy_self_process_never_attributed() {
        let engine = AttributionEngine::default();
        let proc = ProcessInfo {
            pid: std::process::id(),
            ppid: Some(100),
            name: "timmy".to_string(),
            memory_bytes: Some(1024),
            run_time_secs: 10,
            start_time: Some(1000),
            ..Default::default()
        };

        let attr = engine.attribute_process(&proc);
        assert_eq!(attr.kind, AgentKind::Unknown);
        assert_eq!(attr.confidence, Confidence::Unknown);
        assert!(!attr.safe_to_terminate);
    }

    #[test]
    fn test_interactive_shell_under_agent_marked_not_safe_to_kill() {
        let engine = AttributionEngine::default();
        let mut procs = vec![
            ProcessInfo {
                pid: 100,
                ppid: Some(1),
                name: "cursor-server".to_string(),
                memory_bytes: Some(1024),
                run_time_secs: 10,
                start_time: Some(1000),
                ..Default::default()
            },
            ProcessInfo {
                pid: 101,
                ppid: Some(100),
                name: "zsh".to_string(),
                memory_bytes: Some(1024),
                run_time_secs: 5,
                start_time: Some(1005),
                ..Default::default()
            },
            ProcessInfo {
                pid: 102,
                ppid: Some(101),
                name: "node".to_string(),
                memory_bytes: Some(1024),
                run_time_secs: 2,
                start_time: Some(1008),
                listening_ports: vec![3000],
                ..Default::default()
            },
        ];

        engine.propagate_tree_attribution(&mut procs);

        // cursor-server is confirmed
        assert_eq!(procs[0].attribution.confidence, Confidence::Confirmed);
        assert!(procs[0].attribution.safe_to_terminate);

        // zsh under agent is identified, but marked safe_to_terminate = FALSE
        assert_eq!(procs[1].attribution.kind, AgentKind::Cursor);
        assert!(!procs[1].attribution.safe_to_terminate);

        // node server under zsh under cursor is identified and safe_to_terminate = TRUE
        assert_eq!(procs[2].attribution.kind, AgentKind::Cursor);
        assert_eq!(procs[2].attribution.confidence, Confidence::HighConfidence);
        assert!(procs[2].attribution.safe_to_terminate);
    }
}
