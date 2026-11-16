use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "timmy",
    author = "TIMMY Contributors",
    version,
    about = "TIMMY: AI Agent Resource Manager\nDiscover, monitor, and safely manage background processes and ports.",
    long_about = None
)]
pub struct Cli {
    /// Path to custom configuration file (TOML)
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,

    /// TUI refresh rate in milliseconds
    #[arg(short, long, global = true, default_value_t = 1000)]
    pub refresh: u64,

    /// Enable verbose diagnostic logging
    #[arg(short, long, global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Launch the interactive terminal UI (default)
    Run,

    /// Print a one-shot snapshot of active processes and AI agent attribution
    Scan {
        /// Show only processes attributed to AI agents
        #[arg(short, long)]
        agents_only: bool,

        /// Output details in JSON format
        #[arg(long)]
        json: bool,
    },

    /// List active listening network ports and their owning processes
    Ports {
        /// Output details in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Inspect system capabilities, permissions, and diagnostic health
    Doctor {
        /// Output details in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Track and manage individual AI coding agent sessions
    Session {
        #[command(subcommand)]
        action: SessionCommands,
    },

    /// Discover, inspect, and monitor Docker containers associated with AI agent workflows
    Docker {
        #[command(subcommand)]
        action: DockerCommands,
    },

    /// Discover and inspect macOS LaunchAgents and LaunchDaemons
    Services {
        /// Filter by domain (user, system, apple)
        #[arg(short, long)]
        domain: Option<String>,

        /// Output details in JSON format
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum DockerCommands {
    /// Inspect Docker daemon connectivity, socket paths, and versions
    Status {
        /// Output details in JSON format
        #[arg(long)]
        json: bool,
    },

    /// List Docker containers and their AI agent session attributions
    List {
        /// Show all containers (running, paused, stopped)
        #[arg(short, long, default_value_t = true)]
        all: bool,

        /// Filter containers by AI agent session identifier
        #[arg(short, long)]
        session: Option<String>,

        /// Output details in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Deeply inspect a specific Docker container
    Inspect {
        /// Container identifier or name
        container_id: String,

        /// Output details in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Display live resource usage metrics for running Docker containers
    Stats {
        /// Output details in JSON format
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum SessionCommands {
    /// Start tracking a new AI coding session
    Start {
        /// Optional AI agent identifier (e.g. claude, cursor, windsurf, aider)
        #[arg(short, long)]
        agent: Option<String>,

        /// Continuously observe resources in the foreground until interrupted (Ctrl+C)
        #[arg(short, long)]
        watch: bool,

        /// Observation interval in seconds when running with --watch (default: 5)
        #[arg(short, long, default_value_t = 5)]
        interval: u64,

        /// Replace any currently active session rather than refusing to start
        #[arg(long)]
        replace: bool,
    },

    /// Watch an active session continuously in the foreground (Ctrl+C to stop)
    Watch {
        /// Session identifier to watch (or active session if omitted)
        session_id: Option<String>,

        /// Observation interval in seconds (default: 5)
        #[arg(short, long, default_value_t = 5)]
        interval: u64,
    },

    /// Display active and previous AI coding sessions
    List {
        /// Output details in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Show detailed information about a specific session (or active session)
    Inspect {
        /// Session identifier (or active session if omitted)
        session_id: Option<String>,

        /// Display hierarchical process lineage tree
        #[arg(short, long)]
        tree: bool,

        /// Show exited intermediate processes in the lineage tree
        #[arg(long)]
        show_exited: bool,

        /// Output details in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Stop tracking a session (does not terminate background processes)
    Stop {
        /// Session identifier to stop (or active session if omitted)
        session_id: Option<String>,
    },

    /// Show background resources and ports associated with a session
    Resources {
        /// Session identifier (or active session if omitted)
        session_id: Option<String>,

        /// Display hierarchical process lineage tree
        #[arg(short, long)]
        tree: bool,

        /// Show exited intermediate processes in the lineage tree
        #[arg(long)]
        show_exited: bool,

        /// Output details in JSON format
        #[arg(long)]
        json: bool,
    },
}
