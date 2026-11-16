/// Current SQLite database schema version.
pub const SCHEMA_VERSION: i32 = 7;

/// SQLite database schema migration script - Version 1.
pub const MIGRATION_V1: &str = r#"
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    pid INTEGER NOT NULL,
    process_name TEXT NOT NULL,
    agent_attribution TEXT NOT NULL,
    signal_sent TEXT NOT NULL,
    success INTEGER NOT NULL,
    note TEXT
);

CREATE TABLE IF NOT EXISTS agent_signatures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    binary_patterns TEXT NOT NULL,
    cmdline_patterns TEXT NOT NULL,
    env_var_markers TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS session_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_start TEXT NOT NULL,
    session_end TEXT,
    processes_observed INTEGER DEFAULT 0,
    terminations_executed INTEGER DEFAULT 0
);
"#;

/// SQLite database schema migration script - Version 2 (AI Agent Session Tracking).
pub const MIGRATION_V2: &str = r#"
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    agent_kind TEXT NOT NULL,
    status TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT,
    root_pid INTEGER,
    root_process_name TEXT,
    confidence INTEGER NOT NULL,
    evidence TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS session_resources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    pid INTEGER,
    name TEXT NOT NULL,
    exe_path TEXT,
    memory_bytes INTEGER,
    cpu_usage REAL,
    ports TEXT,
    confidence INTEGER NOT NULL,
    evidence TEXT NOT NULL,
    is_detached INTEGER NOT NULL DEFAULT 0,
    is_protected INTEGER NOT NULL DEFAULT 0,
    safe_to_terminate INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    process_start_time INTEGER,
    FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS session_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    process_count INTEGER NOT NULL,
    total_memory_bytes INTEGER NOT NULL,
    total_cpu_usage REAL NOT NULL,
    ports_count INTEGER NOT NULL,
    FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);
CREATE INDEX IF NOT EXISTS idx_session_resources_session ON session_resources(session_id);
CREATE INDEX IF NOT EXISTS idx_session_snapshots_session ON session_snapshots(session_id);
"#;

/// SQLite database schema migration script - Version 3 (Safety Hardening & Invariant Enforcement).
pub const MIGRATION_V3: &str = r#"
-- Ensure all unknown or inferred historical session resources are flagged unsafe by default
UPDATE session_resources SET safe_to_terminate = 0 WHERE confidence < 2;
"#;

/// SQLite database schema migration script - Version 4 (Observer Coordination Leases).
pub const MIGRATION_V4: &str = r#"
CREATE TABLE IF NOT EXISTS observer_leases (
    session_id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    acquired_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_renewed_at TEXT NOT NULL,
    FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_observer_leases_owner ON observer_leases(owner_id);
"#;

/// SQLite database schema migration script - Version 5 (Fencing Tokens & Generation History).
pub const MIGRATION_V5: &str = r#"
CREATE TABLE IF NOT EXISTS session_lease_generations (
    session_id TEXT PRIMARY KEY,
    last_fencing_token INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS session_lease_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    fencing_token INTEGER NOT NULL,
    action TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_lease_history_session ON session_lease_history(session_id);

-- Backfill session_lease_generations from existing observer_leases
INSERT INTO session_lease_generations (session_id, last_fencing_token, updated_at)
SELECT session_id, COALESCE(MAX(fencing_token), 1), COALESCE(MAX(last_renewed_at), datetime('now'))
FROM observer_leases
GROUP BY session_id
ON CONFLICT(session_id) DO UPDATE SET
    last_fencing_token = MAX(session_lease_generations.last_fencing_token, excluded.last_fencing_token),
    updated_at = excluded.updated_at;

-- Backfill session_lease_history for existing active leases
INSERT INTO session_lease_history (session_id, owner_id, fencing_token, action, timestamp)
SELECT session_id, owner_id, fencing_token, 'MIGRATED', COALESCE(last_renewed_at, datetime('now'))
FROM observer_leases;
"#;

/// SQLite database schema migration script - Version 6 (Structured Launch Provenance & Root Binding).
pub const MIGRATION_V6: &str = r#"
CREATE INDEX IF NOT EXISTS idx_sessions_root_pid ON sessions(root_pid);
"#;

/// SQLite database schema migration script - Version 7 (Persistent Process Lineage).
pub const MIGRATION_V7: &str = r#"
CREATE TABLE IF NOT EXISTS process_lineage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    parent_pid INTEGER NOT NULL,
    parent_start_tvsec INTEGER NOT NULL,
    parent_start_tvusec INTEGER NOT NULL,
    parent_name TEXT,
    parent_exe TEXT,
    child_pid INTEGER NOT NULL,
    child_start_tvsec INTEGER NOT NULL,
    child_start_tvusec INTEGER NOT NULL,
    child_name TEXT NOT NULL,
    child_exe TEXT,
    first_observed_at TEXT NOT NULL,
    last_observed_at TEXT NOT NULL,
    observation_count INTEGER NOT NULL DEFAULT 1,
    snapshot_id INTEGER,
    source TEXT NOT NULL,
    status TEXT NOT NULL,
    validation_details TEXT,
    FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE,
    FOREIGN KEY(snapshot_id) REFERENCES session_snapshots(id) ON DELETE SET NULL,
    UNIQUE(session_id, parent_pid, parent_start_tvsec, parent_start_tvusec, child_pid, child_start_tvsec, child_start_tvusec)
);

CREATE INDEX IF NOT EXISTS idx_lineage_session ON process_lineage(session_id);
CREATE INDEX IF NOT EXISTS idx_lineage_child ON process_lineage(session_id, child_pid, child_start_tvsec, child_start_tvusec);
CREATE INDEX IF NOT EXISTS idx_lineage_parent ON process_lineage(session_id, parent_pid, parent_start_tvsec, parent_start_tvusec);
CREATE INDEX IF NOT EXISTS idx_lineage_status ON process_lineage(session_id, status);
"#;
