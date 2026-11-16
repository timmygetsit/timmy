use super::schema::{
    MIGRATION_V1, MIGRATION_V2, MIGRATION_V3, MIGRATION_V4, MIGRATION_V5, MIGRATION_V6,
    MIGRATION_V7,
};
use crate::model::agent::{AgentKind, Confidence};
use crate::model::lineage::{LineageSource, LineageStatus, ProcessLineageEdge};
use crate::model::process::{ProcessIncarnation, ProcessStartTime};
use crate::model::session::{SessionInfo, SessionStatus, TrackedResource};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Lock error: {0}")]
    Lock(String),
    #[error("Session '{0}' not found in storage")]
    SessionNotFound(String),
    #[error("Session '{0}' is not active")]
    SessionNotActive(String),
    #[error("Observer lease for session '{session_id}' not held by caller '{owner_id}'")]
    LeaseNotHeld {
        session_id: String,
        owner_id: String,
    },
    #[error("Observer lease for session '{session_id}' expired at {expired_at}")]
    LeaseExpired {
        session_id: String,
        owner_id: String,
        expired_at: String,
    },
    #[error("Observer lease fencing token conflict for session '{session_id}': expected generation {expected_token}, but active generation is {current_token} (owned by '{current_owner}')")]
    LeaseFencingConflict {
        session_id: String,
        expected_token: u64,
        current_token: u64,
        current_owner: String,
    },
}

/// An active observer lease record for multi-process monitoring coordination.
#[derive(Debug, Clone, PartialEq)]
pub struct ObserverLease {
    pub session_id: String,
    pub owner_id: String,
    pub fencing_token: u64,
    pub acquired_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_renewed_at: DateTime<Utc>,
}

impl ObserverLease {
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

/// The result of an atomic lease acquisition attempt.
#[derive(Debug, Clone, PartialEq)]
pub enum LeaseAcquisitionResult {
    /// Successfully acquired a new lease as the authoritative observer.
    Acquired(ObserverLease),
    /// Successfully renewed an existing lease owned by the same observer.
    Renewed(ObserverLease),
    /// Successfully recovered a lease after a previous observer crashed or expired.
    RecoveredFromExpired {
        lease: ObserverLease,
        previous_owner: String,
    },
    /// Lease is currently held and unexpired by another observer.
    AlreadyHeld {
        current_owner: String,
        current_generation: u64,
        expires_at: DateTime<Utc>,
    },
}

/// Audit log record representing a termination event.
#[derive(Debug, Clone)]
pub struct AuditRecord {
    pub timestamp: String,
    pub pid: u32,
    pub process_name: String,
    pub agent_attribution: String,
    pub signal_sent: String,
    pub success: bool,
    pub note: Option<String>,
}

/// A snapshot observation record representing session resource state at a specific timestamp.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionSnapshotRecord {
    pub id: i64,
    pub session_id: String,
    pub timestamp: String,
    pub process_count: usize,
    pub total_memory_bytes: u64,
    pub total_cpu_usage: f32,
    pub ports_count: usize,
}

/// Database manager for TIMMY.
pub struct StorageManager {
    conn: Mutex<Connection>,
}

impl StorageManager {
    /// Opens or creates SQLite database at the specified path, executing versioned migrations.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, StorageError> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA busy_timeout = 5000;
             PRAGMA foreign_keys = ON;
             PRAGMA synchronous = NORMAL;",
        )?;
        Self::run_migrations(&mut conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Creates an in-memory SQLite database (useful for tests or ephemeral runs).
    pub fn open_in_memory() -> Result<Self, StorageError> {
        let mut conn = Connection::open_in_memory()?;
        conn.execute_batch(
            "PRAGMA busy_timeout = 5000;
             PRAGMA foreign_keys = ON;",
        )?;
        Self::run_migrations(&mut conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Runs versioned schema migrations safely and atomically.
    pub fn run_migrations(conn: &mut Connection) -> Result<(), rusqlite::Error> {
        let version: i32 = conn
            .query_row("PRAGMA user_version;", [], |row| row.get(0))
            .unwrap_or(0);

        if version < 1 {
            let tx = conn.transaction()?;
            tx.execute_batch(MIGRATION_V1)?;
            tx.execute_batch("PRAGMA user_version = 1;")?;
            tx.commit()?;
        }

        if version < 2 {
            let tx = conn.transaction()?;
            tx.execute_batch(MIGRATION_V2)?;
            tx.execute_batch("PRAGMA user_version = 2;")?;
            tx.commit()?;
        }

        if version < 3 {
            let tx = conn.transaction()?;
            tx.execute_batch(MIGRATION_V3)?;
            tx.execute_batch("PRAGMA user_version = 3;")?;
            tx.commit()?;
        }

        if version < 4 {
            let tx = conn.transaction()?;
            tx.execute_batch(MIGRATION_V4)?;
            tx.execute_batch("PRAGMA user_version = 4;")?;
            tx.commit()?;
        }

        if version < 5 {
            let tx = conn.transaction()?;

            let has_col: bool = tx
                .prepare("PRAGMA table_info(observer_leases);")?
                .query_map([], |row| row.get::<_, String>(1))?
                .filter_map(Result::ok)
                .any(|col| col == "fencing_token");

            if !has_col {
                tx.execute_batch(
                    "ALTER TABLE observer_leases ADD COLUMN fencing_token INTEGER NOT NULL DEFAULT 1;",
                )?;
            }

            tx.execute_batch(MIGRATION_V5)?;
            tx.execute_batch("PRAGMA user_version = 5;")?;
            tx.commit()?;
        }

        if version < 6 {
            let tx = conn.transaction()?;

            let session_cols: Vec<String> = tx
                .prepare("PRAGMA table_info(sessions);")?
                .query_map([], |row| row.get::<_, String>(1))?
                .filter_map(Result::ok)
                .collect();

            if !session_cols.contains(&"root_binding".to_string()) {
                tx.execute_batch("ALTER TABLE sessions ADD COLUMN root_binding TEXT;")?;
            }

            let resource_cols: Vec<String> = tx
                .prepare("PRAGMA table_info(session_resources);")?
                .query_map([], |row| row.get::<_, String>(1))?
                .filter_map(Result::ok)
                .collect();

            if !resource_cols.contains(&"provenance".to_string()) {
                tx.execute_batch("ALTER TABLE session_resources ADD COLUMN provenance TEXT;")?;
            }

            tx.execute_batch(MIGRATION_V6)?;
            tx.execute_batch("PRAGMA user_version = 6;")?;
            tx.commit()?;
        }

        if version < 7 {
            let tx = conn.transaction()?;
            tx.execute_batch(MIGRATION_V7)?;
            tx.execute_batch("PRAGMA user_version = 7;")?;
            tx.commit()?;
        }

        Ok(())
    }

    /// Records a process termination attempt in the audit log.
    pub fn log_termination(&self, record: &AuditRecord) -> Result<(), StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Lock(e.to_string()))?;

        conn.execute(
            "INSERT INTO audit_log (timestamp, pid, process_name, agent_attribution, signal_sent, success, note)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                record.timestamp,
                record.pid,
                record.process_name,
                record.agent_attribution,
                record.signal_sent,
                if record.success { 1 } else { 0 },
                record.note,
            ],
        )?;

        Ok(())
    }

    /// Retrieves the most recent termination records.
    pub fn get_recent_audits(&self, limit: usize) -> Result<Vec<AuditRecord>, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Lock(e.to_string()))?;

        let mut stmt = conn.prepare(
            "SELECT timestamp, pid, process_name, agent_attribution, signal_sent, success, note
             FROM audit_log ORDER BY id DESC LIMIT ?1",
        )?;

        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(AuditRecord {
                timestamp: row.get(0)?,
                pid: row.get(1)?,
                process_name: row.get(2)?,
                agent_attribution: row.get(3)?,
                signal_sent: row.get(4)?,
                success: row.get::<_, i32>(5)? == 1,
                note: row.get(6)?,
            })
        })?;

        let mut results = Vec::new();
        for r in rows {
            results.push(r?);
        }
        Ok(results)
    }

    // =========================================================================
    // AI AGENT SESSION PERSISTENCE
    // =========================================================================

    /// Saves or updates a session record.
    pub fn save_session(&self, session: &SessionInfo) -> Result<(), StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Lock(e.to_string()))?;

        let evidence_str = session.evidence.join("; ");
        let start_str = session.start_time.to_rfc3339();
        let end_str = session.end_time.map(|t| t.to_rfc3339());
        let status_str = session.status.to_string();
        let agent_str = session.agent_kind.to_string();
        let confidence_val = session.confidence.to_code();

        let root_binding_json = session
            .root_binding
            .as_ref()
            .and_then(|b| serde_json::to_string(b).ok());

        conn.execute(
            "INSERT INTO sessions (id, agent_kind, status, start_time, end_time, root_pid, root_process_name, confidence, evidence, created_at, root_binding)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(id) DO UPDATE SET
                agent_kind = excluded.agent_kind,
                status = excluded.status,
                start_time = excluded.start_time,
                end_time = excluded.end_time,
                root_pid = excluded.root_pid,
                root_process_name = excluded.root_process_name,
                confidence = excluded.confidence,
                evidence = excluded.evidence,
                root_binding = excluded.root_binding",
            params![
                session.id,
                agent_str,
                status_str,
                start_str,
                end_str,
                session.root_pid,
                session.root_process_name,
                confidence_val,
                evidence_str,
                Utc::now().to_rfc3339(),
                root_binding_json,
            ],
        )?;

        if session.status != SessionStatus::Active {
            let _ = conn.execute(
                "DELETE FROM observer_leases WHERE session_id = ?1",
                params![session.id],
            );
        }

        Ok(())
    }

    /// Retrieves an individual session by its identifier.
    pub fn get_session(&self, id: &str) -> Result<Option<SessionInfo>, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Lock(e.to_string()))?;

        let mut stmt = conn.prepare(
            "SELECT id, agent_kind, status, start_time, end_time, root_pid, root_process_name, confidence, evidence, root_binding
             FROM sessions WHERE id = ?1",
        )?;

        let session = stmt
            .query_row(params![id], Self::row_to_session)
            .optional()?;

        if let Some(mut sess) = session {
            // Load tracked resources to populate summary metrics
            let resources = Self::query_resources(&conn, &sess.id)?;
            Self::enrich_session_with_resources(&mut sess, &resources);
            Ok(Some(sess))
        } else {
            Ok(None)
        }
    }

    /// Retrieves the most recent active session, if any.
    pub fn get_active_session(&self) -> Result<Option<SessionInfo>, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Lock(e.to_string()))?;

        let mut stmt = conn.prepare(
            "SELECT id, agent_kind, status, start_time, end_time, root_pid, root_process_name, confidence, evidence, root_binding
             FROM sessions WHERE status = 'ACTIVE' ORDER BY start_time DESC LIMIT 1",
        )?;

        let session = stmt.query_row([], Self::row_to_session).optional()?;

        if let Some(mut sess) = session {
            let resources = Self::query_resources(&conn, &sess.id)?;
            Self::enrich_session_with_resources(&mut sess, &resources);
            Ok(Some(sess))
        } else {
            Ok(None)
        }
    }

    /// Lists all sessions, ordered by start time descending.
    pub fn list_sessions(&self) -> Result<Vec<SessionInfo>, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Lock(e.to_string()))?;

        let mut stmt = conn.prepare(
            "SELECT id, agent_kind, status, start_time, end_time, root_pid, root_process_name, confidence, evidence, root_binding
             FROM sessions ORDER BY start_time DESC",
        )?;

        let rows = stmt.query_map([], Self::row_to_session)?;

        let mut sessions = Vec::new();
        for r in rows {
            let mut sess = r?;
            let resources = Self::query_resources(&conn, &sess.id)?;
            Self::enrich_session_with_resources(&mut sess, &resources);
            sessions.push(sess);
        }

        Ok(sessions)
    }

    /// Replaces tracked resources for a session while preserving original first_seen timestamps.
    pub fn save_session_resources(
        &self,
        session_id: &str,
        resources: &[TrackedResource],
    ) -> Result<(), StorageError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Lock(e.to_string()))?;

        let tx = conn.transaction()?;

        // Capture existing first_seen timestamps to preserve them across observation updates
        let mut existing_first_seen: HashMap<(Option<u32>, String), String> = HashMap::new();
        {
            let mut stmt = tx.prepare(
                "SELECT pid, name, first_seen FROM session_resources WHERE session_id = ?1",
            )?;
            let rows = stmt.query_map(params![session_id], |row| {
                let pid: Option<u32> = row.get(0)?;
                let name: String = row.get(1)?;
                let first_seen: String = row.get(2)?;
                Ok(((pid, name), first_seen))
            })?;
            for (key, val) in rows.flatten() {
                existing_first_seen.insert(key, val);
            }
        }

        // Delete previous resources for this session
        tx.execute(
            "DELETE FROM session_resources WHERE session_id = ?1",
            params![session_id],
        )?;

        for r in resources {
            let ports_str = r
                .listening_ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",");
            let evidence_str = r.evidence.join("; ");

            let first_seen_str = existing_first_seen
                .get(&(r.pid, r.name.clone()))
                .cloned()
                .unwrap_or_else(|| r.first_seen.to_rfc3339());

            let provenance_json = r
                .provenance
                .as_ref()
                .and_then(|p| serde_json::to_string(p).ok());

            tx.execute(
                "INSERT INTO session_resources (
                    session_id, pid, name, exe_path, memory_bytes, cpu_usage, ports,
                    confidence, evidence, is_detached, is_protected, safe_to_terminate,
                    first_seen, last_seen, process_start_time, provenance
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
                params![
                    r.session_id,
                    r.pid,
                    r.name,
                    r.exe_path,
                    r.memory_bytes.map(|m| m as i64),
                    r.cpu_usage.map(|c| c as f64),
                    ports_str,
                    r.confidence.to_code(),
                    evidence_str,
                    if r.is_detached { 1 } else { 0 },
                    if r.is_protected { 1 } else { 0 },
                    if r.safe_to_terminate { 1 } else { 0 },
                    first_seen_str,
                    r.last_seen.to_rfc3339(),
                    r.process_start_time.map(|t| t as i64),
                    provenance_json,
                ],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    /// Retrieves tracked resources for a session.
    pub fn get_session_resources(
        &self,
        session_id: &str,
    ) -> Result<Vec<TrackedResource>, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Lock(e.to_string()))?;

        Self::query_resources(&conn, session_id)
    }

    /// Records an aggregated snapshot of session metrics over time, returning the snapshot row ID.
    pub fn record_session_snapshot(
        &self,
        session_id: &str,
        proc_count: usize,
        total_memory: u64,
        total_cpu: f32,
        ports_count: usize,
    ) -> Result<i64, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Lock(e.to_string()))?;

        conn.execute(
            "INSERT INTO session_snapshots (session_id, timestamp, process_count, total_memory_bytes, total_cpu_usage, ports_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                session_id,
                Utc::now().to_rfc3339(),
                proc_count as i64,
                total_memory as i64,
                total_cpu as f64,
                ports_count as i64,
            ],
        )?;

        Ok(conn.last_insert_rowid())
    }

    pub fn get_session_snapshots(
        &self,
        session_id: &str,
    ) -> Result<Vec<SessionSnapshotRecord>, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Lock(e.to_string()))?;

        let mut stmt = conn.prepare(
            "SELECT id, session_id, timestamp, process_count, total_memory_bytes, total_cpu_usage, ports_count
             FROM session_snapshots WHERE session_id = ?1 ORDER BY id ASC",
        )?;

        let rows = stmt.query_map(params![session_id], |row| {
            Ok(SessionSnapshotRecord {
                id: row.get(0)?,
                session_id: row.get(1)?,
                timestamp: row.get(2)?,
                process_count: row.get::<_, i64>(3)? as usize,
                total_memory_bytes: row.get::<_, i64>(4)? as u64,
                total_cpu_usage: row.get::<_, f64>(5)? as f32,
                ports_count: row.get::<_, i64>(6)? as usize,
            })
        })?;

        let mut results = Vec::new();
        for r in rows {
            results.push(r?);
        }
        Ok(results)
    }

    /// Prunes historical records beyond retention thresholds.
    pub fn prune_history(
        &self,
        retention_days: u32,
        max_snapshots_per_session: usize,
    ) -> Result<usize, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Lock(e.to_string()))?;

        let cutoff = Utc::now() - chrono::Duration::days(retention_days as i64);
        let cutoff_str = cutoff.to_rfc3339();

        // 1. Delete stopped or completed sessions older than retention cutoff
        let deleted_sessions = conn.execute(
            "DELETE FROM sessions WHERE status != 'ACTIVE' AND start_time < ?1",
            params![cutoff_str],
        )?;

        // 2. Prune old snapshots exceeding max_snapshots_per_session
        conn.execute(
            "DELETE FROM session_snapshots
             WHERE id NOT IN (
                 SELECT id FROM session_snapshots AS s
                 WHERE s.session_id = session_snapshots.session_id
                 ORDER BY id DESC LIMIT ?1
             )",
            params![max_snapshots_per_session as i64],
        )?;

        Ok(deleted_sessions)
    }

    // =========================================================================
    // OBSERVER LEASES (MULTI-PROCESS OBSERVATION COORDINATION & FENCING)
    // =========================================================================

    fn get_next_fencing_token_in_tx(
        tx: &rusqlite::Transaction,
        session_id: &str,
    ) -> Result<u64, rusqlite::Error> {
        let last_token: Option<i64> = tx
            .query_row(
                "SELECT last_fencing_token FROM session_lease_generations WHERE session_id = ?1",
                params![session_id],
                |row| row.get(0),
            )
            .optional()?;

        let lease_token: Option<i64> = tx
            .query_row(
                "SELECT fencing_token FROM observer_leases WHERE session_id = ?1",
                params![session_id],
                |row| row.get(0),
            )
            .optional()?;

        let current_max = match (last_token, lease_token) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };

        let next_token = match current_max {
            Some(t) => (t as u64).saturating_add(1),
            None => 1,
        };

        tx.execute(
            "INSERT INTO session_lease_generations (session_id, last_fencing_token, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(session_id) DO UPDATE SET
                last_fencing_token = MAX(session_lease_generations.last_fencing_token, excluded.last_fencing_token),
                updated_at = excluded.updated_at",
            params![session_id, next_token as i64, Utc::now().to_rfc3339()],
        )?;

        Ok(next_token)
    }

    fn log_lease_history_in_tx(
        tx: &rusqlite::Transaction,
        session_id: &str,
        owner_id: &str,
        token: u64,
        action: &str,
    ) -> Result<(), rusqlite::Error> {
        tx.execute(
            "INSERT INTO session_lease_history (session_id, owner_id, fencing_token, action, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                session_id,
                owner_id,
                token as i64,
                action,
                Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Atomically acquires an observer lease for an active session with a monotonic fencing token.
    pub fn acquire_observer_lease(
        &self,
        session_id: &str,
        owner_id: &str,
        ttl_secs: u64,
    ) -> Result<LeaseAcquisitionResult, StorageError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Lock(e.to_string()))?;

        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        // 1. Session must exist and be ACTIVE
        let session_status: Option<String> = tx
            .query_row(
                "SELECT status FROM sessions WHERE id = ?1",
                params![session_id],
                |row| row.get(0),
            )
            .optional()?;

        let status_str = match session_status {
            Some(s) => s,
            None => return Err(StorageError::SessionNotFound(session_id.to_string())),
        };

        if status_str != "ACTIVE" {
            return Err(StorageError::SessionNotActive(session_id.to_string()));
        }

        let now = Utc::now();
        let expires_at = now + chrono::Duration::seconds(ttl_secs as i64);

        let existing_lease: Option<(String, i64, String, String)> = tx
            .query_row(
                "SELECT owner_id, fencing_token, acquired_at, expires_at FROM observer_leases WHERE session_id = ?1",
                params![session_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;

        let result = match existing_lease {
            None => {
                let token = Self::get_next_fencing_token_in_tx(&tx, session_id)?;
                tx.execute(
                    "INSERT INTO observer_leases (session_id, owner_id, fencing_token, acquired_at, expires_at, last_renewed_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        session_id,
                        owner_id,
                        token as i64,
                        now.to_rfc3339(),
                        expires_at.to_rfc3339(),
                        now.to_rfc3339(),
                    ],
                )?;
                Self::log_lease_history_in_tx(&tx, session_id, owner_id, token, "ACQUIRED")?;
                LeaseAcquisitionResult::Acquired(ObserverLease {
                    session_id: session_id.to_string(),
                    owner_id: owner_id.to_string(),
                    fencing_token: token,
                    acquired_at: now,
                    expires_at,
                    last_renewed_at: now,
                })
            }
            Some((curr_owner, curr_token_i64, acq_str, exp_str)) => {
                let curr_token = curr_token_i64 as u64;
                let existing_expires = DateTime::parse_from_rfc3339(&exp_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or(now);
                let existing_acq = DateTime::parse_from_rfc3339(&acq_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or(now);

                if curr_owner == owner_id {
                    tx.execute(
                        "UPDATE observer_leases SET expires_at = ?1, last_renewed_at = ?2 WHERE session_id = ?3 AND owner_id = ?4 AND fencing_token = ?5",
                        params![expires_at.to_rfc3339(), now.to_rfc3339(), session_id, owner_id, curr_token as i64],
                    )?;
                    Self::log_lease_history_in_tx(
                        &tx, session_id, owner_id, curr_token, "RENEWED",
                    )?;
                    LeaseAcquisitionResult::Renewed(ObserverLease {
                        session_id: session_id.to_string(),
                        owner_id: owner_id.to_string(),
                        fencing_token: curr_token,
                        acquired_at: existing_acq,
                        expires_at,
                        last_renewed_at: now,
                    })
                } else if existing_expires > now {
                    LeaseAcquisitionResult::AlreadyHeld {
                        current_owner: curr_owner,
                        current_generation: curr_token,
                        expires_at: existing_expires,
                    }
                } else {
                    // Expired lease recovery by new owner creates a new fencing generation
                    let token = Self::get_next_fencing_token_in_tx(&tx, session_id)?;
                    tx.execute(
                        "UPDATE observer_leases SET owner_id = ?1, fencing_token = ?2, acquired_at = ?3, expires_at = ?4, last_renewed_at = ?5 WHERE session_id = ?6",
                        params![
                            owner_id,
                            token as i64,
                            now.to_rfc3339(),
                            expires_at.to_rfc3339(),
                            now.to_rfc3339(),
                            session_id,
                        ],
                    )?;
                    Self::log_lease_history_in_tx(&tx, session_id, owner_id, token, "RECOVERED")?;
                    LeaseAcquisitionResult::RecoveredFromExpired {
                        lease: ObserverLease {
                            session_id: session_id.to_string(),
                            owner_id: owner_id.to_string(),
                            fencing_token: token,
                            acquired_at: now,
                            expires_at,
                            last_renewed_at: now,
                        },
                        previous_owner: curr_owner,
                    }
                }
            }
        };

        tx.commit()?;
        Ok(result)
    }

    /// Renews an existing observer lease if owned by caller with the matching fencing token and if session is still ACTIVE.
    pub fn renew_observer_lease(
        &self,
        session_id: &str,
        owner_id: &str,
        fencing_token: u64,
        ttl_secs: u64,
    ) -> Result<bool, StorageError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Lock(e.to_string()))?;

        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        // Session must be active
        let session_status: Option<String> = tx
            .query_row(
                "SELECT status FROM sessions WHERE id = ?1",
                params![session_id],
                |row| row.get(0),
            )
            .optional()?;

        match session_status {
            Some(s) if s == "ACTIVE" => {}
            _ => {
                tx.rollback()?;
                return Ok(false);
            }
        }

        let current: Option<(String, i64)> = tx
            .query_row(
                "SELECT owner_id, fencing_token FROM observer_leases WHERE session_id = ?1",
                params![session_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        match current {
            Some((curr_owner, curr_token))
                if curr_owner == owner_id && (curr_token as u64) == fencing_token =>
            {
                let now = Utc::now();
                let expires_at = now + chrono::Duration::seconds(ttl_secs as i64);
                tx.execute(
                    "UPDATE observer_leases SET expires_at = ?1, last_renewed_at = ?2 WHERE session_id = ?3 AND owner_id = ?4 AND fencing_token = ?5",
                    params![expires_at.to_rfc3339(), now.to_rfc3339(), session_id, owner_id, curr_token],
                )?;
                Self::log_lease_history_in_tx(&tx, session_id, owner_id, fencing_token, "RENEWED")?;
                tx.commit()?;
                Ok(true)
            }
            _ => {
                tx.rollback()?;
                Ok(false)
            }
        }
    }

    /// Releases an observer lease held by the caller, matching both owner and fencing token.
    pub fn release_observer_lease(
        &self,
        session_id: &str,
        owner_id: &str,
        fencing_token: u64,
    ) -> Result<bool, StorageError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Lock(e.to_string()))?;

        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        let changes = tx.execute(
            "DELETE FROM observer_leases WHERE session_id = ?1 AND owner_id = ?2 AND fencing_token = ?3",
            params![session_id, owner_id, fencing_token as i64],
        )?;

        if changes > 0 {
            Self::log_lease_history_in_tx(&tx, session_id, owner_id, fencing_token, "RELEASED")?;
            tx.commit()?;
            Ok(true)
        } else {
            tx.rollback()?;
            Ok(false)
        }
    }

    /// Retrieves the current observer lease for a session, if any.
    pub fn get_observer_lease(
        &self,
        session_id: &str,
    ) -> Result<Option<ObserverLease>, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Lock(e.to_string()))?;

        let row = conn
            .query_row(
                "SELECT session_id, owner_id, fencing_token, acquired_at, expires_at, last_renewed_at
                 FROM observer_leases WHERE session_id = ?1",
                params![session_id],
                |row| {
                    let s_id: String = row.get(0)?;
                    let o_id: String = row.get(1)?;
                    let f_token: i64 = row.get(2)?;
                    let acq_str: String = row.get(3)?;
                    let exp_str: String = row.get(4)?;
                    let ren_str: String = row.get(5)?;

                    let acquired_at = DateTime::parse_from_rfc3339(&acq_str)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now());
                    let expires_at = DateTime::parse_from_rfc3339(&exp_str)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now());
                    let last_renewed_at = DateTime::parse_from_rfc3339(&ren_str)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now());

                    Ok(ObserverLease {
                        session_id: s_id,
                        owner_id: o_id,
                        fencing_token: f_token as u64,
                        acquired_at,
                        expires_at,
                        last_renewed_at,
                    })
                },
            )
            .optional()?;

        Ok(row)
    }

    /// Retrieves the highest fencing generation issued for a session, even if lease was released.
    pub fn get_last_fencing_token(&self, session_id: &str) -> Result<u64, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Lock(e.to_string()))?;

        let gen_token: Option<i64> = conn
            .query_row(
                "SELECT last_fencing_token FROM session_lease_generations WHERE session_id = ?1",
                params![session_id],
                |row| row.get(0),
            )
            .optional()?;

        let lease_token: Option<i64> = conn
            .query_row(
                "SELECT fencing_token FROM observer_leases WHERE session_id = ?1",
                params![session_id],
                |row| row.get(0),
            )
            .optional()?;

        let max_token = match (gen_token, lease_token) {
            (Some(a), Some(b)) => a.max(b),
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => 0,
        };

        Ok(max_token as u64)
    }

    /// Atomically validates lease ownership and fencing token before committing session resources, snapshots, and lineage.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_session_observation_with_lineage(
        &self,
        session_id: &str,
        owner_id: &str,
        fencing_token: u64,
        session: &SessionInfo,
        resources: &[TrackedResource],
        snapshot_metrics: (usize, u64, f32, usize),
        lineage_edges: &[ProcessLineageEdge],
    ) -> Result<(), StorageError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Lock(e.to_string()))?;

        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        // 1. Session must exist and be ACTIVE
        let session_status: Option<String> = tx
            .query_row(
                "SELECT status FROM sessions WHERE id = ?1",
                params![session_id],
                |row| row.get(0),
            )
            .optional()?;

        match session_status {
            Some(s) if s == "ACTIVE" => {}
            Some(_) => {
                tx.rollback()?;
                return Err(StorageError::SessionNotActive(session_id.to_string()));
            }
            None => {
                tx.rollback()?;
                return Err(StorageError::SessionNotFound(session_id.to_string()));
            }
        }

        // 2. Validate current lease owner, fencing generation, and expiry
        let active_lease: Option<(String, i64, String)> = tx
            .query_row(
                "SELECT owner_id, fencing_token, expires_at FROM observer_leases WHERE session_id = ?1",
                params![session_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;

        let (curr_owner, curr_token, exp_str) = match active_lease {
            Some(l) => l,
            None => {
                tx.rollback()?;
                return Err(StorageError::LeaseNotHeld {
                    session_id: session_id.to_string(),
                    owner_id: owner_id.to_string(),
                });
            }
        };

        if curr_owner != owner_id || (curr_token as u64) != fencing_token {
            tx.rollback()?;
            return Err(StorageError::LeaseFencingConflict {
                session_id: session_id.to_string(),
                expected_token: fencing_token,
                current_token: curr_token as u64,
                current_owner: curr_owner,
            });
        }

        let now = Utc::now();
        let expires_at = DateTime::parse_from_rfc3339(&exp_str)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or(now);

        if expires_at <= now {
            tx.rollback()?;
            return Err(StorageError::LeaseExpired {
                session_id: session_id.to_string(),
                owner_id: owner_id.to_string(),
                expired_at: exp_str,
            });
        }

        // 3. Atomically perform all mutations:
        // 3a. Update session summary
        let evidence_str = session.evidence.join("; ");
        let start_str = session.start_time.to_rfc3339();
        let end_str = session.end_time.map(|t| t.to_rfc3339());
        let status_str = session.status.to_string();
        let agent_str = session.agent_kind.to_string();
        let confidence_val = session.confidence.to_code();
        let root_binding_json = session
            .root_binding
            .as_ref()
            .and_then(|b| serde_json::to_string(b).ok());

        tx.execute(
            "INSERT INTO sessions (id, agent_kind, status, start_time, end_time, root_pid, root_process_name, confidence, evidence, created_at, root_binding)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(id) DO UPDATE SET
                agent_kind = excluded.agent_kind,
                status = excluded.status,
                start_time = excluded.start_time,
                end_time = excluded.end_time,
                root_pid = excluded.root_pid,
                root_process_name = excluded.root_process_name,
                confidence = excluded.confidence,
                evidence = excluded.evidence,
                root_binding = excluded.root_binding",
            params![
                session.id,
                agent_str,
                status_str,
                start_str,
                end_str,
                session.root_pid,
                session.root_process_name,
                confidence_val,
                evidence_str,
                now.to_rfc3339(),
                root_binding_json,
            ],
        )?;

        // 3b. Overwrite session resources
        tx.execute(
            "DELETE FROM session_resources WHERE session_id = ?1",
            params![session_id],
        )?;

        let mut insert_res = tx.prepare(
            "INSERT INTO session_resources (
                session_id, pid, name, exe_path, memory_bytes, cpu_usage, ports,
                confidence, evidence, is_detached, is_protected, safe_to_terminate,
                first_seen, last_seen, process_start_time, provenance
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        )?;

        for r in resources {
            let ports_str = r
                .listening_ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",");
            let res_evidence_str = r.evidence.join("; ");
            let first_seen_str = r.first_seen.to_rfc3339();
            let provenance_json = r
                .provenance
                .as_ref()
                .and_then(|p| serde_json::to_string(p).ok());

            insert_res.execute(params![
                session_id,
                r.pid,
                r.name,
                r.exe_path,
                r.memory_bytes.map(|m| m as i64),
                r.cpu_usage.map(|c| c as f64),
                ports_str,
                r.confidence.to_code(),
                res_evidence_str,
                if r.is_detached { 1 } else { 0 },
                if r.is_protected { 1 } else { 0 },
                if r.safe_to_terminate { 1 } else { 0 },
                first_seen_str,
                r.last_seen.to_rfc3339(),
                r.process_start_time.map(|t| t as i64),
                provenance_json,
            ])?;
        }
        drop(insert_res);

        // 3c. Insert session snapshot record
        let (proc_count, total_memory, total_cpu, ports_count) = snapshot_metrics;
        tx.execute(
            "INSERT INTO session_snapshots (session_id, timestamp, process_count, total_memory_bytes, total_cpu_usage, ports_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                session_id,
                now.to_rfc3339(),
                proc_count as i64,
                total_memory as i64,
                total_cpu as f64,
                ports_count as i64,
            ],
        )?;

        let snapshot_id = tx.last_insert_rowid();

        // 3d. Record lineage edges atomically in the same transaction
        if !lineage_edges.is_empty() {
            Self::record_lineage_edges_in_tx(&tx, session_id, lineage_edges, Some(snapshot_id))?;
        }

        tx.commit()?;
        Ok(())
    }

    /// Atomically validates lease ownership and fencing token before committing session resources and snapshots.
    pub fn commit_session_observation(
        &self,
        session_id: &str,
        owner_id: &str,
        fencing_token: u64,
        session: &SessionInfo,
        resources: &[TrackedResource],
        snapshot_metrics: (usize, u64, f32, usize),
    ) -> Result<(), StorageError> {
        self.commit_session_observation_with_lineage(
            session_id,
            owner_id,
            fencing_token,
            session,
            resources,
            snapshot_metrics,
            &[],
        )
    }

    /// Records process lineage edges within an existing transaction.
    pub fn record_lineage_edges_in_tx(
        tx: &rusqlite::Transaction,
        session_id: &str,
        edges: &[ProcessLineageEdge],
        snapshot_id: Option<i64>,
    ) -> Result<(), StorageError> {
        let mut stmt = tx.prepare(
            "INSERT INTO process_lineage (
                session_id, parent_pid, parent_start_tvsec, parent_start_tvusec, parent_name, parent_exe,
                child_pid, child_start_tvsec, child_start_tvusec, child_name, child_exe,
                first_observed_at, last_observed_at, observation_count, snapshot_id, source, status, validation_details
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
            ON CONFLICT(session_id, parent_pid, parent_start_tvsec, parent_start_tvusec, child_pid, child_start_tvsec, child_start_tvusec) DO UPDATE SET
                last_observed_at = excluded.last_observed_at,
                observation_count = process_lineage.observation_count + 1,
                snapshot_id = COALESCE(excluded.snapshot_id, process_lineage.snapshot_id),
                status = excluded.status,
                validation_details = excluded.validation_details",
        )?;

        for edge in edges {
            let p_exe = edge
                .parent_exe
                .as_ref()
                .map(|p| p.to_string_lossy().to_string());
            let c_exe = edge
                .child_exe
                .as_ref()
                .map(|p| p.to_string_lossy().to_string());
            let snap_id = edge.snapshot_id.or(snapshot_id);

            stmt.execute(params![
                session_id,
                edge.parent.pid,
                edge.parent.start_time.tv_sec as i64,
                edge.parent.start_time.tv_usec as i64,
                edge.parent_name,
                p_exe,
                edge.child.pid,
                edge.child.start_time.tv_sec as i64,
                edge.child.start_time.tv_usec as i64,
                edge.child_name,
                c_exe,
                edge.first_observed_at.to_rfc3339(),
                edge.last_observed_at.to_rfc3339(),
                edge.observation_count as i64,
                snap_id,
                edge.source.to_string(),
                edge.status.to_string(),
                edge.validation_details,
            ])?;
        }

        Ok(())
    }

    /// Atomically records process lineage edges under active observer lease and fencing token guard.
    pub fn record_lineage_edges_fenced(
        &self,
        session_id: &str,
        owner_id: &str,
        fencing_token: u64,
        edges: &[ProcessLineageEdge],
    ) -> Result<(), StorageError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Lock(e.to_string()))?;

        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        // 1. Session must exist and be ACTIVE
        let session_status: Option<String> = tx
            .query_row(
                "SELECT status FROM sessions WHERE id = ?1",
                params![session_id],
                |row| row.get(0),
            )
            .optional()?;

        match session_status {
            Some(s) if s == "ACTIVE" => {}
            Some(_) => {
                tx.rollback()?;
                return Err(StorageError::SessionNotActive(session_id.to_string()));
            }
            None => {
                tx.rollback()?;
                return Err(StorageError::SessionNotFound(session_id.to_string()));
            }
        }

        // 2. Validate current lease owner, fencing generation, and expiry
        let active_lease: Option<(String, i64, String)> = tx
            .query_row(
                "SELECT owner_id, fencing_token, expires_at FROM observer_leases WHERE session_id = ?1",
                params![session_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;

        let (curr_owner, curr_token, exp_str) = match active_lease {
            Some(l) => l,
            None => {
                tx.rollback()?;
                return Err(StorageError::LeaseNotHeld {
                    session_id: session_id.to_string(),
                    owner_id: owner_id.to_string(),
                });
            }
        };

        if curr_owner != owner_id || (curr_token as u64) != fencing_token {
            tx.rollback()?;
            return Err(StorageError::LeaseFencingConflict {
                session_id: session_id.to_string(),
                expected_token: fencing_token,
                current_token: curr_token as u64,
                current_owner: curr_owner,
            });
        }

        let now = Utc::now();
        let expires_at = DateTime::parse_from_rfc3339(&exp_str)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or(now);

        if expires_at <= now {
            tx.rollback()?;
            return Err(StorageError::LeaseExpired {
                session_id: session_id.to_string(),
                owner_id: owner_id.to_string(),
                expired_at: exp_str,
            });
        }

        Self::record_lineage_edges_in_tx(&tx, session_id, edges, None)?;
        tx.commit()?;
        Ok(())
    }

    /// Saves or updates process lineage edges in a single transaction.
    pub fn save_lineage_edges(
        &self,
        session_id: &str,
        edges: &[ProcessLineageEdge],
    ) -> Result<(), StorageError> {
        if edges.is_empty() {
            return Ok(());
        }
        let mut conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Lock(e.to_string()))?;

        let tx = conn.transaction()?;
        Self::record_lineage_edges_in_tx(&tx, session_id, edges, None)?;
        tx.commit()?;
        Ok(())
    }

    /// Retrieves all recorded process lineage edges for a given session.
    pub fn get_lineage_edges(
        &self,
        session_id: &str,
    ) -> Result<Vec<ProcessLineageEdge>, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Lock(e.to_string()))?;

        let mut stmt = conn.prepare(
            "SELECT id, session_id, parent_pid, parent_start_tvsec, parent_start_tvusec, parent_name, parent_exe,
                    child_pid, child_start_tvsec, child_start_tvusec, child_name, child_exe,
                    first_observed_at, last_observed_at, observation_count, snapshot_id, source, status, validation_details
             FROM process_lineage
             WHERE session_id = ?1
             ORDER BY id ASC",
        )?;

        let edges = stmt
            .query_map(params![session_id], Self::row_to_lineage_edge)?
            .filter_map(Result::ok)
            .collect();

        Ok(edges)
    }

    /// Looks up the recorded parent edge for a specific child process incarnation.
    pub fn get_lineage_edge_for_child(
        &self,
        session_id: &str,
        child: &ProcessIncarnation,
    ) -> Result<Option<ProcessLineageEdge>, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Lock(e.to_string()))?;

        let edge = conn
            .query_row(
                "SELECT id, session_id, parent_pid, parent_start_tvsec, parent_start_tvusec, parent_name, parent_exe,
                        child_pid, child_start_tvsec, child_start_tvusec, child_name, child_exe,
                        first_observed_at, last_observed_at, observation_count, snapshot_id, source, status, validation_details
                 FROM process_lineage
                 WHERE session_id = ?1 AND child_pid = ?2 AND child_start_tvsec = ?3 AND child_start_tvusec = ?4",
                params![session_id, child.pid, child.start_time.tv_sec as i64, child.start_time.tv_usec as i64],
                Self::row_to_lineage_edge,
            )
            .optional()?;

        Ok(edge)
    }

    /// Looks up all child edges recorded for a given parent process incarnation.
    pub fn get_lineage_edges_for_parent(
        &self,
        session_id: &str,
        parent: &ProcessIncarnation,
    ) -> Result<Vec<ProcessLineageEdge>, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Lock(e.to_string()))?;

        let mut stmt = conn.prepare(
            "SELECT id, session_id, parent_pid, parent_start_tvsec, parent_start_tvusec, parent_name, parent_exe,
                    child_pid, child_start_tvsec, child_start_tvusec, child_name, child_exe,
                    first_observed_at, last_observed_at, observation_count, snapshot_id, source, status, validation_details
             FROM process_lineage
             WHERE session_id = ?1 AND parent_pid = ?2 AND parent_start_tvsec = ?3 AND parent_start_tvusec = ?4
             ORDER BY id ASC",
        )?;

        let edges = stmt
            .query_map(
                params![
                    session_id,
                    parent.pid,
                    parent.start_time.tv_sec as i64,
                    parent.start_time.tv_usec as i64
                ],
                Self::row_to_lineage_edge,
            )?
            .filter_map(Result::ok)
            .collect();

        Ok(edges)
    }

    /// Updates the status of all edges where the specified process incarnation is the parent.
    pub fn update_lineage_status_for_parent(
        &self,
        session_id: &str,
        parent: &ProcessIncarnation,
        new_status: LineageStatus,
    ) -> Result<(), StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Lock(e.to_string()))?;

        conn.execute(
            "UPDATE process_lineage SET status = ?1
             WHERE session_id = ?2 AND parent_pid = ?3 AND parent_start_tvsec = ?4 AND parent_start_tvusec = ?5",
            params![
                new_status.to_string(),
                session_id,
                parent.pid,
                parent.start_time.tv_sec as i64,
                parent.start_time.tv_usec as i64,
            ],
        )?;

        Ok(())
    }

    // =========================================================================
    // PRIVATE HELPERS
    // =========================================================================

    fn row_to_lineage_edge(row: &rusqlite::Row) -> rusqlite::Result<ProcessLineageEdge> {
        let id: i64 = row.get(0)?;
        let session_id: String = row.get(1)?;
        let parent_pid: u32 = row.get::<_, i64>(2)? as u32;
        let parent_sec: i64 = row.get(3)?;
        let parent_usec: i64 = row.get(4)?;
        let parent_name: Option<String> = row.get(5)?;
        let parent_exe: Option<String> = row.get(6)?;
        let child_pid: u32 = row.get::<_, i64>(7)? as u32;
        let child_sec: i64 = row.get(8)?;
        let child_usec: i64 = row.get(9)?;
        let child_name: String = row.get(10)?;
        let child_exe: Option<String> = row.get(11)?;
        let first_str: String = row.get(12)?;
        let last_str: String = row.get(13)?;
        let obs_count: i64 = row.get(14)?;
        let snapshot_id: Option<i64> = row.get(15)?;
        let source_str: String = row.get(16)?;
        let status_str: String = row.get(17)?;
        let validation_details: Option<String> = row.get(18)?;

        let parent = ProcessIncarnation::new(
            parent_pid,
            ProcessStartTime::new(parent_sec as u64, parent_usec as u64),
        );
        let child = ProcessIncarnation::new(
            child_pid,
            ProcessStartTime::new(child_sec as u64, child_usec as u64),
        );

        let first_observed_at = DateTime::parse_from_rfc3339(&first_str)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());
        let last_observed_at = DateTime::parse_from_rfc3339(&last_str)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        let source = source_str
            .parse::<LineageSource>()
            .unwrap_or(LineageSource::CompleteSnapshotObservation);
        let status = status_str
            .parse::<LineageStatus>()
            .unwrap_or(LineageStatus::BothActive);

        Ok(ProcessLineageEdge {
            id: Some(id),
            session_id,
            parent,
            child,
            parent_name,
            parent_exe: parent_exe.map(PathBuf::from),
            child_name,
            child_exe: child_exe.map(PathBuf::from),
            first_observed_at,
            last_observed_at,
            observation_count: obs_count as u64,
            snapshot_id,
            source,
            status,
            validation_details,
        })
    }

    fn row_to_session(row: &rusqlite::Row) -> rusqlite::Result<SessionInfo> {
        let id: String = row.get(0)?;
        let agent_str: String = row.get(1)?;
        let status_str: String = row.get(2)?;
        let start_str: String = row.get(3)?;
        let end_str: Option<String> = row.get(4)?;
        let root_pid: Option<u32> = row.get(5)?;
        let root_process_name: Option<String> = row.get(6)?;
        let confidence_code: i32 = row.get(7)?;
        let evidence_str: String = row.get(8)?;
        let root_binding_json: Option<String> = row.get(9).ok().flatten();

        let agent_kind = AgentKind::from_str_name(&agent_str);
        let status = status_str
            .parse::<SessionStatus>()
            .unwrap_or(SessionStatus::Stopped);
        let start_time = DateTime::parse_from_rfc3339(&start_str)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());
        let end_time = end_str.and_then(|s| {
            DateTime::parse_from_rfc3339(&s)
                .map(|dt| dt.with_timezone(&Utc))
                .ok()
        });
        let confidence = Confidence::from_code(confidence_code);
        let evidence = evidence_str
            .split(';')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let root_binding = root_binding_json.and_then(|s| serde_json::from_str(&s).ok());

        Ok(SessionInfo {
            id,
            agent_kind,
            status,
            start_time,
            end_time,
            root_pid,
            root_process_name,
            confidence,
            evidence,
            tracked_pids: Vec::new(),
            total_memory_bytes: 0,
            total_cpu_usage: 0.0,
            open_ports: Vec::new(),
            resource_count: 0,
            root_binding,
        })
    }

    fn query_resources(
        conn: &Connection,
        session_id: &str,
    ) -> Result<Vec<TrackedResource>, StorageError> {
        let mut stmt = conn.prepare(
            "SELECT session_id, pid, name, exe_path, memory_bytes, cpu_usage, ports,
                    confidence, evidence, is_detached, is_protected, safe_to_terminate,
                    first_seen, last_seen, process_start_time, provenance
             FROM session_resources WHERE session_id = ?1",
        )?;

        let rows = stmt.query_map(params![session_id], |row| {
            let session_id: String = row.get(0)?;
            let pid: Option<u32> = row.get(1)?;
            let name: String = row.get(2)?;
            let exe_path: Option<String> = row.get(3)?;
            let memory_bytes: Option<i64> = row.get(4)?;
            let cpu_usage: Option<f64> = row.get(5)?;
            let ports_str: Option<String> = row.get(6).ok().flatten();
            let confidence_code: i32 = row.get(7).unwrap_or(0);
            let evidence_str: Option<String> = row.get(8).ok().flatten();
            let is_detached: i32 = row.get(9).unwrap_or(0);
            let is_protected: i32 = row.get(10).unwrap_or(0);
            let safe_to_terminate: i32 = row.get(11).unwrap_or(0);
            let first_str: Option<String> = row.get(12).ok().flatten();
            let last_str: Option<String> = row.get(13).ok().flatten();
            let process_start_time: Option<i64> = row.get(14).ok().flatten();
            let provenance_json: Option<String> = row.get(15).ok().flatten();

            let ports = ports_str
                .as_deref()
                .unwrap_or("")
                .split(',')
                .filter_map(|p| p.trim().parse::<u16>().ok())
                .collect();
            let evidence = evidence_str
                .as_deref()
                .unwrap_or("")
                .split(';')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let first_seen = first_str
                .as_deref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(Utc::now);
            let last_seen = last_str
                .as_deref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(Utc::now);
            let provenance = provenance_json.and_then(|s| serde_json::from_str(&s).ok());

            Ok(TrackedResource {
                session_id,
                pid,
                name,
                exe_path,
                memory_bytes: memory_bytes.map(|m| m as u64),
                cpu_usage: cpu_usage.map(|c| c as f32),
                listening_ports: ports,
                confidence: Confidence::from_code(confidence_code),
                evidence,
                is_detached: is_detached == 1,
                is_protected: is_protected == 1,
                safe_to_terminate: safe_to_terminate == 1,
                first_seen,
                last_seen,
                process_start_time: process_start_time.map(|t| t as u64),
                provenance,
            })
        })?;

        let mut res = Vec::new();
        for r in rows {
            res.push(r?);
        }
        Ok(res)
    }

    fn enrich_session_with_resources(session: &mut SessionInfo, resources: &[TrackedResource]) {
        let mut pids = Vec::new();
        let mut ports = Vec::new();
        let mut total_mem = 0u64;
        let mut total_cpu = 0.0f32;

        for r in resources {
            if let Some(pid) = r.pid {
                pids.push(pid);
            }
            for p in &r.listening_ports {
                ports.push(*p);
            }
            if let Some(mem) = r.memory_bytes {
                total_mem += mem;
            }
            if let Some(cpu) = r.cpu_usage {
                total_cpu += cpu;
            }
        }

        ports.sort_unstable();
        ports.dedup();

        session.tracked_pids = pids;
        session.open_ports = ports;
        session.total_memory_bytes = total_mem;
        session.total_cpu_usage = total_cpu;
        session.resource_count = resources.len();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::provenance::LaunchProvenance;

    #[test]
    fn test_storage_in_memory() {
        let storage = StorageManager::open_in_memory().expect("Should open memory db");
        let record = AuditRecord {
            timestamp: "2026-11-11T12:00:00Z".to_string(),
            pid: 12345,
            process_name: "node".to_string(),
            agent_attribution: "Claude Code".to_string(),
            signal_sent: "SIGTERM".to_string(),
            success: true,
            note: Some("Graceful exit".to_string()),
        };
        storage.log_termination(&record).expect("Must log");
        let recents = storage.get_recent_audits(10).expect("Must retrieve");
        assert_eq!(recents.len(), 1);
        assert_eq!(recents[0].pid, 12345);
        assert_eq!(recents[0].process_name, "node");
    }

    #[test]
    fn test_session_lifecycle_persistence() {
        let storage = StorageManager::open_in_memory().expect("Should open memory db");
        let start = Utc::now();
        let session = SessionInfo {
            id: "sess-test-01".to_string(),
            agent_kind: AgentKind::ClaudeCode,
            status: SessionStatus::Active,
            start_time: start,
            end_time: None,
            root_pid: Some(4001),
            root_process_name: Some("claude".to_string()),
            confidence: Confidence::Confirmed,
            evidence: vec!["Explicit test agent".to_string()],
            tracked_pids: vec![4001, 4002],
            total_memory_bytes: 0,
            total_cpu_usage: 0.0,
            open_ports: Vec::new(),
            resource_count: 0,
            root_binding: Some(LaunchProvenance::root_binding(
                "sess-test-01".to_string(),
                4001,
                Some(1000),
                "claude".to_string(),
                Some(std::path::PathBuf::from("/usr/local/bin/claude")),
                Some(1),
                "Root test binding".to_string(),
            )),
        };

        storage.save_session(&session).expect("Must save session");

        let active = storage
            .get_active_session()
            .expect("Must query active")
            .expect("Should have active session");
        assert_eq!(active.id, "sess-test-01");
        assert_eq!(active.agent_kind, AgentKind::ClaudeCode);
        assert_eq!(active.status, SessionStatus::Active);
        assert!(active.root_binding.is_some());
        assert_eq!(active.root_binding.unwrap().process.pid, 4001);

        // Save resources for this session
        let res1 = TrackedResource {
            session_id: "sess-test-01".to_string(),
            pid: Some(4001),
            name: "claude".to_string(),
            exe_path: Some("/usr/local/bin/claude".to_string()),
            memory_bytes: Some(1024 * 1024 * 50),
            cpu_usage: Some(2.0),
            listening_ports: vec![],
            confidence: Confidence::Confirmed,
            evidence: vec!["Root agent".to_string()],
            is_detached: false,
            is_protected: false,
            safe_to_terminate: true,
            first_seen: start,
            last_seen: start,
            process_start_time: Some(1000),
            provenance: Some(LaunchProvenance::root_binding(
                "sess-test-01".to_string(),
                4001,
                Some(1000),
                "claude".to_string(),
                Some(std::path::PathBuf::from("/usr/local/bin/claude")),
                Some(1),
                "Root resource binding".to_string(),
            )),
        };
        let res2 = TrackedResource {
            session_id: "sess-test-01".to_string(),
            pid: Some(4002),
            name: "node".to_string(),
            exe_path: Some("/usr/local/bin/node".to_string()),
            memory_bytes: Some(1024 * 1024 * 100),
            cpu_usage: Some(0.5),
            listening_ports: vec![3000, 8080],
            confidence: Confidence::HighConfidence,
            evidence: vec!["Child worker".to_string()],
            is_detached: false,
            is_protected: false,
            safe_to_terminate: true,
            first_seen: start,
            last_seen: start,
            process_start_time: Some(1005),
            provenance: Some(LaunchProvenance::discovered_descendant(
                "sess-test-01".to_string(),
                4002,
                Some(1005),
                "node".to_string(),
                Some(std::path::PathBuf::from("/usr/local/bin/node")),
                4001,
                "Child worker discovered in process tree".to_string(),
            )),
        };

        storage
            .save_session_resources("sess-test-01", &[res1, res2])
            .expect("Must save resources");

        let fetched = storage
            .get_session("sess-test-01")
            .expect("Must query")
            .expect("Session must exist");
        assert_eq!(fetched.resource_count, 2);
        assert_eq!(fetched.open_ports, vec![3000, 8080]);
        assert_eq!(fetched.total_memory_bytes, 1024 * 1024 * 150);

        let resources = storage
            .get_session_resources("sess-test-01")
            .expect("Must fetch resources");
        assert_eq!(resources.len(), 2);
        assert!(resources[0].provenance.is_some());
        assert_eq!(
            resources[0].provenance.as_ref().unwrap().source,
            crate::model::provenance::ProvenanceSource::VerifiedSessionRootBinding
        );
        assert!(resources[1].provenance.is_some());
        assert_eq!(
            resources[1].provenance.as_ref().unwrap().source,
            crate::model::provenance::ProvenanceSource::DiscoveredDescendant
        );

        // Test stopping session
        let mut stopped = fetched;
        stopped.status = SessionStatus::Stopped;
        stopped.end_time = Some(Utc::now());
        storage.save_session(&stopped).expect("Must update");

        let active_after = storage
            .get_active_session()
            .expect("Must query active after stop");
        assert!(active_after.is_none());

        let list = storage.list_sessions().expect("Must list");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].status, SessionStatus::Stopped);
    }
}
