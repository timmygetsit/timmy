use chrono::Utc;
use rusqlite::{params, Connection};
use std::path::Path;
use tempfile::NamedTempFile;
use timmy::storage::{LeaseAcquisitionResult, StorageManager};

/// Pre-V5 schema definition for observer_leases (without fencing_token column).
const PRE_V5_MIGRATION_V4: &str = r#"
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

/// Helper to construct a SQLite database representing schema version 4.
fn create_pre_v5_database<P: AsRef<Path>>(path: P) -> Connection {
    let conn = Connection::open(path).expect("open raw sqlite db");
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA busy_timeout = 5000;
         PRAGMA foreign_keys = ON;
         PRAGMA synchronous = NORMAL;",
    )
    .expect("pragmas");

    // Execute V1 through V3
    conn.execute_batch(timmy::storage::MIGRATION_V1)
        .expect("v1");
    conn.execute_batch(timmy::storage::MIGRATION_V2)
        .expect("v2");
    conn.execute_batch(timmy::storage::MIGRATION_V3)
        .expect("v3");

    // Execute original V4 without fencing_token
    conn.execute_batch(PRE_V5_MIGRATION_V4).expect("pre-v5 v4");
    conn.execute_batch("PRAGMA user_version = 4;")
        .expect("set user_version to 4");

    conn
}

/// Helper to insert a session record in a pre-V5 database.
fn insert_session(conn: &Connection, session_id: &str, status: &str) {
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO sessions (id, agent_kind, status, start_time, confidence, evidence, created_at)
         VALUES (?1, 'claude', ?2, ?3, 2, '[]', ?4)",
        params![session_id, status, now, now],
    )
    .expect("insert session");
}

#[test]
fn test_migration_v5_backfill_existing_lease_without_fencing_token_column() {
    let tmp = NamedTempFile::new().expect("temp file");
    let db_path = tmp.path();

    // 1. Create a database strictly at version 4 without fencing_token column
    {
        let conn = create_pre_v5_database(db_path);

        insert_session(&conn, "sess-v4-01", "ACTIVE");

        let now = Utc::now();
        let exp = now + chrono::Duration::seconds(60);
        conn.execute(
            "INSERT INTO observer_leases (session_id, owner_id, acquired_at, expires_at, last_renewed_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                "sess-v4-01",
                "owner-original",
                now.to_rfc3339(),
                exp.to_rfc3339(),
                now.to_rfc3339(),
            ],
        )
        .expect("insert pre-v5 lease");

        let version: i32 = conn
            .query_row("PRAGMA user_version;", [], |r| r.get(0))
            .expect("query version");
        assert_eq!(version, 4, "Must start at schema version 4");
    }

    // 2. Open with StorageManager, which executes versioned migrations to V5
    let storage = StorageManager::open(db_path).expect("open and migrate to v5");

    // Verify user_version upgraded to 5
    let lease = storage
        .get_observer_lease("sess-v4-01")
        .expect("query lease")
        .expect("lease must exist");

    // Requirement 1 & 6: Existing lease preserved, owner preserved, fencing_token defaulted to 1
    assert_eq!(lease.session_id, "sess-v4-01");
    assert_eq!(lease.owner_id, "owner-original");
    assert_eq!(lease.fencing_token, 1);

    // Requirement 2 & 3: session_lease_generations populated from existing lease with token >= 1
    let last_gen = storage
        .get_last_fencing_token("sess-v4-01")
        .expect("get last token");
    assert_eq!(
        last_gen, 1,
        "session_lease_generations must be backfilled to token 1"
    );

    // Requirement 7: Subsequent acquisition receives strictly greater token
    let acq_result = storage
        .acquire_observer_lease("sess-v4-01", "owner-original", 10)
        .expect("renew existing");
    match acq_result {
        LeaseAcquisitionResult::Renewed(l) => {
            assert_eq!(l.fencing_token, 1, "Renewal must preserve current token 1");
        }
        _ => panic!("Expected Renewed for same owner"),
    }
}

#[test]
fn test_migration_v5_preserves_higher_fencing_tokens_across_multiple_sessions() {
    let tmp = NamedTempFile::new().expect("temp file");
    let db_path = tmp.path();

    // 1. Create a database where observer_leases already has fencing_token column with varying tokens
    {
        let conn = create_pre_v5_database(db_path);

        // Add fencing_token column before V5 migration to simulate pre-release / custom values
        conn.execute_batch(
            "ALTER TABLE observer_leases ADD COLUMN fencing_token INTEGER NOT NULL DEFAULT 1;",
        )
        .expect("add fencing_token column");

        insert_session(&conn, "sess-token-1", "ACTIVE");
        insert_session(&conn, "sess-token-15", "ACTIVE");
        insert_session(&conn, "sess-token-99", "ACTIVE");

        let now = Utc::now();
        let exp = now + chrono::Duration::seconds(60);

        conn.execute(
            "INSERT INTO observer_leases (session_id, owner_id, fencing_token, acquired_at, expires_at, last_renewed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params!["sess-token-1", "owner-1", 1, now.to_rfc3339(), exp.to_rfc3339(), now.to_rfc3339()],
        ).expect("insert sess 1");

        conn.execute(
            "INSERT INTO observer_leases (session_id, owner_id, fencing_token, acquired_at, expires_at, last_renewed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params!["sess-token-15", "owner-15", 15, now.to_rfc3339(), exp.to_rfc3339(), now.to_rfc3339()],
        ).expect("insert sess 15");

        conn.execute(
            "INSERT INTO observer_leases (session_id, owner_id, fencing_token, acquired_at, expires_at, last_renewed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params!["sess-token-99", "owner-99", 99, now.to_rfc3339(), exp.to_rfc3339(), now.to_rfc3339()],
        ).expect("insert sess 99");

        // Verify version is still 4
        let version: i32 = conn
            .query_row("PRAGMA user_version;", [], |r| r.get(0))
            .expect("version");
        assert_eq!(version, 4);
    }

    // 2. Open via StorageManager, triggering V5 migration
    let storage = StorageManager::open(db_path).expect("open storage");

    // Check generation backfills
    assert_eq!(storage.get_last_fencing_token("sess-token-1").unwrap(), 1);
    assert_eq!(storage.get_last_fencing_token("sess-token-15").unwrap(), 15);
    assert_eq!(storage.get_last_fencing_token("sess-token-99").unwrap(), 99);

    // Verify existing active leases and owners are intact
    let l1 = storage.get_observer_lease("sess-token-1").unwrap().unwrap();
    assert_eq!(l1.owner_id, "owner-1");
    assert_eq!(l1.fencing_token, 1);

    let l15 = storage
        .get_observer_lease("sess-token-15")
        .unwrap()
        .unwrap();
    assert_eq!(l15.owner_id, "owner-15");
    assert_eq!(l15.fencing_token, 15);

    let l99 = storage
        .get_observer_lease("sess-token-99")
        .unwrap()
        .unwrap();
    assert_eq!(l99.owner_id, "owner-99");
    assert_eq!(l99.fencing_token, 99);
}

#[test]
fn test_migration_v5_subsequent_acquisition_strictly_greater_fencing_token() {
    let tmp = NamedTempFile::new().expect("temp file");
    let db_path = tmp.path();

    // Setup pre-V5 with expired leases
    {
        let conn = create_pre_v5_database(db_path);
        insert_session(&conn, "sess-sub-01", "ACTIVE");
        insert_session(&conn, "sess-sub-42", "ACTIVE");

        conn.execute_batch(
            "ALTER TABLE observer_leases ADD COLUMN fencing_token INTEGER NOT NULL DEFAULT 1;",
        )
        .expect("add col");

        let past = Utc::now() - chrono::Duration::seconds(30);
        conn.execute(
            "INSERT INTO observer_leases (session_id, owner_id, fencing_token, acquired_at, expires_at, last_renewed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params!["sess-sub-01", "old-owner-1", 1, past.to_rfc3339(), past.to_rfc3339(), past.to_rfc3339()],
        ).expect("insert 1");

        conn.execute(
            "INSERT INTO observer_leases (session_id, owner_id, fencing_token, acquired_at, expires_at, last_renewed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params!["sess-sub-42", "old-owner-42", 42, past.to_rfc3339(), past.to_rfc3339(), past.to_rfc3339()],
        ).expect("insert 42");
    }

    let storage = StorageManager::open(db_path).expect("open and migrate");

    // Acquire expired lease for sess-sub-01 with new owner
    let res1 = storage
        .acquire_observer_lease("sess-sub-01", "new-owner-1", 10)
        .expect("recover 1");
    match res1 {
        LeaseAcquisitionResult::RecoveredFromExpired {
            lease,
            previous_owner,
        } => {
            assert_eq!(previous_owner, "old-owner-1");
            assert_eq!(lease.owner_id, "new-owner-1");
            assert_eq!(lease.fencing_token, 2, "Token 1 must increment to 2");
        }
        _ => panic!("Expected RecoveredFromExpired for sess-sub-01"),
    }

    // Acquire expired lease for sess-sub-42 with new owner
    let res42 = storage
        .acquire_observer_lease("sess-sub-42", "new-owner-42", 10)
        .expect("recover 42");
    match res42 {
        LeaseAcquisitionResult::RecoveredFromExpired {
            lease,
            previous_owner,
        } => {
            assert_eq!(previous_owner, "old-owner-42");
            assert_eq!(lease.owner_id, "new-owner-42");
            assert_eq!(lease.fencing_token, 43, "Token 42 must increment to 43");
        }
        _ => panic!("Expected RecoveredFromExpired for sess-sub-42"),
    }

    // Attempting renewal with old token must fail
    let old_renew = storage
        .renew_observer_lease("sess-sub-42", "old-owner-42", 42, 10)
        .unwrap();
    assert!(!old_renew, "Old owner presenting token 42 must be rejected");

    // Attempting release with old token must fail
    let old_release = storage
        .release_observer_lease("sess-sub-42", "old-owner-42", 42)
        .unwrap();
    assert!(
        !old_release,
        "Old owner presenting token 42 cannot release lease"
    );
}

#[test]
fn test_migration_v5_database_reopening_idempotency() {
    let tmp = NamedTempFile::new().expect("temp file");
    let db_path = tmp.path();

    // 1. Create pre-V5
    {
        let conn = create_pre_v5_database(db_path);
        insert_session(&conn, "sess-reopen", "ACTIVE");
    }

    // 2. First open & migration
    {
        let storage = StorageManager::open(db_path).expect("open 1");
        let res = storage
            .acquire_observer_lease("sess-reopen", "owner-a", 10)
            .expect("acq");
        match res {
            LeaseAcquisitionResult::Acquired(l) => {
                assert_eq!(l.fencing_token, 1);
            }
            _ => panic!("Expected Acquired"),
        }
        assert_eq!(storage.get_last_fencing_token("sess-reopen").unwrap(), 1);
    }

    // 3. Second open: must not re-run migration or reset tokens
    {
        let storage = StorageManager::open(db_path).expect("open 2");
        assert_eq!(
            storage.get_last_fencing_token("sess-reopen").unwrap(),
            1,
            "Last fencing token must remain 1 after reopening"
        );

        let lease = storage.get_observer_lease("sess-reopen").unwrap().unwrap();
        assert_eq!(lease.owner_id, "owner-a");
        assert_eq!(lease.fencing_token, 1);

        // Third open: release and acquire again
        storage
            .release_observer_lease("sess-reopen", "owner-a", 1)
            .expect("release");
        assert!(storage.get_observer_lease("sess-reopen").unwrap().is_none());
        assert_eq!(
            storage.get_last_fencing_token("sess-reopen").unwrap(),
            1,
            "Fencing history preserved after lease deletion"
        );
    }

    // 4. Third open: acquire new lease; generation must be 2
    {
        let storage = StorageManager::open(db_path).expect("open 3");
        let res = storage
            .acquire_observer_lease("sess-reopen", "owner-b", 10)
            .expect("acq 2");
        match res {
            LeaseAcquisitionResult::Acquired(l) => {
                assert_eq!(
                    l.fencing_token, 2,
                    "Next acquisition after release must be 2"
                );
            }
            _ => panic!("Expected Acquired with token 2"),
        }
    }
}

#[test]
fn test_migration_v5_atomic_failure_immediately_before_version_update() {
    let tmp = NamedTempFile::new().expect("temp file");
    let db_path = tmp.path();

    // 1. Create a pre-V5 database at version 4 with an active lease
    {
        let conn = create_pre_v5_database(db_path);
        insert_session(&conn, "sess-atomic-fail", "ACTIVE");

        let now = Utc::now();
        let exp = now + chrono::Duration::seconds(60);
        conn.execute(
            "INSERT INTO observer_leases (session_id, owner_id, acquired_at, expires_at, last_renewed_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                "sess-atomic-fail",
                "owner-before-fail",
                now.to_rfc3339(),
                exp.to_rfc3339(),
                now.to_rfc3339(),
            ],
        )
        .expect("insert lease");
    }

    // 2. Inject failure immediately before the version update inside the transaction
    {
        let mut conn = Connection::open(db_path).expect("open raw");
        let res: Result<(), rusqlite::Error> = (|| {
            let tx = conn.transaction()?;

            // Perform column addition
            tx.execute_batch(
                "ALTER TABLE observer_leases ADD COLUMN fencing_token INTEGER NOT NULL DEFAULT 1;",
            )?;

            // Perform V5 table creations & backfills
            tx.execute_batch(timmy::storage::MIGRATION_V5)?;

            // Injected failure immediately before PRAGMA user_version = 5 / commit
            if true {
                return Err(rusqlite::Error::ExecuteReturnedResults);
            }

            tx.execute_batch("PRAGMA user_version = 5;")?;
            tx.commit()?;
            Ok(())
        })();

        assert!(res.is_err(), "Simulated migration failure must trigger");

        // 3. Verify atomic rollback: neither schema changes nor version update were committed
        let version: i32 = conn
            .query_row("PRAGMA user_version;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            version, 4,
            "user_version must remain 4 when failure occurs before commit"
        );

        let gen_table_exists: bool = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='session_lease_generations';")
            .unwrap()
            .exists([])
            .unwrap();
        assert!(
            !gen_table_exists,
            "session_lease_generations table must be rolled back"
        );

        let history_table_exists: bool = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='session_lease_history';")
            .unwrap()
            .exists([])
            .unwrap();
        assert!(
            !history_table_exists,
            "session_lease_history table must be rolled back"
        );

        let has_col: bool = conn
            .prepare("PRAGMA table_info(observer_leases);")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .filter_map(Result::ok)
            .any(|col| col == "fencing_token");
        assert!(
            !has_col,
            "fencing_token column addition must be rolled back"
        );
    }

    // 4. Normal migration completes successfully and sets user_version to 5 atomically
    let storage = StorageManager::open(db_path).expect("normal migration succeeds");
    assert_eq!(
        storage.get_last_fencing_token("sess-atomic-fail").unwrap(),
        1
    );

    // 5. Verify repeated database opens do not re-run V5 or duplicate history records
    let raw_conn = Connection::open(db_path).expect("open raw");
    let initial_history_count: i64 = raw_conn
        .query_row("SELECT count(*) FROM session_lease_history", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(
        initial_history_count, 1,
        "Expected 1 MIGRATED history entry"
    );

    for _ in 0..5 {
        let reopened = StorageManager::open(db_path).expect("reopen");
        assert_eq!(
            reopened.get_last_fencing_token("sess-atomic-fail").unwrap(),
            1
        );
    }

    let final_history_count: i64 = raw_conn
        .query_row("SELECT count(*) FROM session_lease_history", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(
        final_history_count, initial_history_count,
        "Repeated opens must never re-run V5 migration or insert duplicate records"
    );
}

#[test]
fn test_migration_v5_failure_and_rollback_behaviour() {
    let tmp = NamedTempFile::new().expect("temp file");
    let db_path = tmp.path();

    // 1. Create a pre-V5 database strictly at version 4
    {
        let conn = create_pre_v5_database(db_path);
        insert_session(&conn, "sess-rollback", "ACTIVE");
    }

    // 2. Manually test migration failure within a transaction to verify rollback
    {
        let mut conn = Connection::open(db_path).expect("open");
        let version_before: i32 = conn
            .query_row("PRAGMA user_version;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version_before, 4);

        // Attempt a migration transaction that intentionally encounters a failure
        let res: Result<(), rusqlite::Error> = (|| {
            let tx = conn.transaction()?;
            // Alter table successfully
            tx.execute_batch(
                "ALTER TABLE observer_leases ADD COLUMN fencing_token INTEGER NOT NULL DEFAULT 1;",
            )?;
            // Execute an intentionally invalid SQL statement
            tx.execute_batch("INVALID SQL THAT CAUSES FAILURE;")?;
            tx.commit()?;
            Ok(())
        })();

        assert!(res.is_err(), "Migration must fail");

        // Verify that on error, PRAGMA user_version remains 4
        let version_after: i32 = conn
            .query_row("PRAGMA user_version;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            version_after, 4,
            "Failed migration transaction must not advance user_version"
        );

        // Verify that the table alteration was rolled back
        let has_col: bool = conn
            .prepare("PRAGMA table_info(observer_leases);")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .filter_map(Result::ok)
            .any(|col| col == "fencing_token");
        assert!(
            !has_col,
            "Rolled-back transaction must revert ALTER TABLE column addition"
        );
    }

    // 3. Now verify that normal StorageManager::open succeeds cleanly
    let storage = StorageManager::open(db_path).expect("clean migration after rollback");
    let raw_conn = Connection::open(db_path).expect("open raw");
    let final_version: i32 = raw_conn
        .query_row("PRAGMA user_version;", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        final_version,
        timmy::storage::SCHEMA_VERSION,
        "Database must now be cleanly at current schema version"
    );
    assert_eq!(
        storage.get_last_fencing_token("sess-rollback").unwrap(),
        0,
        "No leases were held, last generation is 0"
    );
}

// =============================================================================
// V6 Migration Tests: Structured Provenance & Root Binding
// =============================================================================

/// Helper to construct a SQLite database representing schema version 5 (pre-V6).
fn create_pre_v6_database<P: AsRef<Path>>(path: P) -> Connection {
    let conn = create_pre_v5_database(path);
    // Add V5 column and tables
    conn.execute_batch(
        "ALTER TABLE observer_leases ADD COLUMN fencing_token INTEGER NOT NULL DEFAULT 1;
         CREATE TABLE IF NOT EXISTS session_lease_generations (
             session_id TEXT PRIMARY KEY,
             last_fencing_token INTEGER NOT NULL DEFAULT 1,
             updated_at TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS session_lease_history (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             session_id TEXT NOT NULL,
             owner_id TEXT NOT NULL,
             fencing_token INTEGER NOT NULL,
             action TEXT NOT NULL,
             timestamp TEXT NOT NULL
         );
         PRAGMA user_version = 5;",
    )
    .expect("setup v5 schema");
    conn
}

#[test]
fn test_migration_v6_from_pre_v6_database_fixtures_preserves_records() {
    let tmp = NamedTempFile::new().expect("temp file");
    let db_path = tmp.path();

    // 1. Create a database strictly at schema version 5 without root_binding or provenance columns
    {
        let conn = create_pre_v6_database(db_path);

        // Verify version is strictly 5
        let ver: i32 = conn
            .query_row("PRAGMA user_version;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ver, 5, "Database must start strictly at version 5");

        // Insert pre-V6 session (no root_binding column)
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO sessions (id, agent_kind, status, start_time, confidence, evidence, created_at, root_pid, root_process_name)
             VALUES (?1, 'claude', 'ACTIVE', ?2, 2, 'Pre-V6 session', ?3, 1234, 'claude')",
            params!["sess-v5-legacy", now, now],
        )
        .expect("insert legacy session");

        // Insert pre-V6 resource (no provenance column)
        conn.execute(
            "INSERT INTO session_resources (session_id, pid, name, exe_path, confidence, evidence, is_detached, is_protected, safe_to_terminate, first_seen, last_seen)
             VALUES (?1, 1234, 'claude', '/usr/local/bin/claude', 2, 'Legacy resource', 0, 0, 1, ?2, ?3)",
            params!["sess-v5-legacy", now, now],
        )
        .expect("insert legacy resource");
    }

    // 2. Open via StorageManager, executing V6 migration
    let storage = StorageManager::open(db_path).expect("open and migrate to v6");

    // 3. Verify user_version upgraded to 7
    let raw_conn = Connection::open(db_path).expect("open raw");
    let version_after: i32 = raw_conn
        .query_row("PRAGMA user_version;", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        version_after, 7,
        "Must be migrated through to schema version 7"
    );

    // 4. Verify idx_sessions_root_pid exists
    let has_index: bool = raw_conn
        .prepare("PRAGMA index_list(sessions);")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .filter_map(Result::ok)
        .any(|idx| idx == "idx_sessions_root_pid");
    assert!(
        has_index,
        "Migration V6 must create idx_sessions_root_pid index"
    );

    // 5. Verify existing legacy session preserved with root_binding: None
    let session = storage
        .get_session("sess-v5-legacy")
        .expect("query session")
        .expect("legacy session must exist");
    assert_eq!(session.id, "sess-v5-legacy");
    assert_eq!(session.root_pid, Some(1234));
    assert!(
        session.root_binding.is_none(),
        "Pre-V6 session must have root_binding: None"
    );

    // 6. Verify existing legacy resource preserved with provenance: None
    let resources = storage
        .get_session_resources("sess-v5-legacy")
        .expect("query resources");
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0].pid, Some(1234));
    assert!(
        resources[0].provenance.is_none(),
        "Pre-V6 resource must have provenance: None"
    );

    // 7. Verify new V6 session with structured root_binding can be stored and retrieved
    use timmy::model::provenance::{LaunchProvenance, ProvenanceSource};
    let mut new_session = session.clone();
    new_session.id = "sess-v6-new".to_string();
    new_session.root_binding = Some(LaunchProvenance::verified_session_root_binding(
        "sess-v6-new".to_string(),
        5678,
        Some(100_000),
        "claude".to_string(),
        Some(std::path::PathBuf::from("/usr/local/bin/claude")),
        Some(1),
        "V6 structured binding".to_string(),
    ));
    storage.save_session(&new_session).expect("save v6 session");

    let reloaded = storage
        .get_session("sess-v6-new")
        .unwrap()
        .expect("must exist");
    assert!(reloaded.root_binding.is_some());
    let binding = reloaded.root_binding.unwrap();
    assert_eq!(binding.source, ProvenanceSource::VerifiedSessionRootBinding);
    assert_eq!(binding.process.pid, 5678);
    assert_eq!(binding.process.start_time, Some(100_000));
}

#[test]
fn test_migration_v6_rollback_on_failure() {
    let tmp = NamedTempFile::new().expect("temp file");
    let db_path = tmp.path();

    // 1. Create a database strictly at schema version 5
    {
        let conn = create_pre_v6_database(db_path);
        let ver: i32 = conn
            .query_row("PRAGMA user_version;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ver, 5);
    }

    // 2. Intentionally execute a failed transaction attempting V6 migration
    {
        let mut conn = Connection::open(db_path).expect("open");
        let res: Result<(), rusqlite::Error> = (|| {
            let tx = conn.transaction()?;
            tx.execute_batch("ALTER TABLE sessions ADD COLUMN root_binding TEXT;")?;
            tx.execute_batch("SYNTAX ERROR TO TRIGGER TRANSACTION ROLLBACK;")?;
            tx.commit()?;
            Ok(())
        })();
        assert!(res.is_err(), "Migration must fail and return error");

        // Verify version remains 5
        let ver: i32 = conn
            .query_row("PRAGMA user_version;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ver, 5, "Failed transaction must not advance user_version");

        // Verify column addition was rolled back
        let has_col: bool = conn
            .prepare("PRAGMA table_info(sessions);")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .filter_map(Result::ok)
            .any(|col| col == "root_binding");
        assert!(
            !has_col,
            "Rolled-back transaction must revert root_binding column"
        );
    }

    // 3. Normal StorageManager::open succeeds cleanly afterwards
    let storage = StorageManager::open(db_path).expect("open cleanly after rollback");
    let raw_conn = Connection::open(db_path).expect("open raw");
    let final_ver: i32 = raw_conn
        .query_row("PRAGMA user_version;", [], |r| r.get(0))
        .unwrap();
    assert_eq!(final_ver, 7, "Must upgrade cleanly to version 7");
    assert!(storage.list_sessions().is_ok());
}

#[test]
fn test_migration_v6_corrupted_json_graceful_handling() {
    let tmp = NamedTempFile::new().expect("temp file");
    let db_path = tmp.path();

    // 1. Migrate to V6
    {
        let _storage = StorageManager::open(db_path).expect("migrate to v6");
    }

    // 2. Directly inject malformed JSON into root_binding and provenance columns
    {
        let conn = Connection::open(db_path).expect("open raw");
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO sessions (id, agent_kind, status, start_time, confidence, evidence, created_at, root_binding)
             VALUES (?1, 'claude', 'ACTIVE', ?2, 2, 'Corrupt test', ?3, '{NOT_VALID_JSON: true}')",
            params!["sess-corrupt", now, now],
        )
        .expect("insert corrupt session");

        conn.execute(
            "INSERT INTO session_resources (session_id, pid, name, exe_path, confidence, evidence, is_detached, is_protected, safe_to_terminate, first_seen, last_seen, provenance)
             VALUES (?1, 9999, 'corrupt-proc', '/bin/bad', 2, 'Corrupt res', 0, 0, 1, ?2, ?3, 'MALFORMED_JSON_STRING')",
            params!["sess-corrupt", now, now],
        )
        .expect("insert corrupt resource");
    }

    // 3. Query via StorageManager — must not panic or error; must safely deserialize as None
    let storage = StorageManager::open(db_path).expect("open db with corrupt json");
    let session = storage
        .get_session("sess-corrupt")
        .expect("must succeed without panic")
        .expect("session must exist");
    assert!(
        session.root_binding.is_none(),
        "Corrupted JSON in root_binding must gracefully decode as None"
    );

    let resources = storage
        .get_session_resources("sess-corrupt")
        .expect("resources query must succeed");
    assert_eq!(resources.len(), 1);
    assert!(
        resources[0].provenance.is_none(),
        "Corrupted JSON in provenance must gracefully decode as None"
    );
}

#[test]
fn test_migration_v6_reopening_idempotency() {
    let tmp = NamedTempFile::new().expect("temp file");
    let db_path = tmp.path();

    // Open first time (migrates V1 through V6)
    {
        let storage1 = StorageManager::open(db_path).expect("first open");
        assert!(storage1.list_sessions().is_ok());
    }

    // Open second time (already at V6)
    {
        let storage2 = StorageManager::open(db_path).expect("second open");
        assert!(storage2.list_sessions().is_ok());
    }

    // Open third time
    {
        let storage3 = StorageManager::open(db_path).expect("third open");
        assert!(storage3.list_sessions().is_ok());
    }

    let conn = Connection::open(db_path).expect("raw open");
    let ver: i32 = conn
        .query_row("PRAGMA user_version;", [], |r| r.get(0))
        .unwrap();
    assert_eq!(ver, 7, "Repeated opens must preserve user_version at 7");
}

// =============================================================================
// Comprehensive Schema Migration Verification: Pre-V5, V5, and V6 Fixtures
// =============================================================================

/// Helper to construct a SQLite database representing schema version 3 (pre-V4, pre-V5).
fn create_v3_database<P: AsRef<Path>>(path: P) -> Connection {
    let conn = Connection::open(path).expect("open raw sqlite db");
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA busy_timeout = 5000;
         PRAGMA foreign_keys = ON;
         PRAGMA synchronous = NORMAL;",
    )
    .expect("pragmas");

    conn.execute_batch(timmy::storage::MIGRATION_V1)
        .expect("v1");
    conn.execute_batch(timmy::storage::MIGRATION_V2)
        .expect("v2");
    conn.execute_batch(timmy::storage::MIGRATION_V3)
        .expect("v3");
    conn.execute_batch("PRAGMA user_version = 3;")
        .expect("set version 3");
    conn
}

/// Helper to construct a SQLite database representing schema version 6 directly.
fn create_v6_database<P: AsRef<Path>>(path: P) -> Connection {
    let conn = Connection::open(path).expect("open raw sqlite db");
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA busy_timeout = 5000;
         PRAGMA foreign_keys = ON;
         PRAGMA synchronous = NORMAL;",
    )
    .expect("pragmas");

    conn.execute_batch(timmy::storage::MIGRATION_V1)
        .expect("v1");
    conn.execute_batch(timmy::storage::MIGRATION_V2)
        .expect("v2");
    conn.execute_batch(timmy::storage::MIGRATION_V3)
        .expect("v3");
    conn.execute_batch(PRE_V5_MIGRATION_V4).expect("v4");
    conn.execute_batch(
        "ALTER TABLE observer_leases ADD COLUMN fencing_token INTEGER NOT NULL DEFAULT 1;
         CREATE TABLE IF NOT EXISTS session_lease_generations (
             session_id TEXT PRIMARY KEY,
             last_fencing_token INTEGER NOT NULL DEFAULT 1,
             updated_at TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS session_lease_history (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             session_id TEXT NOT NULL,
             owner_id TEXT NOT NULL,
             fencing_token INTEGER NOT NULL,
             action TEXT NOT NULL,
             timestamp TEXT NOT NULL
         );
         CREATE INDEX IF NOT EXISTS idx_lease_history_session ON session_lease_history(session_id);
         ALTER TABLE sessions ADD COLUMN root_binding TEXT;
         ALTER TABLE session_resources ADD COLUMN provenance TEXT;
         CREATE INDEX IF NOT EXISTS idx_sessions_root_pid ON sessions(root_pid);
         PRAGMA user_version = 6;",
    )
    .expect("v6 schema");
    conn
}

#[test]
fn test_migration_genuine_pre_v5_v4_upgrades_to_v6_complete() {
    let tmp = NamedTempFile::new().expect("temp file");
    let db_path = tmp.path();

    // 1. Create a genuine pre-V5 database at schema version 4
    {
        let conn = create_pre_v5_database(db_path);
        let ver: i32 = conn
            .query_row("PRAGMA user_version;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ver, 4, "Must start strictly at schema version 4");

        // Insert legacy session and resource
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO sessions (id, agent_kind, status, start_time, confidence, evidence, created_at, root_pid, root_process_name)
             VALUES (?1, 'claude', 'ACTIVE', ?2, 2, 'Pre-V5 test session', ?3, 1001, 'claude')",
            params!["sess-prev5-v4", now, now],
        )
        .expect("insert legacy v4 session");

        conn.execute(
            "INSERT INTO session_resources (session_id, pid, name, exe_path, confidence, evidence, is_detached, is_protected, safe_to_terminate, first_seen, last_seen)
             VALUES (?1, 1001, 'claude', '/usr/local/bin/claude', 2, 'Legacy v4 resource', 0, 0, 1, ?2, ?3)",
            params!["sess-prev5-v4", now, now],
        )
        .expect("insert legacy v4 resource");

        // Insert legacy lease (without fencing_token)
        let exp = (Utc::now() + chrono::Duration::seconds(60)).to_rfc3339();
        conn.execute(
            "INSERT INTO observer_leases (session_id, owner_id, acquired_at, expires_at, last_renewed_at)
             VALUES (?1, 'owner-v4', ?2, ?3, ?4)",
            params!["sess-prev5-v4", now, exp, now],
        )
        .expect("insert legacy v4 lease");
    }

    // 2. Open via StorageManager, migrating through V5 and V6
    let storage = StorageManager::open(db_path).expect("open and migrate pre-v5 to v6");

    // 3. Verify user_version upgraded through all migrations to 6
    let raw_conn = Connection::open(db_path).expect("open raw");
    let final_ver: i32 = raw_conn
        .query_row("PRAGMA user_version;", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        final_ver, 7,
        "Pre-V5 database must migrate through all intermediate steps to version 7"
    );

    // 4. Verify V5 backfill results: lease has fencing_token defaulted to 1, generation recorded
    let lease = storage
        .get_observer_lease("sess-prev5-v4")
        .unwrap()
        .expect("lease must survive");
    assert_eq!(
        lease.fencing_token, 1,
        "V5 migration must default fencing_token to 1"
    );
    assert_eq!(lease.owner_id, "owner-v4");

    let last_gen = storage.get_last_fencing_token("sess-prev5-v4").unwrap();
    assert_eq!(
        last_gen, 1,
        "V5 migration must backfill lease generation to 1"
    );

    // 5. Verify V6 columns and index exist
    let has_root_binding_col: bool = raw_conn
        .prepare("PRAGMA table_info(sessions);")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .filter_map(Result::ok)
        .any(|col| col == "root_binding");
    assert!(
        has_root_binding_col,
        "V6 migration must add root_binding column"
    );

    let has_prov_col: bool = raw_conn
        .prepare("PRAGMA table_info(session_resources);")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .filter_map(Result::ok)
        .any(|col| col == "provenance");
    assert!(has_prov_col, "V6 migration must add provenance column");

    // 6. Verify existing legacy session and resource survived and decode with None
    let session = storage
        .get_session("sess-prev5-v4")
        .unwrap()
        .expect("session must survive");
    assert_eq!(session.id, "sess-prev5-v4");
    assert_eq!(session.root_pid, Some(1001));
    assert!(
        session.root_binding.is_none(),
        "Pre-V5 session must decode root_binding as None"
    );

    let resources = storage.get_session_resources("sess-prev5-v4").unwrap();
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0].pid, Some(1001));
    assert!(
        resources[0].provenance.is_none(),
        "Pre-V5 resource must decode provenance as None"
    );

    // 7. Verify reopening is idempotent
    let storage2 = StorageManager::open(db_path).expect("reopen");
    let reloaded_session = storage2
        .get_session("sess-prev5-v4")
        .unwrap()
        .expect("reloaded session");
    assert_eq!(reloaded_session.id, "sess-prev5-v4");
    assert!(reloaded_session.root_binding.is_none());
}

#[test]
fn test_migration_genuine_pre_v5_v3_upgrades_to_v6_complete() {
    let tmp = NamedTempFile::new().expect("temp file");
    let db_path = tmp.path();

    // 1. Create a genuine pre-V5 database at schema version 3 (before observer_leases existed)
    {
        let conn = create_v3_database(db_path);
        let ver: i32 = conn
            .query_row("PRAGMA user_version;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ver, 3, "Must start strictly at schema version 3");

        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO sessions (id, agent_kind, status, start_time, confidence, evidence, created_at, root_pid, root_process_name)
             VALUES (?1, 'claude', 'ACTIVE', ?2, 2, 'Pre-V4/V5 test session', ?3, 3003, 'claude')",
            params!["sess-prev5-v3", now, now],
        )
        .expect("insert legacy v3 session");

        conn.execute(
            "INSERT INTO session_resources (session_id, pid, name, exe_path, confidence, evidence, is_detached, is_protected, safe_to_terminate, first_seen, last_seen)
             VALUES (?1, 3003, 'claude', '/usr/local/bin/claude', 2, 'Legacy v3 resource', 0, 0, 1, ?2, ?3)",
            params!["sess-prev5-v3", now, now],
        )
        .expect("insert legacy v3 resource");
    }

    // 2. Open via StorageManager, migrating through V4, V5, and V6
    let storage = StorageManager::open(db_path).expect("open and migrate v3 to v6");

    // 3. Verify user_version upgraded to 6
    let raw_conn = Connection::open(db_path).expect("open raw");
    let final_ver: i32 = raw_conn
        .query_row("PRAGMA user_version;", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        final_ver, 7,
        "V3 database must migrate through V4, V5, V6 to V7"
    );

    // 4. Verify existing session and resource survived and decode with None
    let session = storage
        .get_session("sess-prev5-v3")
        .unwrap()
        .expect("session must survive");
    assert_eq!(session.id, "sess-prev5-v3");
    assert_eq!(session.root_pid, Some(3003));
    assert!(
        session.root_binding.is_none(),
        "Pre-V5 session must decode root_binding as None"
    );

    let resources = storage.get_session_resources("sess-prev5-v3").unwrap();
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0].pid, Some(3003));
    assert!(
        resources[0].provenance.is_none(),
        "Pre-V5 resource must decode provenance as None"
    );

    // 5. Verify reopening is idempotent
    let storage2 = StorageManager::open(db_path).expect("reopen");
    assert!(storage2.get_session("sess-prev5-v3").unwrap().is_some());
}

#[test]
fn test_migration_pre_v5_v4_rollback_preserves_schema_and_data() {
    let tmp = NamedTempFile::new().expect("temp file");
    let db_path = tmp.path();

    // 1. Create a genuine pre-V5 database at schema version 4 with data
    {
        let conn = create_pre_v5_database(db_path);
        let ver: i32 = conn
            .query_row("PRAGMA user_version;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ver, 4);

        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO sessions (id, agent_kind, status, start_time, confidence, evidence, created_at, root_pid, root_process_name)
             VALUES (?1, 'claude', 'ACTIVE', ?2, 2, 'Pre-V5 rollback test', ?3, 4004, 'claude')",
            params!["sess-rollback-v4", now, now],
        )
        .expect("insert session");

        let exp = (Utc::now() + chrono::Duration::seconds(60)).to_rfc3339();
        conn.execute(
            "INSERT INTO observer_leases (session_id, owner_id, acquired_at, expires_at, last_renewed_at)
             VALUES (?1, 'owner-rb', ?2, ?3, ?4)",
            params!["sess-rollback-v4", now, exp, now],
        )
        .expect("insert lease");
    }

    // 2. Simulate an aborted migration transaction attempting to upgrade V4 -> V5
    {
        let mut conn = Connection::open(db_path).expect("open raw");
        let res: Result<(), rusqlite::Error> = (|| {
            let tx = conn.transaction()?;
            tx.execute_batch(
                "ALTER TABLE observer_leases ADD COLUMN fencing_token INTEGER NOT NULL DEFAULT 1;",
            )?;
            tx.execute_batch("SYNTAX_ERROR_TRIGGERING_ROLLBACK;")?;
            tx.commit()?;
            Ok(())
        })();
        assert!(res.is_err(), "Migration attempt must fail");

        // Verify schema version is still 4
        let ver: i32 = conn
            .query_row("PRAGMA user_version;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ver, 4, "Failed transaction must leave user_version at 4");

        // Verify fencing_token column was not added
        let has_col: bool = conn
            .prepare("PRAGMA table_info(observer_leases);")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .filter_map(Result::ok)
            .any(|col| col == "fencing_token");
        assert!(
            !has_col,
            "Rolled back transaction must revert column addition"
        );

        // Verify session and lease records remain intact
        let session_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sessions WHERE id = 'sess-rollback-v4';",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            session_count, 1,
            "Session data must remain intact after rollback"
        );

        let lease_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM observer_leases WHERE session_id = 'sess-rollback-v4';",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            lease_count, 1,
            "Lease data must remain intact after rollback"
        );
    }

    // 3. Normal StorageManager::open succeeds cleanly afterwards
    let storage = StorageManager::open(db_path).expect("open cleanly after rollback");
    let raw_conn = Connection::open(db_path).expect("open raw");
    let final_ver: i32 = raw_conn
        .query_row("PRAGMA user_version;", [], |r| r.get(0))
        .unwrap();
    assert_eq!(final_ver, 7, "Must upgrade cleanly to version 7");
    assert!(storage.get_session("sess-rollback-v4").unwrap().is_some());
}

#[test]
fn test_migration_v6_fixture_direct_open_idempotent() {
    let tmp = NamedTempFile::new().expect("temp file");
    let db_path = tmp.path();

    // 1. Create a database strictly at schema version 6 with both Some and None fields
    {
        let conn = create_v6_database(db_path);
        let ver: i32 = conn
            .query_row("PRAGMA user_version;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ver, 6, "Database must start strictly at version 6");

        let now = Utc::now().to_rfc3339();
        // Session A: root_binding is None
        conn.execute(
            "INSERT INTO sessions (id, agent_kind, status, start_time, confidence, evidence, created_at, root_pid, root_process_name, root_binding)
             VALUES (?1, 'claude', 'ACTIVE', ?2, 2, 'V6 session None', ?3, 6001, 'claude', NULL)",
            params!["sess-v6-none", now, now],
        )
        .expect("insert v6 session none");

        // Session B: root_binding is structured JSON
        use timmy::model::provenance::LaunchProvenance;
        let binding = LaunchProvenance::verified_session_root_binding(
            "sess-v6-some".to_string(),
            6002,
            Some(12345),
            "claude".to_string(),
            Some(std::path::PathBuf::from("/usr/local/bin/claude")),
            Some(1),
            "V6 test binding".to_string(),
        );
        let binding_json = serde_json::to_string(&binding).unwrap();
        conn.execute(
            "INSERT INTO sessions (id, agent_kind, status, start_time, confidence, evidence, created_at, root_pid, root_process_name, root_binding)
             VALUES (?1, 'claude', 'ACTIVE', ?2, 2, 'V6 session Some', ?3, 6002, 'claude', ?4)",
            params!["sess-v6-some", now, now, binding_json],
        )
        .expect("insert v6 session some");

        // Resource A: provenance is None
        conn.execute(
            "INSERT INTO session_resources (session_id, pid, name, exe_path, confidence, evidence, is_detached, is_protected, safe_to_terminate, first_seen, last_seen, provenance)
             VALUES (?1, 6001, 'claude', '/usr/local/bin/claude', 2, 'V6 res None', 0, 0, 1, ?2, ?3, NULL)",
            params!["sess-v6-none", now, now],
        )
        .expect("insert v6 res none");

        // Resource B: provenance is structured JSON
        use timmy::model::provenance::ParentIdentity;
        let prov = LaunchProvenance::observed_spawn(
            "sess-v6-some".to_string(),
            6002,
            Some(12345),
            "claude".to_string(),
            Some(std::path::PathBuf::from("/usr/local/bin/claude")),
            ParentIdentity {
                ppid: 1,
                start_time: None,
                start_time_precise: None,
                name: None,
            },
            "V6 test provenance".to_string(),
        );
        let prov_json = serde_json::to_string(&prov).unwrap();
        conn.execute(
            "INSERT INTO session_resources (session_id, pid, name, exe_path, confidence, evidence, is_detached, is_protected, safe_to_terminate, first_seen, last_seen, provenance)
             VALUES (?1, 6002, 'claude', '/usr/local/bin/claude', 2, 'V6 res Some', 0, 0, 1, ?2, ?3, ?4)",
            params!["sess-v6-some", now, now, prov_json],
        )
        .expect("insert v6 res some");
    }

    // 2. Open via StorageManager
    let storage = StorageManager::open(db_path).expect("open v6 db");

    // Verify user_version remains 6
    let raw_conn = Connection::open(db_path).expect("open raw");
    let ver: i32 = raw_conn
        .query_row("PRAGMA user_version;", [], |r| r.get(0))
        .unwrap();
    assert_eq!(ver, 7, "V6 database must upgrade to version 7");

    // 3. Verify None decodes as None
    let sess_none = storage
        .get_session("sess-v6-none")
        .unwrap()
        .expect("sess none");
    assert!(sess_none.root_binding.is_none());
    let res_none = storage.get_session_resources("sess-v6-none").unwrap();
    assert!(res_none[0].provenance.is_none());

    // 4. Verify Some decodes as Some with accurate structured values
    let sess_some = storage
        .get_session("sess-v6-some")
        .unwrap()
        .expect("sess some");
    assert!(sess_some.root_binding.is_some());
    let binding = sess_some.root_binding.unwrap();
    assert_eq!(binding.process.pid, 6002);
    assert_eq!(binding.process.start_time, Some(12345));

    let res_some = storage.get_session_resources("sess-v6-some").unwrap();
    assert!(res_some[0].provenance.is_some());
    let prov = res_some[0].provenance.as_ref().unwrap();
    assert_eq!(prov.process.pid, 6002);

    // 5. Verify reopening is idempotent
    let storage2 = StorageManager::open(db_path).expect("reopen v6 db");
    assert!(storage2.get_session("sess-v6-some").unwrap().is_some());
}

// =============================================================================
// V7 Migration Tests: Persistent Process Lineage
// =============================================================================

#[test]
fn test_migration_v7_from_v6_database_fixtures_preserves_records_and_creates_lineage_table() {
    let tmp = NamedTempFile::new().expect("temp file");
    let db_path = tmp.path();

    // 1. Create a database strictly at schema version 6
    {
        let conn = create_v6_database(db_path);
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO sessions (id, agent_kind, status, start_time, confidence, evidence, created_at, root_pid, root_process_name, root_binding)
             VALUES (?1, 'claude', 'ACTIVE', ?2, 2, 'V6 test session', ?3, 7001, 'claude', NULL)",
            params!["sess-v6-to-v7", now, now],
        )
        .expect("insert v6 session");
    }

    // 2. Open via StorageManager, executing V7 migration
    let storage = StorageManager::open(db_path).expect("open and migrate to v7");

    // 3. Verify user_version upgraded to 7
    let raw_conn = Connection::open(db_path).expect("open raw");
    let version_after: i32 = raw_conn
        .query_row("PRAGMA user_version;", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version_after, 7, "Must be migrated to schema version 7");

    // 4. Verify process_lineage table exists
    let table_exists: bool = raw_conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='process_lineage';",
            [],
            |r| r.get::<_, i64>(0),
        )
        .map(|c| c == 1)
        .unwrap();
    assert!(
        table_exists,
        "process_lineage table must exist in V7 schema"
    );

    // 5. Verify indexes exist
    let indexes: Vec<String> = raw_conn
        .prepare("PRAGMA index_list(process_lineage);")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    assert!(indexes.contains(&"idx_lineage_session".to_string()));
    assert!(indexes.contains(&"idx_lineage_child".to_string()));
    assert!(indexes.contains(&"idx_lineage_parent".to_string()));
    assert!(indexes.contains(&"idx_lineage_status".to_string()));

    // 6. Verify pre-existing session preserved
    let session = storage
        .get_session("sess-v6-to-v7")
        .expect("query")
        .unwrap();
    assert_eq!(session.root_pid, Some(7001));

    // 7. Verify lineage operations work
    use timmy::model::lineage::ProcessLineageEdge;
    use timmy::model::process::{ProcessIncarnation, ProcessStartTime};
    let edge = ProcessLineageEdge::new_snapshot_edge(
        "sess-v6-to-v7".to_string(),
        ProcessIncarnation::new(7001, ProcessStartTime::new(1000, 0)),
        ProcessIncarnation::new(7002, ProcessStartTime::new(1001, 0)),
        Some("claude".to_string()),
        None,
        "node".to_string(),
        None,
        Utc::now(),
        None,
    );
    let edges = vec![edge];
    let mut raw_conn2 = Connection::open(db_path).unwrap();
    let tx = raw_conn2.transaction().unwrap();
    StorageManager::record_lineage_edges_in_tx(&tx, "sess-v6-to-v7", &edges, None).unwrap();
    tx.commit().unwrap();

    let retrieved = storage.get_lineage_edges("sess-v6-to-v7").unwrap();
    assert_eq!(retrieved.len(), 1);
    assert_eq!(retrieved[0].parent.pid, 7001);
    assert_eq!(retrieved[0].child.pid, 7002);
}

#[test]
fn test_migration_v7_rollback_on_failure() {
    let tmp = NamedTempFile::new().expect("temp file");
    let db_path = tmp.path();

    // 1. Create a V6 database
    {
        let conn = create_v6_database(db_path);
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO sessions (id, agent_kind, status, start_time, confidence, evidence, created_at, root_pid, root_process_name, root_binding)
             VALUES (?1, 'claude', 'ACTIVE', ?2, 2, 'V6 session', ?3, 7005, 'claude', NULL)",
            params!["sess-v7-fail", now, now],
        )
        .unwrap();
    }

    // 2. Intentionally execute a failed transaction attempting V7 migration
    {
        let mut conn = Connection::open(db_path).unwrap();
        let tx = conn.transaction().unwrap();
        tx.execute_batch(timmy::storage::schema::MIGRATION_V7)
            .unwrap();
        // Cause intentional failure before committing or updating user_version
        let fail_res: Result<(), _> =
            tx.execute_batch("INSERT INTO non_existent_table VALUES (1);");
        assert!(fail_res.is_err());
        tx.rollback().unwrap();
    }

    // Verify database remains at version 6 and process_lineage table was rolled back
    {
        let conn = Connection::open(db_path).unwrap();
        let ver: i32 = conn
            .query_row("PRAGMA user_version;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            ver, 6,
            "Failed migration must leave database at schema version 6"
        );
        let table_exists: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='process_lineage';",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|c| c == 1)
            .unwrap();
        assert!(
            !table_exists,
            "process_lineage table must not exist after rollback"
        );
    }

    // 3. Normal StorageManager::open succeeds cleanly afterwards
    let storage = StorageManager::open(db_path).expect("open cleanly after rollback");
    let raw_conn = Connection::open(db_path).expect("open raw");
    let final_ver: i32 = raw_conn
        .query_row("PRAGMA user_version;", [], |r| r.get(0))
        .unwrap();
    assert_eq!(final_ver, 7, "Must upgrade cleanly to version 7");
    assert!(storage.get_session("sess-v7-fail").unwrap().is_some());
}

#[test]
fn test_migration_v7_reopening_idempotency() {
    let tmp = NamedTempFile::new().expect("temp file");
    let db_path = tmp.path();

    // Open first time (migrates to V7)
    {
        let storage1 = StorageManager::open(db_path).expect("first open");
        assert!(storage1.list_sessions().is_ok());
    }

    // Open second time (already at V7)
    {
        let storage2 = StorageManager::open(db_path).expect("second open");
        assert!(storage2.list_sessions().is_ok());
    }

    // Open third time
    {
        let storage3 = StorageManager::open(db_path).expect("third open");
        assert!(storage3.list_sessions().is_ok());
    }

    let conn = Connection::open(db_path).expect("raw open");
    let ver: i32 = conn
        .query_row("PRAGMA user_version;", [], |r| r.get(0))
        .unwrap();
    assert_eq!(ver, 7, "Repeated opens must preserve user_version at 7");
}
