pub mod db;
pub mod schema;

pub use db::{
    AuditRecord, LeaseAcquisitionResult, ObserverLease, SessionSnapshotRecord, StorageError,
    StorageManager,
};
pub use schema::{
    MIGRATION_V1, MIGRATION_V2, MIGRATION_V3, MIGRATION_V4, MIGRATION_V5, MIGRATION_V6,
    SCHEMA_VERSION,
};
use std::path::PathBuf;

/// Helper to obtain standard database path.
pub fn default_db_path() -> PathBuf {
    if let Some(proj_dirs) = directories::ProjectDirs::from("com", "timmy", "timmy") {
        proj_dirs.data_dir().join("timmy.db")
    } else {
        PathBuf::from("timmy.db")
    }
}
