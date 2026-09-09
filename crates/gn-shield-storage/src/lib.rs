//! Storage abstraction and embedded migrations for GN-Shield using SQLite via rusqlite.
//!
//! Enforces WAL journal mode, incremental schema versions (`PRAGMA user_version`),
//! audit logging, quarantine records, and dynamic allowlist overrides.

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, Mutex};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug)]
pub enum StorageError {
    Sqlite(rusqlite::Error),
    Migration(String),
    Poisoned,
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sqlite(e) => write!(f, "Database error: {e}"),
            Self::Migration(s) => write!(f, "Migration error: {s}"),
            Self::Poisoned => write!(f, "Storage mutex lock poisoned"),
        }
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sqlite(e) => Some(e),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for StorageError {
    fn from(err: rusqlite::Error) -> Self {
        Self::Sqlite(err)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditLogEntry {
    pub id: Option<i64>,
    pub timestamp: String,
    pub event_type: String,
    pub target: String,
    pub decision: String,
    pub reason: String,
    pub static_score: Option<f32>,
    pub hash_reputation: Option<f32>,
    pub behavior_score: Option<f32>,
    pub action_taken: String,
}

#[derive(Debug, Clone, Default)]
pub struct AuditLogFilter {
    pub decision: Option<String>,
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuarantinedFileEntry {
    pub id: i64,
    pub original_path: String,
    pub quarantine_path: String,
    pub sha256: String,
    pub quarantined_at: String,
    pub reason: String,
    pub restored: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AllowlistOverrideEntry {
    pub id: i64,
    pub entry_type: String,
    pub value: String,
    pub reason: String,
    pub added_at: String,
}

#[derive(Clone)]
pub struct StorageManager {
    conn: Arc<Mutex<Connection>>,
    pub schema_version: u32,
}

impl StorageManager {
    /// Connects to a SQLite database file (or in-memory if ":memory:"),
    /// enables WAL mode, and applies pending migrations.
    pub fn open<P: AsRef<Path>>(path: P) -> std::result::Result<Self, StorageError> {
        let conn = Connection::open(path)?;
        Self::init_connection(conn)
    }

    /// Creates an in-memory storage manager (useful for testing).
    pub fn open_in_memory() -> std::result::Result<Self, StorageError> {
        let conn = Connection::open_in_memory()?;
        Self::init_connection(conn)
    }

    fn init_connection(conn: Connection) -> std::result::Result<Self, StorageError> {
        // Configure WAL mode and normal synchronous flag
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;

        let current_version: u32 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;

        if current_version < SCHEMA_VERSION {
            Self::apply_migrations(&conn, current_version, SCHEMA_VERSION)?;
        }

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            schema_version: SCHEMA_VERSION,
        })
    }

    fn apply_migrations(
        conn: &Connection,
        from_version: u32,
        to_version: u32,
    ) -> std::result::Result<(), StorageError> {
        if from_version < 1 && to_version >= 1 {
            conn.execute_batch(
                "
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    static_score REAL,
                    hash_reputation REAL,
                    behavior_score REAL,
                    action_taken TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_audit_log_decision ON audit_log(decision);

                CREATE TABLE IF NOT EXISTS quarantined_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    original_path TEXT NOT NULL,
                    quarantine_path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    quarantined_at TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    restored INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS allowlist_overrides (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entry_type TEXT NOT NULL,
                    value TEXT NOT NULL UNIQUE,
                    reason TEXT NOT NULL,
                    added_at TEXT NOT NULL
                );
                ",
            )?;

            conn.pragma_update(None, "user_version", 1)?;
        }

        Ok(())
    }

    pub fn record_decision(&self, entry: &AuditLogEntry) -> std::result::Result<i64, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::Poisoned)?;
        conn.execute(
            "INSERT INTO audit_log (timestamp, event_type, target, decision, reason, static_score, hash_reputation, behavior_score, action_taken)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                entry.timestamp,
                entry.event_type,
                entry.target,
                entry.decision,
                entry.reason,
                entry.static_score,
                entry.hash_reputation,
                entry.behavior_score,
                entry.action_taken,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn query_audit_log(
        &self,
        filter: AuditLogFilter,
    ) -> std::result::Result<Vec<AuditLogEntry>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::Poisoned)?;
        let limit = if filter.limit == 0 { 50 } else { filter.limit };

        let mut query = String::from(
            "SELECT id, timestamp, event_type, target, decision, reason, static_score, hash_reputation, behavior_score, action_taken
             FROM audit_log",
        );

        if let Some(ref decision) = filter.decision {
            query.push_str(&format!(" WHERE decision = '{decision}'"));
        }

        query.push_str(&format!(" ORDER BY id DESC LIMIT {limit}"));

        let mut stmt = conn.prepare(&query)?;
        let rows = stmt.query_map([], |row| {
            Ok(AuditLogEntry {
                id: Some(row.get(0)?),
                timestamp: row.get(1)?,
                event_type: row.get(2)?,
                target: row.get(3)?,
                decision: row.get(4)?,
                reason: row.get(5)?,
                static_score: row.get(6)?,
                hash_reputation: row.get(7)?,
                behavior_score: row.get(8)?,
                action_taken: row.get(9)?,
            })
        })?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    pub fn record_quarantine(
        &self,
        original_path: &str,
        quarantine_path: &str,
        sha256: &str,
        reason: &str,
    ) -> std::result::Result<i64, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::Poisoned)?;
        let now = chrono_or_fallback_now();
        conn.execute(
            "INSERT INTO quarantined_files (original_path, quarantine_path, sha256, quarantined_at, reason, restored)
             VALUES (?1, ?2, ?3, ?4, ?5, 0)",
            params![original_path, quarantine_path, sha256, now, reason],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn list_quarantined_files(
        &self,
    ) -> std::result::Result<Vec<QuarantinedFileEntry>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::Poisoned)?;
        let mut stmt = conn.prepare(
            "SELECT id, original_path, quarantine_path, sha256, quarantined_at, reason, restored
             FROM quarantined_files WHERE restored = 0 ORDER BY id DESC",
        )?;

        let rows = stmt.query_map([], |row| {
            let restored_int: i32 = row.get(6)?;
            Ok(QuarantinedFileEntry {
                id: row.get(0)?,
                original_path: row.get(1)?,
                quarantine_path: row.get(2)?,
                sha256: row.get(3)?,
                quarantined_at: row.get(4)?,
                reason: row.get(5)?,
                restored: restored_int != 0,
            })
        })?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    pub fn mark_quarantine_restored(
        &self,
        id: i64,
    ) -> std::result::Result<Option<QuarantinedFileEntry>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::Poisoned)?;
        let entry: Option<QuarantinedFileEntry> = conn
            .query_row(
                "SELECT id, original_path, quarantine_path, sha256, quarantined_at, reason, restored
                 FROM quarantined_files WHERE id = ?1",
                params![id],
                |row| {
                    let restored_int: i32 = row.get(6)?;
                    Ok(QuarantinedFileEntry {
                        id: row.get(0)?,
                        original_path: row.get(1)?,
                        quarantine_path: row.get(2)?,
                        sha256: row.get(3)?,
                        quarantined_at: row.get(4)?,
                        reason: row.get(5)?,
                        restored: restored_int != 0,
                    })
                },
            )
            .ok();

        if let Some(mut e) = entry {
            conn.execute(
                "UPDATE quarantined_files SET restored = 1 WHERE id = ?1",
                params![id],
            )?;
            e.restored = true;
            Ok(Some(e))
        } else {
            Ok(None)
        }
    }

    pub fn add_allowlist_override(
        &self,
        entry_type: &str,
        value: &str,
        reason: &str,
    ) -> std::result::Result<(), StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::Poisoned)?;
        let now = chrono_or_fallback_now();
        conn.execute(
            "INSERT OR REPLACE INTO allowlist_overrides (entry_type, value, reason, added_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![entry_type, value, reason, now],
        )?;
        Ok(())
    }

    pub fn remove_allowlist_override(
        &self,
        entry_type: &str,
        value: &str,
    ) -> std::result::Result<bool, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::Poisoned)?;
        let affected = conn.execute(
            "DELETE FROM allowlist_overrides WHERE entry_type = ?1 AND value = ?2",
            params![entry_type, value],
        )?;
        Ok(affected > 0)
    }

    pub fn get_allowlist_overrides(
        &self,
    ) -> std::result::Result<Vec<AllowlistOverrideEntry>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::Poisoned)?;
        let mut stmt = conn.prepare(
            "SELECT id, entry_type, value, reason, added_at
             FROM allowlist_overrides ORDER BY id ASC",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(AllowlistOverrideEntry {
                id: row.get(0)?,
                entry_type: row.get(1)?,
                value: row.get(2)?,
                reason: row.get(3)?,
                added_at: row.get(4)?,
            })
        })?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }
}

fn chrono_or_fallback_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}.{:03}Z", duration.as_secs(), duration.subsec_millis())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_manager_initialization_and_migration() {
        let storage = StorageManager::open_in_memory().expect("open in memory failed");
        assert_eq!(storage.schema_version, 1);
    }

    #[test]
    fn test_audit_log_record_and_query() {
        let storage = StorageManager::open_in_memory().expect("open failed");
        let entry1 = AuditLogEntry {
            id: None,
            timestamp: "2026-09-09T12:00:00Z".to_string(),
            event_type: "file_access".to_string(),
            target: "/tmp/sample.bin".to_string(),
            decision: "Block".to_string(),
            reason: "KnownBadHash".to_string(),
            static_score: Some(0.9),
            hash_reputation: Some(1.0),
            behavior_score: Some(0.0),
            action_taken: "Terminated and quarantined".to_string(),
        };

        let id = storage.record_decision(&entry1).expect("record failed");
        assert!(id > 0);

        let logs = storage
            .query_audit_log(AuditLogFilter {
                decision: Some("Block".to_string()),
                limit: 10,
            })
            .expect("query failed");

        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].target, "/tmp/sample.bin");
        assert_eq!(logs[0].decision, "Block");
    }

    #[test]
    fn test_quarantine_record_and_restore() {
        let storage = StorageManager::open_in_memory().expect("open failed");
        let qid = storage
            .record_quarantine(
                "/home/user/malware.exe",
                "/var/lib/gn-shield/quarantine/malware.exe.quarantine",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "High entropy and EICAR signature",
            )
            .expect("quarantine failed");

        let quarantined = storage.list_quarantined_files().expect("list failed");
        assert_eq!(quarantined.len(), 1);
        assert_eq!(quarantined[0].id, qid);
        assert!(!quarantined[0].restored);

        let restored = storage
            .mark_quarantine_restored(qid)
            .expect("restore failed")
            .expect("entry found");
        assert!(restored.restored);

        let remaining = storage.list_quarantined_files().expect("list failed");
        assert!(remaining.is_empty());
    }

    #[test]
    fn test_allowlist_overrides() {
        let storage = StorageManager::open_in_memory().expect("open failed");
        storage
            .add_allowlist_override(
                "domain",
                "custom-tunnel.org",
                "Developer tunnel approved via CLI",
            )
            .expect("add override failed");

        let overrides = storage.get_allowlist_overrides().expect("get failed");
        assert_eq!(overrides.len(), 1);
        assert_eq!(overrides[0].value, "custom-tunnel.org");

        let removed = storage
            .remove_allowlist_override("domain", "custom-tunnel.org")
            .expect("remove failed");
        assert!(removed);

        let overrides_after = storage.get_allowlist_overrides().expect("get failed");
        assert!(overrides_after.is_empty());
    }
}
