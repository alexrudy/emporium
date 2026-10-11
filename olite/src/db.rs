//! The shared SQLite connection and its schema.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use rusqlite::{Connection, TransactionBehavior};

/// Errors from the SQLite stores.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// SQLite reported an error.
    #[error("sqlite error")]
    Sqlite(#[from] rusqlite::Error),

    /// A stored value couldn't be serialized or deserialized.
    #[error("failed to (de)serialize stored data")]
    Json(#[from] serde_json::Error),

    /// The blocking task running the query panicked or was cancelled.
    #[error("database task failed")]
    Task(#[from] tokio::task::JoinError),

    /// The database was written by a newer version of this crate.
    #[error("database schema version {found} is newer than the supported version {supported}")]
    SchemaTooNew {
        /// The schema version found in the database.
        found: u32,
        /// The newest schema version this crate knows.
        supported: u32,
    },
}

/// Schema migrations, applied in order. The database's `user_version`
/// records how many have run, so append new entries; never edit old ones.
const MIGRATIONS: &[&str] = &[r#"
    CREATE TABLE oath_sessions (
        id TEXT PRIMARY KEY NOT NULL,
        data TEXT NOT NULL,
        expires_at INTEGER NOT NULL
    );
    CREATE INDEX oath_sessions_expires_at ON oath_sessions (expires_at);

    CREATE TABLE oath_users (
        provider TEXT NOT NULL,
        username TEXT NOT NULL,
        data TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (provider, username)
    );
"#];

const SCHEMA_VERSION: u32 = MIGRATIONS.len() as u32;

/// How long a query waits for another connection's write lock.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// A shared handle to a SQLite database holding sessions and users.
///
/// Cloning shares the same connection. Queries run on tokio's blocking
/// thread pool, one at a time.
#[derive(Debug, Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    /// Opens (or creates) the database file at `path`, enables WAL
    /// journaling, and brings the schema up to date.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let conn = Connection::open(path)?;
        conn.pragma_update_and_check(None, "journal_mode", "wal", |_| Ok(()))?;
        Self::from_connection(conn)
    }

    /// Opens a private in-memory database, lost when the last clone is
    /// dropped. Useful for tests.
    pub fn open_in_memory() -> Result<Self, Error> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    /// Wraps an existing connection, bringing the schema up to date.
    pub fn from_connection(mut conn: Connection) -> Result<Self, Error> {
        conn.busy_timeout(BUSY_TIMEOUT)?;
        migrate(&mut conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Runs `f` with the connection on the blocking thread pool.
    pub(crate) async fn call<F, R>(&self, f: F) -> Result<R, Error>
    where
        F: FnOnce(&mut Connection) -> Result<R, Error> + Send + 'static,
        R: Send + 'static,
    {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || f(&mut conn.lock())).await?
    }
}

fn migrate(conn: &mut Connection) -> Result<(), Error> {
    // An immediate transaction takes the write lock up front, so two
    // processes opening the same file can't both run a migration.
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let version: u32 = tx.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version > SCHEMA_VERSION {
        return Err(Error::SchemaTooNew {
            found: version,
            supported: SCHEMA_VERSION,
        });
    }
    for migration in &MIGRATIONS[version as usize..] {
        tx.execute_batch(migration)?;
    }
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reopening_keeps_schema() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.sqlite3");
        drop(Database::open(&path).unwrap());
        drop(Database::open(&path).unwrap());
    }

    #[test]
    fn newer_schema_is_rejected() {
        let conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .unwrap();
        let err = Database::from_connection(conn).unwrap_err();
        assert!(matches!(err, Error::SchemaTooNew { .. }), "{err:?}");
    }
}
