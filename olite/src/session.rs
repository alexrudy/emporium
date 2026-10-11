//! [`SessionStore`] on SQLite.

use std::time::Duration;

use chrono::Utc;
use oath::server::{SessionData, SessionId, SessionStore};
use rusqlite::{OptionalExtension as _, params};

use crate::db::{Database, Error};

/// A [`SessionStore`] persisting sessions in the `oath_sessions` table.
///
/// Sessions expire `ttl` after they're created. Expired sessions are
/// treated as absent and deleted when read; call
/// [`SqliteSessionStore::prune_expired`] periodically to clear out the
/// ones that are never read again. Cloning shares the same database.
#[derive(Debug, Clone)]
pub struct SqliteSessionStore {
    db: Database,
    ttl: Duration,
}

impl SqliteSessionStore {
    /// Creates a store on `db` whose sessions expire after `ttl`.
    pub fn new(db: Database, ttl: Duration) -> Self {
        Self { db, ttl }
    }

    /// Deletes every expired session, returning how many were removed.
    pub async fn prune_expired(&self) -> Result<usize, Error> {
        let now = Utc::now().timestamp_millis();
        self.db
            .call(move |conn| {
                Ok(conn.execute(
                    "DELETE FROM oath_sessions WHERE expires_at <= ?1",
                    params![now],
                )?)
            })
            .await
    }

    fn expires_at(&self) -> i64 {
        let ttl = chrono::Duration::from_std(self.ttl).unwrap_or(chrono::Duration::days(30));
        (Utc::now() + ttl).timestamp_millis()
    }
}

#[async_trait::async_trait]
impl SessionStore for SqliteSessionStore {
    type Error = Error;

    async fn create(&self, data: SessionData) -> Result<SessionId, Error> {
        let id = SessionId::generate();
        let json = serde_json::to_string(&data)?;
        let expires_at = self.expires_at();
        let key = id.as_str().to_owned();
        self.db
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO oath_sessions (id, data, expires_at) VALUES (?1, ?2, ?3)",
                    params![key, json, expires_at],
                )?;
                Ok(())
            })
            .await?;
        Ok(id)
    }

    async fn get(&self, id: &SessionId) -> Result<Option<SessionData>, Error> {
        let key = id.as_str().to_owned();
        let now = Utc::now().timestamp_millis();
        let json = self
            .db
            .call(move |conn| {
                let row: Option<(String, i64)> = conn
                    .query_row(
                        "SELECT data, expires_at FROM oath_sessions WHERE id = ?1",
                        params![key],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?;
                match row {
                    Some((_, expires_at)) if expires_at <= now => {
                        conn.execute("DELETE FROM oath_sessions WHERE id = ?1", params![key])?;
                        Ok(None)
                    }
                    Some((json, _)) => Ok(Some(json)),
                    None => Ok(None),
                }
            })
            .await?;
        json.map(|json| serde_json::from_str(&json))
            .transpose()
            .map_err(Error::from)
    }

    async fn delete(&self, id: &SessionId) -> Result<(), Error> {
        let key = id.as_str().to_owned();
        self.db
            .call(move |conn| {
                conn.execute("DELETE FROM oath_sessions WHERE id = ?1", params![key])?;
                Ok(())
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use oath::server::ProviderId;

    use super::*;

    fn store(ttl: Duration) -> SqliteSessionStore {
        SqliteSessionStore::new(Database::open_in_memory().unwrap(), ttl)
    }

    fn alice() -> SessionData {
        SessionData::Authenticated {
            provider: ProviderId::new("google").unwrap(),
            username: "alice".into(),
        }
    }

    #[tokio::test]
    async fn round_trip() {
        let store = store(Duration::from_secs(60));
        let id = store.create(alice()).await.unwrap();
        match store.get(&id).await.unwrap() {
            Some(SessionData::Authenticated { provider, username }) => {
                assert_eq!(provider.as_str(), "google");
                assert_eq!(username, "alice");
            }
            other => panic!("expected authenticated session, got {other:?}"),
        }
        store.delete(&id).await.unwrap();
        assert!(store.get(&id).await.unwrap().is_none());
        // Deleting again is a no-op.
        store.delete(&id).await.unwrap();
    }

    #[tokio::test]
    async fn unknown_id_is_absent() {
        let store = store(Duration::from_secs(60));
        assert!(store.get(&SessionId::generate()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn expires_after_ttl() {
        let store = store(Duration::ZERO);
        let id = store.create(alice()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(store.get(&id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn prune_removes_only_expired() {
        let db = Database::open_in_memory().unwrap();
        let short = SqliteSessionStore::new(db.clone(), Duration::ZERO);
        let long = SqliteSessionStore::new(db, Duration::from_secs(60));
        short.create(alice()).await.unwrap();
        let kept = long.create(alice()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;

        assert_eq!(long.prune_expired().await.unwrap(), 1);
        assert!(long.get(&kept).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.sqlite3");
        let ttl = Duration::from_secs(60);

        let id = SqliteSessionStore::new(Database::open(&path).unwrap(), ttl)
            .create(alice())
            .await
            .unwrap();
        let store = SqliteSessionStore::new(Database::open(&path).unwrap(), ttl);
        assert!(store.get(&id).await.unwrap().is_some());
    }
}
