//! [`UserStore`] on SQLite.

use std::fmt;
use std::marker::PhantomData;

use chrono::Utc;
use oath::server::{ProviderId, UserStore};
use rusqlite::{OptionalExtension as _, params};
use serde::{Serialize, de::DeserializeOwned};

use crate::db::{Database, Error};

/// A [`UserStore`] persisting user records in the `oath_users` table,
/// keyed by `(provider, username)`.
///
/// Records of type `T` are stored as JSON. Cloning shares the same
/// database.
pub struct SqliteUserStore<T> {
    db: Database,
    _marker: PhantomData<fn() -> T>,
}

impl<T> SqliteUserStore<T> {
    /// Creates a store on `db`.
    pub fn new(db: Database) -> Self {
        Self {
            db,
            _marker: PhantomData,
        }
    }
}

impl<T> fmt::Debug for SqliteUserStore<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqliteUserStore")
            .field("db", &self.db)
            .finish()
    }
}

impl<T> Clone for SqliteUserStore<T> {
    fn clone(&self) -> Self {
        Self::new(self.db.clone())
    }
}

#[async_trait::async_trait]
impl<T> UserStore for SqliteUserStore<T>
where
    T: Serialize + DeserializeOwned + Send + Sync + 'static,
{
    type Data = T;
    type Error = Error;

    async fn get(&self, provider: &ProviderId, username: &str) -> Result<Option<T>, Error> {
        let provider = provider.as_str().to_owned();
        let username = username.to_owned();
        let json: Option<String> = self
            .db
            .call(move |conn| {
                Ok(conn
                    .query_row(
                        "SELECT data FROM oath_users WHERE provider = ?1 AND username = ?2",
                        params![provider, username],
                        |row| row.get(0),
                    )
                    .optional()?)
            })
            .await?;
        json.map(|json| serde_json::from_str(&json))
            .transpose()
            .map_err(Error::from)
    }

    async fn put(&self, provider: &ProviderId, username: &str, data: &T) -> Result<(), Error> {
        let provider = provider.as_str().to_owned();
        let username = username.to_owned();
        let json = serde_json::to_string(data)?;
        let now = Utc::now().timestamp_millis();
        self.db
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO oath_users (provider, username, data, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?4)
                     ON CONFLICT (provider, username)
                     DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at",
                    params![provider, username, json, now],
                )?;
                Ok(())
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct Profile {
        display_name: Option<String>,
    }

    fn profile(name: &str) -> Profile {
        Profile {
            display_name: Some(name.into()),
        }
    }

    fn google() -> ProviderId {
        ProviderId::new("google").unwrap()
    }

    fn store() -> SqliteUserStore<Profile> {
        SqliteUserStore::new(Database::open_in_memory().unwrap())
    }

    #[tokio::test]
    async fn missing_user_is_absent() {
        assert!(store().get(&google(), "abc").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn put_replaces_existing() {
        let store = store();
        store
            .put(&google(), "abc", &profile("Alice"))
            .await
            .unwrap();
        store
            .put(&google(), "abc", &profile("Alicia"))
            .await
            .unwrap();
        assert_eq!(
            store.get(&google(), "abc").await.unwrap(),
            Some(profile("Alicia"))
        );
    }

    #[tokio::test]
    async fn keeps_providers_apart() {
        let store = store();
        let okta = ProviderId::new("okta").unwrap();
        store
            .put(&google(), "abc", &profile("Google"))
            .await
            .unwrap();
        store.put(&okta, "abc", &profile("Okta")).await.unwrap();

        assert_eq!(
            store.get(&google(), "abc").await.unwrap(),
            Some(profile("Google"))
        );
        assert_eq!(
            store.get(&okta, "abc").await.unwrap(),
            Some(profile("Okta"))
        );
        assert!(
            store
                .get(&ProviderId::default(), "abc")
                .await
                .unwrap()
                .is_none()
        );
    }
}
