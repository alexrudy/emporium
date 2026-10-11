//! Session and user storage backends, chosen in config.
//!
//! [`StoreConfig`] (the `[sessions.store]` table) picks a backend;
//! [`StoreConfig::open`] builds a [`Sessions`] and a [`Users`] store on
//! it. Both are enums over the backends compiled in, so the rest of the
//! app sees one concrete type whichever is configured.
//!
//! | `backend`  | Cargo feature | Persists? |
//! |------------|---------------|-----------|
//! | `"memory"` | (always)      | no        |
//! | `"sqlite"` | `sqlite`      | yes       |
//!
//! Every backend can be named in config; choosing one that isn't
//! compiled in fails at startup with [`StoreError::Disabled`].

use std::convert::Infallible;
use std::path::PathBuf;
use std::time::Duration;

use oath::server::{
    InMemorySessionStore, ProviderId, SessionData, SessionId, SessionStore, UserStore,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::user::{InMemoryUserStore, UserProfile};

/// How often expired sessions are swept from backends that don't expire
/// them on their own.
#[cfg_attr(not(feature = "sqlite"), allow(dead_code))]
const PRUNE_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Where sessions and user profiles are stored.
///
/// ```toml
/// [sessions.store]
/// backend = "sqlite"
/// path = "/var/lib/myapp/auth.sqlite3"
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "backend", rename_all = "lowercase")]
pub enum StoreConfig {
    /// In process memory: everyone is signed out on restart.
    #[default]
    Memory,
    /// A SQLite database file, created if missing. Requires the `sqlite`
    /// feature.
    Sqlite {
        /// Path to the database file.
        path: PathBuf,
    },
}

/// A storage backend failed.
#[derive(Debug, Error)]
pub enum StoreError {
    /// The configured backend isn't compiled into this build.
    #[error("the `{0}` store backend requires building with the `{0}` feature")]
    Disabled(&'static str),

    /// `sessions.ttl` is negative.
    #[error("session ttl must not be negative")]
    NegativeTtl,

    /// The SQLite backend failed.
    #[cfg(feature = "sqlite")]
    #[error("sqlite store error")]
    Sqlite(#[from] olite::Error),
}

impl From<Infallible> for StoreError {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

/// The session and user stores opened from a [`StoreConfig`].
#[derive(Debug, Clone)]
pub struct Stores {
    /// Session storage.
    pub sessions: Sessions,
    /// User profile storage.
    pub users: Users,
}

impl StoreConfig {
    /// Opens the configured backend. Sessions expire after `ttl`.
    ///
    /// Backends that don't expire sessions themselves get a background
    /// task pruning them every hour, so this must be called within a
    /// tokio runtime.
    pub async fn open(&self, ttl: Duration) -> Result<Stores, StoreError> {
        match self {
            Self::Memory => Ok(Stores {
                sessions: Sessions::Memory(InMemorySessionStore::new(ttl)),
                users: Users::Memory(InMemoryUserStore::new()),
            }),
            #[cfg(feature = "sqlite")]
            Self::Sqlite { path } => {
                let db = olite::Database::open(path)?;
                let sessions = olite::SqliteSessionStore::new(db.clone(), ttl);
                spawn_pruner(sessions.clone());
                Ok(Stores {
                    sessions: Sessions::Sqlite(sessions),
                    users: Users::Sqlite(olite::SqliteUserStore::new(db)),
                })
            }
            #[cfg(not(feature = "sqlite"))]
            Self::Sqlite { .. } => Err(StoreError::Disabled("sqlite")),
        }
    }
}

#[cfg(feature = "sqlite")]
fn spawn_pruner(sessions: olite::SqliteSessionStore) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(PRUNE_INTERVAL);
        loop {
            interval.tick().await;
            match sessions.prune_expired().await {
                Ok(0) => {}
                Ok(count) => tracing::debug!(count, "pruned expired sessions"),
                Err(error) => tracing::warn!(%error, "failed to prune expired sessions"),
            }
        }
    });
}

/// The configured [`SessionStore`].
#[derive(Debug, Clone)]
pub enum Sessions {
    /// See [`StoreConfig::Memory`].
    Memory(InMemorySessionStore),
    /// See [`StoreConfig::Sqlite`].
    #[cfg(feature = "sqlite")]
    Sqlite(olite::SqliteSessionStore),
}

#[async_trait::async_trait]
impl SessionStore for Sessions {
    type Error = StoreError;

    async fn create(&self, data: SessionData) -> Result<SessionId, StoreError> {
        match self {
            Self::Memory(store) => Ok(store.create(data).await?),
            #[cfg(feature = "sqlite")]
            Self::Sqlite(store) => Ok(store.create(data).await?),
        }
    }

    async fn get(&self, id: &SessionId) -> Result<Option<SessionData>, StoreError> {
        match self {
            Self::Memory(store) => Ok(store.get(id).await?),
            #[cfg(feature = "sqlite")]
            Self::Sqlite(store) => Ok(store.get(id).await?),
        }
    }

    async fn delete(&self, id: &SessionId) -> Result<(), StoreError> {
        match self {
            Self::Memory(store) => Ok(store.delete(id).await?),
            #[cfg(feature = "sqlite")]
            Self::Sqlite(store) => Ok(store.delete(id).await?),
        }
    }
}

/// The configured [`UserStore`] of [`UserProfile`]s.
#[derive(Debug, Clone)]
pub enum Users {
    /// See [`StoreConfig::Memory`].
    Memory(InMemoryUserStore),
    /// See [`StoreConfig::Sqlite`].
    #[cfg(feature = "sqlite")]
    Sqlite(olite::SqliteUserStore<UserProfile>),
}

#[async_trait::async_trait]
impl UserStore for Users {
    type Data = UserProfile;
    type Error = StoreError;

    async fn get(
        &self,
        provider: &ProviderId,
        username: &str,
    ) -> Result<Option<UserProfile>, StoreError> {
        match self {
            Self::Memory(store) => Ok(store.get(provider, username).await?),
            #[cfg(feature = "sqlite")]
            Self::Sqlite(store) => Ok(store.get(provider, username).await?),
        }
    }

    async fn put(
        &self,
        provider: &ProviderId,
        username: &str,
        data: &UserProfile,
    ) -> Result<(), StoreError> {
        match self {
            Self::Memory(store) => Ok(store.put(provider, username, data).await?),
            #[cfg(feature = "sqlite")]
            Self::Sqlite(store) => Ok(store.put(provider, username, data).await?),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TTL: Duration = Duration::from_secs(60);

    fn parse(source: &str) -> StoreConfig {
        toml::from_str(source).unwrap()
    }

    #[test]
    fn parses_backends() {
        assert_eq!(parse(r#"backend = "memory""#), StoreConfig::Memory);
        assert_eq!(
            parse("backend = \"sqlite\"\npath = \"/tmp/auth.sqlite3\""),
            StoreConfig::Sqlite {
                path: "/tmp/auth.sqlite3".into()
            }
        );
    }

    async fn round_trip(stores: &Stores) {
        let google = ProviderId::new("google").unwrap();
        let profile = UserProfile {
            display_name: Some("Alice".into()),
        };
        stores.users.put(&google, "abc", &profile).await.unwrap();
        assert_eq!(
            stores.users.get(&google, "abc").await.unwrap(),
            Some(profile)
        );

        let id = stores
            .sessions
            .create(SessionData::Authenticated {
                provider: google,
                username: "abc".into(),
            })
            .await
            .unwrap();
        assert!(stores.sessions.get(&id).await.unwrap().is_some());
        stores.sessions.delete(&id).await.unwrap();
        assert!(stores.sessions.get(&id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn memory_round_trip() {
        let stores = StoreConfig::Memory.open(TTL).await.unwrap();
        round_trip(&stores).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn sqlite_round_trip() {
        // Persistence across reopening is covered by olite's own tests.
        let config = StoreConfig::Sqlite {
            path: ":memory:".into(),
        };
        round_trip(&config.open(TTL).await.unwrap()).await;
    }

    #[cfg(not(feature = "sqlite"))]
    #[tokio::test]
    async fn sqlite_without_feature_is_an_error() {
        let config = StoreConfig::Sqlite {
            path: "auth.sqlite3".into(),
        };
        assert!(matches!(
            config.open(TTL).await,
            Err(StoreError::Disabled("sqlite"))
        ));
    }
}
