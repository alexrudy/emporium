//! The shared Valkey connection.

use std::fmt;

use oath::server::{ProviderId, SessionId};
use redis::aio::ConnectionManager;
use redis::{Client, IntoConnectionInfo};

/// Errors from the Valkey stores.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Valkey reported an error, or couldn't be reached.
    #[error("valkey error")]
    Valkey(#[from] redis::RedisError),

    /// A stored value couldn't be serialized or deserialized.
    #[error("failed to (de)serialize stored data")]
    Json(#[from] serde_json::Error),
}

/// The default key prefix.
const DEFAULT_PREFIX: &str = "oath";

/// A shared handle to a Valkey server holding sessions and users.
///
/// Cloning shares the same connection, which reconnects on its own if
/// the server goes away. Keys are namespaced by a prefix (`oath` by
/// default; see [`Valkey::with_prefix`]).
#[derive(Clone)]
pub struct Valkey {
    conn: ConnectionManager,
    prefix: String,
}

impl fmt::Debug for Valkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Valkey")
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

impl Valkey {
    /// Connects to the server at `url` (e.g. `redis://127.0.0.1:6379`,
    /// `rediss://` for TLS, or `redis+unix:///path/to/socket`).
    ///
    /// Fails if the server can't be reached now; once connected, dropped
    /// connections are re-established automatically.
    pub async fn connect(url: impl IntoConnectionInfo) -> Result<Self, Error> {
        let client = Client::open(url)?;
        Ok(Self::from_manager(ConnectionManager::new(client).await?))
    }

    /// Wraps an existing connection manager, e.g. one built with a custom
    /// [`redis::aio::ConnectionManagerConfig`].
    pub fn from_manager(conn: ConnectionManager) -> Self {
        Self {
            conn,
            prefix: DEFAULT_PREFIX.to_owned(),
        }
    }

    /// Namespaces keys under `prefix` instead of `oath`, to share a
    /// server between apps.
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    /// A clone of the connection, for issuing commands.
    pub(crate) fn conn(&self) -> ConnectionManager {
        self.conn.clone()
    }

    pub(crate) fn session_key(&self, id: &SessionId) -> String {
        session_key(&self.prefix, id)
    }

    pub(crate) fn user_key(&self, provider: &ProviderId, username: &str) -> String {
        user_key(&self.prefix, provider, username)
    }
}

fn session_key(prefix: &str, id: &SessionId) -> String {
    format!("{prefix}:session:{}", id.as_str())
}

fn user_key(prefix: &str, provider: &ProviderId, username: &str) -> String {
    format!("{prefix}:user:{}:{username}", provider.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_layout() {
        let google = ProviderId::new("google").unwrap();
        assert_eq!(
            session_key(DEFAULT_PREFIX, &SessionId::from_string("abc")),
            "oath:session:abc"
        );
        assert_eq!(
            user_key(DEFAULT_PREFIX, &google, "alice"),
            "oath:user:google:alice"
        );
        // The provider can't contain `:`, so a `:` in the username is
        // unambiguous.
        assert_eq!(user_key("app", &google, "a:b"), "app:user:google:a:b");
    }
}
