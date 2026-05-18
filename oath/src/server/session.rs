//! Session state for the `/auth/login` and `/auth/callback` handlers.
//!
//! [`SessionData`] is the per-session payload — either the in-flight
//! pre-auth state (state token + PKCE verifier) or the authenticated
//! user's identity. [`SessionStore`] abstracts the backing store;
//! [`InMemorySessionStore`] is the bundled default.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use rand::TryRngCore as _;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::grant::PendingAuthorization;

/// What kind of session this is.
///
/// Both variants share the same `SessionId` namespace and live in the
/// same [`SessionStore`]. Cookies determine which one is loaded:
///   - the `preauth` cookie points to a [`SessionData::Pending`]
///   - the `session` cookie points to a [`SessionData::Authenticated`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionData {
    /// In-flight authorization-code request awaiting the callback.
    Pending {
        /// State + PKCE verifier persisted across the redirect.
        pending: PendingAuthorization,
        /// Optional URL to redirect the user back to after login.
        #[serde(default)]
        return_to: Option<String>,
    },
    /// Authenticated session pointing to a stored user.
    Authenticated {
        /// The persistent user identifier (typically the OIDC `sub`).
        username: String,
    },
}

/// Opaque random identifier for a session.
///
/// Generated from 32 random bytes encoded as 43-character base64url
/// (no padding) — the same shape as [`crate::StateToken`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(String);

impl SessionId {
    /// Generate a fresh, high-entropy session id.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut bytes)
            .expect("OsRng must provide random bytes");
        Self(URL_SAFE_NO_PAD.encode(bytes))
    }

    /// Wrap an existing string. Use only when round-tripping through a
    /// signed cookie value the caller has already validated.
    pub fn from_string(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The underlying string representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Storage abstraction for session data.
///
/// Implementations must be safe for concurrent access from multiple
/// async tasks. The trait intentionally does not expose session expiry
/// or eviction policies — those are the implementation's concern.
#[async_trait::async_trait]
pub trait SessionStore: Send + Sync + 'static {
    /// The error type produced by store operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Persist a new session and return its fresh id.
    async fn create(&self, data: SessionData) -> Result<SessionId, Self::Error>;

    /// Load the session for `id`, or `None` if it's absent / expired.
    async fn get(&self, id: &SessionId) -> Result<Option<SessionData>, Self::Error>;

    /// Remove the session for `id`. Idempotent.
    async fn delete(&self, id: &SessionId) -> Result<(), Self::Error>;
}

#[derive(Debug)]
struct Entry {
    data: SessionData,
    expires_at: DateTime<Utc>,
}

/// Default in-process [`SessionStore`] keyed by [`SessionId`].
///
/// Backed by a [`DashMap`] for lock-free reads. Entries past their TTL
/// are treated as absent on `get` and pruned lazily there.
///
/// For multi-instance deployments, swap in a Redis- or database-backed
/// store implementing [`SessionStore`].
#[derive(Debug, Clone)]
pub struct InMemorySessionStore {
    sessions: Arc<DashMap<SessionId, Entry>>,
    ttl: StdDuration,
}

impl Default for InMemorySessionStore {
    fn default() -> Self {
        Self::new(StdDuration::from_secs(60 * 60 * 24 * 30))
    }
}

impl InMemorySessionStore {
    /// Create a new in-memory store. Sessions expire after `ttl`.
    pub fn new(ttl: StdDuration) -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
            ttl,
        }
    }
}

#[async_trait::async_trait]
impl SessionStore for InMemorySessionStore {
    type Error = Infallible;

    async fn create(&self, data: SessionData) -> Result<SessionId, Self::Error> {
        let id = SessionId::generate();
        let entry = Entry {
            data,
            expires_at: Utc::now()
                + chrono::Duration::from_std(self.ttl).unwrap_or(chrono::Duration::days(30)),
        };
        self.sessions.insert(id.clone(), entry);
        Ok(id)
    }

    async fn get(&self, id: &SessionId) -> Result<Option<SessionData>, Self::Error> {
        let now = Utc::now();
        // Lazy eviction: drop expired entries when we see them.
        if let Some(entry) = self.sessions.get(id) {
            if entry.expires_at < now {
                drop(entry);
                self.sessions.remove(id);
                return Ok(None);
            }
            return Ok(Some(entry.data.clone()));
        }
        Ok(None)
    }

    async fn delete(&self, id: &SessionId) -> Result<(), Self::Error> {
        self.sessions.remove(id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_id_generate_is_43_chars() {
        let id = SessionId::generate();
        assert_eq!(id.as_str().len(), 43);
    }

    #[test]
    fn session_id_pairs_are_distinct() {
        let a = SessionId::generate();
        let b = SessionId::generate();
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn in_memory_round_trip() {
        let store = InMemorySessionStore::default();
        let data = SessionData::Authenticated {
            username: "alice".into(),
        };
        let id = store.create(data.clone()).await.unwrap();
        let loaded = store.get(&id).await.unwrap().unwrap();
        match loaded {
            SessionData::Authenticated { username } => assert_eq!(username, "alice"),
            _ => panic!("expected authenticated session"),
        }
        store.delete(&id).await.unwrap();
        assert!(store.get(&id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn in_memory_expires_after_ttl() {
        let store = InMemorySessionStore::new(StdDuration::from_millis(0));
        let id = store
            .create(SessionData::Authenticated {
                username: "alice".into(),
            })
            .await
            .unwrap();
        // Any subsequent get sees a stale entry and returns None.
        tokio::time::sleep(StdDuration::from_millis(5)).await;
        assert!(store.get(&id).await.unwrap().is_none());
    }
}
