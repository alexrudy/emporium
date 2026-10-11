//! [`SessionStore`] on Valkey.

use std::time::Duration;

use oath::server::{SessionData, SessionId, SessionStore};
use redis::{AsyncCommands as _, SetExpiry, SetOptions};

use crate::client::{Error, Valkey};

/// A [`SessionStore`] keeping each session in a `{prefix}:session:{id}`
/// key that expires `ttl` after the session is created.
///
/// Valkey removes expired sessions itself. Cloning shares the same
/// connection.
#[derive(Debug, Clone)]
pub struct ValkeySessionStore {
    valkey: Valkey,
    ttl: Duration,
}

impl ValkeySessionStore {
    /// Creates a store on `valkey` whose sessions expire after `ttl`.
    pub fn new(valkey: Valkey, ttl: Duration) -> Self {
        Self { valkey, ttl }
    }
}

/// `ttl` in milliseconds. Valkey rejects an expiry of zero, so round up
/// to the smallest it accepts.
fn ttl_millis(ttl: Duration) -> u64 {
    u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX).max(1)
}

#[async_trait::async_trait]
impl SessionStore for ValkeySessionStore {
    type Error = Error;

    async fn create(&self, data: SessionData) -> Result<SessionId, Error> {
        let id = SessionId::generate();
        let json = serde_json::to_string(&data)?;
        let options = SetOptions::default().with_expiration(SetExpiry::PX(ttl_millis(self.ttl)));
        let _: Option<String> = self
            .valkey
            .conn()
            .set_options(self.valkey.session_key(&id), json, options)
            .await?;
        Ok(id)
    }

    async fn get(&self, id: &SessionId) -> Result<Option<SessionData>, Error> {
        let json: Option<String> = self.valkey.conn().get(self.valkey.session_key(id)).await?;
        Ok(json.map(|json| serde_json::from_str(&json)).transpose()?)
    }

    async fn delete(&self, id: &SessionId) -> Result<(), Error> {
        let _: usize = self.valkey.conn().del(self.valkey.session_key(id)).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use oath::server::ProviderId;

    use super::*;
    use crate::testing::valkey;

    fn alice() -> SessionData {
        SessionData::Authenticated {
            provider: ProviderId::new("google").unwrap(),
            username: "alice".into(),
        }
    }

    #[test]
    fn ttl_is_at_least_one_millisecond() {
        assert_eq!(ttl_millis(Duration::ZERO), 1);
        assert_eq!(ttl_millis(Duration::from_secs(2)), 2000);
        assert_eq!(ttl_millis(Duration::MAX), u64::MAX);
    }

    #[tokio::test]
    async fn round_trip() {
        let Some(valkey) = valkey().await else {
            return;
        };
        let store = ValkeySessionStore::new(valkey, Duration::from_secs(60));
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
        let Some(valkey) = valkey().await else {
            return;
        };
        let store = ValkeySessionStore::new(valkey, Duration::from_secs(60));
        assert!(store.get(&SessionId::generate()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn expires_after_ttl() {
        let Some(valkey) = valkey().await else {
            return;
        };
        let store = ValkeySessionStore::new(valkey, Duration::from_millis(50));
        let id = store.create(alice()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(store.get(&id).await.unwrap().is_none());
    }
}
