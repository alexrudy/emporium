//! [`UserStore`] on Valkey.

use std::fmt;
use std::marker::PhantomData;

use oath::server::{ProviderId, UserStore};
use redis::AsyncCommands as _;
use serde::{Serialize, de::DeserializeOwned};

use crate::client::{Error, Valkey};

/// A [`UserStore`] keeping each user record in a
/// `{prefix}:user:{provider}:{username}` key, with no expiry.
///
/// Records of type `T` are stored as JSON. Cloning shares the same
/// connection.
pub struct ValkeyUserStore<T> {
    valkey: Valkey,
    _marker: PhantomData<fn() -> T>,
}

impl<T> ValkeyUserStore<T> {
    /// Creates a store on `valkey`.
    pub fn new(valkey: Valkey) -> Self {
        Self {
            valkey,
            _marker: PhantomData,
        }
    }
}

impl<T> fmt::Debug for ValkeyUserStore<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValkeyUserStore")
            .field("valkey", &self.valkey)
            .finish()
    }
}

impl<T> Clone for ValkeyUserStore<T> {
    fn clone(&self) -> Self {
        Self::new(self.valkey.clone())
    }
}

#[async_trait::async_trait]
impl<T> UserStore for ValkeyUserStore<T>
where
    T: Serialize + DeserializeOwned + Send + Sync + 'static,
{
    type Data = T;
    type Error = Error;

    async fn get(&self, provider: &ProviderId, username: &str) -> Result<Option<T>, Error> {
        let json: Option<String> = self
            .valkey
            .conn()
            .get(self.valkey.user_key(provider, username))
            .await?;
        Ok(json.map(|json| serde_json::from_str(&json)).transpose()?)
    }

    async fn put(&self, provider: &ProviderId, username: &str, data: &T) -> Result<(), Error> {
        let json = serde_json::to_string(data)?;
        let _: () = self
            .valkey
            .conn()
            .set(self.valkey.user_key(provider, username), json)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;
    use crate::testing::valkey;

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

    #[tokio::test]
    async fn missing_user_is_absent() {
        let Some(valkey) = valkey().await else {
            return;
        };
        let store = ValkeyUserStore::<Profile>::new(valkey);
        assert!(store.get(&google(), "abc").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn put_replaces_existing() {
        let Some(valkey) = valkey().await else {
            return;
        };
        let store = ValkeyUserStore::new(valkey);
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
        let Some(valkey) = valkey().await else {
            return;
        };
        let store = ValkeyUserStore::new(valkey);
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
