//! Persisted user record + identity resolver.
//!
//! [`AppUser`] is a minimal user represntation.

use std::convert::Infallible;
use std::fmt;
use std::sync::Arc;

use dashmap::DashSet;
use oath::server::{Identity, IdentityResolver, ProviderId, UserStore, parse_id_token};
use serde::{Deserialize, Serialize};

/// An authenticated user.
///
/// Users are identified by `(provider, username)`: OIDC `sub` claims are
/// only unique per provider. [`Display`](fmt::Display) renders the pair as
/// `{provider}:{username}`, e.g. for logging.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AppUser {
    /// The provider the user signed in with.
    pub provider: ProviderId,
    /// The user's identifier at that provider (the OIDC `sub`).
    pub username: String,
}

impl AppUser {
    /// Creates a new [`AppUser`].
    pub fn new(provider: ProviderId, username: String) -> Self {
        Self { provider, username }
    }
}

impl fmt::Display for AppUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.provider, self.username)
    }
}

/// A no-op user store that does nothing,
/// and stores users in memory.
#[derive(Default, Debug, Clone)]
pub struct NoOpUserStore {
    users: Arc<DashSet<(ProviderId, String)>>,
}

impl NoOpUserStore {
    /// Creates a new [`NoOpUserStore`] with an empty user set.
    pub fn new() -> Self {
        Self {
            users: Arc::new(DashSet::new()),
        }
    }
}

#[async_trait::async_trait]
impl UserStore for NoOpUserStore {
    type Data = ();
    type Error = Infallible;

    async fn get(&self, provider: &ProviderId, username: &str) -> Result<Option<()>, Infallible> {
        if self
            .users
            .contains(&(provider.clone(), username.to_owned()))
        {
            Ok(Some(()))
        } else {
            Ok(None)
        }
    }

    async fn put(
        &self,
        provider: &ProviderId,
        username: &str,
        _data: &(),
    ) -> Result<(), Infallible> {
        self.users.insert((provider.clone(), username.to_owned()));
        Ok(())
    }
}

/// Default identity resolver: the username is the `sub` from the
/// `id_token`. The provider is tracked alongside it by the session and
/// the user store.
pub fn identity_resolver() -> IdentityResolver<()> {
    IdentityResolver::new(|tokens| async move {
        let claims = parse_id_token(&tokens)?;
        Ok(Identity {
            username: claims.sub,
            data: (),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn store_keeps_providers_apart() {
        let store = NoOpUserStore::new();
        let google = ProviderId::new("google").unwrap();
        let okta = ProviderId::new("okta").unwrap();

        store.put(&google, "abc", &()).await.unwrap();
        assert!(store.get(&google, "abc").await.unwrap().is_some());
        assert!(store.get(&okta, "abc").await.unwrap().is_none());
    }

    #[test]
    fn displays_provider_and_username() {
        let user = AppUser::new(ProviderId::new("google").unwrap(), "abc".into());
        assert_eq!(user.to_string(), "google:abc");
    }
}
