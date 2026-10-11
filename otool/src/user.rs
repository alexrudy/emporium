//! Persisted user record + identity resolver.
//!
//! [`AppUser`] is a minimal user represntation.

use std::convert::Infallible;
use std::sync::Arc;

use dashmap::DashSet;
use oath::server::{Identity, IdentityResolver, ProviderId, UserStore, parse_id_token};
use serde::{Deserialize, Serialize};

/// An authenticated user.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AppUser {
    /// The provider the user signed in with.
    pub provider: ProviderId,
    /// The user's stable identifier, `{provider}:{sub}`. OIDC `sub`
    /// claims are only unique per provider, hence the prefix.
    pub username: String,
}

impl AppUser {
    /// Creates a new [`AppUser`].
    pub fn new(provider: ProviderId, username: String) -> Self {
        Self { provider, username }
    }
}

/// A no-op user store that does nothing,
/// and stores users in memory.
#[derive(Default, Debug, Clone)]
pub struct NoOpUserStore {
    users: Arc<DashSet<String>>,
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

    async fn get(&self, username: &str) -> Result<Option<()>, Infallible> {
        if self.users.contains(username) {
            Ok(Some(()))
        } else {
            Ok(None)
        }
    }

    async fn put(&self, username: &str, _data: &()) -> Result<(), Infallible> {
        self.users.insert(username.to_string());
        Ok(())
    }
}

/// Default identity resolver: the username is `{provider}:{sub}` from
/// the `id_token`, so users from different providers can't collide.
pub fn identity_resolver() -> IdentityResolver<()> {
    IdentityResolver::with_provider(|provider: ProviderId, tokens| async move {
        let claims = parse_id_token(&tokens)?;
        Ok(Identity {
            username: format!("{provider}:{}", claims.sub),
            data: (),
        })
    })
}
