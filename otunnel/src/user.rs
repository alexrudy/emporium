//! Persisted user record + identity resolver.
//!
//! [`AppUser`] is a minimal user represntation.

use std::convert::Infallible;
use std::sync::Arc;

use dashmap::DashSet;
use oath::server::{Identity, IdentityResolver, UserStore, parse_id_token};
use serde::{Deserialize, Serialize};

/// What ott persists for each user.
///
/// `created_at` and `last_login_at` are bookkeeping the demo computes
/// at callback time; they aren't part of any OIDC spec.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AppUser {
    pub username: String,
}

impl AppUser {
    pub fn new(username: String) -> Self {
        Self { username }
    }
}

#[derive(Default, Debug, Clone)]
pub struct NoOpUserStore {
    users: Arc<DashSet<String>>,
}

impl NoOpUserStore {
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

/// Default identity resolver: parse the `id_token` and project the
/// claims into an [`AppUser`].
///
/// Note: `created_at` is overwritten on every login because the
/// resolver doesn't know whether the user already exists. Phase C
/// polish: read the existing record first and preserve `created_at`.
pub fn identity_resolver() -> IdentityResolver<()> {
    IdentityResolver::new(|tokens| async move {
        let claims = parse_id_token(&tokens)?;
        let display_name = claims
            .name
            .clone()
            .or_else(|| claims.preferred_username.clone())
            .unwrap_or_else(|| claims.sub.clone());
        Ok(Identity {
            username: display_name,
            data: (),
        })
    })
}
