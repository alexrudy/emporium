//! Signed-in users: the [`AppUser`] handlers see, the in-memory
//! [`InMemoryUserStore`] of profiles, and the identity resolver that
//! fills it from ID tokens.

use std::convert::Infallible;
use std::fmt;
use std::sync::Arc;

use dashmap::DashMap;
use oath::server::{IdClaims, Identity, IdentityResolver, ProviderId, UserStore, parse_id_token};
use serde::{Deserialize, Serialize};

/// An authenticated user.
///
/// Users are identified by `(provider, username)`: OIDC `sub` claims are
/// only unique per provider. [`Display`](fmt::Display) renders the user
/// for logs as `Alice (google:1234)`, or `google:1234` without a display
/// name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AppUser {
    /// The provider the user signed in with.
    pub provider: ProviderId,
    /// The user's identifier at that provider (the OIDC `sub`).
    pub username: String,
    /// A human-readable name from the ID token, if the provider sent one.
    pub display_name: Option<String>,
}

impl AppUser {
    /// Creates a new [`AppUser`] without a display name.
    pub fn new(provider: ProviderId, username: String) -> Self {
        Self {
            provider,
            username,
            display_name: None,
        }
    }

    /// Sets the display name.
    pub fn with_display_name(mut self, name: Option<String>) -> Self {
        self.display_name = name;
        self
    }
}

impl fmt::Display for AppUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.display_name {
            Some(name) => write!(f, "{name} ({}:{})", self.provider, self.username),
            None => write!(f, "{}:{}", self.provider, self.username),
        }
    }
}

/// What [`InMemoryUserStore`] remembers about each user.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserProfile {
    /// A human-readable name: the ID token's `name`, else
    /// `preferred_username`, else `email`.
    pub display_name: Option<String>,
}

impl UserProfile {
    /// Pick a display name from ID token claims.
    pub fn from_claims(claims: &IdClaims) -> Self {
        let display_name = [&claims.name, &claims.preferred_username, &claims.email]
            .into_iter()
            .flatten()
            .map(|value| value.trim())
            .find(|value| !value.is_empty())
            .map(str::to_owned);
        Self { display_name }
    }
}

/// An in-memory [`UserStore`] of [`UserProfile`]s, keyed by
/// `(provider, username)`.
///
/// Like the session store, it's lost on restart; the two are in step, so
/// every live session has a profile. Cloning shares the same store.
#[derive(Default, Debug, Clone)]
pub struct InMemoryUserStore {
    users: Arc<DashMap<(ProviderId, String), UserProfile>>,
}

impl InMemoryUserStore {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl UserStore for InMemoryUserStore {
    type Data = UserProfile;
    type Error = Infallible;

    async fn get(
        &self,
        provider: &ProviderId,
        username: &str,
    ) -> Result<Option<UserProfile>, Infallible> {
        Ok(self
            .users
            .get(&(provider.clone(), username.to_owned()))
            .map(|entry| entry.clone()))
    }

    async fn put(
        &self,
        provider: &ProviderId,
        username: &str,
        data: &UserProfile,
    ) -> Result<(), Infallible> {
        self.users
            .insert((provider.clone(), username.to_owned()), data.clone());
        Ok(())
    }
}

/// Default identity resolver: the username is the `sub` from the
/// `id_token`, and the profile records a display name from its claims.
/// The provider is tracked alongside the username by the session and the
/// user store.
pub fn identity_resolver() -> IdentityResolver<UserProfile> {
    IdentityResolver::new(|tokens| async move {
        let claims = parse_id_token(&tokens)?;
        Ok(Identity {
            data: UserProfile::from_claims(&claims),
            username: claims.sub,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn google() -> ProviderId {
        ProviderId::new("google").unwrap()
    }

    #[tokio::test]
    async fn store_keeps_providers_apart() {
        let store = InMemoryUserStore::new();
        let okta = ProviderId::new("okta").unwrap();
        let profile = UserProfile {
            display_name: Some("Alice".into()),
        };

        store.put(&google(), "abc", &profile).await.unwrap();
        assert_eq!(store.get(&google(), "abc").await.unwrap(), Some(profile));
        assert!(store.get(&okta, "abc").await.unwrap().is_none());
    }

    #[test]
    fn display_includes_name_when_known() {
        let user = AppUser::new(google(), "abc".into());
        assert_eq!(user.to_string(), "google:abc");
        let user = user.with_display_name(Some("Alice".into()));
        assert_eq!(user.to_string(), "Alice (google:abc)");
    }

    fn claims(json: serde_json::Value) -> IdClaims {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn display_name_falls_back_through_claims() {
        let cases = [
            (
                serde_json::json!({"sub": "1", "name": "Alice", "preferred_username": "alice", "email": "a@x"}),
                Some("Alice"),
            ),
            (
                serde_json::json!({"sub": "1", "name": " ", "preferred_username": "alice"}),
                Some("alice"),
            ),
            (
                serde_json::json!({"sub": "1", "email": "alice@example.com"}),
                Some("alice@example.com"),
            ),
            (serde_json::json!({"sub": "1"}), None),
        ];
        for (json, expected) in cases {
            assert_eq!(
                UserProfile::from_claims(&claims(json.clone()))
                    .display_name
                    .as_deref(),
                expected,
                "{json}"
            );
        }
    }
}
