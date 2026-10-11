//! Configuration for otool-based applications.

use std::collections::BTreeMap;

use cookie::Key;
use oath::server::ProviderId;
pub use oath::{provider::OAuthProviderConfig, server::OAuth2RouterConfig};
use secret::Secret;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::store::StoreConfig;

/// Configuration for the session management system.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionsConfig {
    /// The time-to-live for session cookies.
    pub ttl: chrono::Duration,

    /// The secret key used for signing session cookies.
    pub key: Secret,

    /// Where sessions and user profiles are stored (`[sessions.store]`).
    /// Defaults to memory.
    pub store: StoreConfig,
}

impl Default for SessionsConfig {
    fn default() -> Self {
        Self {
            ttl: chrono::Duration::hours(48),
            key: data_encoding::BASE64
                .encode(Key::generate().master())
                .into(),
            store: StoreConfig::default(),
        }
    }
}

/// The OAuth providers an app signs users in with.
///
/// Meant to be `#[serde(flatten)]`ed into an app's top-level config:
///
/// ```toml
/// # A single provider, mounted at /auth/login and /auth/callback.
/// [provider]
/// client_id = "..."
///
/// # Additional providers, mounted at /auth/<id>/login and
/// # /auth/<id>/callback.
/// [providers.google]
/// client_id = "..."
///
/// # Which provider serves /auth/login. Defaults to [provider], or the
/// # only configured provider. Without one, /auth/login lists them all.
/// default_provider = "google"
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProvidersConfig {
    /// The original single provider, registered as
    /// [`ProviderId::default`] and mounted at `{prefix}/login` and
    /// `{prefix}/callback` so existing redirect URIs keep working. It is
    /// always the default provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<OAuthProviderConfig>,

    /// Providers by id, mounted at `{prefix}/{id}/login` and
    /// `{prefix}/{id}/callback`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub providers: BTreeMap<ProviderId, OAuthProviderConfig>,

    /// Which provider serves `{prefix}/login`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_provider: Option<ProviderId>,
}

/// [`ProvidersConfig`] is inconsistent.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ProvidersConfigError {
    /// Neither `[provider]` nor any `[providers.<id>]` is configured.
    #[error("no OAuth providers configured: set [provider] or [providers.<id>]")]
    NoProviders,

    /// `[providers.default]` collides with `[provider]`'s id.
    #[error("[providers.{0}] can't be combined with [provider], which uses that id")]
    ReservedId(ProviderId),

    /// `default_provider` names a provider that isn't configured.
    #[error("default_provider {0:?} is not a configured provider")]
    UnknownDefault(ProviderId),

    /// `default_provider` is set alongside `[provider]`.
    #[error("default_provider {0:?} conflicts with [provider], which is always the default")]
    DefaultConflict(ProviderId),
}

impl ProvidersConfig {
    /// Check the configuration is consistent.
    pub fn validate(&self) -> Result<(), ProvidersConfigError> {
        if self.provider.is_none() && self.providers.is_empty() {
            return Err(ProvidersConfigError::NoProviders);
        }
        let root = ProviderId::default();
        if self.provider.is_some() && self.providers.contains_key(&root) {
            return Err(ProvidersConfigError::ReservedId(root));
        }
        if let Some(default) = &self.default_provider {
            if self.provider.is_some() && *default != root {
                return Err(ProvidersConfigError::DefaultConflict(default.clone()));
            }
            if self.provider.is_none() && !self.providers.contains_key(default) {
                return Err(ProvidersConfigError::UnknownDefault(default.clone()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> OAuthProviderConfig {
        serde_json::from_value(serde_json::json!({
            "provider_name": "Test",
            "client_id": "client",
            "endpoints": { "issuer": "https://issuer.example.com" },
        }))
        .unwrap()
    }

    fn id(s: &str) -> ProviderId {
        ProviderId::new(s).unwrap()
    }

    #[test]
    fn validate() {
        let mut cfg = ProvidersConfig::default();
        assert_eq!(cfg.validate(), Err(ProvidersConfigError::NoProviders));

        cfg.provider = Some(provider());
        assert_eq!(cfg.validate(), Ok(()));

        cfg.providers.insert(id("google"), provider());
        assert_eq!(cfg.validate(), Ok(()));

        cfg.default_provider = Some(id("google"));
        assert_eq!(
            cfg.validate(),
            Err(ProvidersConfigError::DefaultConflict(id("google")))
        );

        cfg.default_provider = None;
        cfg.providers.insert(ProviderId::default(), provider());
        assert_eq!(
            cfg.validate(),
            Err(ProvidersConfigError::ReservedId(ProviderId::default()))
        );

        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(id("google"), provider());
        cfg.default_provider = Some(id("okta"));
        assert_eq!(
            cfg.validate(),
            Err(ProvidersConfigError::UnknownDefault(id("okta")))
        );
    }
}
