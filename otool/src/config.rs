//! Configuration for otool-based applications.

use cookie::Key;
pub use oath::{provider::OAuthProviderConfig, server::OAuth2RouterConfig};
use secret::Secret;
use serde::{Deserialize, Serialize};

/// Configuration for the session management system.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionsConfig {
    /// The time-to-live for session cookies.
    pub ttl: chrono::Duration,

    /// The secret key used for signing session cookies.
    pub key: Secret,
}

impl Default for SessionsConfig {
    fn default() -> Self {
        Self {
            ttl: chrono::Duration::hours(48),
            key: data_encoding::BASE64
                .encode(Key::generate().master())
                .into(),
        }
    }
}
