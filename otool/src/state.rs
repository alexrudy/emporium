//! Application state management, holding configuration and session state.

use std::time::Duration;

use axum::extract::FromRef;
use cookie::Key;
use oath::{
    provider::OAuthProviderConfig,
    server::{InMemorySessionStore, OAuth2RouterConfig},
};

use crate::config::SessionsConfig;

/// The application state, holding configuration and session state.
#[derive(Debug, Clone)]
pub struct AppState {
    /// The OAuth2 router configuration.
    pub oauth_router: OAuth2RouterConfig,

    /// The OAuth provider configuration.
    pub oauth_provider: OAuthProviderConfig,

    /// The application configuration.
    pub sessions: SessionsConfig,

    /// The session store for managing user sessions.
    pub sessions_store: InMemorySessionStore,
}

impl AppState {
    /// Creates a new `AppState` with the given configuration.
    pub fn new(
        router: OAuth2RouterConfig,
        provider: OAuthProviderConfig,
        sessions: SessionsConfig,
    ) -> Self {
        Self {
            oauth_router: router,
            oauth_provider: provider,
            sessions,
            sessions_store: InMemorySessionStore::new(Duration::from_hours(48)),
        }
    }
}

impl FromRef<AppState> for Key {
    fn from_ref(input: &AppState) -> Self {
        Key::from(input.sessions.key.revealed().as_bytes())
    }
}
