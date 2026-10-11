//! Application state management, holding configuration and session state.

use std::time::Duration;

use axum::extract::FromRef;
use cookie::Key;
use oath::server::{InMemorySessionStore, OAuth2RouterConfig};

use crate::config::{ProvidersConfig, SessionsConfig};
use crate::user::InMemoryUserStore;

/// The application state, holding configuration and session state.
#[derive(Debug, Clone)]
pub struct AppState {
    /// The OAuth2 router configuration.
    pub oauth_router: OAuth2RouterConfig,

    /// The OAuth providers to sign in with.
    pub providers: ProvidersConfig,

    /// The application configuration.
    pub sessions: SessionsConfig,

    /// The session store for managing user sessions.
    pub sessions_store: InMemorySessionStore,

    /// Profiles (display names) of users who have signed in.
    pub users_store: InMemoryUserStore,
}

impl AppState {
    /// Creates a new `AppState` with the given configuration.
    pub fn new(
        router: OAuth2RouterConfig,
        providers: ProvidersConfig,
        sessions: SessionsConfig,
    ) -> Self {
        Self {
            oauth_router: router,
            providers,
            sessions,
            sessions_store: InMemorySessionStore::new(Duration::from_hours(48)),
            users_store: InMemoryUserStore::new(),
        }
    }
}

impl FromRef<AppState> for Key {
    fn from_ref(input: &AppState) -> Self {
        Key::from(input.sessions.key.revealed().as_bytes())
    }
}
