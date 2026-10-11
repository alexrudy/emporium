//! Application state management, holding configuration and session state.

use axum::extract::FromRef;
use cookie::Key;
use oath::server::OAuth2RouterConfig;

use crate::config::{ProvidersConfig, SessionsConfig};
use crate::store::{Sessions, StoreError, Stores, Users};

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
    pub sessions_store: Sessions,

    /// Profiles (display names) of users who have signed in.
    pub users_store: Users,
}

impl AppState {
    /// Creates a new `AppState`, opening the stores configured in
    /// `sessions.store`. Sessions expire after `sessions.ttl`.
    pub async fn new(
        router: OAuth2RouterConfig,
        providers: ProvidersConfig,
        sessions: SessionsConfig,
    ) -> Result<Self, StoreError> {
        let ttl = sessions.ttl.to_std().map_err(|_| StoreError::NegativeTtl)?;
        let Stores {
            sessions: sessions_store,
            users: users_store,
        } = sessions.store.open(ttl).await?;
        Ok(Self {
            oauth_router: router,
            providers,
            sessions,
            sessions_store,
            users_store,
        })
    }
}

impl FromRef<AppState> for Key {
    fn from_ref(input: &AppState) -> Self {
        Key::from(input.sessions.key.revealed().as_bytes())
    }
}
