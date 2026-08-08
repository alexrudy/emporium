//! OTools provides the primitives to implement an OAuth Client via Axum with basic user and session management.

use cookie::Key;
use oath::{
    Error,
    server::{InMemorySessionStore, OAuth2Router},
};

use self::{state::AppState, user::NoOpUserStore};

pub mod auth;
pub mod config;
pub mod cookies;
pub mod state;
pub mod user;

/// Build an OAuth2 Router
pub async fn build_router<C>(
    state: &AppState,
) -> Result<OAuth2Router<InMemorySessionStore, NoOpUserStore, C>, Error> {
    let endpoint = state.oauth_provider.provider().await?;

    let oauth = OAuth2Router::new(
        endpoint,
        state.sessions_store.clone(),
        NoOpUserStore::new(),
        user::identity_resolver(),
        Key::from(state.sessions.key.revealed().as_bytes()),
    );

    Ok(oauth.config(state.oauth_router.clone()))
}
