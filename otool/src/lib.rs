//! OTools provides the primitives to implement an OAuth Client via Axum with basic user and session management.

use cookie::Key;
use oath::server::{InMemorySessionStore, OAuth2Router, Provider};
use thiserror::Error;

use self::config::{OAuthProviderConfig, ProvidersConfigError};
use self::{state::AppState, user::NoOpUserStore};

pub mod auth;
pub mod chooser;
pub mod config;
pub mod cookies;
pub mod state;
pub mod user;

pub use self::chooser::{login_chooser, router_with_chooser};

/// Building the OAuth2 router failed.
#[derive(Debug, Error)]
pub enum BuildError {
    /// The provider configuration is inconsistent.
    #[error(transparent)]
    Config(#[from] ProvidersConfigError),

    /// A provider's endpoints could not be resolved (e.g. OIDC discovery
    /// failed).
    #[error("OAuth provider {id}: {source}")]
    Provider {
        /// The provider's id.
        id: oath::server::ProviderId,
        /// The underlying error.
        #[source]
        source: oath::Error,
    },
}

/// Build an OAuth2 Router for every configured provider.
///
/// `[provider]` is mounted at `{prefix}/login` and `{prefix}/callback`;
/// each `[providers.<id>]` at `{prefix}/<id>/login` and
/// `{prefix}/<id>/callback`. Use [`router_with_chooser`] to turn the
/// result into an `axum::Router` with a provider chooser when there's no
/// default provider.
pub async fn build_router<C>(
    state: &AppState,
) -> Result<OAuth2Router<InMemorySessionStore, NoOpUserStore, C>, BuildError> {
    let providers = &state.providers;
    providers.validate()?;
    let router_config = &state.oauth_router;

    let mut oauth = OAuth2Router::multi_provider(
        state.sessions_store.clone(),
        NoOpUserStore::new(),
        user::identity_resolver(),
        Key::from(state.sessions.key.revealed().as_bytes()),
    )
    .config(router_config.clone());

    if let Some(config) = &providers.provider {
        let endpoint = resolve(config, &router_config.callback_path(), &Default::default()).await?;
        oauth = oauth.provider(customize(Provider::root(endpoint), config));
    }

    for (id, config) in &providers.providers {
        let endpoint = resolve(config, &router_config.provider_callback_path(id), id).await?;
        oauth = oauth.provider(customize(Provider::new(id.clone(), endpoint), config));
    }

    if let Some(default) = &providers.default_provider {
        oauth = oauth.default_provider(default.clone());
    }

    Ok(oauth)
}

async fn resolve(
    config: &OAuthProviderConfig,
    callback_path: &str,
    id: &oath::server::ProviderId,
) -> Result<oath::TokenEndpoint, BuildError> {
    config
        .provider(callback_path)
        .await
        .map_err(|source| BuildError::Provider {
            id: id.clone(),
            source,
        })
}

fn customize(provider: Provider, config: &OAuthProviderConfig) -> Provider {
    let provider = provider.with_display_name(config.provider_name.clone());
    match &config.scopes {
        Some(scopes) => provider.with_scopes(scopes.clone()),
        None => provider,
    }
}
