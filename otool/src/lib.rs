//! OTools provides the primitives to implement an OAuth Client via Axum with basic user and session management.
//!
//! It wraps [`oath::server`] with the configuration and glue shared by
//! the gateway-style apps in this workspace (`ogateway`, `otunnel`):
//!
//! - [`config::ProvidersConfig`]: `[provider]`, `[providers.<id>]`, and
//!   `default_provider`, meant to be `#[serde(flatten)]`ed into an app's
//!   config; [`config::SessionsConfig`] for the cookie key and TTL.
//! - [`state::AppState`]: router config, providers, and the in-memory
//!   session store.
//! - [`build_router`]: resolves every provider (running OIDC discovery)
//!   and registers it with an [`OAuth2Router`]; [`router_with_chooser`]
//!   turns that into an `axum::Router`, adding a "Sign in with …" page at
//!   `{prefix}/login` when there's no default provider.
//! - [`auth::CurrentUser`] / [`auth::OptionalCurrentUser`]: extractors
//!   that load the signed-in [`user::AppUser`] (provider + `sub`) from
//!   the session cookie.
//!
//! Users aren't persisted: [`user::NoOpUserStore`] only remembers who has
//! signed in since startup.

use std::time::Duration;

use cookie::Key;
use oath::server::{InMemorySessionStore, OAuth2Router, Provider, ProviderId};
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

/// How long [`build_router`] waits for each provider's endpoints (OIDC
/// discovery) before giving up on it.
pub const PROVIDER_SETUP_TIMEOUT: Duration = Duration::from_secs(10);

/// Building the OAuth2 router failed.
#[derive(Debug, Error)]
pub enum BuildError {
    /// The provider configuration is inconsistent.
    #[error(transparent)]
    Config(#[from] ProvidersConfigError),

    /// Every configured provider failed to set up.
    #[error(
        "no OAuth provider could be set up: {}",
        .0.iter().map(ToString::to_string).collect::<Vec<_>>().join("; ")
    )]
    NoProviders(Vec<ProviderFailure>),
}

/// A provider that couldn't be set up.
#[derive(Debug, Error)]
#[error("OAuth provider {id}: {source}")]
pub struct ProviderFailure {
    /// The provider's id.
    pub id: ProviderId,
    /// Why it failed.
    #[source]
    pub source: ProviderSetupError,
}

/// Why a provider couldn't be set up.
#[derive(Debug, Error)]
pub enum ProviderSetupError {
    /// Resolving its endpoints failed (e.g. OIDC discovery returned an
    /// error, or the issuer was unreachable).
    #[error(transparent)]
    Endpoint(#[from] oath::Error),
    /// Resolving its endpoints took too long.
    #[error("timed out after {0:?}")]
    Timeout(Duration),
}

/// Build an OAuth2 Router for every configured provider.
///
/// `[provider]` is mounted at `{prefix}/login` and `{prefix}/callback`;
/// each `[providers.<id>]` at `{prefix}/<id>/login` and
/// `{prefix}/<id>/callback`. Use [`router_with_chooser`] to turn the
/// result into an `axum::Router` with a provider chooser when there's no
/// default provider.
///
/// Providers are set up concurrently, each limited to
/// [`PROVIDER_SETUP_TIMEOUT`]. A provider that fails (say, its issuer is
/// down) is logged and left out, so the others keep working; restart to
/// pick it up again. If it was the `default_provider`, `{prefix}/login`
/// falls back to the usual default (the only remaining provider, or the
/// chooser). Only if *every* provider fails is this an error.
pub async fn build_router<C>(
    state: &AppState,
) -> Result<OAuth2Router<InMemorySessionStore, NoOpUserStore, C>, BuildError> {
    build_router_with_timeout(state, PROVIDER_SETUP_TIMEOUT).await
}

async fn build_router_with_timeout<C>(
    state: &AppState,
    timeout: Duration,
) -> Result<OAuth2Router<InMemorySessionStore, NoOpUserStore, C>, BuildError> {
    let providers = &state.providers;
    providers.validate()?;
    let router_config = &state.oauth_router;

    struct Planned<'a> {
        is_root: bool,
        id: ProviderId,
        config: &'a OAuthProviderConfig,
        callback_path: String,
    }

    let root = providers.provider.as_ref().map(|config| Planned {
        is_root: true,
        id: ProviderId::default(),
        config,
        callback_path: router_config.callback_path(),
    });
    let planned: Vec<Planned<'_>> = root
        .into_iter()
        .chain(providers.providers.iter().map(|(id, config)| Planned {
            is_root: false,
            id: id.clone(),
            config,
            callback_path: router_config.provider_callback_path(id),
        }))
        .collect();

    let results = futures::future::join_all(
        planned
            .iter()
            .map(|p| resolve(p.config, &p.callback_path, timeout)),
    )
    .await;

    let mut oauth = OAuth2Router::multi_provider(
        state.sessions_store.clone(),
        NoOpUserStore::new(),
        user::identity_resolver(),
        Key::from(state.sessions.key.revealed().as_bytes()),
    )
    .config(router_config.clone());

    let mut failures = Vec::new();
    for (planned, result) in planned.into_iter().zip(results) {
        match result {
            Ok(endpoint) => {
                let provider = if planned.is_root {
                    Provider::root(endpoint)
                } else {
                    Provider::new(planned.id, endpoint)
                };
                oauth = oauth.provider(customize(provider, planned.config));
            }
            Err(source) => {
                let failure = ProviderFailure {
                    id: planned.id,
                    source,
                };
                tracing::error!(error = %failure, "skipping OAuth provider");
                failures.push(failure);
            }
        }
    }

    if oauth.providers().next().is_none() {
        return Err(BuildError::NoProviders(failures));
    }

    if let Some(default) = &providers.default_provider {
        if failures.iter().any(|failure| failure.id == *default) {
            tracing::warn!(
                provider = %default,
                "default provider is unavailable; /auth/login falls back"
            );
        } else {
            oauth = oauth.default_provider(default.clone());
        }
    }

    Ok(oauth)
}

async fn resolve(
    config: &OAuthProviderConfig,
    callback_path: &str,
    timeout: Duration,
) -> Result<oath::TokenEndpoint, ProviderSetupError> {
    match tokio::time::timeout(timeout, config.provider(callback_path)).await {
        Ok(result) => Ok(result?),
        Err(_) => Err(ProviderSetupError::Timeout(timeout)),
    }
}

fn customize(provider: Provider, config: &OAuthProviderConfig) -> Provider {
    let mut provider = provider
        .with_display_name(config.provider_name.clone())
        .with_iss_parameter(config.iss_parameter);
    if let Some(scopes) = &config.scopes {
        provider = provider.with_scopes(scopes.clone());
    }
    if config.skip_issuer_validation {
        provider = provider.skip_issuer_validation();
    }
    provider
}

#[cfg(test)]
mod tests {
    use super::*;

    fn discover(issuer: &str) -> OAuthProviderConfig {
        serde_json::from_value(serde_json::json!({
            "provider_name": "Test",
            "client_id": "c",
            "endpoints": { "issuer": issuer },
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn slow_discovery_times_out() {
        // Accepts connections (via the backlog) but never answers.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());

        let result = resolve(
            &discover(&issuer),
            "/auth/callback",
            Duration::from_millis(200),
        )
        .await;
        assert!(
            matches!(result, Err(ProviderSetupError::Timeout(_))),
            "{result:?}"
        );
        drop(listener);
    }

    #[tokio::test]
    async fn slow_provider_is_skipped() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut providers = config::ProvidersConfig::default();
        providers.providers.insert(
            "slow".parse().unwrap(),
            discover(&format!("http://{}", listener.local_addr().unwrap())),
        );
        providers.providers.insert(
            "fast".parse().unwrap(),
            serde_json::from_value(serde_json::json!({
                "provider_name": "Fast",
                "client_id": "c",
                "endpoints": {
                    "auth_uri": "https://fast.example.com/authorize",
                    "token_uri": "https://fast.example.com/token",
                },
            }))
            .unwrap(),
        );
        let state = AppState::new(
            Default::default(),
            providers,
            config::SessionsConfig::default(),
        );

        let oauth = build_router_with_timeout::<http::Uri>(&state, Duration::from_millis(200))
            .await
            .unwrap();
        let ids: Vec<_> = oauth.providers().map(|p| p.id().to_string()).collect();
        assert_eq!(ids, ["fast"]);
        drop(listener);
    }
}
