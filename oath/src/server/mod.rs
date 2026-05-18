//! Optional axum router for hosting an OAuth2 login flow.
//!
//! This module is gated behind the `server` cargo feature. It bundles
//! together the protocol primitives from the rest of the crate with
//! pluggable session and user stores, signed cookies, and three
//! routes:
//!
//! - `GET  {prefix}/login` — generates state + PKCE verifier, sets the
//!   pre-auth cookie, redirects the user to the provider.
//! - `GET  {prefix}/callback` — verifies state, exchanges the code,
//!   extracts identity, persists the user, sets the session cookie,
//!   redirects.
//! - `POST {prefix}/logout` — deletes the session row, clears the
//!   session cookie.
//!
//! Build via [`OAuth2Router::new`] + chainable config methods, then
//! call [`OAuth2Router::into_router`] to get an `axum::Router` you can
//! merge into your own app.

mod config;
mod error;
mod handlers;
mod identity;
mod session;
mod storage;
mod users;

use std::sync::Arc;

use axum::Router;
use axum::extract::Extension;
use axum::routing::{get, post};
use cookie::Key;

use crate::{ScopeSet, TokenEndpoint};

pub use self::config::{CookieNames, OAuth2RouterConfig};
pub use self::error::{BoxError, ServerError};
pub use self::handlers::is_user_denied;
pub use self::identity::{IdClaims, Identity, IdentityError, IdentityResolver, parse_id_token};
pub use self::session::{InMemorySessionStore, SessionData, SessionId, SessionStore};
pub use self::storage::{JsonFileUserStore, sanitize_username};
pub use self::users::UserStore;

use self::handlers::RouterState;

/// Builder for an `axum::Router` serving the OAuth2 login flow.
///
/// Use [`OAuth2Router::new`] to provide the required pieces — a
/// [`TokenEndpoint`], a [`SessionStore`], a [`UserStore`], an
/// [`IdentityResolver`], and a cookie signing [`Key`] — then chain
/// optional methods to tweak the routes, cookies, and scopes.
///
/// Calling [`OAuth2Router::into_router`] produces a stateless
/// `axum::Router<()>` that you can merge into your application's main
/// router.
pub struct OAuth2Router<S, U>
where
    U: UserStore,
{
    endpoint: TokenEndpoint,
    sessions: Arc<S>,
    users: Arc<U>,
    identity: IdentityResolver<U::Data>,
    cookie_key: Key,
    config: OAuth2RouterConfig,
}

impl<S, U> std::fmt::Debug for OAuth2Router<S, U>
where
    U: UserStore,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuth2Router")
            .field("endpoint", &self.endpoint)
            .field("config", &self.config)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl<S, U> OAuth2Router<S, U>
where
    S: SessionStore,
    U: UserStore,
{
    /// Construct a router builder with the required pieces.
    pub fn new(
        endpoint: TokenEndpoint,
        sessions: S,
        users: U,
        identity: IdentityResolver<U::Data>,
        cookie_key: Key,
    ) -> Self {
        Self {
            endpoint,
            sessions: Arc::new(sessions),
            users: Arc::new(users),
            identity,
            cookie_key,
            config: OAuth2RouterConfig::default(),
        }
    }

    /// Set the scopes requested in the authorization URL.
    pub fn scopes(mut self, scopes: ScopeSet) -> Self {
        self.config.scopes = scopes;
        self
    }

    /// Set the route prefix (default `/auth`). The router will expose
    /// `{prefix}/login`, `{prefix}/callback`, and `{prefix}/logout`.
    pub fn route_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.config.route_prefix = prefix.into();
        self
    }

    /// Override cookie names.
    pub fn cookies(mut self, names: CookieNames) -> Self {
        self.config.cookies = names;
        self
    }

    /// Override the post-login redirect target. Default `/`.
    pub fn login_landing(mut self, target: impl Into<String>) -> Self {
        self.config.login_landing = target.into();
        self
    }

    /// Override the post-logout redirect target. Default `/`.
    pub fn logout_landing(mut self, target: impl Into<String>) -> Self {
        self.config.logout_landing = target.into();
        self
    }

    /// Set the `Secure` attribute on cookies (default `true`). Turn
    /// off only for HTTP-bound dev environments — never in production.
    pub fn secure_cookies(mut self, secure: bool) -> Self {
        self.config.secure_cookies = secure;
        self
    }

    /// Replace the whole configuration in one shot.
    pub fn config(mut self, config: OAuth2RouterConfig) -> Self {
        self.config = config;
        self
    }

    /// Produce the `axum::Router`.
    ///
    /// Generic over the consumer's axum state type `AxS` so the router
    /// can be merged into an `axum::Router<AxS>` of any shape; OAuth2
    /// state is threaded via `Extension` internally, not axum state.
    pub fn into_router<AxS>(self) -> Router<AxS>
    where
        AxS: Clone + Send + Sync + 'static,
    {
        let state = Arc::new(RouterState {
            endpoint: self.endpoint,
            config: self.config.clone(),
            sessions: self.sessions,
            users: self.users,
            identity: self.identity,
            cookie_key: self.cookie_key,
        });

        Router::<AxS>::new()
            .route(&self.config.login_path(), get(handlers::login::<S, U>))
            .route(
                &self.config.callback_path(),
                get(handlers::callback::<S, U>),
            )
            .route(&self.config.logout_path(), post(handlers::logout::<S, U>))
            .layer(Extension(state))
    }
}
