//! Optional axum router for hosting an OAuth2 login flow.
//!
//! This module is gated behind the `server` cargo feature. It bundles
//! together the protocol primitives from the rest of the crate with
//! pluggable session and user stores, signed cookies, and these
//! routes:
//!
//! - `GET  {prefix}/{provider}/login` — generates state + PKCE
//!   verifier, sets the pre-auth cookie, redirects the user to the
//!   provider.
//! - `GET  {prefix}/{provider}/callback` — verifies the provider and
//!   state, exchanges the code, extracts identity, persists the user,
//!   sets the session cookie, redirects.
//! - `GET  {prefix}/login` — login with the default provider, if there
//!   is one.
//! - `POST {prefix}/logout` — deletes the session row, clears the
//!   session cookie.
//!
//! A provider registered via [`OAuth2Router::new`] is instead mounted
//! at `{prefix}/login` and `{prefix}/callback`, so single-provider
//! deployments keep their registered redirect URI.
//!
//! Build via [`OAuth2Router::new`] (one provider) or
//! [`OAuth2Router::multi_provider`] + [`OAuth2Router::provider`], chain
//! config methods, then call [`OAuth2Router::into_router`] to get an
//! `axum::Router` you can merge into your own app.

mod config;
mod error;
mod handlers;
mod identity;
mod redirect;
mod registry;
mod session;

#[cfg(feature = "json-file-user-store")]
mod storage;
mod users;

use std::sync::Arc;

use axum::Router;
use axum::extract::Extension;
use axum::routing::{get, post};
use cookie::Key;
use http::Uri;

use crate::{ScopeSet, TokenEndpoint};

use self::registry::Mount;

pub use self::config::{CookieNames, OAuth2RouterConfig};
pub use self::error::{BoxError, ServerError};
pub use self::handlers::is_user_denied;
pub use self::identity::{
    IdClaims, Identity, IdentityError, IdentityResolver, parse_id_token, validate_id_token,
};
pub use self::redirect::{
    ExtractRedirect, ForwardedError, ForwardedHeader, TrustedHeader, XForwardedHeaders,
};
pub use self::registry::{InvalidProviderId, IssParameterError, Provider, ProviderId};
pub use self::session::{InMemorySessionStore, SessionData, SessionId, SessionStore};
pub use crate::provider::IssParameter;

#[cfg(feature = "json-file-user-store")]
pub use self::storage::JsonFileUserStore;

pub use self::users::UserStore;

use self::handlers::RouterState;

/// Builder for an `axum::Router` serving the OAuth2 login flow.
///
/// Use [`OAuth2Router::new`] to provide the required pieces — a
/// [`TokenEndpoint`], a [`SessionStore`], a [`UserStore`], an
/// [`IdentityResolver`], and a cookie signing [`Key`] — then chain
/// optional methods to tweak the routes, cookies, and scopes.
///
/// For multiple providers, start from [`OAuth2Router::multi_provider`]
/// (or [`OAuth2Router::new`], to keep an existing provider at its
/// current paths) and register each with [`OAuth2Router::provider`].
///
/// Calling [`OAuth2Router::into_router`] produces a stateless
/// `axum::Router<()>` that you can merge into your application's main
/// router.
pub struct OAuth2Router<S, U, C = Uri>
where
    U: UserStore,
{
    providers: Vec<Provider>,
    default_provider: Option<ProviderId>,
    sessions: Arc<S>,
    users: Arc<U>,
    identity: IdentityResolver<U::Data>,
    cookie_key: Key,
    config: OAuth2RouterConfig,
    redirect: Option<Arc<C>>,
}

impl<S, U, C> std::fmt::Debug for OAuth2Router<S, U, C>
where
    U: UserStore,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuth2Router")
            .field("providers", &self.providers)
            .field("default_provider", &self.default_provider)
            .field("config", &self.config)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl<S, U, C> OAuth2Router<S, U, C>
where
    S: SessionStore,
    U: UserStore,
{
    /// Construct a router builder for a single provider.
    ///
    /// The provider is registered as [`ProviderId::default`] and mounted
    /// at `{prefix}/login` and `{prefix}/callback`; its endpoint's
    /// redirect URI should point at [`OAuth2RouterConfig::callback_path`].
    /// It is the default provider, and more providers can be added with
    /// [`OAuth2Router::provider`].
    pub fn new(
        endpoint: TokenEndpoint,
        sessions: S,
        users: U,
        identity: IdentityResolver<U::Data>,
        cookie_key: Key,
    ) -> Self {
        let mut router = Self::multi_provider(sessions, users, identity, cookie_key);
        router.providers.push(Provider::root(endpoint));
        router
    }

    /// Construct a router builder with no providers registered yet.
    ///
    /// Register providers with [`OAuth2Router::provider`]; each is
    /// mounted at `{prefix}/{id}/login` and `{prefix}/{id}/callback`.
    pub fn multi_provider(
        sessions: S,
        users: U,
        identity: IdentityResolver<U::Data>,
        cookie_key: Key,
    ) -> Self {
        Self {
            providers: Vec::new(),
            default_provider: None,
            sessions: Arc::new(sessions),
            users: Arc::new(users),
            identity,
            cookie_key,
            config: OAuth2RouterConfig::default(),
            redirect: None,
        }
    }

    /// Register a provider.
    ///
    /// # Panics
    ///
    /// If a provider with the same id is already registered.
    pub fn provider(mut self, provider: Provider) -> Self {
        assert!(
            self.get_provider(provider.id()).is_none(),
            "OAuth2 provider {} registered twice",
            provider.id()
        );
        self.providers.push(provider);
        self
    }

    /// Serve `id` at `{prefix}/login`, in addition to its own login
    /// route.
    ///
    /// Without this, the default provider is the one registered via
    /// [`OAuth2Router::new`], or the only registered provider. If there
    /// is no default, `{prefix}/login` is left unrouted so the app can
    /// mount its own provider chooser there.
    pub fn default_provider(mut self, id: ProviderId) -> Self {
        self.default_provider = Some(id);
        self
    }

    /// Registered providers, in registration order.
    pub fn providers(&self) -> impl Iterator<Item = &Provider> {
        self.providers.iter()
    }

    /// Look up a registered provider by id.
    pub fn get_provider(&self, id: &ProviderId) -> Option<&Provider> {
        self.providers.iter().find(|p| p.id() == id)
    }

    /// Path of the login route for provider `id`, if registered.
    pub fn login_path(&self, id: &ProviderId) -> Option<String> {
        self.get_provider(id).map(|p| p.login_path(&self.config))
    }

    /// Set the default scopes requested in the authorization URL.
    /// Providers can override this with [`Provider::with_scopes`].
    pub fn scopes(mut self, scopes: ScopeSet) -> Self {
        self.config.scopes = scopes;
        self
    }

    /// Set the route prefix (default `/auth`). All routes are mounted
    /// under it.
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

    /// Derive each provider's redirect URI from the request's public
    /// origin: the extracted scheme + host joined to the provider's
    /// callback path (e.g. `https://app1.example.com/auth/google/callback`).
    ///
    /// This overrides the `redirect_uri` configured on each provider's
    /// [`TokenEndpoint`], for both the authorization request and the
    /// code exchange. Use [`TrustedHeader`] when serving several hosts
    /// behind a proxy, or a fixed [`Uri`] origin for a single host.
    pub fn redirect(mut self, redirect: Arc<C>) -> Self {
        self.redirect = Some(redirect);
        self
    }

    /// The router configuration.
    pub fn router_config(&self) -> &OAuth2RouterConfig {
        &self.config
    }

    /// The provider that will serve `{prefix}/login`, if any.
    ///
    /// When this is `None`, `{prefix}/login` is left unrouted so the app
    /// can mount its own provider chooser there. Also `None` if the
    /// default-provider configuration is invalid (which makes
    /// [`OAuth2Router::into_router`] panic).
    pub fn default_login_provider(&self) -> Option<ProviderId> {
        self.resolve_default_provider().ok().flatten()
    }

    /// Resolve which provider, if any, serves `{prefix}/login`.
    fn resolve_default_provider(&self) -> Result<Option<ProviderId>, String> {
        let root = self
            .providers
            .iter()
            .find(|p| p.mount == Mount::Root)
            .map(|p| p.id().clone());

        match (&self.default_provider, root) {
            (Some(explicit), Some(root)) if *explicit != root => Err(format!(
                "default_provider({explicit}) conflicts with the provider registered via \
                 OAuth2Router::new, which always serves the default login route"
            )),
            (Some(explicit), None) if self.get_provider(explicit).is_none() => Err(format!(
                "default_provider({explicit}) is not a registered provider"
            )),
            (Some(explicit), _) => Ok(Some(explicit.clone())),
            (None, Some(root)) => Ok(Some(root)),
            (None, None) => Ok(match self.providers.as_slice() {
                [only] => Some(only.id().clone()),
                _ => None,
            }),
        }
    }

    /// Produce the `axum::Router`.
    ///
    /// Generic over the consumer's axum state type `AxS` so the router
    /// can be merged into an `axum::Router<AxS>` of any shape; OAuth2
    /// state is threaded via `Extension` internally, not axum state.
    ///
    /// # Panics
    ///
    /// If no providers are registered, or if [`OAuth2Router::default_provider`]
    /// names an unregistered provider or conflicts with a provider
    /// registered via [`OAuth2Router::new`].
    pub fn into_router<AxS>(self) -> Router<AxS>
    where
        AxS: Clone + Send + Sync + 'static,
        C: ExtractRedirect + Send + Sync + 'static,
    {
        assert!(
            !self.providers.is_empty(),
            "OAuth2Router has no providers registered"
        );
        let default_provider = self
            .resolve_default_provider()
            .unwrap_or_else(|message| panic!("{message}"));

        let mut router = Router::<AxS>::new();
        for provider in self.providers {
            let login_path = provider.login_path(&self.config);
            let callback_path = provider.callback_path(&self.config);
            let is_default = default_provider.as_ref() == Some(provider.id());
            let provider = Arc::new(provider);

            router = router.route(
                &callback_path,
                get(handlers::callback::<S, U>).layer(Extension(provider.clone())),
            );
            router = router.route(
                &login_path,
                get(handlers::login::<S, U, C>).layer(Extension(provider.clone())),
            );
            if is_default && login_path != self.config.login_path() {
                router = router.route(
                    &self.config.login_path(),
                    get(handlers::login::<S, U, C>).layer(Extension(provider)),
                );
            }
        }

        let state = Arc::new(RouterState {
            config: self.config.clone(),
            sessions: self.sessions,
            users: self.users,
            identity: self.identity,
            cookie_key: self.cookie_key,
        });

        router
            .route(&self.config.logout_path(), post(handlers::logout::<S, U>))
            .layer(Extension(state))
            .layer(Extension(self.redirect))
    }
}

/// Reject usernames that could escape the configured path prefix.
///
/// Rejects: empty strings, strings longer than 255 bytes, any character
/// that is `is_control()` or one of `/`, `\\`, `\0`, and the literal
/// path-traversal tokens `.`, `..`. A literal `..` substring anywhere
/// in the name is also rejected.
pub fn sanitize_username(username: &str) -> Result<(), ServerError> {
    if username.is_empty() {
        return Err(ServerError::InvalidUsername("empty"));
    }
    if username.len() > 255 {
        return Err(ServerError::InvalidUsername("too long"));
    }
    if username == "." || username == ".." {
        return Err(ServerError::InvalidUsername("path traversal"));
    }
    if username.contains("..") {
        return Err(ServerError::InvalidUsername("embedded `..`"));
    }
    for c in username.chars() {
        // Check the specific path-separator set first so a `\0` is
        // reported as "path separator" rather than the less-specific
        // "control character".
        if matches!(c, '/' | '\\' | '\0') {
            return Err(ServerError::InvalidUsername("path separator"));
        }
        if c.is_control() {
            return Err(ServerError::InvalidUsername("control character"));
        }
    }
    Ok(())
}
