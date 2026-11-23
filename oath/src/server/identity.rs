//! Identity extraction from an issued [`crate::TokenSet`].
//!
//! `oath` v1 doesn't verify the `id_token` signature. The bundled
//! [`parse_id_token`] helper base64url-decodes the payload and parses
//! the claims as [`IdClaims`]. Consumers compose their own resolver
//! around it via [`IdentityResolver::new`].

use std::error::Error as StdError;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use thiserror::Error;

use crate::identity::IdClaims;
use crate::{AccessToken, RefreshToken, ScopeSet, TokenSet};

use super::registry::ProviderId;

/// A set of ID token claims and tokens extracted from an issued [`crate::TokenSet`].
#[derive(Debug, Clone)]
pub struct IdTokenSet {
    /// The access token to attach to outgoing requests.
    pub access_token: AccessToken,
    /// The refresh token, if the server returned one.
    pub refresh_token: Option<RefreshToken>,
    /// The granted scopes, if the server returned them.
    pub scope: Option<ScopeSet>,
    /// The OIDC claims, if they were validated.
    pub claims: Option<IdClaims>,
}

impl From<TokenSet> for IdTokenSet {
    fn from(tokens: TokenSet) -> Self {
        Self {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            scope: tokens.scope,
            claims: None,
        }
    }
}

/// Identity extracted from a [`TokenSet`] during the callback.
///
/// `username` is the stable per-provider identifier (typically the OIDC
/// `sub` claim); the [`crate::server::UserStore`] keys records by it
/// together with the provider. `data` is the app-defined payload to
/// persist.
#[derive(Debug, Clone)]
pub struct Identity<T> {
    /// Stable per-provider user identifier.
    pub username: String,
    /// App-defined payload, stored in the [`crate::server::UserStore`].
    pub data: T,
}

/// Reasons identity resolution can fail.
#[derive(Debug, Error)]
pub enum IdentityError {
    /// The [`TokenSet`] carried no `id_token` to parse.
    #[error("token set did not include an id_token")]
    MissingIdToken,

    /// Any other error raised by a custom resolver.
    #[error("{0}")]
    Other(#[from] Box<dyn StdError + Send + Sync + 'static>),
}

type BoxedFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
type ResolverFn<T> = dyn Fn(ProviderId, IdTokenSet) -> BoxedFuture<'static, Result<Identity<T>, IdentityError>>
    + Send
    + Sync
    + 'static;

/// Type-erased async closure that turns a [`TokenSet`] into an
/// [`Identity<T>`].
///
/// Construct via [`IdentityResolver::new`] with an async closure, or
/// [`IdentityResolver::with_provider`] when the resolver needs to know
/// which provider issued the tokens.
pub struct IdentityResolver<T> {
    inner: Arc<ResolverFn<T>>,
}

impl<T> Clone for IdentityResolver<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T> fmt::Debug for IdentityResolver<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityResolver").finish_non_exhaustive()
    }
}

impl<T> IdentityResolver<T>
where
    T: Send + 'static,
{
    /// Wrap an async closure that produces an [`Identity<T>`].
    ///
    /// ```
    /// # use oath::server::{IdTokenSet, Identity, IdentityResolver};
    /// # #[derive(Debug)]
    /// struct AppUser { email: String }
    /// let resolver = IdentityResolver::new(|tokens: IdTokenSet| async move {
    ///     let claims = tokens.claims.unwrap();
    ///     Ok(Identity {
    ///         username: claims.sub.clone(),
    ///         data: AppUser {
    ///             email: claims.email.unwrap_or_default(),
    ///         },
    ///     })
    /// });
    /// # let _ = resolver;
    /// ```
    pub fn new<F, Fut>(f: F) -> Self
    where
        F: Fn(IdTokenSet) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Identity<T>, IdentityError>> + Send + 'static,
    {
        Self {
            inner: Arc::new(move |_provider, tokens| Box::pin(f(tokens))),
        }
    }

    /// Wrap an async closure that also receives the [`ProviderId`] the
    /// tokens came from, e.g. to read provider-specific claims or record
    /// the provider in the user's data.
    ///
    /// There's no need to namespace `username` by provider: the
    /// [`crate::server::UserStore`] and the session both key users by
    /// `(provider, username)`.
    ///
    /// ```
    /// # use oath::server::{Identity, IdentityResolver, ProviderId, IdTokenSet};
    /// struct AppUser { provider: ProviderId, email: Option<String> }
    /// let resolver = IdentityResolver::with_provider(|provider: ProviderId, tokens: IdTokenSet| async move {
    ///     let claims = tokens.claims.unwrap();
    ///     Ok(Identity {
    ///         username: claims.sub,
    ///         data: AppUser { provider, email: claims.email },
    ///     })
    /// });
    /// # let _ = resolver;
    /// ```
    pub fn with_provider<F, Fut>(f: F) -> Self
    where
        F: Fn(ProviderId, IdTokenSet) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Identity<T>, IdentityError>> + Send + 'static,
    {
        Self {
            inner: Arc::new(move |provider, tokens| Box::pin(f(provider, tokens))),
        }
    }

    /// Invoke the resolver for tokens issued by `provider`.
    pub async fn resolve(
        &self,
        provider: &ProviderId,
        tokens: IdTokenSet,
    ) -> Result<Identity<T>, IdentityError> {
        (self.inner)(provider.clone(), tokens).await
    }
}
