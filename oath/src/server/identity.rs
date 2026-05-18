//! Identity extraction from an issued [`crate::TokenSet`].
//!
//! `oath` v1 doesn't verify the `id_token` signature. The bundled
//! [`parse_id_token`] helper base64url-decodes the payload and parses
//! the claims as [`IdClaims`]. Consumers compose their own resolver
//! around it via [`IdentityResolver::new`].

use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::TokenSet;

/// Identity extracted from a [`TokenSet`] during the callback.
///
/// `username` is the stable per-provider identifier the
/// [`crate::server::UserStore`] keys by (typically the OIDC `sub`
/// claim). `data` is the app-defined payload to persist.
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
    /// The `id_token` was not three dot-separated segments.
    #[error("id_token did not have three base64url-encoded segments")]
    MalformedIdToken,
    /// The payload segment did not base64url-decode.
    #[error("id_token payload base64 decode failed: {0}")]
    DecodeFailed(#[source] base64::DecodeError),
    /// The decoded payload was not valid JSON for [`IdClaims`].
    #[error("id_token claims JSON parse failed: {0}")]
    InvalidJson(#[source] serde_json::Error),
    /// The `sub` claim was missing or empty.
    #[error("id_token had no `sub` claim")]
    MissingSubject,
    /// Any other error raised by a custom resolver.
    #[error("{0}")]
    Other(#[from] Box<dyn StdError + Send + Sync + 'static>),
}

/// A minimal subset of OIDC ID Token claims.
///
/// Unknown claims are captured in [`IdClaims::extra`] so
/// provider-specific fields remain inspectable.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IdClaims {
    /// Subject — the stable per-provider user identifier.
    pub sub: String,
    /// User's email address, if disclosed.
    #[serde(default)]
    pub email: Option<String>,
    /// Whether the email has been verified by the provider.
    #[serde(default)]
    pub email_verified: Option<bool>,
    /// User's display name.
    #[serde(default)]
    pub name: Option<String>,
    /// Provider's notion of a shorter username (e.g., GitHub login).
    #[serde(default)]
    pub preferred_username: Option<String>,
    /// URL to a profile picture.
    #[serde(default)]
    pub picture: Option<String>,
    /// Any additional claims the provider returned.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// Base64url-decode the middle segment of `id_token` and parse it as
/// [`IdClaims`].
///
/// **Signature is not verified.** This is acceptable when:
/// 1. TLS to the token endpoint is intact, *and*
/// 2. The token came from a `TokenEndpoint::exchange` call (so the
///    provider issued it directly to us).
///
/// Verifying the signature requires fetching the provider's JWKS and
/// checking issuer + audience claims; that lands as part of OIDC
/// discovery support (deferred to v1.1).
pub fn parse_id_token(tokens: &TokenSet) -> Result<IdClaims, IdentityError> {
    let id_token = tokens
        .id_token
        .as_deref()
        .ok_or(IdentityError::MissingIdToken)?;

    let mut parts = id_token.split('.');
    let _header = parts.next().ok_or(IdentityError::MalformedIdToken)?;
    let payload = parts.next().ok_or(IdentityError::MalformedIdToken)?;
    let _signature = parts.next().ok_or(IdentityError::MalformedIdToken)?;
    if parts.next().is_some() {
        return Err(IdentityError::MalformedIdToken);
    }

    let decoded = URL_SAFE_NO_PAD
        .decode(payload.as_bytes())
        .map_err(IdentityError::DecodeFailed)?;
    let claims: IdClaims = serde_json::from_slice(&decoded).map_err(IdentityError::InvalidJson)?;
    if claims.sub.is_empty() {
        return Err(IdentityError::MissingSubject);
    }
    Ok(claims)
}

type BoxedFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
type ResolverFn<T> = dyn Fn(TokenSet) -> BoxedFuture<'static, Result<Identity<T>, IdentityError>>
    + Send
    + Sync
    + 'static;

/// Type-erased async closure that turns a [`TokenSet`] into an
/// [`Identity<T>`].
///
/// Construct via [`IdentityResolver::new`] with an async closure.
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
    /// # use oath::server::{parse_id_token, Identity, IdentityResolver};
    /// # use oath::TokenSet;
    /// # #[derive(Debug)]
    /// struct AppUser { email: String }
    /// let resolver = IdentityResolver::new(|tokens: TokenSet| async move {
    ///     let claims = parse_id_token(&tokens)?;
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
        F: Fn(TokenSet) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Identity<T>, IdentityError>> + Send + 'static,
    {
        Self {
            inner: Arc::new(move |tokens| Box::pin(f(tokens))),
        }
    }

    /// Invoke the resolver.
    pub async fn resolve(&self, tokens: TokenSet) -> Result<Identity<T>, IdentityError> {
        (self.inner)(tokens).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccessToken, RefreshToken, TokenSet};
    use secret::Secret;

    fn make_tokens(id_token: Option<&str>) -> TokenSet {
        TokenSet {
            access_token: AccessToken::new(Secret::from("a"), None),
            refresh_token: Some(RefreshToken::new(Secret::from("r"))),
            scope: None,
            id_token: id_token.map(|s| s.to_owned()),
        }
    }

    fn jwt(payload_json: &str) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(b"signature-bytes-go-here");
        format!("{header}.{payload}.{signature}")
    }

    #[test]
    fn parse_typical_oidc_claims() {
        let token = jwt(r#"{"sub":"abc123","email":"alice@example.com","name":"Alice"}"#);
        let tokens = make_tokens(Some(&token));
        let claims = parse_id_token(&tokens).unwrap();
        assert_eq!(claims.sub, "abc123");
        assert_eq!(claims.email.as_deref(), Some("alice@example.com"));
        assert_eq!(claims.name.as_deref(), Some("Alice"));
    }

    #[test]
    fn missing_id_token() {
        let tokens = make_tokens(None);
        assert!(matches!(
            parse_id_token(&tokens),
            Err(IdentityError::MissingIdToken)
        ));
    }

    #[test]
    fn malformed_id_token() {
        let tokens = make_tokens(Some("only.two"));
        assert!(matches!(
            parse_id_token(&tokens),
            Err(IdentityError::MalformedIdToken)
        ));
    }

    #[test]
    fn missing_sub_claim() {
        let token = jwt(r#"{"email":"alice@example.com"}"#);
        let tokens = make_tokens(Some(&token));
        assert!(matches!(
            parse_id_token(&tokens),
            Err(IdentityError::InvalidJson(_))
        ));
    }

    #[test]
    fn extra_claims_captured() {
        let token = jwt(r#"{"sub":"x","provider_specific":"value"}"#);
        let tokens = make_tokens(Some(&token));
        let claims = parse_id_token(&tokens).unwrap();
        assert_eq!(
            claims.extra.get("provider_specific"),
            Some(&serde_json::Value::String("value".into())),
        );
    }
}
