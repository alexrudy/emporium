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

use super::registry::ProviderId;

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
    /// The `iss` claim doesn't match the provider's issuer.
    #[error("id_token issuer {actual:?} does not match the provider's issuer {expected:?}")]
    IssuerMismatch {
        /// The provider's issuer identifier.
        expected: String,
        /// The token's `iss` claim, if any.
        actual: Option<String>,
    },
    /// The `aud` claim doesn't include this client.
    #[error("id_token audience {actual:?} does not include client {expected:?}")]
    AudienceMismatch {
        /// This client's `client_id`.
        expected: String,
        /// The token's `aud` claim values.
        actual: Vec<String>,
    },
    /// The `azp` claim names a different client.
    #[error("id_token authorized party {actual:?} is not client {expected:?}")]
    AuthorizedPartyMismatch {
        /// This client's `client_id`.
        expected: String,
        /// The token's `azp` claim.
        actual: String,
    },
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
/// checking issuer + audience claims.
pub fn parse_id_token(tokens: &TokenSet) -> Result<IdClaims, IdentityError> {
    let claims: IdClaims = decode_id_token(tokens)?;
    if claims.sub.is_empty() {
        return Err(IdentityError::MissingSubject);
    }
    Ok(claims)
}

/// Check that the `id_token` was issued by the expected provider, for
/// this client (OIDC Core §3.1.3.7, steps 2–5):
///
/// - `iss` must exactly equal `expected_issuer`, when one is given
///   (e.g. from discovery; see [`crate::TokenEndpoint::issuer`]);
/// - `aud` must be present and include `client_id`;
/// - `azp`, if present, must equal `client_id`.
///
/// With several providers configured, this catches tokens minted by
/// one provider (or for another client) arriving through another's
/// flow.
///
/// **Signature, `exp`, and `nonce` are not checked.** Like
/// [`parse_id_token`], this relies on the token having come straight
/// from the provider's token endpoint over TLS.
pub fn validate_id_token(
    tokens: &TokenSet,
    client_id: &str,
    expected_issuer: Option<&str>,
) -> Result<(), IdentityError> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Audience {
        One(String),
        Many(Vec<String>),
    }

    #[derive(Deserialize)]
    struct BindingClaims {
        #[serde(default)]
        iss: Option<String>,
        #[serde(default)]
        aud: Option<Audience>,
        #[serde(default)]
        azp: Option<String>,
    }

    let claims: BindingClaims = decode_id_token(tokens)?;

    if let Some(expected) = expected_issuer
        && claims.iss.as_deref() != Some(expected)
    {
        return Err(IdentityError::IssuerMismatch {
            expected: expected.to_owned(),
            actual: claims.iss,
        });
    }

    let audience = match claims.aud {
        Some(Audience::One(aud)) => vec![aud],
        Some(Audience::Many(aud)) => aud,
        None => Vec::new(),
    };
    if !audience.iter().any(|aud| aud == client_id) {
        return Err(IdentityError::AudienceMismatch {
            expected: client_id.to_owned(),
            actual: audience,
        });
    }

    if let Some(azp) = claims.azp
        && azp != client_id
    {
        return Err(IdentityError::AuthorizedPartyMismatch {
            expected: client_id.to_owned(),
            actual: azp,
        });
    }

    Ok(())
}

/// Base64url-decode the `id_token` payload and deserialize it.
fn decode_id_token<T: serde::de::DeserializeOwned>(tokens: &TokenSet) -> Result<T, IdentityError> {
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
    serde_json::from_slice(&decoded).map_err(IdentityError::InvalidJson)
}

type BoxedFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
type ResolverFn<T> = dyn Fn(ProviderId, TokenSet) -> BoxedFuture<'static, Result<Identity<T>, IdentityError>>
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
    /// # use oath::server::{parse_id_token, Identity, IdentityResolver, ProviderId};
    /// # use oath::TokenSet;
    /// struct AppUser { provider: ProviderId, email: Option<String> }
    /// let resolver = IdentityResolver::with_provider(|provider: ProviderId, tokens: TokenSet| async move {
    ///     let claims = parse_id_token(&tokens)?;
    ///     Ok(Identity {
    ///         username: claims.sub,
    ///         data: AppUser { provider, email: claims.email },
    ///     })
    /// });
    /// # let _ = resolver;
    /// ```
    pub fn with_provider<F, Fut>(f: F) -> Self
    where
        F: Fn(ProviderId, TokenSet) -> Fut + Send + Sync + 'static,
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
        tokens: TokenSet,
    ) -> Result<Identity<T>, IdentityError> {
        (self.inner)(provider.clone(), tokens).await
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

    fn validate(payload: &str, issuer: Option<&str>) -> Result<(), IdentityError> {
        validate_id_token(&make_tokens(Some(&jwt(payload))), "client", issuer)
    }

    #[test]
    fn validate_accepts_matching_claims() {
        let iss = Some("https://idp.example.com");
        validate(r#"{"iss":"https://idp.example.com","aud":"client"}"#, iss).unwrap();
        validate(
            r#"{"iss":"https://idp.example.com","aud":["other","client"],"azp":"client"}"#,
            iss,
        )
        .unwrap();
        // Without an expected issuer, `iss` isn't checked.
        validate(r#"{"iss":"https://anything","aud":"client"}"#, None).unwrap();
    }

    #[test]
    fn validate_rejects_wrong_issuer() {
        let iss = Some("https://idp.example.com");
        for payload in [
            r#"{"iss":"https://evil.example.com","aud":"client"}"#,
            r#"{"iss":"https://idp.example.com/","aud":"client"}"#,
            r#"{"aud":"client"}"#,
        ] {
            assert!(
                matches!(
                    validate(payload, iss),
                    Err(IdentityError::IssuerMismatch { .. })
                ),
                "{payload}"
            );
        }
    }

    #[test]
    fn validate_rejects_wrong_audience() {
        for payload in [
            r#"{"aud":"other"}"#,
            r#"{"aud":["other","another"]}"#,
            r#"{"aud":[]}"#,
            r#"{}"#,
        ] {
            assert!(
                matches!(
                    validate(payload, None),
                    Err(IdentityError::AudienceMismatch { .. })
                ),
                "{payload}"
            );
        }
    }

    #[test]
    fn validate_rejects_wrong_authorized_party() {
        assert!(matches!(
            validate(r#"{"aud":["client","other"],"azp":"other"}"#, None),
            Err(IdentityError::AuthorizedPartyMismatch { .. })
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
