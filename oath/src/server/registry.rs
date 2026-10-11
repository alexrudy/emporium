//! Provider registry for [`crate::server::OAuth2Router`].
//!
//! A [`Provider`] pairs a [`TokenEndpoint`] with a stable
//! [`ProviderId`] that appears in route paths and in persisted
//! [`crate::server::SessionData`].

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::provider::IssParameter;
use crate::{ScopeSet, TokenEndpoint};

use super::config::OAuth2RouterConfig;

const DEFAULT_PROVIDER_ID: &str = "default";
const MAX_PROVIDER_ID_LEN: usize = 64;

/// Stable identifier for a registered OAuth2 provider, e.g. `google`.
///
/// Provider ids appear in route paths (`{prefix}/{id}/login`), file
/// paths, and session data, so they're restricted to lowercase ASCII
/// letters, digits, `-`, and `_`, and must be 1–64 bytes long.
///
/// Uppercase is rejected rather than lowercased: config loaders that
/// lowercase environment variable names (like the `config` crate) would
/// otherwise turn `Google` in a file and `GOOGLE` in the environment into
/// two entries that silently collapse into one. Rejecting it also keeps
/// ids distinct on case-insensitive filesystems.
///
/// [`ProviderId::default`] is `"default"`: the id used by
/// [`crate::server::OAuth2Router::new`] for its single provider, and the
/// id assumed for session data persisted before providers were tracked.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct ProviderId(String);

impl ProviderId {
    /// Validate and wrap a provider id.
    pub fn new(id: impl Into<String>) -> Result<Self, InvalidProviderId> {
        let id = id.into();
        if id.is_empty() {
            return Err(InvalidProviderId {
                id,
                reason: "empty",
            });
        }
        if id.len() > MAX_PROVIDER_ID_LEN {
            return Err(InvalidProviderId {
                id,
                reason: "longer than 64 bytes",
            });
        }
        if id.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(InvalidProviderId {
                id,
                reason: "must be lowercase",
            });
        }
        if !id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        {
            return Err(InvalidProviderId {
                id,
                reason: "only lowercase ASCII letters, digits, `-`, and `_` are allowed",
            });
        }
        Ok(Self(id))
    }

    /// The id as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for ProviderId {
    fn default() -> Self {
        Self(DEFAULT_PROVIDER_ID.into())
    }
}

impl fmt::Display for ProviderId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for ProviderId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromStr for ProviderId {
    type Err = InvalidProviderId;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl TryFrom<String> for ProviderId {
    type Error = InvalidProviderId;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for ProviderId {
    type Error = InvalidProviderId;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for ProviderId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw).map_err(serde::de::Error::custom)
    }
}

/// A string could not be used as a [`ProviderId`].
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("invalid provider id {id:?}: {reason}")]
pub struct InvalidProviderId {
    id: String,
    reason: &'static str,
}

/// An authorization response failed the RFC 9207 `iss` check.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum IssParameterError {
    /// The response's `iss` names a different issuer.
    #[error(
        "authorization response iss {actual:?} does not match the provider's issuer {expected:?}"
    )]
    Mismatch {
        /// The provider's issuer.
        expected: String,
        /// The response's `iss` parameter.
        actual: String,
    },
    /// The provider sends `iss` (or it's required), but the response has
    /// none.
    #[error("authorization response has no iss parameter; expected {expected:?}")]
    Missing {
        /// The provider's issuer.
        expected: String,
    },
    /// [`IssParameter::Required`] is set, but the provider's issuer isn't
    /// known (e.g. explicit endpoints without one).
    #[error("the iss parameter is required, but the provider's issuer is not known")]
    UnknownIssuer,
}

/// Where a provider's login and callback routes are mounted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mount {
    /// `{prefix}/{id}/login` and `{prefix}/{id}/callback`.
    Scoped,
    /// `{prefix}/login` and `{prefix}/callback`. Used by
    /// [`crate::server::OAuth2Router::new`] so single-provider
    /// deployments keep their registered redirect URI.
    Root,
}

/// An OAuth2 provider registered with [`crate::server::OAuth2Router`].
#[derive(Debug, Clone)]
pub struct Provider {
    id: ProviderId,
    endpoint: TokenEndpoint,
    scopes: Option<ScopeSet>,
    display_name: Option<String>,
    validate_issuer: bool,
    iss_parameter: IssParameter,
    pub(crate) mount: Mount,
}

impl Provider {
    /// Register `endpoint` under `id`.
    ///
    /// The endpoint's redirect URI must point at this provider's
    /// callback route, i.e.
    /// [`OAuth2RouterConfig::provider_callback_path`] joined to your
    /// public origin.
    pub fn new(id: ProviderId, endpoint: TokenEndpoint) -> Self {
        Self {
            id,
            endpoint,
            scopes: None,
            display_name: None,
            validate_issuer: true,
            iss_parameter: IssParameter::Auto,
            mount: Mount::Scoped,
        }
    }

    /// Register `endpoint` as [`ProviderId::default`], mounted at
    /// `{prefix}/login` and `{prefix}/callback`.
    ///
    /// This is what [`crate::server::OAuth2Router::new`] does with its
    /// endpoint; use it directly to keep an existing single-provider
    /// deployment's redirect URI while customizing the provider. The
    /// endpoint's redirect URI should point at
    /// [`OAuth2RouterConfig::callback_path`]. A root provider is always
    /// the default provider.
    pub fn root(endpoint: TokenEndpoint) -> Self {
        Self {
            mount: Mount::Root,
            ..Self::new(ProviderId::default(), endpoint)
        }
    }

    /// Request these scopes from this provider instead of the router's
    /// [`OAuth2RouterConfig::scopes`].
    pub fn with_scopes(mut self, scopes: ScopeSet) -> Self {
        self.scopes = Some(scopes);
        self
    }

    /// Human-readable name, e.g. for a "Sign in with X" button.
    pub fn with_display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = Some(name.into());
        self
    }

    /// Don't compare ID tokens' `iss` claim to the endpoint's
    /// [issuer](TokenEndpoint::issuer). The `aud` / `azp` checks still
    /// apply.
    ///
    /// Only for providers whose discovery document doesn't state the
    /// exact issuer, e.g. Microsoft Entra's multi-tenant `common`
    /// endpoint, which advertises a `{tenantid}` placeholder.
    pub fn skip_issuer_validation(mut self) -> Self {
        self.validate_issuer = false;
        self
    }

    /// How to treat the RFC 9207 `iss` parameter on this provider's
    /// authorization responses. Defaults to [`IssParameter::Auto`]; use
    /// [`IssParameter::Ignored`] to opt out for providers that get it
    /// wrong.
    pub fn with_iss_parameter(mut self, policy: IssParameter) -> Self {
        self.iss_parameter = policy;
        self
    }

    /// Check an authorization response's `iss` parameter against this
    /// provider's [`IssParameter`] policy (RFC 9207 §2.4). The comparison
    /// is exact string equality.
    pub fn check_iss_parameter(&self, iss: Option<&str>) -> Result<(), IssParameterError> {
        let required = match self.iss_parameter {
            IssParameter::Ignored => return Ok(()),
            IssParameter::Required => true,
            IssParameter::Auto => self
                .endpoint
                .authorization_response_iss_parameter_supported(),
        };

        let Some(expected) = self.endpoint.issuer() else {
            return if self.iss_parameter == IssParameter::Required {
                Err(IssParameterError::UnknownIssuer)
            } else {
                Ok(())
            };
        };

        match iss {
            Some(actual) if actual == expected => Ok(()),
            Some(actual) => Err(IssParameterError::Mismatch {
                expected: expected.to_owned(),
                actual: actual.to_owned(),
            }),
            None if required => Err(IssParameterError::Missing {
                expected: expected.to_owned(),
            }),
            None => Ok(()),
        }
    }

    /// The provider's id.
    pub fn id(&self) -> &ProviderId {
        &self.id
    }

    /// The provider's token endpoint.
    pub fn endpoint(&self) -> &TokenEndpoint {
        &self.endpoint
    }

    /// Scope override for this provider, if any.
    pub fn scopes(&self) -> Option<&ScopeSet> {
        self.scopes.as_ref()
    }

    /// Display name, falling back to the provider id.
    pub fn display_name(&self) -> &str {
        self.display_name.as_deref().unwrap_or(self.id.as_str())
    }

    /// Path of this provider's login route under `config`.
    pub fn login_path(&self, config: &OAuth2RouterConfig) -> String {
        match self.mount {
            Mount::Scoped => config.provider_login_path(&self.id),
            Mount::Root => config.login_path(),
        }
    }

    /// Path of this provider's callback route under `config`.
    pub fn callback_path(&self, config: &OAuth2RouterConfig) -> String {
        match self.mount {
            Mount::Scoped => config.provider_callback_path(&self.id),
            Mount::Root => config.callback_path(),
        }
    }

    /// The issuer ID tokens must carry, if it's known and checked.
    pub(crate) fn expected_issuer(&self) -> Option<&str> {
        self.validate_issuer
            .then(|| self.endpoint.issuer())
            .flatten()
    }

    pub(crate) fn effective_scopes(&self, config: &OAuth2RouterConfig) -> ScopeSet {
        self.scopes.clone().unwrap_or_else(|| config.scopes.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_simple_ids() {
        for id in ["google", "my-idp", "okta_prod", "a1", "1"] {
            assert_eq!(ProviderId::new(id).unwrap().as_str(), id);
        }
    }

    #[test]
    fn rejects_uppercase() {
        for id in ["Google", "OKTA", "my-IdP", "A1"] {
            let err = ProviderId::new(id).unwrap_err();
            assert!(err.to_string().contains("lowercase"), "{id}: {err}");
        }
        assert!(serde_json::from_str::<ProviderId>(r#""Google""#).is_err());
    }

    #[test]
    fn rejects_unsafe_ids() {
        for id in ["", "a/b", "..", "a b", "ümlaut", "a?b", &"x".repeat(65)] {
            assert!(ProviderId::new(id).is_err(), "{id:?} should be rejected");
        }
    }

    #[test]
    fn deserialize_validates() {
        assert!(serde_json::from_str::<ProviderId>(r#""google""#).is_ok());
        assert!(serde_json::from_str::<ProviderId>(r#""../etc""#).is_err());
    }

    #[test]
    fn default_is_default() {
        assert_eq!(ProviderId::default().as_str(), "default");
    }

    const ISSUER: &str = "https://idp.example.com";

    fn provider(issuer: Option<&str>, supported: bool, policy: IssParameter) -> Provider {
        let mut builder = TokenEndpoint::builder()
            .client_id("c")
            .token_uri("https://idp.example.com/token".parse().unwrap())
            .authorization_response_iss_parameter_supported(supported)
            .transport(api_client::mock::MockService::new());
        if let Some(issuer) = issuer {
            builder = builder.issuer(issuer);
        }
        Provider::new(ProviderId::new("idp").unwrap(), builder.build().unwrap())
            .with_iss_parameter(policy)
    }

    fn mismatch() -> IssParameterError {
        IssParameterError::Mismatch {
            expected: ISSUER.into(),
            actual: "https://evil.example.com".into(),
        }
    }

    fn missing() -> IssParameterError {
        IssParameterError::Missing {
            expected: ISSUER.into(),
        }
    }

    #[test]
    fn auto_checks_iss_when_present() {
        for supported in [false, true] {
            let p = provider(Some(ISSUER), supported, IssParameter::Auto);
            assert_eq!(p.check_iss_parameter(Some(ISSUER)), Ok(()));
            assert_eq!(
                p.check_iss_parameter(Some("https://evil.example.com")),
                Err(mismatch())
            );
            // Exact comparison: no trailing-slash normalization.
            assert!(
                p.check_iss_parameter(Some("https://idp.example.com/"))
                    .is_err()
            );
        }
    }

    #[test]
    fn auto_requires_iss_only_when_advertised() {
        let p = provider(Some(ISSUER), false, IssParameter::Auto);
        assert_eq!(p.check_iss_parameter(None), Ok(()));

        let p = provider(Some(ISSUER), true, IssParameter::Auto);
        assert_eq!(p.check_iss_parameter(None), Err(missing()));
    }

    #[test]
    fn auto_without_known_issuer_skips() {
        let p = provider(None, true, IssParameter::Auto);
        assert_eq!(p.check_iss_parameter(None), Ok(()));
        assert_eq!(p.check_iss_parameter(Some("https://anything")), Ok(()));
    }

    #[test]
    fn required_always_requires_iss() {
        let p = provider(Some(ISSUER), false, IssParameter::Required);
        assert_eq!(p.check_iss_parameter(Some(ISSUER)), Ok(()));
        assert_eq!(p.check_iss_parameter(None), Err(missing()));

        let p = provider(None, false, IssParameter::Required);
        assert_eq!(
            p.check_iss_parameter(Some(ISSUER)),
            Err(IssParameterError::UnknownIssuer)
        );
    }

    #[test]
    fn ignored_never_checks() {
        let p = provider(Some(ISSUER), true, IssParameter::Ignored);
        assert_eq!(p.check_iss_parameter(None), Ok(()));
        assert_eq!(
            p.check_iss_parameter(Some("https://evil.example.com")),
            Ok(())
        );
    }
}
