//! Configuration for OAuth Providers

use http::{Uri, uri::InvalidUri};
use secret::Secret;
use serde::{Deserialize, Serialize};

use crate::{Error, ProviderMetadata, ScopeSet, TokenEndpoint};

/// Configuration for an OAuth provider endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthProviderConfig {
    /// Public origin the provider's redirect URI lives under.
    /// Combined with the router's callback path (e.g. `/auth/callback`)
    /// to form the redirect URI sent in the authorization request.
    #[serde(default, with = "serde_uri_opt")]
    pub external_origin: Option<Uri>,
    /// Display name shown on the "Sign in with X" button.
    pub provider_name: String,
    /// OAuth2 client id issued by the provider.
    pub client_id: String,
    /// OAuth2 client secret issued by the provider.
    #[serde(default)]
    pub client_secret: Option<Secret>,
    /// How to discover (or hard-code) the provider's endpoints.
    pub endpoints: ProviderEndpoints,
    /// Scopes to request from this provider, overriding the router's
    /// default scopes.
    #[serde(default)]
    pub scopes: Option<ScopeSet>,
    /// Don't check ID tokens' `iss` claim against the issuer from
    /// discovery (`aud` is still checked). Only for providers whose
    /// discovery document doesn't state the exact issuer, e.g. Microsoft
    /// Entra's multi-tenant `common` endpoint. See
    /// `oath::server::Provider::skip_issuer_validation`.
    ///
    /// Accepts `"true"` / `"false"` strings as well as booleans, so it can
    /// be set from environment variables even when this struct is
    /// `#[serde(flatten)]`ed (which stops config loaders from converting
    /// strings for us).
    #[serde(
        default,
        deserialize_with = "bool_or_string::deserialize",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub skip_issuer_validation: bool,
    /// How to treat the RFC 9207 `iss` parameter on authorization
    /// responses. Defaults to [`IssParameter::Auto`].
    #[serde(default, skip_serializing_if = "IssParameter::is_auto")]
    pub iss_parameter: IssParameter,
}

/// How to treat the RFC 9207 `iss` parameter that providers may add to
/// authorization responses (the callback's query string).
///
/// The parameter names the issuer that produced the response. Checking
/// it against the provider the login was sent to defends against IdP
/// mix-up attacks; per-provider callback routes already provide that
/// defense, so this is a second line.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IssParameter {
    /// The RFC 9207 behavior: if the response has an `iss`, it must equal
    /// the provider's issuer; if the provider advertises support
    /// (`authorization_response_iss_parameter_supported` in discovery),
    /// responses without one are rejected. Without a known issuer (e.g.
    /// explicit endpoints), the parameter can't be checked and is
    /// ignored.
    #[default]
    Auto,
    /// Every response must carry an `iss` equal to the provider's issuer,
    /// even if discovery doesn't advertise support. Requires a known
    /// issuer.
    Required,
    /// Don't look at the parameter. For providers that send one that
    /// doesn't match their issuer, or advertise support but don't send
    /// it.
    Ignored,
}

impl IssParameter {
    fn is_auto(&self) -> bool {
        *self == Self::Auto
    }
}

impl std::str::FromStr for IssParameter {
    type Err = InvalidIssParameter;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "required" => Ok(Self::Required),
            "ignored" => Ok(Self::Ignored),
            _ => Err(InvalidIssParameter(s.to_owned())),
        }
    }
}

/// A string wasn't `auto`, `required`, or `ignored`.
#[derive(Debug, Clone, thiserror::Error)]
#[error("invalid iss parameter policy {0:?}: expected auto, required, or ignored")]
pub struct InvalidIssParameter(String);

impl OAuthProviderConfig {
    /// Public redirect URI sent in the authorization request: the
    /// configured `external_origin` joined to `callback_path`.
    ///
    /// `callback_path` should be the path the callback handler is
    /// mounted at, e.g. `OAuth2RouterConfig::callback_path()` when
    /// using the `server` feature.
    pub fn redirect_uri(&self, callback_path: &str) -> Result<Uri, InvalidUri> {
        let path = callback_path.trim_start_matches('/');
        match self.external_origin.as_ref().map(ToString::to_string) {
            Some(base) => format!("{}/{path}", base.trim_end_matches('/')).parse(),
            None => format!("/{path}").parse(),
        }
    }

    /// Resolve the provider's endpoints and build a [`TokenEndpoint`]
    /// whose redirect URI points at `callback_path`.
    pub async fn provider(&self, callback_path: &str) -> Result<TokenEndpoint, Error> {
        let redirect_uri = self.redirect_uri(callback_path)?;
        let builder = TokenEndpoint::builder()
            .client_id(self.client_id.clone())
            .redirect_uri(redirect_uri);

        let builder = if let Some(secret) = &self.client_secret {
            builder.client_secret(secret.clone())
        } else {
            builder
        };

        let builder = match &self.endpoints {
            ProviderEndpoints::Explicit {
                auth_uri,
                token_uri,
            } => builder
                .auth_uri(auth_uri.clone())
                .token_uri(token_uri.clone()),
            ProviderEndpoints::Discover { issuer } => {
                let well_known = ProviderMetadata::well_known_url(issuer);
                tracing::info!(%issuer, %well_known, "fetching OIDC discovery metadata");
                let metadata = ProviderMetadata::discover(issuer).await?;
                tracing::info!(
                    token_endpoint = %metadata.token_endpoint,
                    authorization_endpoint = ?metadata.authorization_endpoint,
                    "discovery succeeded",
                );
                builder.from_metadata(&metadata)?
            }
        };

        Ok(builder.build().unwrap())
    }
}

/// How ott resolves the provider's authorization, token, and (optional)
/// device endpoints. Either the operator supplies an `OAUTH_ISSUER`
/// (a discovery URL is derived from it and fetched at startup) or
/// they wire `OAUTH_AUTH_URI` and `OAUTH_TOKEN_URI` explicitly.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProviderEndpoints {
    /// Endpoints will be discovered from
    /// `<issuer>/.well-known/openid-configuration` at startup.
    Discover {
        /// The provider's issuer URL.
        #[serde(with = "serde_uri")]
        issuer: Uri,
    },
    /// Endpoints are pinned at config-load time.
    Explicit {
        /// `authorization_endpoint`.
        #[serde(with = "serde_uri")]
        auth_uri: Uri,
        /// `token_endpoint`.
        #[serde(with = "serde_uri")]
        token_uri: Uri,
    },
}

impl ProviderEndpoints {
    /// Construct a [`ProviderEndpoints`] from the given environment variables.
    pub fn from_provider<F>(get: &F) -> Result<Self, ProviderEndpointError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let issuer = get("OAUTH_ISSUER");
        let auth = get("OAUTH_AUTH_URI");
        let token = get("OAUTH_TOKEN_URI");
        match (issuer, auth, token) {
            (Some(raw), _, _) => {
                let uri = parse_configured_uri(&raw, "OAUTH_ISSUER")?;
                Ok(ProviderEndpoints::Discover { issuer: uri })
            }
            (None, Some(auth_raw), Some(token_raw)) => {
                let auth_uri = parse_configured_uri(&auth_raw, "OAUTH_AUTH_URI")?;
                let token_uri = parse_configured_uri(&token_raw, "OAUTH_TOKEN_URI")?;
                Ok(ProviderEndpoints::Explicit {
                    auth_uri,
                    token_uri,
                })
            }
            _ => Err(ProviderEndpointError::NotConfigured),
        }
    }
}

/// Error when resolving a provider endpoint
#[derive(Debug, thiserror::Error)]
pub enum ProviderEndpointError {
    /// No endpoint discovery can be constructed from available environment data.
    #[error(
        "set set OAUTH_ISSUER for `.well-known` discovery, or set both OAUTH_AUTH_URI and OAUTH_TOKEN_URI explicitly"
    )]
    NotConfigured,

    /// Endpoint URI is not valid
    #[error("invalid provider {source} parsing {uri} from {var}")]
    InvalidUri {
        /// The underlying URI parsing error.
        #[source]
        source: InvalidUri,

        /// The raw URI string from the configuration variable.
        uri: String,

        /// The name of the configuration variable that contained the URI.
        var: String,
    },
}

/// Parses a configured URI string into a [`Uri`] value, with error handling for invalid URIs.
pub fn parse_configured_uri(raw: &str, name: &str) -> Result<Uri, ProviderEndpointError> {
    raw.parse::<Uri>()
        .map_err(|source| ProviderEndpointError::InvalidUri {
            source,
            uri: raw.into(),
            var: name.into(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(external_origin: Option<&str>) -> OAuthProviderConfig {
        OAuthProviderConfig {
            external_origin: external_origin.map(|o| o.parse().unwrap()),
            provider_name: "Test".into(),
            client_id: "client".into(),
            client_secret: None,
            endpoints: ProviderEndpoints::Discover {
                issuer: "https://issuer.example.com".parse().unwrap(),
            },
            scopes: None,
            skip_issuer_validation: false,
            iss_parameter: IssParameter::Auto,
        }
    }

    #[test]
    fn redirect_uri_uses_callback_path() {
        let cfg = config(Some("https://app.example.com"));
        assert_eq!(
            cfg.redirect_uri("/oauth/callback").unwrap().to_string(),
            "https://app.example.com/oauth/callback",
        );
    }

    #[test]
    fn redirect_uri_normalizes_slashes() {
        let cfg = config(Some("https://app.example.com/"));
        assert_eq!(
            cfg.redirect_uri("/auth/callback").unwrap().to_string(),
            "https://app.example.com/auth/callback",
        );
        assert_eq!(
            cfg.redirect_uri("auth/callback").unwrap().to_string(),
            "https://app.example.com/auth/callback",
        );
    }

    #[test]
    fn skip_issuer_validation_accepts_bools_and_strings() {
        let parse = |value: serde_json::Value| {
            serde_json::from_value::<OAuthProviderConfig>(serde_json::json!({
                "provider_name": "Test",
                "client_id": "c",
                "endpoints": { "issuer": "https://issuer.example.com" },
                "skip_issuer_validation": value,
            }))
            .map(|config| config.skip_issuer_validation)
        };

        for (value, expected) in [
            (serde_json::json!(true), true),
            (serde_json::json!(false), false),
            (serde_json::json!("true"), true),
            (serde_json::json!("False"), false),
            (serde_json::json!("yes"), true),
            (serde_json::json!("0"), false),
            (serde_json::json!(1), true),
        ] {
            assert_eq!(parse(value.clone()).unwrap(), expected, "{value}");
        }
        assert!(parse(serde_json::json!("maybe")).is_err());
        assert!(parse(serde_json::json!(2)).is_err());
    }

    #[test]
    fn redirect_uri_without_origin_is_relative() {
        let cfg = config(None);
        assert_eq!(
            cfg.redirect_uri("/sso/callback").unwrap().to_string(),
            "/sso/callback",
        );
    }
}

mod serde_uri {
    use http::Uri;
    use serde::de::Visitor;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Uri, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct UriVisitor;

        impl<'de> Visitor<'de> for UriVisitor {
            type Value = Uri;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a string URI")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                v.parse::<Uri>()
                    .map_err(|source| E::custom(format!("invalid URI: {source}")))
            }
        }

        deserializer.deserialize_str(UriVisitor)
    }

    pub fn serialize<S>(uri: &Uri, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&uri.to_string())
    }
}

/// Deserialize a bool from a boolean or a string (`true`/`false`,
/// `yes`/`no`, `on`/`off`, `1`/`0`, case-insensitive).
mod bool_or_string {
    use std::fmt;

    use serde::de::{self, Visitor};

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<bool, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct BoolVisitor;

        impl Visitor<'_> for BoolVisitor {
            type Value = bool;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a boolean, or a string like \"true\" or \"false\"")
            }

            fn visit_bool<E: de::Error>(self, v: bool) -> Result<bool, E> {
                Ok(v)
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<bool, E> {
                match v.trim().to_ascii_lowercase().as_str() {
                    "true" | "yes" | "on" | "1" => Ok(true),
                    "false" | "no" | "off" | "0" => Ok(false),
                    _ => Err(E::invalid_value(de::Unexpected::Str(v), &self)),
                }
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<bool, E> {
                match v {
                    0 => Ok(false),
                    1 => Ok(true),
                    _ => Err(E::invalid_value(de::Unexpected::Unsigned(v), &self)),
                }
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<bool, E> {
                match v {
                    0 => Ok(false),
                    1 => Ok(true),
                    _ => Err(E::invalid_value(de::Unexpected::Signed(v), &self)),
                }
            }
        }

        deserializer.deserialize_any(BoolVisitor)
    }
}

pub(crate) mod serde_uri_opt {
    use http::Uri;
    use serde::de::Visitor;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Uri>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct UriVisitor;

        impl<'de> Visitor<'de> for UriVisitor {
            type Value = Option<Uri>;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a string URI")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                v.parse::<Uri>()
                    .map_err(|source| E::custom(format!("invalid URI: {source}")))
                    .map(Some)
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(None)
            }
        }

        deserializer.deserialize_str(UriVisitor)
    }

    pub fn serialize<S>(uri: &Option<Uri>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match uri.as_ref() {
            Some(uri) => serializer.serialize_str(&uri.to_string()),
            None => serializer.serialize_none(),
        }
    }
}
