//! Configuration for OAuth Providers

use http::{Uri, uri::InvalidUri};
use secret::Secret;
use serde::{Deserialize, Serialize};

use crate::{Error, ProviderMetadata, TokenEndpoint};

/// Configuration for an OAuth provider endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthProviderConfig {
    /// Public origin the provider's redirect URI lives under.
    /// Combined with `/auth/callback` to form the redirect URI sent in
    /// the authorization request.
    #[serde(with = "serde_uri")]
    pub external_origin: Uri,
    /// Display name shown on the "Sign in with X" button.
    pub provider_name: String,
    /// OAuth2 client id issued by the provider.
    pub client_id: String,
    /// OAuth2 client secret issued by the provider.
    #[serde(default)]
    pub client_secret: Option<Secret>,
    /// How to discover (or hard-code) the provider's endpoints.
    pub endpoints: ProviderEndpoints,
}

impl OAuthProviderConfig {
    /// Public redirect URI sent in the authorization request: the
    /// configured `external_origin` joined to `/auth/callback`.
    pub fn redirect_uri(&self) -> Uri {
        let base = self.external_origin.to_string();
        let trimmed = base.trim_end_matches('/');
        format!("{trimmed}/auth/callback")
            .parse()
            .expect("validated external_origin + known path is a valid Uri")
    }

    /// Resolve the provider's endpoints and build a [`TokenEndpoint`].
    pub async fn provider(&self) -> Result<TokenEndpoint, Error> {
        let builder = TokenEndpoint::builder()
            .client_id(self.client_id.clone())
            .redirect_uri(self.redirect_uri());

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
