//! OIDC Discovery 1.0 / RFC 8414 metadata.
//!
//! [`ProviderMetadata`] models the JSON document a provider publishes
//! at `<issuer>/.well-known/openid-configuration`. Use
//! [`ProviderMetadata::discover`] (or [`ProviderMetadata::fetch_with_transport`]
//! in tests) to load it, then feed it to
//! [`crate::endpoint::TokenEndpointBuilder::from_metadata`] to populate
//! a [`crate::TokenEndpoint`] without hand-typing each URL.
//!
//! ```no_run
//! # use oath::{ProviderMetadata, TokenEndpoint};
//! # use secret::Secret;
//! # async fn discover() -> Result<TokenEndpoint, Box<dyn std::error::Error>> {
//! let metadata = ProviderMetadata::discover(
//!     &"https://accounts.google.com".parse()?,
//! ).await?;
//!
//! let endpoint = TokenEndpoint::builder()
//!     .from_metadata(&metadata)?
//!     .client_id("my-app")
//!     .client_secret(Secret::from("super-secret"))
//!     .redirect_uri("https://app.example.com/auth/callback".parse()?)
//!     .build()?;
//! # Ok(endpoint)
//! # }
//! ```

use std::collections::BTreeMap;

use http::header::{ACCEPT, HeaderValue};
use http::{Method, Request, Response, Uri};
use http_body_util::BodyExt as _;
use hyperdriver::Body;
use hyperdriver::client::SharedClientService;
use tower::ServiceExt as _;

use crate::error::Error;

use serde::Deserialize;

/// A subset of the OIDC Discovery / RFC 8414 metadata document.
///
/// Fields the spec marks REQUIRED — `issuer` and `token_endpoint` —
/// fail deserialization when absent. Everything else is `Option`-typed
/// or defaults empty. Provider-specific extras land in [`extra`](Self::extra).
#[derive(Debug, Clone, Deserialize)]
pub struct ProviderMetadata {
    /// The issuer identifier the provider asserts. Required by OIDC.
    pub issuer: String,

    /// `/authorize` URL. REQUIRED for the authorization-code flow.
    #[serde(default)]
    pub authorization_endpoint: Option<String>,

    /// `/token` URL. REQUIRED for every grant except implicit.
    pub token_endpoint: String,

    /// RFC 8628 device authorization endpoint, if the provider supports
    /// the device-code grant.
    #[serde(default)]
    pub device_authorization_endpoint: Option<String>,

    /// `/userinfo` URL. Useful for non-id_token-bearing flows or to
    /// fetch claims beyond what the id_token carries.
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,

    /// JWKS URL — required for id_token signature verification.
    #[serde(default)]
    pub jwks_uri: Option<String>,

    /// RFC 7009 token revocation endpoint.
    #[serde(default)]
    pub revocation_endpoint: Option<String>,

    /// OIDC end-session endpoint, used by RP-initiated logout.
    #[serde(default)]
    pub end_session_endpoint: Option<String>,

    /// Scopes the provider advertises support for.
    #[serde(default)]
    pub scopes_supported: Vec<String>,

    /// `response_type` values the provider supports.
    #[serde(default)]
    pub response_types_supported: Vec<String>,

    /// `grant_type` values the provider supports.
    #[serde(default)]
    pub grant_types_supported: Vec<String>,

    /// PKCE `code_challenge_method` values supported. `oath`'s
    /// authorization-code flow defaults to `S256`.
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,

    /// Client authentication methods supported at the token endpoint.
    /// Common values: `client_secret_basic`, `client_secret_post`,
    /// `none`.
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Vec<String>,

    /// Any additional fields the provider returned.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl ProviderMetadata {
    /// Compute the OIDC well-known URL for an issuer:
    /// `<issuer>/.well-known/openid-configuration`.
    ///
    /// Per OIDC Discovery 1.0 §4 the path is appended to the issuer
    /// URL as-is (the issuer may itself contain a path, e.g.
    /// `https://example.com/realms/foo`).
    pub fn well_known_url(issuer: &Uri) -> Uri {
        let s = issuer.to_string();
        let trimmed = s.trim_end_matches('/');
        format!("{trimmed}/.well-known/openid-configuration")
            .parse()
            .expect("issuer Uri + known path is a valid Uri")
    }

    /// Fetch metadata from `<issuer>/.well-known/openid-configuration`
    /// using a default TLS transport.
    pub async fn discover(issuer: &Uri) -> Result<Self, Error> {
        let url = Self::well_known_url(issuer);
        Self::fetch_with_transport(url, default_transport()).await
    }

    /// Fetch metadata from an explicit URL using an injected transport.
    /// Used by tests with a `MockService`; production callers usually
    /// want [`ProviderMetadata::discover`].
    pub async fn fetch_with_transport<S>(url: Uri, transport: S) -> Result<Self, Error>
    where
        S: tower::Service<
                http::Request<Body>,
                Response = http::Response<Body>,
                Error = hyperdriver::client::Error,
            > + Clone
            + Send
            + Sync
            + 'static,
        S::Future: Send + 'static,
    {
        let request = Request::builder()
            .method(Method::GET)
            .uri(url.clone())
            .header(ACCEPT, HeaderValue::from_static("application/json"))
            .body(Body::empty())
            .expect("discovery request builds");

        let response = transport
            .oneshot(request)
            .await
            .map_err(|e| Error::Transport(api_client::Error::Request(e)))?;

        parse_metadata(response, url).await
    }

    /// Parse the `issuer` field as a [`Uri`].
    pub fn issuer_uri(&self) -> Result<Uri, Error> {
        parse_uri(&self.issuer, "issuer")
    }

    /// Parse `token_endpoint` as a [`Uri`].
    pub fn token_uri(&self) -> Result<Uri, Error> {
        parse_uri(&self.token_endpoint, "token_endpoint")
    }

    /// Parse `authorization_endpoint` as a [`Uri`], if present.
    pub fn authorization_uri(&self) -> Result<Option<Uri>, Error> {
        opt_uri(&self.authorization_endpoint, "authorization_endpoint")
    }

    /// Parse `device_authorization_endpoint` as a [`Uri`], if present.
    pub fn device_authorization_uri(&self) -> Result<Option<Uri>, Error> {
        opt_uri(
            &self.device_authorization_endpoint,
            "device_authorization_endpoint",
        )
    }

    /// Parse `userinfo_endpoint` as a [`Uri`], if present.
    pub fn userinfo_uri(&self) -> Result<Option<Uri>, Error> {
        opt_uri(&self.userinfo_endpoint, "userinfo_endpoint")
    }
}

fn parse_uri(raw: &str, field: &'static str) -> Result<Uri, Error> {
    raw.parse::<Uri>().map_err(|source| Error::Deserialize {
        source: serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("metadata field {field} is not a valid URI: {source}"),
        )),
        body: raw.to_owned(),
    })
}

fn opt_uri(raw: &Option<String>, field: &'static str) -> Result<Option<Uri>, Error> {
    raw.as_deref().map(|s| parse_uri(s, field)).transpose()
}

async fn parse_metadata(response: Response<Body>, url: Uri) -> Result<ProviderMetadata, Error> {
    let (parts, body) = response.into_parts();
    let status = parts.status;
    let collected = body
        .collect()
        .await
        .map_err(|e| Error::Transport(api_client::Error::ResponseBody(e)))?;
    let bytes = collected.to_bytes();

    if !status.is_success() {
        return Err(Error::BadResponse {
            status,
            body: format!("{url}: {body}", body = String::from_utf8_lossy(&bytes),),
        });
    }

    serde_json::from_slice::<ProviderMetadata>(&bytes).map_err(|source| Error::Deserialize {
        source,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    })
}

fn default_transport() -> SharedClientService<Body, Body> {
    hyperdriver::Client::build_tcp_http()
        .with_default_tls()
        .build_service()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_url_appends_path() {
        let issuer: Uri = "https://accounts.google.com".parse().unwrap();
        assert_eq!(
            ProviderMetadata::well_known_url(&issuer).to_string(),
            "https://accounts.google.com/.well-known/openid-configuration",
        );
    }

    #[test]
    fn well_known_url_strips_trailing_slash() {
        let issuer: Uri = "https://accounts.google.com/".parse().unwrap();
        assert_eq!(
            ProviderMetadata::well_known_url(&issuer).to_string(),
            "https://accounts.google.com/.well-known/openid-configuration",
        );
    }

    #[test]
    fn well_known_url_preserves_issuer_path() {
        let issuer: Uri = "https://example.com/realms/main".parse().unwrap();
        assert_eq!(
            ProviderMetadata::well_known_url(&issuer).to_string(),
            "https://example.com/realms/main/.well-known/openid-configuration",
        );
    }

    #[test]
    fn deserializes_google_shaped_metadata() {
        // Trimmed real-shape response.
        let body = r#"{
            "issuer": "https://accounts.google.com",
            "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
            "device_authorization_endpoint": "https://oauth2.googleapis.com/device/code",
            "token_endpoint": "https://oauth2.googleapis.com/token",
            "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
            "revocation_endpoint": "https://oauth2.googleapis.com/revoke",
            "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
            "response_types_supported": ["code", "token", "id_token"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "scopes_supported": ["openid", "email", "profile"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            "code_challenge_methods_supported": ["plain", "S256"],
            "claims_supported": ["sub", "email", "name"]
        }"#;
        let metadata: ProviderMetadata = serde_json::from_str(body).unwrap();
        assert_eq!(metadata.issuer, "https://accounts.google.com");
        assert_eq!(
            metadata.token_endpoint,
            "https://oauth2.googleapis.com/token",
        );
        assert_eq!(
            metadata.authorization_uri().unwrap().unwrap().to_string(),
            "https://accounts.google.com/o/oauth2/v2/auth",
        );
        assert_eq!(
            metadata
                .device_authorization_uri()
                .unwrap()
                .unwrap()
                .to_string(),
            "https://oauth2.googleapis.com/device/code",
        );
        assert!(
            metadata
                .code_challenge_methods_supported
                .iter()
                .any(|m| m == "S256"),
        );
        // Unknown fields land in `extra`.
        assert!(metadata.extra.contains_key("claims_supported"));
    }

    #[test]
    fn missing_token_endpoint_fails_parse() {
        let body = r#"{"issuer":"https://x"}"#;
        let err = serde_json::from_str::<ProviderMetadata>(body).unwrap_err();
        assert!(err.to_string().contains("token_endpoint"));
    }
}
