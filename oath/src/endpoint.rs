//! Low-level OAuth2 token endpoint.
//!
//! [`TokenEndpoint`] knows how to POST a [`crate::grant::TokenRequest`]
//! to the configured `/token` URL and parse the response back into a
//! [`crate::token::TokenResponse`]. It does not own a [`crate::token::TokenSet`]
//! — refreshing a long-lived credential happens at the layer above.

use std::fmt;
use std::sync::Arc;

use http::{HeaderValue, Method, Request, Response, Uri};
use http_body_util::BodyExt as _;
use hyperdriver::Body;
use hyperdriver::client::SharedClientService;
use hyperdriver::service::SharedService;
use secret::Secret;
use thiserror::Error;
use tower::ServiceExt as _;

use crate::error::{Error, TokenErrorCode, TokenErrorResponse};
use crate::grant::{DeviceAuthorizationResponse, DeviceCodeRequest, TokenRequest};
use crate::scope::ScopeSet;
use crate::token::TokenResponse;

/// How the client credentials are presented to the token endpoint.
///
/// RFC 6749 §2.3.1 lets the server accept either form. Some providers
/// only accept one or the other; check the provider's documentation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ClientAuthStyle {
    /// `client_id` and `client_secret` go in the request body. Default.
    #[default]
    RequestBody,
    /// `client_id` and `client_secret` go in an HTTP Basic auth header.
    BasicAuthHeader,
}

/// Reasons [`TokenEndpointBuilder::build`] can fail.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BuilderError {
    /// `client_id` was not set.
    #[error("TokenEndpoint requires a client_id")]
    MissingClientId,
    /// `token_uri` was not set.
    #[error("TokenEndpoint requires a token_uri")]
    MissingTokenUri,
}

struct Inner {
    client_id: String,
    client_secret: Option<Secret>,
    auth_uri: Option<Uri>,
    token_uri: Uri,
    device_uri: Option<Uri>,
    redirect_uri: Option<Uri>,
    auth_style: ClientAuthStyle,
    transport: SharedClientService<Body, Body>,
}

impl fmt::Debug for Inner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenEndpoint")
            .field("client_id", &self.client_id)
            .field("client_secret", &self.client_secret)
            .field("auth_uri", &self.auth_uri)
            .field("token_uri", &self.token_uri)
            .field("device_uri", &self.device_uri)
            .field("redirect_uri", &self.redirect_uri)
            .field("auth_style", &self.auth_style)
            .finish_non_exhaustive()
    }
}

/// A configured handle to an OAuth2 token endpoint.
///
/// Cheaply cloneable — internally `Arc`-backed.
#[derive(Debug, Clone)]
pub struct TokenEndpoint {
    inner: Arc<Inner>,
}

impl TokenEndpoint {
    /// Start configuring a new endpoint. See [`TokenEndpointBuilder`].
    pub fn builder() -> TokenEndpointBuilder {
        TokenEndpointBuilder::default()
    }

    /// The configured `client_id`.
    pub fn client_id(&self) -> &str {
        &self.inner.client_id
    }

    /// The authorization endpoint URI, if configured.
    pub fn auth_uri(&self) -> Option<&Uri> {
        self.inner.auth_uri.as_ref()
    }

    /// The token endpoint URI.
    pub fn token_uri(&self) -> &Uri {
        &self.inner.token_uri
    }

    /// The device authorization endpoint URI, if configured.
    pub fn device_uri(&self) -> Option<&Uri> {
        self.inner.device_uri.as_ref()
    }

    /// The configured redirect URI, if any. Sent as `redirect_uri` in
    /// authorization-code exchanges and in the authorization URL.
    pub fn redirect_uri(&self) -> Option<&Uri> {
        self.inner.redirect_uri.as_ref()
    }

    /// The configured client-auth style.
    pub fn auth_style(&self) -> ClientAuthStyle {
        self.inner.auth_style
    }

    /// Exchange a grant for a token response.
    pub async fn exchange(&self, grant: impl Into<TokenRequest>) -> Result<TokenResponse, Error> {
        let fields = grant.into().build_fields(self.inner.redirect_uri.as_ref());
        self.post_form_for(&self.inner.token_uri, fields).await
    }

    /// Initiate the device authorization grant (RFC 8628 §3.1).
    ///
    /// POSTs `client_id` (+ optional `scope`) to the configured
    /// `device_uri`. The returned [`DeviceAuthorizationResponse`] holds
    /// the `user_code` you display to the user and the `device_code`
    /// you feed to [`Self::poll_device_token`].
    pub async fn start_device_flow(
        &self,
        scope: Option<ScopeSet>,
    ) -> Result<DeviceAuthorizationResponse, Error> {
        let device_uri = self
            .inner
            .device_uri
            .clone()
            .ok_or(Error::MissingDeviceUri)?;
        let mut fields = Vec::with_capacity(1);
        if let Some(scope) = scope {
            fields.push(("scope", scope.to_string()));
        }
        self.post_form_for(&device_uri, fields).await
    }

    /// Poll the token endpoint until the user completes the device flow.
    ///
    /// Honors the server's `interval` and `expires_in`. Per RFC 8628 §3.5,
    /// `authorization_pending` is silently retried, and `slow_down`
    /// increases the polling interval by 5 seconds. Other server-issued
    /// errors (including `access_denied` and `expired_token`) propagate as
    /// [`Error::TokenError`]. If `expires_in` elapses without a result,
    /// returns [`Error::DeviceFlowTimeout`].
    pub async fn poll_device_token(
        &self,
        auth: &DeviceAuthorizationResponse,
    ) -> Result<TokenResponse, Error> {
        let deadline =
            tokio::time::Instant::now() + std::time::Duration::from_secs(auth.expires_in);
        let mut interval = std::time::Duration::from_secs(auth.interval.max(1));

        loop {
            tokio::time::sleep(interval).await;

            if tokio::time::Instant::now() >= deadline {
                return Err(Error::DeviceFlowTimeout);
            }

            let request = DeviceCodeRequest::new(auth.device_code.clone());
            match self.exchange(request).await {
                Ok(response) => return Ok(response),
                Err(Error::TokenError(err)) => match err.code {
                    TokenErrorCode::Other(ref code) if code == "authorization_pending" => {
                        // Keep polling at the same cadence.
                    }
                    TokenErrorCode::Other(ref code) if code == "slow_down" => {
                        // RFC 8628 §3.5: increase the polling interval by 5 seconds.
                        interval += std::time::Duration::from_secs(5);
                    }
                    _ => return Err(Error::TokenError(err)),
                },
                Err(other) => return Err(other),
            }
        }
    }

    async fn post_form_for<R>(
        &self,
        target: &Uri,
        mut fields: Vec<(&'static str, String)>,
    ) -> Result<R, Error>
    where
        R: serde::de::DeserializeOwned,
    {
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(target.clone())
            .header(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/x-www-form-urlencoded"),
            )
            .header(
                http::header::ACCEPT,
                HeaderValue::from_static("application/json"),
            );

        match self.inner.auth_style {
            ClientAuthStyle::RequestBody => {
                fields.push(("client_id", self.inner.client_id.clone()));
                if let Some(secret) = &self.inner.client_secret {
                    fields.push(("client_secret", secret.revealed().to_owned()));
                }
            }
            ClientAuthStyle::BasicAuthHeader => {
                let header = api_client::basic_auth(
                    &self.inner.client_id,
                    self.inner.client_secret.as_ref().map(Secret::revealed),
                );
                builder = builder.header(http::header::AUTHORIZATION, header);
            }
        }

        let body = serde_urlencoded::to_string(&fields).expect("OAuth2 form fields must serialize");
        let request = builder
            .body(Body::from(body))
            .expect("OAuth2 form request must build");

        let response = self
            .inner
            .transport
            .clone()
            .oneshot(request)
            .await
            .map_err(|e| Error::Transport(api_client::Error::Request(e)))?;

        parse_response(response).await
    }
}

async fn parse_response<R: serde::de::DeserializeOwned>(
    response: Response<Body>,
) -> Result<R, Error> {
    let (parts, body) = response.into_parts();
    let status = parts.status;

    let collected = body
        .collect()
        .await
        .map_err(|e| Error::Transport(api_client::Error::ResponseBody(e)))?;
    let bytes = collected.to_bytes();

    if status.is_success() {
        return serde_json::from_slice::<R>(&bytes).map_err(|source| Error::Deserialize {
            source,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        });
    }

    // Non-2xx: try the OAuth2 §5.2 error envelope first; fall back to
    // a generic BadResponse if the body doesn't match.
    if let Ok(err) = serde_json::from_slice::<TokenErrorResponse>(&bytes) {
        return Err(Error::TokenError(err));
    }
    Err(Error::BadResponse {
        status,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    })
}

/// Builder for [`TokenEndpoint`].
#[derive(Default)]
pub struct TokenEndpointBuilder {
    client_id: Option<String>,
    client_secret: Option<Secret>,
    auth_uri: Option<Uri>,
    token_uri: Option<Uri>,
    device_uri: Option<Uri>,
    redirect_uri: Option<Uri>,
    auth_style: ClientAuthStyle,
    transport: Option<SharedClientService<Body, Body>>,
}

impl fmt::Debug for TokenEndpointBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenEndpointBuilder")
            .field("client_id", &self.client_id)
            .field("client_secret", &self.client_secret)
            .field("auth_uri", &self.auth_uri)
            .field("token_uri", &self.token_uri)
            .field("device_uri", &self.device_uri)
            .field("redirect_uri", &self.redirect_uri)
            .field("auth_style", &self.auth_style)
            .finish_non_exhaustive()
    }
}

impl TokenEndpointBuilder {
    /// Required: the OAuth2 client identifier issued by the provider.
    pub fn client_id(mut self, id: impl Into<String>) -> Self {
        self.client_id = Some(id.into());
        self
    }

    /// Optional: the client secret. Public clients omit this.
    pub fn client_secret(mut self, secret: impl Into<Secret>) -> Self {
        self.client_secret = Some(secret.into());
        self
    }

    /// Required: the token endpoint URI (`/oauth/token`).
    pub fn token_uri(mut self, uri: Uri) -> Self {
        self.token_uri = Some(uri);
        self
    }

    /// Optional: the authorization endpoint URI. Required for the
    /// authorization-code grant ([`crate::grant::AuthorizationUrl`]).
    pub fn auth_uri(mut self, uri: Uri) -> Self {
        self.auth_uri = Some(uri);
        self
    }

    /// Optional: the device authorization endpoint URI. Required to use
    /// [`TokenEndpoint::start_device_flow`] (RFC 8628).
    pub fn device_uri(mut self, uri: Uri) -> Self {
        self.device_uri = Some(uri);
        self
    }

    /// Optional: the redirect URI registered with the provider.
    ///
    /// Used by [`crate::grant::AuthorizationUrl`] and appended to the
    /// authorization-code grant body. Per RFC 6749 §4.1.3 it MUST match
    /// the value used in the authorization request.
    pub fn redirect_uri(mut self, uri: Uri) -> Self {
        self.redirect_uri = Some(uri);
        self
    }

    /// How to send client credentials. Defaults to
    /// [`ClientAuthStyle::RequestBody`].
    pub fn auth_style(mut self, style: ClientAuthStyle) -> Self {
        self.auth_style = style;
        self
    }

    /// Inject a transport service. Intended primarily for tests using
    /// `api_client::mock::MockService`; production callers should
    /// usually rely on the default TLS-enabled transport.
    pub fn transport<S>(mut self, service: S) -> Self
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
        self.transport = Some(SharedService::new(service));
        self
    }

    /// Finalize the builder.
    pub fn build(self) -> Result<TokenEndpoint, BuilderError> {
        let client_id = self.client_id.ok_or(BuilderError::MissingClientId)?;
        let token_uri = self.token_uri.ok_or(BuilderError::MissingTokenUri)?;

        let transport = self.transport.unwrap_or_else(default_transport);

        Ok(TokenEndpoint {
            inner: Arc::new(Inner {
                client_id,
                client_secret: self.client_secret,
                auth_uri: self.auth_uri,
                token_uri,
                device_uri: self.device_uri,
                redirect_uri: self.redirect_uri,
                auth_style: self.auth_style,
                transport,
            }),
        })
    }
}

fn default_transport() -> SharedClientService<Body, Body> {
    hyperdriver::Client::build_tcp_http()
        .with_default_tls()
        .build_service()
}

#[cfg(test)]
mod tests {
    use super::*;
    use api_client::mock::MockService;
    use http::StatusCode;

    use crate::grant::{AuthorizationCodeRequest, ClientCredentialsRequest, RefreshRequest};
    use crate::pkce::PkceVerifier;
    use crate::scope::ScopeSet;
    use crate::token::{RefreshToken, TokenType};

    fn token_uri() -> Uri {
        "https://example.com/oauth/token".parse().unwrap()
    }

    fn json_response(status: StatusCode, body: &[u8]) -> (StatusCode, http::HeaderMap, Vec<u8>) {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        (status, headers, body.to_vec())
    }

    fn endpoint_with(mock: MockService) -> TokenEndpoint {
        TokenEndpoint::builder()
            .client_id("the-client")
            .client_secret(Secret::from("the-secret"))
            .token_uri(token_uri())
            .transport(mock)
            .build()
            .unwrap()
    }

    #[test]
    fn builder_requires_client_id_and_token_uri() {
        let err = TokenEndpoint::builder()
            .token_uri(token_uri())
            .build()
            .unwrap_err();
        assert_eq!(err, BuilderError::MissingClientId);

        let err = TokenEndpoint::builder().client_id("x").build().unwrap_err();
        assert_eq!(err, BuilderError::MissingTokenUri);
    }

    #[tokio::test]
    async fn client_credentials_happy_path() {
        let mut mock = MockService::new();
        let (status, headers, body) = json_response(
            StatusCode::OK,
            br#"{"access_token":"atok","token_type":"Bearer","expires_in":3600}"#,
        );
        mock.add("/oauth/token", status, headers, body);
        let endpoint = endpoint_with(mock);

        let scope: ScopeSet = "read write".parse().unwrap();
        let response = endpoint
            .exchange(ClientCredentialsRequest::new().scope(scope))
            .await
            .expect("exchange should succeed");

        assert_eq!(response.access_token.revealed(), "atok");
        assert_eq!(response.token_type, TokenType::Bearer);
        assert_eq!(response.expires_in, Some(3600));
        assert!(response.refresh_token.is_none());
    }

    #[tokio::test]
    async fn authorization_code_with_pkce_happy_path() {
        let mut mock = MockService::new();
        let (status, headers, body) = json_response(
            StatusCode::OK,
            br#"{"access_token":"a","token_type":"Bearer","refresh_token":"r","expires_in":600}"#,
        );
        mock.add("/oauth/token", status, headers, body);

        let endpoint = TokenEndpoint::builder()
            .client_id("c")
            .client_secret(Secret::from("s"))
            .token_uri(token_uri())
            .redirect_uri("https://app.example.com/cb".parse().unwrap())
            .transport(mock)
            .build()
            .unwrap();

        let verifier = PkceVerifier::generate();
        let response = endpoint
            .exchange(AuthorizationCodeRequest::new("the-code").pkce(verifier))
            .await
            .unwrap();
        assert_eq!(response.access_token.revealed(), "a");
        assert_eq!(response.refresh_token.unwrap().revealed(), "r");
    }

    #[tokio::test]
    async fn refresh_grant_happy_path() {
        let mut mock = MockService::new();
        let (status, headers, body) = json_response(
            StatusCode::OK,
            br#"{"access_token":"new","token_type":"Bearer"}"#,
        );
        mock.add("/oauth/token", status, headers, body);
        let endpoint = endpoint_with(mock);

        let refresh = RefreshToken::new(Secret::from("old-refresh"));
        let response = endpoint
            .exchange(RefreshRequest::new(refresh))
            .await
            .unwrap();
        assert_eq!(response.access_token.revealed(), "new");
    }

    #[tokio::test]
    async fn oauth2_error_body_maps_to_token_error() {
        let mut mock = MockService::new();
        let (status, headers, body) = json_response(
            StatusCode::BAD_REQUEST,
            br#"{"error":"invalid_grant","error_description":"bad code"}"#,
        );
        mock.add("/oauth/token", status, headers, body);
        let endpoint = endpoint_with(mock);

        let err = endpoint
            .exchange(AuthorizationCodeRequest::new("nope"))
            .await
            .unwrap_err();

        match err {
            Error::TokenError(resp) => {
                assert_eq!(resp.code, crate::error::TokenErrorCode::InvalidGrant);
                assert_eq!(resp.error_description.as_deref(), Some("bad code"));
            }
            other => panic!("expected TokenError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn non_oauth2_error_falls_back_to_bad_response() {
        let mut mock = MockService::new();
        let (status, headers, body) =
            json_response(StatusCode::INTERNAL_SERVER_ERROR, b"upstream is on fire");
        mock.add("/oauth/token", status, headers, body);
        let endpoint = endpoint_with(mock);

        let err = endpoint
            .exchange(ClientCredentialsRequest::new())
            .await
            .unwrap_err();

        match err {
            Error::BadResponse { status, body } => {
                assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
                assert_eq!(body, "upstream is on fire");
            }
            other => panic!("expected BadResponse, got {other:?}"),
        }
    }
}
