//! OAuth2-aware HTTP client with proactive refresh.
//!
//! [`OAuth2Client`] wraps an [`api_client::ApiClient<AccessToken>`] plus
//! the [`crate::endpoint::TokenEndpoint`] it should refresh against. It
//! mirrors `ApiClient`'s HTTP method surface (`get`, `post`, ...) but
//! returns an [`OAuth2RequestBuilder`] whose `send()` calls
//! [`OAuth2Client::ensure_fresh`] before the request goes out — so a
//! near-expired token is replaced *before* the API call rather than
//! after a 401.

use std::sync::Arc;
use std::time::Duration;

use api_client::ApiClient;
use api_client::request::RequestBuilder;
use api_client::response::Response;
use chrono::Utc;
use http::header::{HeaderName, HeaderValue};
use http::{Method, Uri};
use hyperdriver::Body;
use serde::Serialize;
use tokio::sync::Mutex;

use crate::endpoint::TokenEndpoint;
use crate::error::Error;
use crate::grant::{ClientCredentialsRequest, RefreshRequest, TokenRequest};
use crate::scope::ScopeSet;
use crate::token::{AccessToken, RefreshToken, TokenResponse, TokenSet};

/// How an [`OAuth2Client`] obtains a fresh access token.
#[derive(Debug, Clone)]
pub enum RefreshStrategy {
    /// Run the client-credentials grant on every refresh. No refresh
    /// token is kept; each refresh is a fresh exchange with the
    /// configured `client_id` / `client_secret`.
    ClientCredentials {
        /// Optional scope set to request on each refresh.
        scope: Option<ScopeSet>,
    },
    /// Exchange a stored refresh token. The token may rotate on each
    /// refresh (RFC 6749 §6); when the server issues a new one, the
    /// stored token is replaced.
    RefreshToken {
        /// Currently-stored refresh token.
        refresh_token: RefreshToken,
        /// Optional scope set to narrow on refresh.
        scope: Option<ScopeSet>,
    },
}

impl RefreshStrategy {
    fn to_request(&self) -> TokenRequest {
        match self {
            Self::ClientCredentials { scope } => {
                let mut r = ClientCredentialsRequest::new();
                if let Some(s) = scope {
                    r = r.scope(s.clone());
                }
                TokenRequest::from(r)
            }
            Self::RefreshToken {
                refresh_token,
                scope,
            } => {
                let mut r = RefreshRequest::new(refresh_token.clone());
                if let Some(s) = scope {
                    r = r.scope(s.clone());
                }
                TokenRequest::from(r)
            }
        }
    }

    fn absorb(&mut self, response: &TokenResponse) {
        if let Self::RefreshToken { refresh_token, .. } = self
            && let Some(rotated) = &response.refresh_token
        {
            *refresh_token = RefreshToken::new(rotated.clone());
        }
    }
}

/// An OAuth2-aware HTTP client that refreshes its access token
/// proactively before every request.
#[derive(Debug, Clone)]
pub struct OAuth2Client {
    api: ApiClient<AccessToken>,
    endpoint: TokenEndpoint,
    strategy: Arc<Mutex<RefreshStrategy>>,
}

impl OAuth2Client {
    /// Construct from a pre-built [`ApiClient`], the
    /// [`TokenEndpoint`] to refresh against, and a [`RefreshStrategy`].
    ///
    /// The `ApiClient`'s authentication slot already holds the current
    /// [`AccessToken`]; `OAuth2Client::ensure_fresh` will call
    /// [`ApiClient::refresh_auth`] to install new tokens via the same
    /// `ArcSwap` slot.
    pub fn new(
        endpoint: TokenEndpoint,
        api: ApiClient<AccessToken>,
        strategy: RefreshStrategy,
    ) -> Self {
        Self {
            api,
            endpoint,
            strategy: Arc::new(Mutex::new(strategy)),
        }
    }

    /// Build from a [`TokenSet`] issued via the authorization-code
    /// grant. Requires the set to carry a refresh token.
    pub fn from_authorization_code(
        endpoint: TokenEndpoint,
        api_base: Uri,
        tokens: TokenSet,
    ) -> Result<Self, Error> {
        let refresh_token = tokens.refresh_token.ok_or(Error::NoRefreshToken)?;
        let scope = tokens.scope;
        let api = ApiClient::new(api_base, tokens.access_token);
        Ok(Self::new(
            endpoint,
            api,
            RefreshStrategy::RefreshToken {
                refresh_token,
                scope,
            },
        ))
    }

    /// Build by exchanging a fresh client-credentials grant.
    ///
    /// Performs the initial network round-trip; the returned client is
    /// ready to issue API requests.
    pub async fn from_client_credentials(
        endpoint: TokenEndpoint,
        api_base: Uri,
        scope: Option<ScopeSet>,
    ) -> Result<Self, Error> {
        let mut request = ClientCredentialsRequest::new();
        if let Some(s) = &scope {
            request = request.scope(s.clone());
        }
        let response = endpoint.exchange(request).await?;
        let tokens = TokenSet::from(response);
        let api = ApiClient::new(api_base, tokens.access_token);
        Ok(Self::new(
            endpoint,
            api,
            RefreshStrategy::ClientCredentials { scope },
        ))
    }

    /// Refresh the access token if (and only if) the currently-stored
    /// one is past its `expires_at` deadline (with the 60-second clock-
    /// drift offset already baked in).
    ///
    /// Cheap when the cached token is still valid: takes a snapshot of
    /// the current `AccessToken`, checks `is_expired`, and returns
    /// immediately. When a refresh is needed, the strategy mutex is
    /// held only long enough for one round-trip — concurrent callers
    /// queue on it, double-check the now-fresh token, and skip the
    /// extra `/token` request.
    pub async fn ensure_fresh(&self) -> Result<(), Error> {
        if !self.access_token_expired() {
            return Ok(());
        }

        let mut strategy = self.strategy.lock().await;

        // Double-check: another task may have refreshed while we waited.
        if !self.access_token_expired() {
            return Ok(());
        }

        self.refresh_locked(&mut strategy).await
    }

    /// Force a refresh now, ignoring whether the current token has
    /// expired. Useful when the server is observed to revoke a token
    /// early — pair with the 401 the API returned.
    pub async fn refresh(&self) -> Result<(), Error> {
        let mut strategy = self.strategy.lock().await;
        self.refresh_locked(&mut strategy).await
    }

    async fn refresh_locked(&self, strategy: &mut RefreshStrategy) -> Result<(), Error> {
        let request = strategy.to_request();
        let response = self.endpoint.exchange(request).await?;
        strategy.absorb(&response);
        let set = TokenSet::from(response);
        self.api.refresh_auth(set.access_token);
        Ok(())
    }

    fn access_token_expired(&self) -> bool {
        self.api.auth().is_expired(Utc::now())
    }

    /// Escape hatch: borrow the inner `ApiClient`. Requests sent via the
    /// returned client **skip** the auto-refresh check — call
    /// [`OAuth2Client::ensure_fresh`] yourself first if you need a
    /// guaranteed-fresh token.
    pub fn api_client(&self) -> &ApiClient<AccessToken> {
        &self.api
    }

    /// Borrow the underlying token endpoint.
    pub fn endpoint(&self) -> &TokenEndpoint {
        &self.endpoint
    }

    fn wrap(&self, inner: RequestBuilder) -> OAuth2RequestBuilder {
        OAuth2RequestBuilder {
            inner,
            client: self.clone(),
        }
    }

    /// Build a GET request.
    pub fn get(&self, endpoint: &str) -> OAuth2RequestBuilder {
        self.wrap(self.api.get(endpoint))
    }

    /// Build a POST request.
    pub fn post(&self, endpoint: &str) -> OAuth2RequestBuilder {
        self.wrap(self.api.post(endpoint))
    }

    /// Build a PUT request.
    pub fn put(&self, endpoint: &str) -> OAuth2RequestBuilder {
        self.wrap(self.api.put(endpoint))
    }

    /// Build a PATCH request.
    pub fn patch(&self, endpoint: &str) -> OAuth2RequestBuilder {
        self.wrap(self.api.patch(endpoint))
    }

    /// Build a DELETE request.
    pub fn delete(&self, endpoint: &str) -> OAuth2RequestBuilder {
        self.wrap(self.api.delete(endpoint))
    }

    /// Build a HEAD request.
    pub fn head(&self, endpoint: &str) -> OAuth2RequestBuilder {
        self.wrap(self.api.head(endpoint))
    }

    /// Build an OPTIONS request.
    pub fn options(&self, endpoint: &str) -> OAuth2RequestBuilder {
        self.wrap(self.api.options(endpoint))
    }

    /// Build a request with a custom method against an absolute URI.
    pub fn builder(&self, uri: Uri, method: Method) -> OAuth2RequestBuilder {
        self.wrap(self.api.builder(uri, method))
    }
}

/// Builder returned by [`OAuth2Client::get`] / [`OAuth2Client::post`] /
/// etc. Forwards every chainable method to the inner
/// [`api_client::request::RequestBuilder`] and intercepts `send()` to
/// refresh the access token first.
#[derive(Debug)]
pub struct OAuth2RequestBuilder {
    inner: RequestBuilder,
    client: OAuth2Client,
}

impl OAuth2RequestBuilder {
    /// Add a header.
    pub fn header<K, V>(self, key: K, value: V) -> Self
    where
        HeaderName: TryFrom<K>,
        <HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        Self {
            inner: self.inner.header(key, value),
            client: self.client,
        }
    }

    /// Add multiple headers.
    pub fn headers<I, K, V>(self, headers: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        HeaderName: TryFrom<K>,
        <HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        Self {
            inner: self.inner.headers(headers),
            client: self.client,
        }
    }

    /// Set the HTTP version.
    pub fn version(self, version: http::Version) -> Self {
        Self {
            inner: self.inner.version(version),
            client: self.client,
        }
    }

    /// Append query parameters.
    pub fn query<T: Serialize + ?Sized>(self, query: &T) -> Result<Self, Error> {
        Ok(Self {
            inner: self.inner.query(query)?,
            client: self.client,
        })
    }

    /// Set a per-request timeout.
    pub fn timeout(self, timeout: Duration) -> Self {
        Self {
            inner: self.inner.timeout(timeout),
            client: self.client,
        }
    }

    /// Set the body.
    pub fn body<B: Into<Body>>(self, body: B) -> Self {
        Self {
            inner: self.inner.body(body),
            client: self.client,
        }
    }

    /// Set the body to JSON-serialized data, with the appropriate
    /// `Content-Type` header.
    pub fn json<D: Serialize>(self, body: D) -> Result<Self, Error> {
        Ok(Self {
            inner: self.inner.json(body)?,
            client: self.client,
        })
    }

    /// Refresh the access token if needed, then send the request.
    pub async fn send(self) -> Result<Response, Error> {
        self.client.ensure_fresh().await?;
        self.inner
            .send()
            .await
            .map_err(|e| Error::Transport(api_client::Error::Request(e)))
    }
}
