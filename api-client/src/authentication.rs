//! Authentication for API clients.
//!
//! The `Authentication` trait is used to authenticate with an API queried via the `ApiClient`.
//!
//! Three implementations are provided:
//! - `BasicAuth` for Basic authentication
//! - `BearerAuth` for Bearer token authentication
//! - `()` for no authentication

use std::sync::Arc;

use arc_swap::ArcSwap;
use http::HeaderValue;
use secret::Secret;
use tower::layer::Layer;

/// Create a basic authentication header value, with the password being optional.
///
/// Basic authentication Base64 encodes the username and password, separated by a colon.
///
/// # Example
/// ```rust
/// use api_client::basic_auth;
/// let username = "username";
/// let password = "password";
///
/// let header = basic_auth(username, Some(password));
/// assert_eq!(header.to_str().unwrap(), "Basic dXNlcm5hbWU6cGFzc3dvcmQ=");
/// ```
pub fn basic_auth<U, P>(username: U, password: Option<P>) -> HeaderValue
where
    U: std::fmt::Display,
    P: std::fmt::Display,
{
    use base64::prelude::BASE64_STANDARD;
    use base64::write::EncoderWriter;
    use std::io::Write;

    let mut buf = b"Basic ".to_vec();
    {
        let mut encoder = EncoderWriter::new(&mut buf, &BASE64_STANDARD);
        let _ = write!(encoder, "{}:", username);
        if let Some(password) = password {
            let _ = write!(encoder, "{}", password);
        }
    }
    let mut header = HeaderValue::from_bytes(&buf).expect("base64 is always valid HeaderValue");
    header.set_sensitive(true);
    header
}

/// Trait to represent authenticating with an API queried via reqwest.
pub trait Authentication: Clone {
    /// Called by the `ApiClient` to implement authorization.
    fn authenticate<B>(&self, req: http::Request<B>) -> http::Request<B>;
}

/// Authentication with a bearer token, often used with an API key.
///
/// The token is stored as a [Secret] to prevent it from being logged.
///
/// # Example
/// ```rust
/// use api_client::BearerAuth;
///
/// let key = "my-secret";
/// let auth = BearerAuth::new(key);
/// let header = auth.header_value();
///
/// assert_eq!(header.to_str().unwrap(), "Bearer my-secret");
/// ```
#[derive(Debug, Clone)]
pub struct BearerAuth(Secret);

impl BearerAuth {
    /// Create a new Bearer authentication with a given key.
    pub fn new<K: Into<Secret>>(key: K) -> Self {
        BearerAuth(key.into())
    }

    /// Get the header value for the Bearer token.
    pub fn header_value(&self) -> HeaderValue {
        let mut header_value: HeaderValue = self
            .0
            .bearer()
            .expect("bearer token is a valid HTTP header value");
        header_value.set_sensitive(true);
        header_value
    }
}

impl Authentication for BearerAuth {
    fn authenticate<B>(&self, mut req: http::Request<B>) -> http::Request<B> {
        if !req.headers().contains_key(http::header::AUTHORIZATION) {
            let headers = req.headers_mut();
            headers.append(http::header::AUTHORIZATION, self.header_value());
        } else {
            tracing::warn!("{} header already set", http::header::AUTHORIZATION);
        }
        req
    }
}

/// Basic authentication, with the password being optional.
///
/// Basic authentication Base64 encodes the username and password, separated by a colon.
/// in a header value prefixed with "Basic ".
#[derive(Debug, Clone)]
pub struct BasicAuth {
    username: String,
    password: Option<Secret>,
}

impl BasicAuth {
    /// Create a new Basic authentication with a given username and optional password.
    pub fn new<U, P>(username: U, password: Option<P>) -> Self
    where
        U: Into<String>,
        P: Into<Secret>,
    {
        BasicAuth {
            username: username.into(),
            password: password.map(Into::into),
        }
    }
}

impl Authentication for BasicAuth {
    fn authenticate<B>(&self, mut req: http::Request<B>) -> http::Request<B> {
        if !req.headers().contains_key(http::header::AUTHORIZATION) {
            let header_value =
                basic_auth(&self.username, self.password.as_ref().map(Secret::revealed));
            let headers = req.headers_mut();
            headers.append(http::header::AUTHORIZATION, header_value);
        } else {
            tracing::warn!("{} header already set", http::header::AUTHORIZATION);
        }
        req
    }
}

impl Authentication for () {
    fn authenticate<B>(&self, req: http::Request<B>) -> http::Request<B> {
        req
    }
}

/// A layer to provide a swappable authentication mechanism.
///
/// This allows users to update the authentication mechanism without needing to recreate the client.
#[derive(Debug)]
pub struct AuthenticationLayer<A> {
    auth: Arc<ArcSwap<A>>,
}

impl<A> Clone for AuthenticationLayer<A> {
    fn clone(&self) -> Self {
        Self {
            auth: self.auth.clone(),
        }
    }
}

impl<A> AuthenticationLayer<A> {
    pub(crate) fn new(auth: Arc<ArcSwap<A>>) -> Self {
        Self { auth }
    }
}

impl<A, S> Layer<S> for AuthenticationLayer<A> {
    type Service = AuthenticationService<A, S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthenticationService::new(inner, self.auth.clone())
    }
}

/// A service to provide a swappable authentication mechanism.
#[derive(Debug)]
pub struct AuthenticationService<A, S> {
    inner: S,
    auth: Arc<ArcSwap<A>>,
}

impl<A, S: Clone> Clone for AuthenticationService<A, S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            auth: self.auth.clone(),
        }
    }
}

impl<A, S> AuthenticationService<A, S> {
    pub(crate) fn new(inner: S, auth: Arc<ArcSwap<A>>) -> Self {
        Self { inner, auth }
    }

    /// Set the authentication object, replacing the one currently in use.
    pub fn set_auth(&self, auth: A) {
        self.auth.store(Arc::new(auth));
    }
}

impl<A, S, BIn, BOut> tower::Service<http::Request<BIn>> for AuthenticationService<A, S>
where
    A: Authentication,
    S: tower::Service<http::Request<BIn>, Response = http::Response<BOut>>,
    S::Future: Send + 'static,
{
    type Response = http::Response<BOut>;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<BIn>) -> Self::Future {
        let req = self.auth.load().authenticate(req);
        self.inner.call(req)
    }
}
