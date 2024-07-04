use std::sync::Arc;

use arc_swap::ArcSwap;
use http::HeaderValue;
use secret::Secret;
use tower::layer::Layer;

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
    /// Called by [Secret] to implement authorization.
    fn authenticate<B>(&self, req: http::Request<B>) -> http::Request<B>;
}

/// Authentication
#[derive(Debug, Clone)]
pub struct BearerAuth(Secret);

impl BearerAuth {
    pub fn new(key: Secret) -> Self {
        BearerAuth(key)
    }
}

impl Authentication for BearerAuth {
    fn authenticate<B>(&self, mut req: http::Request<B>) -> http::Request<B> {
        if !req.headers().contains_key(http::header::AUTHORIZATION) {
            let mut header_value: http::header::HeaderValue =
                format!("Bearer {}", self.0.revealed()).parse().unwrap();
            header_value.set_sensitive(true);
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
}

impl<A, S, B> tower::Service<http::Request<B>> for AuthenticationService<A, S>
where
    A: Authentication,
    S: tower::Service<http::Request<B>, Response = http::Response<B>>,
    S::Future: Send + 'static,
{
    type Response = http::Response<B>;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        let req = self.auth.load().authenticate(req);
        self.inner.call(req)
    }
}
