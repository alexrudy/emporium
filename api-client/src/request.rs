//! Request building utilities

use std::time::Duration;

use http::Uri;
use http::{header::HeaderValue, HeaderName};
use serde::Serialize;
use tower::ServiceExt as _;

use crate::basic_auth;
use crate::error::Error;

use crate::uri::UriExtension;
use crate::{response::Response, ApiClient};

// type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;
type Result<T, E = Error> = std::result::Result<T, E>;

/// Extension trait for HTTP requests
pub trait RequestExt {
    /// Add a basic authentication header to the request
    fn basic_auth<U, P>(self, username: U, password: Option<P>) -> Self
    where
        U: std::fmt::Display,
        P: std::fmt::Display;

    /// Add a bearer authentication header to the request
    fn bearer_auth<T>(self, token: T) -> Self
    where
        T: std::fmt::Display;

    /// Get the parts of the request, excluding the body, without
    /// consuming the request
    fn parts(&self) -> http::request::Parts;
}

impl<B> RequestExt for http::Request<B> {
    fn basic_auth<U, P>(mut self, username: U, password: Option<P>) -> Self
    where
        U: std::fmt::Display,
        P: std::fmt::Display,
    {
        let hrds = self.headers_mut();
        hrds.append(http::header::AUTHORIZATION, basic_auth(username, password));

        self
    }

    fn bearer_auth<T>(mut self, token: T) -> Self
    where
        T: std::fmt::Display,
    {
        let mut value = HeaderValue::from_str(&format!("Bearer {}", token)).unwrap();
        value.set_sensitive(true);

        self.headers_mut()
            .append(http::header::AUTHORIZATION, value);

        self
    }

    fn parts(&self) -> http::request::Parts {
        let mut builder = http::request::Request::builder()
            .uri(self.uri().clone())
            .method(self.method().clone());

        if let Some(headers) = builder.headers_mut() {
            *headers = self.headers().clone();
        }

        let (parts, _) = builder.body(()).unwrap().into_parts();
        parts
    }
}

impl RequestExt for http::request::Builder {
    fn basic_auth<U, P>(self, username: U, password: Option<P>) -> Self
    where
        U: std::fmt::Display,
        P: std::fmt::Display,
    {
        self.header(http::header::AUTHORIZATION, basic_auth(username, password))
    }

    fn bearer_auth<T>(self, token: T) -> Self
    where
        T: std::fmt::Display,
    {
        let mut value = HeaderValue::from_str(&format!("Bearer {}", token)).unwrap();
        value.set_sensitive(true);

        self.header(http::header::AUTHORIZATION, value)
    }

    fn parts(&self) -> http::request::Parts {
        let mut builder = http::request::Request::builder()
            .uri(self.uri_ref().expect("valid request").clone())
            .method(self.method_ref().expect("valid request").clone());

        if let Some(headers) = builder.headers_mut() {
            *headers = self.headers_ref().expect("valid request").clone();
        }

        let (parts, _) = builder.body(()).unwrap().into_parts();
        parts
    }
}

/// Builder for HTTP requests on an API client
#[derive(Debug)]
pub struct RequestBuilder {
    req: http::request::Builder,
    client: hyperdriver::client::SharedClientService<hyperdriver::Body>,
    body: Option<hyperdriver::Body>,
    timeout: Option<Duration>,
}

impl RequestBuilder {
    /// Create a new request builder
    pub fn new<A>(client: ApiClient<A>, uri: Uri, method: http::Method) -> Self {
        Self {
            req: http::Request::builder().method(method).uri(uri),
            client: client.inner.inner.clone(),
            body: None,
            timeout: None,
        }
    }

    /// Add a header to the request
    pub fn header<K, V>(mut self, key: K, value: V) -> Self
    where
        HeaderName: TryFrom<K>,
        <HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        self.req = self.req.header(key, value);
        self
    }

    /// Add multiple headers to the request
    pub fn headers<I, K, V>(mut self, headers: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        HeaderName: TryFrom<K>,
        <HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        for (key, value) in headers {
            self.req = self.req.header(key, value);
        }

        self
    }

    /// Get a mutable reference to the headers of the request
    pub fn headers_mut(&mut self) -> Option<&mut http::header::HeaderMap> {
        self.req.headers_mut()
    }

    /// Add query parameters to the request
    pub fn query<T: Serialize + ?Sized>(mut self, query: &T) -> Result<Self, Error> {
        let uri = self.req.uri_ref().expect("missing uri").clone();
        self.req = self.req.uri(uri.append_query(query)?);
        Ok(self)
    }

    /// Set the timeout for the request
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set the body of the request
    pub fn body<B: Into<hyperdriver::Body>>(self, body: B) -> Self {
        Self {
            body: Some(body.into()),
            ..self
        }
    }

    /// Set the body of the request as JSON
    pub fn json<D: Serialize>(self, body: D) -> Result<Self> {
        let body = bytes::Bytes::from(
            serde_json::to_vec(&body).map_err(|err| Error::ResponseBody(err.into()))?,
        );
        Ok(self.body(body))
    }

    /// Send the request and return the response
    pub async fn send(self) -> Result<Response, hyperdriver::client::Error> {
        let req = self
            .req
            .body(self.body.unwrap_or_else(hyperdriver::Body::empty))
            .expect("valid request");

        let parts = req.parts();
        let future = self.client.oneshot(req);

        if let Some(timeout) = self.timeout {
            match tokio::time::timeout(timeout, future).await {
                Ok(res) => Ok(res.map(|response| Response::new(parts, response))?),
                Err(_) => Err(hyperdriver::client::Error::RequestTimeout),
            }
        } else {
            Ok(future
                .await
                .map(|response| Response::new(parts, response))?)
        }
    }

    /// Build the request
    pub fn build(self) -> Result<http::Request<hyperdriver::Body>, http::Error> {
        self.req
            .body(self.body.unwrap_or_else(hyperdriver::Body::empty))
    }
}
