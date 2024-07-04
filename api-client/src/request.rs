use std::time::Duration;

use http::{header::HeaderValue, HeaderName, Uri};

use crate::basic_auth;
use crate::{response::ApiResponse, ApiClient, Authentication};

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;
type Result<T, E = BoxError> = std::result::Result<T, E>;

pub trait RequestExt {
    fn basic_auth<U, P>(self, username: U, password: Option<P>) -> Self
    where
        U: std::fmt::Display,
        P: std::fmt::Display;

    fn bearer_auth<T>(self, token: T) -> Self
    where
        T: std::fmt::Display;

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

#[derive(Debug)]
pub struct RequestBuilder<A> {
    req: http::request::Builder,
    client: ApiClient<A>,
    body: Option<hyperdriver::Body>,
    timeout: Option<Duration>,
}

impl<A> RequestBuilder<A> {
    pub fn new(client: ApiClient<A>, uri: Uri, method: http::Method) -> Self {
        Self {
            req: http::Request::builder().method(method).uri(uri),
            client,
            body: None,
            timeout: None,
        }
    }

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

    pub fn headers_mut(&mut self) -> Option<&mut http::header::HeaderMap> {
        self.req.headers_mut()
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn body<B: Into<hyperdriver::Body>>(self, body: B) -> Self {
        Self {
            body: Some(body.into()),
            ..self
        }
    }

    pub async fn send(self) -> Result<ApiResponse>
    where
        A: Authentication,
    {
        let req = self
            .req
            .body(self.body.unwrap_or_else(hyperdriver::Body::empty))?;

        if let Some(timeout) = self.timeout {
            match tokio::time::timeout(timeout, self.client.execute(req)).await {
                Ok(res) => Ok(res?),
                Err(_) => return Err("Request timed out".into()),
            }
        } else {
            Ok(self.client.execute(req).await?)
        }
    }
}
