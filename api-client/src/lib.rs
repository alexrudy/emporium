//! A library for building HTTP clients for APIs

#![allow(clippy::arc_with_non_send_sync)]

use std::future::Future;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use arc_swap::Guard;
use http::Method;
use http::Uri;
use hyperdriver::service::SharedService;
use hyperdriver::Body;
pub use secret::Secret;
use tower::util::BoxCloneService;
use tower::ServiceExt;

mod adapt;
mod authentication;
pub mod error;
mod paginate;
pub mod request;
pub mod response;
mod retry;
pub mod timeout;
pub mod uri;

pub use self::adapt::AdaptClientIncomingLayer;
pub use self::authentication::{
    basic_auth, Authentication, AuthenticationLayer, AuthenticationService, BasicAuth, BearerAuth,
};
pub use self::error::Error;
pub use self::paginate::{Paginated, PaginatedData, PaginationInfo, Paginator};
pub use self::request::RequestBuilder;
pub use self::request::RequestExt;
use self::response::Response;
pub use self::retry::{Attempts, Backoff};
use self::timeout::SharedDuration;
use self::timeout::SharedTimeoutLayer;
use self::uri::UriExtension as _;

/// A boxed service used for API requests in the Client
pub type ApiService =
    BoxCloneService<http::Request<Body>, http::Response<Body>, hyperdriver::client::Error>;

/// A boxed future used for API requests in the Client
pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The default API client timeout
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
struct InnerClient<A> {
    base: ArcSwap<Uri>,
    inner: hyperdriver::client::SharedClientService<Body, Body>,
    authentication: Arc<ArcSwap<A>>,
    timeout: SharedDuration,
}

/// A client for accessing APIs over HTTP / HTTPS
///
/// Useful inner object to wrap for individual API clients.
#[derive(Debug, Clone)]
pub struct ApiClient<A> {
    inner: Arc<InnerClient<A>>,
}

impl<A> ApiClient<A>
where
    A: Authentication + Send + Sync + 'static,
{
    /// Create a new API Client from a base URL and an authentication method
    pub fn new(base: Uri, authentication: A) -> Self {
        let authentication = Arc::new(ArcSwap::new(Arc::new(authentication)));
        let timeout_layer = SharedTimeoutLayer::new(DEFAULT_TIMEOUT);
        let timeout = timeout_layer.timeout().clone();

        let inner = hyperdriver::Client::build_tcp_http()
            .with_default_tls()
            .layer(timeout_layer)
            .layer(AuthenticationLayer::new(authentication.clone()))
            .build_service();

        ApiClient {
            inner: Arc::new(InnerClient {
                base: ArcSwap::new(Arc::new(base)),
                inner: SharedService::new(inner),
                authentication,
                timeout,
            }),
        }
    }

    /// Create a new API Client from a base URL and an authentication method, as well as an inner service
    /// which will be used to make the HTTP requests.
    pub fn new_with_inner_service<S>(base: Uri, authentication: A, inner: S) -> Self
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
        let authentication = Arc::new(ArcSwap::new(Arc::new(authentication)));
        let timeout_layer = SharedTimeoutLayer::new(DEFAULT_TIMEOUT);
        let timeout = timeout_layer.timeout().clone();
        let service = tower::ServiceBuilder::new()
            .layer(SharedService::layer())
            .layer(timeout_layer)
            .layer(AuthenticationLayer::new(authentication.clone()))
            .service(inner);

        ApiClient {
            inner: Arc::new(InnerClient {
                base: ArcSwap::new(Arc::new(base)),
                inner: service,
                authentication,
                timeout,
            }),
        }
    }

    /// Set the base URL for the client
    pub fn set_base(&self, base: Uri) {
        self.inner.base.store(Arc::new(base));
    }

    /// Get a reference to the current base URI
    pub fn get_base(&self) -> impl Deref<Target = Arc<Uri>> {
        self.inner.base.load()
    }

    /// Get the current client timeout
    pub fn get_timeout(&self) -> Duration {
        self.inner.timeout.get()
    }

    /// Set the client timeout
    pub fn set_timeout(&self, timeout: Duration) {
        self.inner.timeout.set(timeout)
    }

    /// Replace the authentication method for the client
    pub fn refresh_auth(&self, authentication: A) {
        self.inner.authentication.store(Arc::new(authentication));
    }

    /// Get the current authentication method
    pub fn auth(&self) -> Guard<Arc<A>> {
        self.inner.authentication.as_ref().load()
    }

    /// Get the inner service used to make HTTP requests
    pub fn inner(&self) -> &hyperdriver::client::SharedClientService<Body, Body> {
        &self.inner.inner
    }
}

impl ApiClient<BearerAuth> {
    /// Create a new API Client with a Bearer token authentication method
    pub fn new_bearer_auth<K: Into<Secret>>(base: Uri, token: K) -> Self {
        Self::new(base, BearerAuth::new(token.into()))
    }
}

impl<A> ApiClient<A>
where
    A: Authentication,
{
    fn join_endpoint(&self, endpoint: &str) -> Uri {
        (*self.inner.base.load_full()).clone().join(endpoint)
    }

    /// Create a GET request builder for the client
    pub fn get(&self, endpoint: &str) -> RequestBuilder {
        let url = self.join_endpoint(endpoint);
        RequestBuilder::new(self.clone(), url, Method::GET)
    }

    /// Create a PUT request builder for the client
    pub fn put(&self, endpoint: &str) -> RequestBuilder {
        let url = self.join_endpoint(endpoint);
        RequestBuilder::new(self.clone(), url, Method::PUT)
    }

    /// Create a POST request builder for the client
    pub fn post(&self, endpoint: &str) -> RequestBuilder {
        let url = self.join_endpoint(endpoint);
        RequestBuilder::new(self.clone(), url, Method::POST)
    }

    /// Create a DELETE request builder for the client
    pub fn delete(&self, endpoint: &str) -> RequestBuilder {
        let url = self.join_endpoint(endpoint);
        RequestBuilder::new(self.clone(), url, Method::DELETE)
    }

    /// Execute a request and return the response
    pub async fn execute(&self, req: http::Request<Body>) -> Result<Response, Error> {
        let parts = req.parts();

        let response = self
            .inner
            .inner
            .clone()
            .oneshot(req)
            .await
            .map_err(Error::Request)?;
        Ok(Response::new(parts, response))
    }
}

/// A set of tools to help with testing API clients
pub mod mock {
    use bytes::Bytes;
    use http::response;
    use hyperdriver::Body;
    use std::collections::HashMap;

    /// A mock response for testing API clients
    #[derive(Debug, Clone)]
    pub struct MockResponse {
        status: http::StatusCode,
        headers: http::HeaderMap,
        body: Vec<u8>,
    }

    impl MockResponse {
        /// Create a new mock response
        pub fn new(status: http::StatusCode, headers: http::HeaderMap, body: Vec<u8>) -> Self {
            Self {
                status,
                headers,
                body,
            }
        }
    }

    /// A mock service for testing API clients which returns pre-configured responses
    /// based on the requested path.
    #[derive(Debug, Default, Clone)]
    pub struct MockService {
        responses: HashMap<String, MockResponse>,
    }

    impl MockService {
        /// Create a new mock service
        pub fn new() -> Self {
            Self {
                responses: Default::default(),
            }
        }

        /// Add a new response to the mock service
        pub fn add(
            &mut self,
            path: &str,
            status: http::StatusCode,
            headers: http::HeaderMap,
            body: Vec<u8>,
        ) {
            let response = MockResponse::new(status, headers, body);
            self.responses.insert(path.to_owned(), response);
        }
    }

    impl tower::Service<http::Request<Body>> for MockService {
        type Response = http::Response<Body>;
        type Error = hyperdriver::client::Error;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(
            &mut self,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: http::Request<Body>) -> Self::Future {
            let path = req.uri().path().to_owned();
            let response = self.responses.get(&path).unwrap_or_else(|| {
                panic!(
                    "No response configured for path: {path}",
                    path = req.uri().path()
                )
            });

            let mut builder = response::Builder::new()
                .status(response.status)
                .version(http::Version::HTTP_11);

            for (key, value) in response.headers.iter() {
                builder = builder.header(key, value);
            }

            let response = builder
                .body(hyperdriver::Body::from(Bytes::from(response.body.clone())))
                .unwrap();

            std::future::ready(Ok(response))
        }
    }
}

#[cfg(test)]
mod test {

    use self::response::ResponseExt as _;

    use super::*;

    #[test]
    fn extensions_produce_send_futures() {
        let client = ApiClient::new_bearer_auth(
            "http://httpbin.org/get/".parse().unwrap(),
            Secret::from("secret garden"),
        );
        let builder = client.get("frobulator");

        fn assert_send<T: Send>(_t: T) {}

        let fut = builder.send();
        assert_send(fut);
    }

    #[tokio::test]
    async fn mock_client_works() {
        let mut mock = crate::mock::MockService::new();
        mock.add(
            "/get/",
            http::StatusCode::OK,
            http::HeaderMap::new(),
            b"frobulator".to_vec(),
        );

        let client = ApiClient::new_with_inner_service(
            "http://httpbin.org/get/".parse().unwrap(),
            BearerAuth::new(Secret::from("secret garden")),
            mock,
        );

        let response = client.get("").send().await.unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
    }
}
