#![allow(clippy::arc_with_non_send_sync)]

use std::future::Future;
use std::sync::Arc;

use arc_swap::ArcSwap;
use arc_swap::Guard;
use http::Method;
use http::Uri;
use hyperdriver::service::SharedService;
pub use secret::Secret;
use tower::util::BoxCloneService;
use tower::ServiceExt;

mod authentication;
mod paginate;
pub mod request;
pub mod response;
mod retry;
pub mod uri;

pub use self::authentication::{
    basic_auth, Authentication, AuthenticationLayer, AuthenticationService, BearerAuth,
};
pub use self::paginate::{Paginated, PaginatedData, PaginationInfo, Paginator};
pub use self::request::RequestBuilder;
pub use self::request::RequestExt;
use self::response::ApiResponse;
pub use self::retry::{Attempts, Backoff};
use self::uri::UriExtension as _;

pub type ApiService = BoxCloneService<
    hyperdriver::body::Request,
    hyperdriver::body::Response,
    hyperdriver::client::Error,
>;
pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A client for accessing APIs over HTTP / HTTPS
///
/// Useful inner object to wrap for individual API clients.
#[derive(Debug, Clone)]
pub struct ApiClient<A> {
    base: Arc<ArcSwap<Uri>>,
    inner: hyperdriver::client::SharedClientService<hyperdriver::Body>,
    authentication: Arc<ArcSwap<A>>,
}

impl<A> ApiClient<A>
where
    A: Authentication + Send + Sync + 'static,
{
    /// Create a new API Client from a base URL and an authentication method
    pub fn new(base: Uri, authentication: A) -> Self {
        let authentication = Arc::new(ArcSwap::new(Arc::new(authentication)));
        let inner = hyperdriver::Client::build_tcp_http()
            .with_default_tls()
            .layer(AuthenticationLayer::new(authentication.clone()))
            .build_service();

        ApiClient {
            base: Arc::new(ArcSwap::new(Arc::new(base))),
            inner,
            authentication,
        }
    }

    pub fn new_with_inner_service<S>(base: Uri, authentication: A, inner: S) -> Self
    where
        S: tower::Service<
                hyperdriver::body::Request,
                Response = hyperdriver::body::Response,
                Error = hyperdriver::client::Error,
            > + Clone
            + Send
            + Sync
            + 'static,
        S::Future: Send + 'static,
    {
        let authentication = Arc::new(ArcSwap::new(Arc::new(authentication)));

        let service = tower::ServiceBuilder::new()
            .layer(SharedService::layer())
            .layer(AuthenticationLayer::new(authentication.clone()))
            .service(inner);

        ApiClient {
            base: Arc::new(ArcSwap::new(Arc::new(base))),
            inner: service,
            authentication,
        }
    }

    pub fn set_base(&self, base: Uri) {
        self.base.store(Arc::new(base));
    }

    pub fn refresh_auth(&self, authentication: A) {
        self.authentication.store(Arc::new(authentication));
    }

    pub fn auth(&self) -> Guard<Arc<A>> {
        self.authentication.as_ref().load()
    }

    pub fn inner(&self) -> &hyperdriver::client::SharedClientService<hyperdriver::Body> {
        &self.inner
    }
}

impl ApiClient<BearerAuth> {
    pub fn new_bearer_auth<K: Into<Secret>>(base: Uri, token: K) -> Self {
        Self::new(base, BearerAuth::new(token.into()))
    }
}

impl<A> ApiClient<A>
where
    A: Authentication,
{
    pub fn get(&self, endpoint: &str) -> RequestBuilder<A> {
        let url = (*self.base.load_full()).clone().join(endpoint);
        RequestBuilder::new(self.clone(), url, Method::GET)
    }

    pub fn put(&self, endpoint: &str) -> RequestBuilder<A> {
        let url = (*self.base.load_full()).clone().join(endpoint);
        RequestBuilder::new(self.clone(), url, Method::PUT)
    }

    pub fn post(&self, endpoint: &str) -> RequestBuilder<A> {
        let url = (*self.base.load_full()).clone().join(endpoint);
        RequestBuilder::new(self.clone(), url, Method::POST)
    }

    pub fn delete(&self, endpoint: &str) -> RequestBuilder<A> {
        let url = (*self.base.load_full()).clone().join(endpoint);
        RequestBuilder::new(self.clone(), url, Method::DELETE)
    }

    pub async fn execute(
        &self,
        req: hyperdriver::body::Request,
    ) -> Result<ApiResponse, hyperdriver::client::Error> {
        let parts = req.parts();

        let response = self.inner.clone().oneshot(req).await?;
        Ok(ApiResponse::new(parts, response))
    }
}

pub mod mock {
    use bytes::Bytes;
    use http::response;
    use std::collections::HashMap;

    #[derive(Debug, Clone)]
    pub struct MockResponse {
        status: http::StatusCode,
        headers: http::HeaderMap,
        body: Vec<u8>,
    }

    impl MockResponse {
        pub fn new(status: http::StatusCode, headers: http::HeaderMap, body: Vec<u8>) -> Self {
            Self {
                status,
                headers,
                body,
            }
        }
    }

    #[derive(Debug, Default, Clone)]
    pub struct MockService {
        responses: HashMap<String, MockResponse>,
    }

    impl MockService {
        pub fn new() -> Self {
            Self {
                responses: Default::default(),
            }
        }

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

    impl tower::Service<hyperdriver::body::Request> for MockService {
        type Response = hyperdriver::body::Response;
        type Error = hyperdriver::client::Error;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(
            &mut self,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: hyperdriver::body::Request) -> Self::Future {
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
