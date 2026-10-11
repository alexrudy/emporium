//! Shared test helpers for the Phase 3 integration tests.
#![allow(dead_code)]

//!
//! [`ScriptedMock`] is a `tower::Service` whose responses come from a
//! per-path queue. Each call records the requested path, the
//! `Authorization` header it carried, and the request body, so tests can
//! assert on call counts and what actually went out.

use std::collections::{HashMap, VecDeque};
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use http::{HeaderMap, StatusCode};
use http_body_util::BodyExt as _;
use hyperdriver::Body;

#[derive(Debug, Clone)]
pub struct RecordedRequest {
    pub path: String,
    pub authorization: Option<String>,
    pub body: Vec<u8>,
}

impl RecordedRequest {
    /// Decode an `application/x-www-form-urlencoded` body.
    pub fn form(&self) -> HashMap<String, String> {
        serde_urlencoded::from_bytes(&self.body).unwrap_or_default()
    }
}

#[derive(Debug, Default, Clone)]
pub struct ScriptedMock {
    #[allow(clippy::type_complexity)]
    queues: Arc<Mutex<HashMap<String, VecDeque<(StatusCode, HeaderMap, Vec<u8>)>>>>,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
}

impl ScriptedMock {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enqueue(&self, path: &str, status: StatusCode, headers: HeaderMap, body: Vec<u8>) {
        self.queues
            .lock()
            .unwrap()
            .entry(path.into())
            .or_default()
            .push_back((status, headers, body));
    }

    pub fn enqueue_json(&self, path: &str, status: StatusCode, body: &[u8]) {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        self.enqueue(path, status, headers, body.to_vec());
    }

    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().unwrap().clone()
    }

    pub fn count_for(&self, path: &str) -> usize {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.path == path)
            .count()
    }
}

impl tower::Service<http::Request<Body>> for ScriptedMock {
    type Response = http::Response<Body>;
    type Error = hyperdriver::client::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<Body>) -> Self::Future {
        let queues = self.queues.clone();
        let requests = self.requests.clone();
        Box::pin(async move {
            let path = req.uri().path().to_owned();
            let authorization = req
                .headers()
                .get(http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok().map(String::from));
            let request_body = req
                .into_body()
                .collect()
                .await
                .map(|collected| collected.to_bytes().to_vec())
                .unwrap_or_default();

            requests.lock().unwrap().push(RecordedRequest {
                path: path.clone(),
                authorization,
                body: request_body,
            });

            let (status, headers, body) = queues
                .lock()
                .unwrap()
                .get_mut(&path)
                .unwrap_or_else(|| panic!("no scripted response queued for {path}"))
                .pop_front()
                .unwrap_or_else(|| panic!("response queue exhausted for {path}"));

            let mut builder = http::Response::builder()
                .status(status)
                .version(http::Version::HTTP_11);
            for (k, v) in headers.iter() {
                builder = builder.header(k, v);
            }
            Ok(builder.body(Body::from(bytes::Bytes::from(body))).unwrap())
        })
    }
}
