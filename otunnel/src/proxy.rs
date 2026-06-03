use std::{fmt, pin::Pin, task::Context};

use axum::body::Body;
use axum::extract::FromRequestParts;
use axum::response::{IntoResponse, Redirect};
use http::{Request, Response};
use hyper::body::Incoming;
use tower_http::request_id::{MakeRequestId, RequestId};
use uuid::Uuid;

use crate::{auth::OptionalCurrentUser, state::AppState};

#[derive(Debug, Clone)]
pub struct ProxyLayer {
    state: AppState,
}

impl ProxyLayer {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }
}

impl<S> tower::Layer<S> for ProxyLayer {
    type Service = ProxyService<S>;

    fn layer(&self, service: S) -> Self::Service {
        ProxyService::new(self.state.clone(), service)
    }
}

#[derive(Debug, Clone)]
pub struct ProxyService<S> {
    state: AppState,
    service: S,
}

impl<S> ProxyService<S> {
    fn new(state: AppState, service: S) -> Self {
        Self { state, service }
    }
}

impl<S> tower::Service<Request<Body>> for ProxyService<S>
where
    S: tower::Service<Request<Body>, Response = Response<Incoming>> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;

    type Error = S::Error;

    type Future = ProxyFuture<S::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let state = self.state.clone();
        let connections = self.service.clone();
        let mut connections = std::mem::replace(&mut self.service, connections);

        ProxyFuture::new(async move {
            let (mut parts, body) = req.into_parts();
            let OptionalCurrentUser(user) =
                OptionalCurrentUser::from_request_parts(&mut parts, &state)
                    .await
                    .unwrap();

            if let Some(user) = user {
                //TODO: Do we need to do host translation here?
                tracing::trace!("Processing request for {}", user.username);

                parts.uri = state.rewrite_uri(&parts.uri);

                let req = Request::from_parts(parts, body);
                return connections
                    .call(req)
                    .await
                    .map(|response| response.map(|incoming| Body::new(incoming)));
            }

            let return_to = parts
                .uri
                .path_and_query()
                .map_or_else(|| "/".to_string(), |p| p.to_string());
            tracing::trace!(%return_to, "Redirecting to login path");

            Ok(Redirect::to(&format!(
                "{}?return_to={}",
                state.config.oath.login_path(),
                return_to
            ))
            .into_response())
        })
    }
}

pub struct ProxyFuture<E> {
    future: Pin<Box<dyn Future<Output = Result<Response<Body>, E>> + Send + 'static>>,
}

impl<E> fmt::Debug for ProxyFuture<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProxyFuture")
    }
}

impl<E> ProxyFuture<E> {
    pub fn new<F>(future: F) -> Self
    where
        F: Future<Output = Result<Response<Body>, E>> + Send + 'static,
    {
        Self {
            future: Box::pin(future),
        }
    }
}

impl<E> Future for ProxyFuture<E> {
    type Output = Result<Response<Body>, E>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> std::task::Poll<Self::Output> {
        self.future.as_mut().poll(cx)
    }
}

/// Set a request ID as a UUID
#[derive(Debug, Clone)]
pub(crate) struct ProxyRequestId;

impl MakeRequestId for ProxyRequestId {
    fn make_request_id<B>(&mut self, _: &http::Request<B>) -> Option<RequestId> {
        Some(RequestId::new(
            Uuid::new_v4().as_hyphenated().to_string().parse().unwrap(),
        ))
    }
}
