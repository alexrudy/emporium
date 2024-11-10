use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

use hyper::body::Incoming;
use tower::Layer;
use tower::Service;

/// Layer to convert a body to use `Body` as the request body from `hyper::body::Incoming`.
#[derive(Debug, Clone)]
pub struct AdaptClientIncomingLayer<BIn, BOut> {
    body: std::marker::PhantomData<fn(BIn) -> BOut>,
}

impl<BIn, BOut> Default for AdaptClientIncomingLayer<BIn, BOut> {
    fn default() -> Self {
        Self {
            body: std::marker::PhantomData,
        }
    }
}

impl<BIn, BOut> AdaptClientIncomingLayer<BIn, BOut> {
    /// Create a new `AdaptBodyLayer`.
    pub fn new() -> Self {
        Self {
            body: std::marker::PhantomData,
        }
    }
}

impl<BIn, BOut, S> Layer<S> for AdaptClientIncomingLayer<BIn, BOut> {
    type Service = AdaptClientIncomingService<S, BIn, BOut>;

    fn layer(&self, inner: S) -> Self::Service {
        AdaptClientIncomingService {
            inner,
            body: std::marker::PhantomData,
        }
    }
}

/// Adapt a service to use `Body` as the request body.
///
/// This is useful when you want to use `Body` as the request body type for a
/// service, and the outer functions require a service that accepts a body
/// type of `http::Request<hyper::body::Incoming>`.
pub struct AdaptClientIncomingService<S, BIn, BOut> {
    inner: S,
    body: std::marker::PhantomData<fn(BIn) -> BOut>,
}

impl<S: Debug, BIn, BOut> Debug for AdaptClientIncomingService<S, BIn, BOut> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("AdaptClientIncomingService")
            .field(&self.inner)
            .finish()
    }
}

impl<S: Default, BIn, BOut> Default for AdaptClientIncomingService<S, BIn, BOut> {
    fn default() -> Self {
        Self {
            inner: S::default(),
            body: std::marker::PhantomData,
        }
    }
}

impl<S: Clone, BIn, BOut> Clone for AdaptClientIncomingService<S, BIn, BOut> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            body: std::marker::PhantomData,
        }
    }
}

impl<S, BIn, BOut> AdaptClientIncomingService<S, BIn, BOut> {
    /// Create a new `AdaptBody` to wrap a service.
    #[allow(dead_code)]
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            body: std::marker::PhantomData,
        }
    }
}

impl<T, BIn, BOut> Service<http::Request<BIn>> for AdaptClientIncomingService<T, BIn, BOut>
where
    T: Service<http::Request<BIn>, Response = http::Response<Incoming>>,
    BOut: From<hyper::body::Incoming>,
{
    type Response = http::Response<BOut>;
    type Error = T::Error;
    type Future = AdaptIncomingFuture<T::Future, BOut, T::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<BIn>) -> Self::Future {
        AdaptIncomingFuture::new(self.inner.call(req))
    }
}

#[derive(Debug)]
#[pin_project::pin_project]
pub struct AdaptIncomingFuture<F, BOut, Error> {
    #[pin]
    future: F,
    body: std::marker::PhantomData<fn() -> (BOut, Error)>,
}

impl<F, BOut, Error> AdaptIncomingFuture<F, BOut, Error> {
    pub fn new(future: F) -> Self {
        Self {
            future,
            body: std::marker::PhantomData,
        }
    }
}

impl<F, BOut, Error> Future for AdaptIncomingFuture<F, BOut, Error>
where
    F: Future<Output = Result<http::Response<hyper::body::Incoming>, Error>>,
    BOut: From<hyper::body::Incoming>,
{
    type Output = Result<http::Response<BOut>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project().future.poll(cx) {
            Poll::Ready(res) => Poll::Ready(res.map(|res| res.map(BOut::from))),
            Poll::Pending => Poll::Pending,
        }
    }
}
