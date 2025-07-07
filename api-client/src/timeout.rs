//! Atomic-sync'd timeouts so that a client can share its timeout across threads.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug)]
struct AtomicDuration {
    seconds: AtomicU64,
    nanos: AtomicU32,
}

impl AtomicDuration {
    fn new(duration: Duration) -> Self {
        let seconds = duration.as_secs();
        let nanos = duration.subsec_nanos();
        AtomicDuration {
            seconds: AtomicU64::new(seconds),
            nanos: AtomicU32::new(nanos),
        }
    }

    fn set(&self, duration: Duration) {
        let seconds = duration.as_secs();
        let nanos = duration.subsec_nanos();
        self.seconds.store(seconds, Ordering::Release);
        self.nanos.store(nanos, Ordering::Release);
    }

    fn get(&self) -> Duration {
        let seconds = self.seconds.load(Ordering::Acquire);
        let nanos = self.nanos.load(Ordering::Acquire);
        Duration::new(seconds, nanos)
    }
}

/// A shared duration that can be cloned, and set from differnet clones.
///
/// Effectively an `Arc<Duration>`.
#[derive(Debug, Clone)]
pub struct SharedDuration {
    duration: Arc<AtomicDuration>,
}

impl SharedDuration {
    /// Create a new shared duration
    pub fn new(timeout: Duration) -> Self {
        Self {
            duration: Arc::new(AtomicDuration::new(timeout)),
        }
    }

    /// Get the duration stored here.
    pub fn get(&self) -> Duration {
        self.duration.get()
    }

    /// Set the duration stored here.
    pub fn set(&self, timeout: Duration) {
        self.duration.set(timeout)
    }
}

/// A layer to apply a timeout using a [`SharedDuration`]
#[derive(Debug, Clone)]
pub struct SharedTimeoutLayer {
    timeout: SharedDuration,
}

impl SharedTimeoutLayer {
    /// Create a new shared timeout layer with the given timeout.
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout: SharedDuration::new(timeout),
        }
    }

    /// Get the shared duration used by this layer.
    pub fn timeout(&self) -> &SharedDuration {
        &self.timeout
    }
}

impl From<SharedDuration> for SharedTimeoutLayer {
    fn from(duration: SharedDuration) -> Self {
        SharedTimeoutLayer { timeout: duration }
    }
}

impl<S> tower::Layer<S> for SharedTimeoutLayer {
    type Service = TimeoutService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TimeoutService {
            service: inner,
            timeout: self.timeout.clone(),
        }
    }
}

/// A [tower::Service] that applies a timeout based on a shared duration.
#[derive(Debug, Clone)]
pub struct TimeoutService<S> {
    service: S,
    timeout: SharedDuration,
}

impl<S> TimeoutService<S> {
    /// Create a new timeout service with the given service and timeout
    pub fn new(service: S, timeout: Duration) -> Self {
        Self {
            service,
            timeout: SharedDuration::new(timeout),
        }
    }

    /// Access the timeout's duration.
    pub fn timeout(&self) -> &SharedDuration {
        &self.timeout
    }

    /// Access the inner service.
    pub fn service(&self) -> &S {
        &self.service
    }

    /// Unwrap into the inner service.
    pub fn into_service(self) -> S {
        self.service
    }
}

impl<S, R> tower::Service<R> for TimeoutService<S>
where
    S: tower::Service<R, Error = hyperdriver::client::Error>,
{
    type Response = S::Response;
    type Error = hyperdriver::client::Error;
    type Future = self::future::TimeoutFuture<S::Future, S::Response>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: R) -> Self::Future {
        self::future::TimeoutFuture::new(self.service.call(req), self.timeout.get())
    }
}

mod future {
    use std::future::{Future, IntoFuture};
    use std::marker::PhantomData;
    use std::pin::Pin;
    use std::task::{ready, Context, Poll};
    use std::time::Duration;

    use pin_project::pin_project;
    use tokio::time::Timeout;

    #[pin_project]
    #[derive(Debug)]
    pub struct TimeoutFuture<F, R> {
        #[pin]
        future: Timeout<F>,
        response: PhantomData<fn() -> R>,
    }

    impl<F, R> TimeoutFuture<F, R> {
        pub(super) fn new<I>(future: I, timeout: Duration) -> Self
        where
            I: IntoFuture<IntoFuture = F>,
        {
            Self {
                future: tokio::time::timeout(timeout, future),
                response: PhantomData,
            }
        }
    }

    impl<F, R> Future for TimeoutFuture<F, R>
    where
        F: Future<Output = Result<R, hyperdriver::client::Error>>,
    {
        type Output = Result<R, hyperdriver::client::Error>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Ready(match ready!(self.project().future.poll(cx)) {
                Ok(Ok(response)) => Ok(response),
                Ok(Err(error)) => Err(error),
                Err(_) => Err(hyperdriver::client::Error::RequestTimeout),
            })
        }
    }
}
