#![allow(clippy::arc_with_non_send_sync)]

use std::{
    fmt,
    future::Future,
    ops::Deref,
    pin::Pin,
    sync::{Arc, Weak},
    time::{Duration, Instant},
};

use futures::FutureExt;
use parking_lot::Mutex;
use tokio::sync::broadcast::{self, error::RecvError};

#[derive(Debug)]
struct RequestInner<T> {
    inflight: Option<Weak<broadcast::Sender<T>>>,
}

impl<T> RequestInner<T>
where
    T: Clone + Send + Sync + 'static,
{
    fn get_reciever(&self) -> Option<broadcast::Receiver<T>> {
        self.inflight
            .as_ref()
            .and_then(Weak::upgrade)
            .map(|tx| tx.subscribe())
    }
}

impl<T> Default for RequestInner<T>
where
    T: Clone + Send + Sync + 'static,
{
    fn default() -> Self {
        RequestInner { inflight: None }
    }
}

pub struct Handle<T> {
    fut: BoxFut<'static, Result<T, RecvError>>,
}

impl<T> fmt::Debug for Handle<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Handle").finish()
    }
}

impl<T> Future for Handle<T> {
    type Output = Result<T, RecvError>;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.fut.poll_unpin(cx)
    }
}

impl<T> Handle<T>
where
    T: Clone + Send + Sync + 'static,
{
    fn new(mut reciever: broadcast::Receiver<T>) -> Self {
        Self {
            fut: Box::pin(async move { reciever.recv().await }),
        }
    }
}

pub type BoxFut<'f, O> = Pin<Box<dyn Future<Output = O> + Send + 'f>>;

/// A coalesced request, which will ensure that only one of
/// these requests can go through to the endpoint.
#[derive(Debug)]
pub struct Request<T> {
    inner: Arc<Mutex<RequestInner<T>>>,
}

impl<T> Clone for Request<T>
where
    T: Clone + Send + Sync + 'static,
{
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<T> Default for Request<T>
where
    T: Clone + Send + Sync + 'static,
{
    fn default() -> Self {
        Self {
            inner: Default::default(),
        }
    }
}

impl<T> Request<T>
where
    T: Clone + Send + Sync + 'static,
{
    /// Get a handle to the one-and-only inflight request for
    /// this request manager.
    pub fn handle<F>(&self, f: F) -> Handle<T>
    where
        F: FnOnce() -> BoxFut<'static, T>,
    {
        // We must take the lock at this point to prevent another thread
        // from starting this request simultaneously.
        let mut inner = self.inner.lock();
        let rx = {
            if let Some(rx) = inner.get_reciever() {
                tracing::trace!("Found inflight request");
                return Handle::new(rx);
            }

            let (tx, rx) = broadcast::channel::<T>(1);

            let tx = Arc::new(tx);
            inner.inflight = Some(Arc::downgrade(&tx));

            let fut = (f)();

            {
                let inner = Arc::clone(&self.inner);
                tracing::trace!("Launching new request");
                tokio::spawn(async move {
                    let res = fut.await;
                    {
                        // We'd like to hold the lock while we are sending responses, so that
                        // we don't have a race condition which cuases some subscriber to not
                        // recieve a response (b/c e.g. they subscribe right after we send)
                        let mut inner = inner.lock();
                        inner.inflight = None;

                        let _ = tx.send(res);
                    }
                });
            };
            rx
        };
        Handle::new(rx)
    }

    pub async fn get<F>(&self, f: F) -> Result<T, RecvError>
    where
        F: FnOnce() -> BoxFut<'static, T>,
    {
        self.handle(f).await
    }
}

#[derive(Debug, Default)]
enum InnerCache<T> {
    #[default]
    Empty,
    Inflight(Request<T>),
    Cached {
        value: T,
        expires: Option<Instant>,
    },
}

impl<T> InnerCache<T> {
    fn new_with_value(value: T, expiration: Option<Duration>) -> Self {
        let expires = expiration.map(|lifetime| Instant::now() + lifetime);
        InnerCache::Cached { value, expires }
    }
}

/// A type for caching a value which is fetched via
/// an async function on the tokio runtime.
#[derive(Debug, Clone)]
pub struct Cached<T> {
    inner: Arc<Mutex<InnerCache<T>>>,
    expiration: Option<Duration>,
}

impl<T> Default for Cached<T> {
    fn default() -> Self {
        Self {
            inner: Default::default(),
            expiration: None,
        }
    }
}

impl<T> Cached<T> {
    #[must_use]
    pub fn new(expiration: Option<Duration>) -> Self {
        Self {
            inner: Default::default(),
            expiration,
        }
    }

    #[must_use]
    pub fn new_with_value(value: T, expiration: Option<Duration>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(InnerCache::new_with_value(value, expiration))),
            expiration,
        }
    }

    pub fn clear(&self) {
        let mut inner = self.inner.lock();
        *inner = InnerCache::Empty;
    }

    pub fn map_cached<F, U>(&self, f: F) -> Option<U>
    where
        F: FnOnce(&T) -> U,
    {
        let inner = self.inner.lock();
        match inner.deref() {
            InnerCache::Cached { value, expires }
                if expires.map(|e| e >= Instant::now()).unwrap_or(true) =>
            {
                Some((f)(value))
            }
            _ => None,
        }
    }
}

impl<T> Cached<T>
where
    T: Clone + Send + Sync + 'static,
{
    pub async fn get<F>(&self, f: F) -> T
    where
        F: FnOnce() -> BoxFut<'static, T>,
    {
        let handle = {
            let mut inner = self.inner.lock();
            match inner.deref() {
                InnerCache::Cached { value, expires }
                    if expires.map(|e| e >= Instant::now()).unwrap_or(true) =>
                {
                    return value.clone()
                }
                InnerCache::Inflight(request) => request.handle(f),
                _ => {
                    // We need to actually run the request.
                    let req = Request::default();
                    let handle = req.handle(|| {
                        let inner = Arc::clone(&self.inner);
                        let expiration = self.expiration;
                        let fut = f();
                        Box::pin(async move {
                            let value = fut.await;
                            {
                                let mut inner = inner.lock();
                                *inner = InnerCache::new_with_value(value.clone(), expiration)
                            }
                            value
                        })
                    });

                    *inner = InnerCache::Inflight(req);
                    handle
                }
            }
        };
        handle.await.unwrap()
    }
}
