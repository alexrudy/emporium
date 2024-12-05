use http::StatusCode;
use hyperdriver::Body;
use tower::retry::Policy;

/// A policy for retrying requests with exponential backoff
#[derive(Debug, Clone)]
pub struct Backoff {
    /// The initial delay for the backoff
    pub delay: std::time::Duration,

    /// The exponent to increase the delay by
    pub exponent: u32,

    /// The maximum delay for the backoff
    pub max_delay: std::time::Duration,
}

impl Backoff {
    /// Create a new backoff policy.
    pub fn new(delay: std::time::Duration, exponent: u32, max_delay: std::time::Duration) -> Self {
        Self {
            delay,
            exponent,
            max_delay,
        }
    }

    /// Increment the backoff delay
    pub fn increment(&self) -> Option<Self> {
        let delay = self.delay.checked_mul(self.exponent)?;

        if delay >= self.max_delay {
            return None;
        }

        Some(Self {
            delay,
            exponent: self.exponent,
            max_delay: self.max_delay,
        })
    }

    /// Create a new backoff policy when the server has rate limited the request
    /// with a specific delay. The policy will continue as normal after the delay.
    pub fn rate_limited(&self, delay: std::time::Duration) -> Self {
        Self {
            delay,
            exponent: self.exponent,
            max_delay: self.max_delay,
        }
    }
}

impl<E> Policy<http::Request<Body>, http::Response<Body>, E> for Backoff {
    type Future = BackoffFuture;

    fn retry(
        &mut self,
        req: &mut http::Request<Body>,
        result: &mut Result<http::Response<Body>, E>,
    ) -> Option<Self::Future> {
        let backoff = self.increment()?;
        match result {
            Ok(res) => match res.status() {
                StatusCode::GATEWAY_TIMEOUT | StatusCode::REQUEST_TIMEOUT => {
                    tracing::debug!("retrying request to {} due to timeout", req.uri());
                    Some(BackoffFuture::new(backoff))
                }
                status if status.is_server_error() => {
                    tracing::debug!("retrying request to {} due to server error", req.uri());
                    Some(BackoffFuture::new(backoff))
                }
                StatusCode::TOO_MANY_REQUESTS => {
                    tracing::debug!("retrying request to {} due to rate limit", req.uri());
                    Some(BackoffFuture::new(
                        req.headers()
                            .get(http::header::RETRY_AFTER)
                            .and_then(|value| {
                                value.to_str().ok().and_then(|value| {
                                    value.parse::<u64>().ok().map(|value| {
                                        let delay = std::time::Duration::from_secs(value);
                                        self.rate_limited(delay)
                                    })
                                })
                            })
                            .unwrap_or(backoff),
                    ))
                }
                _ => None,
            },
            Err(_) => {
                tracing::warn!("retrying request to {} due to error", req.uri());
                Some(BackoffFuture::new(backoff))
            }
        }
    }

    fn clone_request(&mut self, req: &http::Request<Body>) -> Option<http::Request<Body>> {
        try_clone_request(req)
    }
}

fn try_clone_request(req: &http::Request<Body>) -> Option<http::Request<Body>> {
    let body = req.body().try_clone()?;

    let mut next = http::Request::builder()
        .method(req.method().clone())
        .uri(req.uri().clone())
        .version(req.version())
        .body(body)
        .unwrap();

    *next.extensions_mut() = req.extensions().clone();
    *next.headers_mut() = req.headers().clone();

    Some(next)
}

#[derive(Debug)]
#[pin_project::pin_project]
pub struct BackoffFuture {
    #[pin]
    sleep: tokio::time::Sleep,
}

impl BackoffFuture {
    pub fn new(backoff: Backoff) -> Self {
        Self {
            sleep: tokio::time::sleep(backoff.delay),
        }
    }
}

impl std::future::Future for BackoffFuture {
    type Output = ();

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.project();
        this.sleep.poll(cx)
    }
}

/// A policy for retrying requests a fixed number of times
#[derive(Debug, Clone)]
pub struct Attempts(usize);

impl Attempts {
    /// Create a new attempts policy
    pub fn new(n: usize) -> Self {
        Self(n)
    }
}

impl Default for Attempts {
    fn default() -> Self {
        Self(3)
    }
}

impl From<usize> for Attempts {
    fn from(n: usize) -> Self {
        Self(n)
    }
}

impl<E> Policy<http::Request<Body>, http::Response<Body>, E> for Attempts {
    type Future = std::future::Ready<()>;

    fn retry(
        &mut self,
        req: &mut http::Request<Body>,
        result: &mut Result<http::Response<Body>, E>,
    ) -> Option<Self::Future> {
        match result {
            Ok(res) => {
                if res.status().is_server_error() && self.0 > 0 {
                    tracing::debug!("retrying request to {} due to server error", req.uri());
                    self.0 -= 1;
                    Some(std::future::ready(()))
                } else {
                    None
                }
            }
            Err(_) => {
                if self.0 > 0 {
                    tracing::debug!("retrying request to {} due to error", req.uri());
                    self.0 -= 1;
                    Some(std::future::ready(()))
                } else {
                    None
                }
            }
        }
    }

    fn clone_request(&mut self, req: &http::Request<Body>) -> Option<http::Request<Body>> {
        try_clone_request(req)
    }
}
