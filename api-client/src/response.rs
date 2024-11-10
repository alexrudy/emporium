//! Response types and traits for working with HTTP responses.

use crate::error::HttpResponseError;
use hyperdriver::Body;

mod futures {
    use std::fmt;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{ready, Context, Poll};

    use http_body_util::combinators::Collect;
    use http_body_util::BodyExt as _;
    use pin_project::pin_project;
    use tower::BoxError;

    #[pin_project]
    pub struct Bytes<Body = hyperdriver::Body>(#[pin] Collect<Body>)
    where
        Body: http_body::Body;

    impl<Body> fmt::Debug for Bytes<Body>
    where
        Body: http_body::Body,
    {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Bytes").finish()
        }
    }

    impl<Body> Future for Bytes<Body>
    where
        Body: http_body::Body,
        Body::Error: Into<BoxError>,
    {
        type Output = Result<bytes::Bytes, BoxError>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let collected = ready!(self.project().0.poll(cx)).map_err(Into::into)?;
            Poll::Ready(Ok(collected.to_bytes()))
        }
    }

    impl<Body> From<Body> for Bytes<Body>
    where
        Body: http_body::Body,
    {
        fn from(body: Body) -> Self {
            Self(body.collect())
        }
    }

    #[pin_project]
    pub struct Text<Body = hyperdriver::Body>(#[pin] Bytes<Body>)
    where
        Body: http_body::Body;

    impl<Body> fmt::Debug for Text<Body>
    where
        Body: http_body::Body,
    {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Text").finish()
        }
    }

    impl<Body> Future for Text<Body>
    where
        Body: http_body::Body,
        Body::Error: Into<BoxError>,
    {
        type Output = Result<String, BoxError>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let collected = ready!(self.project().0.poll(cx))?;
            Poll::Ready(String::from_utf8(collected.to_vec()).map_err(Into::into))
        }
    }

    impl<Body> From<Bytes<Body>> for Text<Body>
    where
        Body: http_body::Body,
    {
        fn from(bytes: Bytes<Body>) -> Self {
            Self(bytes)
        }
    }

    impl<Body> From<Body> for Text<Body>
    where
        Body: http_body::Body,
    {
        fn from(body: Body) -> Self {
            Self(Bytes::from(body))
        }
    }

    #[pin_project]
    pub struct Json<T, Body = hyperdriver::Body>
    where
        Body: http_body::Body,
    {
        #[pin]
        inner: Bytes<Body>,
        _phantom: std::marker::PhantomData<T>,
    }

    impl<T, B> fmt::Debug for Json<T, B>
    where
        B: http_body::Body,
    {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Json").finish()
        }
    }

    impl<T, B> Future for Json<T, B>
    where
        T: serde::de::DeserializeOwned,
        B: http_body::Body,
        B::Error: Into<BoxError>,
    {
        type Output = Result<T, BoxError>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let bytes = ready!(self.project().inner.poll(cx))?;
            Poll::Ready(serde_json::from_slice(&bytes).map_err(Into::into))
        }
    }

    impl<T, Body> From<Body> for Json<T, Body>
    where
        Body: http_body::Body,
    {
        fn from(body: Body) -> Self {
            Self {
                inner: Bytes::from(body),
                _phantom: std::marker::PhantomData,
            }
        }
    }

    impl<T, Body> From<Bytes<Body>> for Json<T, Body>
    where
        Body: http_body::Body,
    {
        fn from(bytes: Bytes<Body>) -> Self {
            Self {
                inner: bytes,
                _phantom: std::marker::PhantomData,
            }
        }
    }
}

/// Extension trait for working with HTTP response bodies.
pub trait ResponseBodyExt<Body>
where
    Body: http_body::Body,
{
    /// Get a reference to the response body.
    fn body(&self) -> &Body;

    /// Collect the response body into a `Bytes` instance.
    fn bytes(self) -> self::futures::Bytes<Body>;

    /// Collect the response body into a `String` instance.
    fn text(self) -> self::futures::Text<Body>
    where
        Self: Sized,
    {
        self.bytes().into()
    }

    /// Collect the body and deserialize it as JSON.
    fn json<T>(self) -> self::futures::Json<T, Body>
    where
        T: serde::de::DeserializeOwned,
        Self: Sized,
    {
        self.bytes().into()
    }
}

/// Extension trait for working with HTTP response types.
pub trait ResponseExt<Body>: ResponseBodyExt<Body>
where
    Body: http_body::Body,
{
    /// Get the status code of the response.
    fn status(&self) -> http::StatusCode;

    /// Get the headers of the response.
    fn headers(&self) -> &http::HeaderMap;

    /// Get the URI of the request that generated the response.
    fn uri(&self) -> &http::Uri;

    /// Get the parts of the request that generated the response.
    fn request(&self) -> &http::request::Parts;

    /// Get the parts of the response.
    fn response(&self) -> &http::response::Parts;
}

impl<Body> ResponseBodyExt<Body> for http::Response<Body>
where
    Body: http_body::Body,
{
    fn body(&self) -> &Body {
        self.body()
    }

    fn bytes(self) -> self::futures::Bytes<Body> {
        self.into_body().into()
    }

    fn text(self) -> self::futures::Text<Body> {
        self.into_body().into()
    }
}

/// Wrapper around an HTTP response that provides additional methods for working with the response,
/// and allows for easy access to the response and request parts.
#[derive(Debug)]
pub struct Response {
    request: http::request::Parts,
    response: http::response::Parts,
    body: Body,
}

impl Response {
    /// Create a new `Response` instance.
    pub fn new(request: http::request::Parts, response: http::response::Response<Body>) -> Self {
        let (response, body) = response.into_parts();

        Self {
            request,
            response,
            body,
        }
    }

    /// Get the parts of the request that generated the response.
    pub fn into_parts(self) -> (http::request::Parts, http::response::Parts, Body) {
        (self.request, self.response, self.body)
    }

    /// Convert the `Response` into an `http::Response` instance.
    pub fn into_response(self) -> http::Response<Body> {
        http::Response::from_parts(self.response, self.body)
    }

    /// Convert the `Response` into an `HttpResponseError` instance.
    pub async fn into_error(self) -> HttpResponseError {
        HttpResponseError::from_response(self).await
    }

    /// Convert the `Response` into an `HttpResponseError` instance if the response status is not a success status.
    pub async fn error_for_status(self) -> Result<Self, HttpResponseError> {
        if self.status().is_success() {
            Ok(self)
        } else {
            Err(self.into_error().await)
        }
    }
}

impl ResponseBodyExt<hyperdriver::Body> for Response {
    fn body(&self) -> &Body {
        &self.body
    }

    fn bytes(self) -> self::futures::Bytes {
        self.body.into()
    }

    fn text(self) -> self::futures::Text {
        self.body.into()
    }
}

impl ResponseExt<hyperdriver::Body> for Response {
    fn status(&self) -> http::StatusCode {
        self.response.status
    }

    fn headers(&self) -> &http::HeaderMap {
        &self.response.headers
    }

    fn uri(&self) -> &http::Uri {
        &self.request.uri
    }

    fn request(&self) -> &http::request::Parts {
        &self.request
    }

    fn response(&self) -> &http::response::Parts {
        &self.response
    }
}
