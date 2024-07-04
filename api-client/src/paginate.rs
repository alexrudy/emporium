use std::collections::VecDeque;
use std::fmt;

use futures::{future::BoxFuture, FutureExt};
use serde::Deserialize;
use thiserror::Error;

use crate::response::{ResponseBodyExt as _, ResponseExt as _};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, Error)]
#[error("Pagination error: {message}")]
pub struct PaginationError {
    message: String,
    source: Option<BoxError>,
}

pub trait Paginator {
    type Item;

    fn items(&mut self) -> Vec<Self::Item>;

    fn pages(&self) -> Option<usize> {
        None
    }

    fn page(&self) -> Option<usize> {
        None
    }

    fn next(
        &self,
        req: http::Request<hyperdriver::Body>,
    ) -> Option<http::Request<hyperdriver::Body>>;
}

pub trait PaginationInfo {
    fn pages(&self) -> Option<usize>;

    fn page(&self) -> Option<usize>;

    fn next(
        &self,
        req: http::Request<hyperdriver::Body>,
    ) -> Option<http::Request<hyperdriver::Body>>;
}

#[derive(Debug, Clone, Deserialize)]
pub struct PaginatedData<T, P> {
    pub data: Vec<T>,

    #[serde(flatten)]
    pub paginate: P,
}

impl<T, P> Paginator for PaginatedData<T, P>
where
    P: PaginationInfo,
{
    type Item = T;

    fn items(&mut self) -> Vec<Self::Item> {
        std::mem::take(&mut self.data)
    }

    fn pages(&self) -> Option<usize> {
        self.paginate.pages()
    }

    fn page(&self) -> Option<usize> {
        self.paginate.page()
    }

    fn next(
        &self,
        req: http::Request<hyperdriver::Body>,
    ) -> Option<http::Request<hyperdriver::Body>> {
        self.paginate.next(req)
    }
}

type NextPageFuture<P> = BoxFuture<'static, Result<Option<P>, BoxError>>;

enum PaginatedStreamState<T, P> {
    Query,
    Buffered(VecDeque<T>),
    Requesting(NextPageFuture<P>),
    Done,
}

#[pin_project::pin_project]
pub struct Paginated<A, T, P> {
    client: crate::ApiClient<A>,
    request: Option<http::Request<hyperdriver::Body>>,
    state: PaginatedStreamState<T, P>,
}

impl<A: fmt::Debug, T, P> fmt::Debug for Paginated<A, T, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Paginated")
            .field("client", &self.client)
            .field("request", &self.request)
            .finish()
    }
}

impl<A, T, P> Paginated<A, T, P> {
    pub fn new(client: crate::ApiClient<A>, request: http::Request<hyperdriver::Body>) -> Self {
        Self {
            client,
            request: Some(request),
            state: PaginatedStreamState::Query,
        }
    }
}

impl<A, T, P> futures::Stream for Paginated<A, T, P>
where
    A: crate::Authentication + Send + Sync + 'static,
    T: serde::de::DeserializeOwned + Send + 'static,
    P: Paginator<Item = T> + serde::de::DeserializeOwned + Send + 'static,
{
    type Item = Result<T, BoxError>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let this = self.project();
        match this.state {
            PaginatedStreamState::Query => {
                let next_future = {
                    let Some(request) = this.request.as_ref() else {
                        tracing::trace!("No more pages to request, stream is done");
                        *this.state = PaginatedStreamState::Done;
                        return std::task::Poll::Ready(None);
                    };

                    let Some(body) = request.body().try_clone() else {
                        tracing::error!("Unable to clone the request body");
                        *this.state = PaginatedStreamState::Done;
                        return std::task::Poll::Ready(None);
                    };

                    let builder = {
                        let mut builder = http::Request::builder()
                            .method(request.method())
                            .uri(request.uri());

                        if let Some(headers) = builder.headers_mut() {
                            *headers = request.headers().clone();
                        }
                        builder.body(body)
                    };

                    let Ok(request) = builder else {
                        tracing::error!("Unable to clone the request");
                        *this.state = PaginatedStreamState::Done;
                        return std::task::Poll::Ready(None);
                    };

                    tracing::trace!("Requesting next page: {:?}", request.uri());

                    let client = this.client.clone();

                    Box::pin(async move {
                        let response = client.execute(request).await?;

                        if !response.status().is_success() {
                            let status = response.status();
                            let text = response.text().await?;
                            return Err(Box::new(PaginationError {
                                message: format!("{}: {}", status, text),
                                source: None,
                            }) as BoxError);
                        }

                        Ok(Some(response.json().await?))
                    })
                };

                *this.state = PaginatedStreamState::Requesting(next_future);
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            }
            PaginatedStreamState::Buffered(ref mut items) => {
                if let Some(item) = items.pop_front() {
                    std::task::Poll::Ready(Some(Ok(item)))
                } else {
                    tracing::trace!("Buffer is empty, requesting next page");
                    *this.state = PaginatedStreamState::Query;
                    cx.waker().wake_by_ref();
                    std::task::Poll::Pending
                }
            }
            PaginatedStreamState::Requesting(ref mut future) => match future.poll_unpin(cx) {
                std::task::Poll::Ready(Ok(Some(mut paginator))) => {
                    tracing::trace!(
                        "Paginated request on page {} of {}",
                        paginator.page().unwrap_or(0),
                        paginator.pages().unwrap_or(0)
                    );

                    *this.state = PaginatedStreamState::Buffered(VecDeque::from(paginator.items()));
                    if let Some(request) = this.request.take() {
                        *this.request = paginator.next(request);
                    }
                    cx.waker().wake_by_ref();
                    std::task::Poll::Pending
                }
                std::task::Poll::Ready(Ok(None)) => {
                    *this.state = PaginatedStreamState::Done;
                    std::task::Poll::Ready(None)
                }

                std::task::Poll::Ready(Err(error)) => {
                    *this.state = PaginatedStreamState::Done;
                    std::task::Poll::Ready(Some(Err(error)))
                }
                std::task::Poll::Pending => std::task::Poll::Pending,
            },
            PaginatedStreamState::Done => std::task::Poll::Ready(None),
        }
    }
}
