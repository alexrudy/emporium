//! Error types for API Clients
use std::fmt;

use http::StatusCode;
use thiserror::Error;

use crate::response::{Response, ResponseBodyExt as _, ResponseExt as _};

// Use a BoxError for body error types, since knowing the specific
// error type can be kind of a pain in the butt.
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// An error occured while sending or recieving an HTTP request
#[derive(Debug, Error)]
pub enum Error {
    /// An HTTP response error occured
    #[error(transparent)]
    Response(#[from] HttpResponseError),

    /// An error occured while recieving the response body
    #[error("Error reading response body: {0}")]
    ResponseBody(#[source] BoxError),

    /// An error occured while sending the request
    #[error(transparent)]
    Request(#[from] hyperdriver::client::Error),

    /// An error occured while building the request
    #[error(transparent)]
    RequestBuilder(#[from] http::Error),

    /// An error occured serializing the query parameters
    #[error("Error serializing query parameters: {0}")]
    QuerySerialization(#[from] crate::uri::QueryError),
}

/// A server returned an error response
#[derive(Debug, Clone)]
pub struct HttpResponseError {
    /// The HTTP status code of the response
    pub status: StatusCode,

    /// The message body of the response
    pub message: String,
}

impl HttpResponseError {
    /// Create a new HTTP response error from a response
    pub async fn from_response(response: Response) -> Self {
        let status = response.status();
        let message = response
            .text()
            .await
            .unwrap_or_else(|err| format!("Failed to read response body: {err}"));

        Self { status, message }
    }
}

impl fmt::Display for HttpResponseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "HTTP {} response: {}", self.status, self.message)
    }
}

impl std::error::Error for HttpResponseError {}
