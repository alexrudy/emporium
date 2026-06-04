//! Mailgun API Error types

use std::fmt;

use serde::Deserialize;

/// Errors that can occur when interacting with the MailGun API.
#[derive(Debug, thiserror::Error)]
pub enum MailGunError {
    /// An error returned by the MailGun API.
    #[error("MailGun API Error: {0}")]
    ApiError(#[from] MailGunApiError),

    /// An error occured while sending the HTTP request.
    #[error("Request Error: {0}")]
    Request(#[from] api_client::error::Error),

    /// An error occured while serializing the request body as form data.
    #[error(transparent)]
    FormData(#[from] formdata::Error),

    /// An error occured while deserializing the response body.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// A resource was not found.
    #[error("{kind} not found: {value}")]
    NotFound {
        /// The reource kind
        kind: &'static str,
        /// The value that was not found
        value: String,
    },
}

/// A MailGun API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ErrorResponse {
    /// A list of errors returned by the MailGun API.
    pub message: String,
}

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("message: ")?;
        f.write_str(&self.message)
    }
}

/// Error response from the MailGun API, including HTTP status code and error messages.
#[derive(Debug, Clone)]
pub struct MailGunApiError {
    status: http::StatusCode,
    message: String,
}

impl MailGunApiError {
    /// Create a new MailGun API error.
    pub fn new(status: http::StatusCode, errors: ErrorResponse) -> Self {
        Self {
            status,
            message: errors.message,
        }
    }
}

impl fmt::Display for MailGunApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "{} {} API Error: {}",
            self.status.as_u16(),
            self.status.as_str(),
            self.message,
        ))
    }
}

impl std::error::Error for MailGunApiError {}
