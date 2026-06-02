//! Errors raised by the server-feature handlers.

use std::error::Error as StdError;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

/// Boxed error from a [`crate::server::SessionStore`],
/// [`crate::server::UserStore`], or identity resolver.
pub type BoxError = Box<dyn StdError + Send + Sync + 'static>;

/// Errors that handlers in the `server` feature can produce.
///
/// The [`IntoResponse`] impl is deliberately terse — it returns the
/// HTTP status but never leaks the underlying error message to the
/// client. The full error is emitted to `tracing` so operators can
/// debug from logs.
#[derive(Debug, Error)]
pub enum ServerError {
    /// Underlying OAuth2 protocol or transport error.
    #[error(transparent)]
    Oauth2(#[from] crate::Error),

    /// Authorization-code callback failed (state mismatch, exchange
    /// rejection, etc.).
    #[error(transparent)]
    Callback(#[from] crate::CallbackError),

    /// No pre-auth session matched the cookie, or it has expired.
    #[error("pre-auth session missing or expired")]
    PreauthMissing,

    /// The configured `state` cookie is missing.
    #[error("missing pre-auth cookie")]
    PreauthCookieMissing,

    /// A required parameter (`code` or `state`) was absent from the
    /// callback query string.
    #[error("missing OAuth2 callback parameter: {0}")]
    MissingCallbackParam(&'static str),

    /// The authorization server returned an error (user denied,
    /// expired authorization, etc.).
    #[error(
        "authorization server returned error: {code}{}",
        description.as_deref().map(|d| format!(": {d}")).unwrap_or_default()
    )]
    ProviderError {
        /// The `error` field value from the callback query string.
        code: String,
        /// Optional `error_description`.
        description: Option<String>,
    },

    /// The identity resolver failed.
    #[error("identity resolution failed: {0}")]
    Identity(#[source] BoxError),

    /// The session store failed.
    #[error("session store error: {0}")]
    SessionStore(#[source] BoxError),

    /// The user store failed.
    #[error("user store error: {0}")]
    UserStore(#[source] BoxError),

    /// Username failed sanitization.
    #[error("invalid username: {0}")]
    InvalidUsername(&'static str),
}

impl ServerError {
    /// Box a session-store error.
    pub fn session_store<E: StdError + Send + Sync + 'static>(err: E) -> Self {
        Self::SessionStore(Box::new(err))
    }

    /// Box a user-store error.
    pub fn user_store<E: StdError + Send + Sync + 'static>(err: E) -> Self {
        Self::UserStore(Box::new(err))
    }

    /// Box an identity-resolver error.
    pub fn identity<E: StdError + Send + Sync + 'static>(err: E) -> Self {
        Self::Identity(Box::new(err))
    }

    /// HTTP status code to use in server responses
    pub fn status_code(&self) -> StatusCode {
        match &self {
            Self::PreauthMissing | Self::PreauthCookieMissing => StatusCode::BAD_REQUEST,
            Self::MissingCallbackParam(_) => StatusCode::BAD_REQUEST,
            Self::ProviderError { .. } => StatusCode::BAD_REQUEST,
            Self::Callback(crate::CallbackError::StateMismatch) => StatusCode::BAD_REQUEST,
            Self::InvalidUsername(_) => StatusCode::BAD_REQUEST,
            Self::Callback(_) | Self::Oauth2(_) => StatusCode::BAD_GATEWAY,
            Self::Identity(_) => StatusCode::BAD_GATEWAY,
            Self::SessionStore(_) | Self::UserStore(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        tracing::warn!(error = ?self, "OAuth2 server handler error");
        let mut response = (status, status.canonical_reason().unwrap_or("error")).into_response();
        response.extensions_mut().insert(Arc::new(self));
        response
    }
}
