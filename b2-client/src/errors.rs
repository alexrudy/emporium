use std::fmt;

use api_client::response::{Response, ResponseBodyExt as _, ResponseExt as _};
use http::StatusCode;
use serde::{de::DeserializeOwned, Deserialize};
use thiserror::Error;

use crate::application::{AuthenticationError, AuthenticationErrorKind};

#[derive(Debug, Clone, Error, Deserialize)]
#[serde(from = "RawErrorInfo")]
#[error("{status}: {message} ({code})")]
pub struct B2Error {
    status: StatusCode,
    code: B2ErrorCode,
    message: String,
}

impl B2Error {
    pub fn status_code(&self) -> StatusCode {
        self.status
    }

    pub fn kind(&self) -> &B2ErrorCode {
        &self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Debug, Clone)]
pub enum B2ErrorCode {
    ExpiredAuthToken,
    BadRequest,
    Other(String),
}

impl fmt::Display for B2ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            B2ErrorCode::ExpiredAuthToken => f.write_str("expired_auth_token"),
            B2ErrorCode::BadRequest => f.write_str("bad_request"),
            B2ErrorCode::Other(message) => f.write_str(message),
        }
    }
}

impl From<String> for B2ErrorCode {
    fn from(value: String) -> Self {
        match value.as_str() {
            "expired_auth_token" => B2ErrorCode::ExpiredAuthToken,
            "bad_request" => B2ErrorCode::BadRequest,
            _ => B2ErrorCode::Other(value),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct RawErrorInfo {
    status: u16,
    code: String,
    message: String,
}

impl From<RawErrorInfo> for B2Error {
    fn from(value: RawErrorInfo) -> Self {
        B2Error {
            status: StatusCode::from_u16(value.status).unwrap(),
            code: value.code.into(),
            message: value.message,
        }
    }
}

#[derive(Debug, Error)]
pub enum B2RequestError {
    #[error(transparent)]
    B2(#[from] B2Error),

    #[error("deserializing: {0} {1}")]
    Serde(#[source] serde_json::Error, String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("no credentials for bucket {0}")]
    NoCredentials(String),

    #[error("body: {0}")]
    Body(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("client: {0}")]
    Client(#[from] hyperdriver::client::Error),

    #[error("Retries exhausted")]
    RetriesExhausted,
}

impl From<AuthenticationError> for B2RequestError {
    fn from(value: AuthenticationError) -> Self {
        match value.kind {
            AuthenticationErrorKind::Body(error) => B2RequestError::Body(error),
            AuthenticationErrorKind::Client(error) => B2RequestError::Client(error),
            AuthenticationErrorKind::Deserialization(error, text) => {
                B2RequestError::Serde(error, text)
            }
            AuthenticationErrorKind::BadRequest(error) => B2RequestError::B2(error),
            AuthenticationErrorKind::Unauthorized(error) => B2RequestError::B2(error),
            AuthenticationErrorKind::UnauthorizedBucket(bucket) => {
                B2RequestError::NoCredentials(bucket.into())
            }
        }
    }
}

impl B2RequestError {
    pub fn unwrap_b2(self) -> B2Error {
        match self {
            B2RequestError::B2(err) => err,
            err => panic!("{err}"),
        }
    }

    pub fn b2(&self) -> Option<&B2Error> {
        match self {
            B2RequestError::B2(err) => Some(err),
            _ => None,
        }
    }
}

#[async_trait::async_trait]
pub(crate) trait B2ResponseExt {
    async fn deserialize<D: DeserializeOwned>(self) -> Result<D, B2RequestError>;
    async fn handle_errors(self) -> Result<Self, B2RequestError>
    where
        Self: Sized;
}

#[async_trait::async_trait]
impl B2ResponseExt for Response {
    async fn handle_errors(self) -> Result<Self, B2RequestError> {
        if self.status().is_success() {
            Ok(self)
        } else {
            let url = self.uri().clone();
            let text = self.text().await.map_err(B2RequestError::Body)?;

            let err: B2Error = serde_json::from_str(&text)
                .map_err(|err| B2RequestError::Serde(err, text.clone()))?;
            b2_response_breadcrumb(&err, &url);
            Err(err.into())
        }
    }

    async fn deserialize<D: DeserializeOwned>(self) -> Result<D, B2RequestError> {
        let resp = self.handle_errors().await?;

        let text = resp.text().await.map_err(B2RequestError::Body)?;

        let resp =
            serde_json::from_str(&text).map_err(|err| B2RequestError::Serde(err, text.clone()))?;
        Ok(resp)
    }
}

fn b2_response_breadcrumb(error: &B2Error, url: &http::Uri) {
    use sentry::protocol::{Breadcrumb, Map};

    let breadcrumb = Breadcrumb {
        ty: "http".into(),
        category: Some("request".into()),
        data: {
            let mut map = Map::new();

            map.insert("url".into(), url.to_string().into());
            map.insert("status_code".into(), error.status_code().to_string().into());
            map.insert("code".into(), error.kind().to_string().into());
            map.insert("message".into(), error.message().to_string().into());
            map.insert("service".into(), "b2".into());
            map
        },
        ..Default::default()
    };

    sentry::add_breadcrumb(breadcrumb);
}
