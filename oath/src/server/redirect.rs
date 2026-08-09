//! Dynamic callback support for oath server integration
//!
//! Sometimes, when behind a proxy, we might want an oath server to be
//! accessible from a dynamic list of hosts. To do this, we need to support
//! extracting the callback host from the incoming request in the handler.

use http::Uri;
use thiserror::Error;

use super::ServerError;

/// Extracts the redirect URI from the incoming request.
pub trait ExtractRedirect {
    /// Extracts the redirect URI from the incoming request.
    fn from_request_parts(
        &self,
        request: &mut axum::http::request::Parts,
    ) -> impl Future<Output = Result<Uri, ServerError>> + Send;
}

impl ExtractRedirect for Uri {
    fn from_request_parts(
        &self,
        #[expect(unused)] request: &mut axum::http::request::Parts,
    ) -> impl Future<Output = Result<Uri, ServerError>> {
        return std::future::ready(Ok(self.clone()));
    }
}

#[derive(Debug, Error)]
pub enum ExtractHeaderError {
    #[error("missing header: {0}")]
    Missing(http::HeaderName),
}

impl From<ExtractHeaderError> for ServerError {
    fn from(value: ExtractHeaderError) -> Self {
        ServerError::ProxyCallback(value.into())
    }
}

/// Extracts the redirect URI from the incoming request using a trusted header.
#[derive(Debug, Clone)]
pub struct TrustedHeader(http::HeaderName);

impl From<http::HeaderName> for TrustedHeader {
    fn from(name: http::HeaderName) -> Self {
        Self(name)
    }
}
impl ExtractRedirect for TrustedHeader {
    fn from_request_parts(
        &self,
        request: &mut axum::http::request::Parts,
    ) -> impl Future<Output = Result<Uri, ServerError>> {
        async {
            let value = request
                .headers
                .get(&self.0)
                .ok_or_else(|| ExtractHeaderError::Missing(self.0.clone()))?;
            let callback = value
                .to_str()
                .map_err(|error| ServerError::ProxyCallback(error.into()))?;
            let uri = callback
                .parse()
                .map_err(|error: http::uri::InvalidUri| ServerError::ProxyCallback(error.into()))?;
            Ok(uri)
        }
    }
}
