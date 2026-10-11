//! Dynamic callback support for oath server integration
//!
//! Sometimes, when behind a proxy, we might want an oath server to be
//! accessible from a dynamic list of hosts. To do this, we need to support
//! extracting the callback host from the incoming request in the handler.
//!
//! An [`ExtractRedirect`] produces the public *origin* (scheme + host)
//! the request arrived on. The router joins it to the provider's
//! callback path, so every provider gets its own callback URI on every
//! host, e.g. `https://app1.example.com/auth/google/callback`.

use http::Uri;
use http::uri::{Authority, Scheme};
use thiserror::Error;

use super::ServerError;

/// Extracts the public origin of the incoming request.
///
/// Only the scheme and authority of the returned [`Uri`] are used; any
/// path is ignored. Returning a full callback URL (e.g.
/// `https://host/auth/callback`) therefore behaves the same as returning
/// `https://host`.
pub trait ExtractRedirect {
    /// Extracts the public origin from the incoming request.
    #[expect(clippy::wrong_self_convention)]
    fn from_request_parts(
        &self,
        request: &mut axum::http::request::Parts,
    ) -> impl Future<Output = Result<Uri, ServerError>> + Send;
}

/// A fixed origin, for deployments served from a single public host.
impl ExtractRedirect for Uri {
    fn from_request_parts(
        &self,
        #[expect(unused)] request: &mut axum::http::request::Parts,
    ) -> impl Future<Output = Result<Uri, ServerError>> {
        std::future::ready(Ok(self.clone()))
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

/// The extracted origin had no scheme or host.
#[derive(Debug, Error)]
#[error("redirect origin {0:?} must include a scheme and host")]
pub struct MissingOrigin(String);

/// Extracts the public origin from a header set by a trusted reverse
/// proxy, e.g. Caddy's `header_up X-Gateway-Origin {scheme}://{host}`.
///
/// Only use this when the header is guaranteed to come from the proxy
/// (e.g. the server is only reachable through it); otherwise clients can
/// choose the redirect URI's host. Providers only redirect to registered
/// URIs, which limits the damage, but don't rely on that.
#[derive(Debug, Clone)]
pub struct TrustedHeader(http::HeaderName);

impl From<http::HeaderName> for TrustedHeader {
    fn from(name: http::HeaderName) -> Self {
        Self(name)
    }
}
impl ExtractRedirect for TrustedHeader {
    async fn from_request_parts(
        &self,
        request: &mut axum::http::request::Parts,
    ) -> Result<Uri, ServerError> {
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

/// Join the scheme + authority of `origin` to `callback_path`.
pub(crate) fn callback_uri(origin: &Uri, callback_path: &str) -> Result<Uri, ServerError> {
    let (Some(scheme), Some(authority)) = (origin.scheme(), origin.authority()) else {
        return Err(ServerError::ProxyCallback(
            MissingOrigin(origin.to_string()).into(),
        ));
    };
    build_uri(scheme, authority, callback_path)
}

fn build_uri(scheme: &Scheme, authority: &Authority, path: &str) -> Result<Uri, ServerError> {
    Uri::builder()
        .scheme(scheme.clone())
        .authority(authority.clone())
        .path_and_query(path)
        .build()
        .map_err(|error| ServerError::ProxyCallback(error.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn join(origin: &str, path: &str) -> Result<String, ServerError> {
        callback_uri(&origin.parse().unwrap(), path).map(|u| u.to_string())
    }

    #[test]
    fn bare_origin_gets_callback_path() {
        assert_eq!(
            join("https://app1.example.com", "/auth/google/callback").unwrap(),
            "https://app1.example.com/auth/google/callback"
        );
    }

    #[test]
    fn origin_with_trailing_slash() {
        assert_eq!(
            join("https://app1.example.com/", "/auth/callback").unwrap(),
            "https://app1.example.com/auth/callback"
        );
    }

    #[test]
    fn full_callback_url_is_reduced_to_origin() {
        assert_eq!(
            join(
                "http://app2.example.com:8080/auth/callback",
                "/auth/okta/callback"
            )
            .unwrap(),
            "http://app2.example.com:8080/auth/okta/callback"
        );
    }

    #[test]
    fn origin_without_scheme_is_rejected() {
        assert!(matches!(
            join("/auth/callback", "/auth/callback"),
            Err(ServerError::ProxyCallback(_))
        ));
        assert!(matches!(
            join("app1.example.com", "/auth/callback"),
            Err(ServerError::ProxyCallback(_))
        ));
    }
}
