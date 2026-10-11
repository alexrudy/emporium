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
//!
//! Bundled extractors:
//!
//! - a fixed [`Uri`], for a single public host;
//! - [`TrustedHeader`], a custom header carrying the origin;
//! - [`ForwardedHeader`], the standard `Forwarded` header (RFC 7239);
//! - [`XForwardedHeaders`], the de-facto `X-Forwarded-Proto`,
//!   `X-Forwarded-Host`, and `X-Forwarded-Port` headers.
//!
//! The header-based extractors trust whatever the request carries, so
//! only use them when the server is reachable exclusively through a
//! proxy that sets (or overwrites) those headers.

use std::str::FromStr as _;

use http::uri::{Authority, Scheme};
use http::{HeaderMap, HeaderName, Uri};
use hyproxy::headers::forward::{
    ForwardedHeader as ForwardedHeaderValue, ForwardedHost, ForwardedProtocol, X_FORWARDED_HOST,
    X_FORWARDED_PROTO,
};
use thiserror::Error;

use super::{BoxError, ServerError};

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

const X_FORWARDED_PORT: HeaderName = HeaderName::from_static("x-forwarded-port");

/// The forwarding headers didn't yield a usable origin.
#[derive(Debug, Error)]
pub enum ForwardedError {
    /// None of the expected forwarding headers were present.
    #[error("missing forwarding header: {0}")]
    Missing(&'static str),

    /// The `Forwarded` header could not be parsed.
    #[error("malformed Forwarded header: {0}")]
    MalformedForwarded(#[source] BoxError),

    /// An `X-Forwarded-*` header value could not be parsed.
    #[error("malformed {header} header: {value:?}")]
    MalformedXForwarded {
        /// Name of the offending header.
        header: &'static str,
        /// The rightmost value, which failed to parse.
        value: String,
    },

    /// The forwarded scheme was not `http` or `https`.
    #[error("forwarded scheme {0:?} is not http or https")]
    UnsupportedScheme(String),

    /// The request's own `Host` header is not a valid `host[:port]`.
    #[error("request host {0:?} is not a valid host")]
    InvalidHost(String),

    /// No scheme was forwarded and no default scheme is configured.
    #[error("no forwarded scheme and no default scheme configured")]
    MissingScheme,
}

impl From<ForwardedError> for ServerError {
    fn from(value: ForwardedError) -> Self {
        ServerError::ProxyCallback(value.into())
    }
}

/// Extracts the public origin from the standard `Forwarded` header
/// (RFC 7239), e.g. `Forwarded: for=192.0.2.60;proto=https;host=app.example.com`.
///
/// When the header lists several hops, the rightmost element is used:
/// that's the one appended by the proxy closest to this server, so a
/// client can't spoof it by sending its own `Forwarded` header. If that
/// element has no `host`, the request's `Host` header (or HTTP/2
/// `:authority`) is used; if it has no `proto`, the
/// [default scheme](Self::with_default_scheme) is used.
///
/// The same trust caveat as [`TrustedHeader`] applies.
#[derive(Debug, Clone, Default)]
pub struct ForwardedHeader {
    default_scheme: Option<Scheme>,
}

impl ForwardedHeader {
    /// An extractor with no default scheme: a missing `proto` is an
    /// error.
    pub fn new() -> Self {
        Self::default()
    }

    /// Scheme to use when the forwarded element has no `proto`.
    pub fn with_default_scheme(mut self, scheme: Scheme) -> Self {
        self.default_scheme = Some(scheme);
        self
    }

    fn origin(&self, parts: &http::request::Parts) -> Result<Uri, ForwardedError> {
        // Repeated headers form one comma-separated list, so the rightmost
        // element is the last element of the last header line.
        let last_line = parts
            .headers
            .get_all(http::header::FORWARDED)
            .iter()
            .next_back()
            .ok_or(ForwardedError::Missing("forwarded"))?;
        let header = ForwardedHeaderValue::parse_header_value(last_line)
            .map_err(|error| ForwardedError::MalformedForwarded(error.into()))?;
        let element = header
            .iter()
            .last()
            .and_then(|record| record.value())
            .ok_or(ForwardedError::Missing("forwarded"))?;

        let scheme = match &element.proto {
            Some(proto) => Some(http_scheme(proto)?),
            None => None,
        };
        build_origin(
            scheme,
            element.host.clone(),
            None,
            parts,
            self.default_scheme.as_ref(),
        )
    }
}

impl ExtractRedirect for ForwardedHeader {
    async fn from_request_parts(
        &self,
        request: &mut axum::http::request::Parts,
    ) -> Result<Uri, ServerError> {
        Ok(self.origin(request)?)
    }
}

/// Extracts the public origin from the de-facto `X-Forwarded-Proto`,
/// `X-Forwarded-Host`, and `X-Forwarded-Port` headers.
///
/// At least one of `X-Forwarded-Proto` and `X-Forwarded-Host` must be
/// present. For comma-separated (or repeated) headers, the rightmost
/// value is used, i.e. the one set by the proxy closest to this server.
///
/// - Without `X-Forwarded-Host`, the request's `Host` header (or HTTP/2
///   `:authority`) is used. Caddy, for example, preserves `Host` by
///   default.
/// - Without `X-Forwarded-Proto`, the
///   [default scheme](Self::with_default_scheme) is used.
/// - `X-Forwarded-Port` is applied only when the host has no port and the
///   port isn't the scheme's default.
///
/// The same trust caveat as [`TrustedHeader`] applies.
#[derive(Debug, Clone, Default)]
pub struct XForwardedHeaders {
    default_scheme: Option<Scheme>,
}

impl XForwardedHeaders {
    /// An extractor with no default scheme: a missing
    /// `X-Forwarded-Proto` is an error.
    pub fn new() -> Self {
        Self::default()
    }

    /// Scheme to use when `X-Forwarded-Proto` is absent.
    pub fn with_default_scheme(mut self, scheme: Scheme) -> Self {
        self.default_scheme = Some(scheme);
        self
    }

    fn origin(&self, parts: &http::request::Parts) -> Result<Uri, ForwardedError> {
        let host = rightmost(&parts.headers, &X_FORWARDED_HOST, "x-forwarded-host", |v| {
            ForwardedHost::from_str(v).ok()
        })?;
        let proto = rightmost(
            &parts.headers,
            &X_FORWARDED_PROTO,
            "x-forwarded-proto",
            |v| ForwardedProtocol::from_str(v).ok(),
        )?;
        let port = rightmost(&parts.headers, &X_FORWARDED_PORT, "x-forwarded-port", |v| {
            v.parse::<u16>().ok()
        })?;

        if host.is_none() && proto.is_none() {
            return Err(ForwardedError::Missing(
                "x-forwarded-proto or x-forwarded-host",
            ));
        }

        let scheme = match &proto {
            Some(proto) => Some(http_scheme(proto)?),
            None => None,
        };
        build_origin(scheme, host, port, parts, self.default_scheme.as_ref())
    }
}

impl ExtractRedirect for XForwardedHeaders {
    async fn from_request_parts(
        &self,
        request: &mut axum::http::request::Parts,
    ) -> Result<Uri, ServerError> {
        Ok(self.origin(request)?)
    }
}

/// Parse the rightmost comma-separated value across all instances of
/// `name`, or `None` if the header is absent.
fn rightmost<T>(
    headers: &HeaderMap,
    name: &HeaderName,
    label: &'static str,
    parse: impl FnOnce(&str) -> Option<T>,
) -> Result<Option<T>, ForwardedError> {
    let Some(line) = headers.get_all(name).iter().next_back() else {
        return Ok(None);
    };
    let malformed = |value: &str| ForwardedError::MalformedXForwarded {
        header: label,
        value: value.to_owned(),
    };
    let line = line
        .to_str()
        .map_err(|_| malformed(&String::from_utf8_lossy(line.as_bytes())))?;
    let value = line.rsplit(',').next().unwrap_or_default().trim();
    parse(value).map(Some).ok_or_else(|| malformed(value))
}

/// Only `http` and `https` make sense for a redirect URI.
fn http_scheme(proto: &ForwardedProtocol) -> Result<Scheme, ForwardedError> {
    let raw = proto.as_bytes();
    let raw = String::from_utf8_lossy(&raw);
    if raw.eq_ignore_ascii_case("https") {
        Ok(Scheme::HTTPS)
    } else if raw.eq_ignore_ascii_case("http") {
        Ok(Scheme::HTTP)
    } else {
        Err(ForwardedError::UnsupportedScheme(raw.into_owned()))
    }
}

/// Combine forwarded values with fallbacks into an origin [`Uri`].
fn build_origin(
    scheme: Option<Scheme>,
    host: Option<ForwardedHost>,
    port: Option<u16>,
    parts: &http::request::Parts,
    default_scheme: Option<&Scheme>,
) -> Result<Uri, ForwardedError> {
    let scheme = scheme
        .or_else(|| parts.uri.scheme().cloned())
        .or_else(|| default_scheme.cloned())
        .ok_or(ForwardedError::MissingScheme)?;

    let host = match host {
        Some(host) => host,
        None => request_host(parts)?,
    };
    let default_port = if scheme == Scheme::HTTPS { 443 } else { 80 };
    let port = host.port().or(port.filter(|&p| p != default_port));
    let host = ForwardedHost::new(host.host().to_owned(), port);

    let authority = Authority::try_from(host.as_bytes().as_ref()).map_err(|_| {
        ForwardedError::InvalidHost(String::from_utf8_lossy(&host.as_bytes()).into())
    })?;
    Uri::builder()
        .scheme(scheme)
        .authority(authority)
        .path_and_query("/")
        .build()
        .map_err(|_| ForwardedError::InvalidHost(String::from_utf8_lossy(&host.as_bytes()).into()))
}

/// The request's own host: the `Host` header, or the HTTP/2 `:authority`.
fn request_host(parts: &http::request::Parts) -> Result<ForwardedHost, ForwardedError> {
    if let Some(value) = parts.headers.get(http::header::HOST) {
        return ForwardedHost::parse_bytes(value.as_bytes()).map_err(|_| {
            ForwardedError::InvalidHost(String::from_utf8_lossy(value.as_bytes()).into())
        });
    }
    let authority = parts
        .uri
        .authority()
        .ok_or(ForwardedError::Missing("host"))?;
    Ok(ForwardedHost::new(
        authority.host().to_owned(),
        authority.port_u16(),
    ))
}

/// Join the scheme + authority of `origin` to `callback_path`.
pub(crate) fn callback_uri(origin: &Uri, callback_path: &str) -> Result<Uri, ServerError> {
    let (Some(scheme), Some(authority)) = (origin.scheme(), origin.authority()) else {
        return Err(ServerError::ProxyCallback(
            MissingOrigin(origin.to_string()).into(),
        ));
    };
    Uri::builder()
        .scheme(scheme.clone())
        .authority(authority.clone())
        .path_and_query(callback_path)
        .build()
        .map_err(|error| ServerError::ProxyCallback(error.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn join(origin: &str, path: &str) -> Result<String, ServerError> {
        callback_uri(&origin.parse().unwrap(), path).map(|u| u.to_string())
    }

    fn parts(headers: &[(&str, &str)]) -> http::request::Parts {
        let mut builder = http::Request::builder().uri("/auth/login");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(()).unwrap().into_parts().0
    }

    fn forwarded(headers: &[(&str, &str)]) -> Result<String, ForwardedError> {
        ForwardedHeader::new()
            .origin(&parts(headers))
            .map(|u| u.to_string())
    }

    fn x_forwarded(headers: &[(&str, &str)]) -> Result<String, ForwardedError> {
        XForwardedHeaders::new()
            .origin(&parts(headers))
            .map(|u| u.to_string())
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

    #[test]
    fn forwarded_single_element() {
        assert_eq!(
            forwarded(&[(
                "forwarded",
                "for=192.0.2.60;proto=https;host=app.example.com"
            )])
            .unwrap(),
            "https://app.example.com/"
        );
    }

    #[test]
    fn forwarded_uses_rightmost_element() {
        assert_eq!(
            forwarded(&[(
                "forwarded",
                "proto=http;host=spoofed.example.com, proto=https;host=app.example.com"
            )])
            .unwrap(),
            "https://app.example.com/"
        );
        assert_eq!(
            forwarded(&[
                ("forwarded", "proto=http;host=spoofed.example.com"),
                ("forwarded", "proto=https;host=app.example.com"),
            ])
            .unwrap(),
            "https://app.example.com/"
        );
    }

    #[test]
    fn forwarded_quoted_host_with_port() {
        assert_eq!(
            forwarded(&[("forwarded", r#"proto=https;host="app.example.com:8443""#)]).unwrap(),
            "https://app.example.com:8443/"
        );
    }

    #[test]
    fn forwarded_without_host_uses_request_host() {
        assert_eq!(
            forwarded(&[
                ("forwarded", "for=192.0.2.60;proto=https"),
                ("host", "app.example.com"),
            ])
            .unwrap(),
            "https://app.example.com/"
        );
    }

    #[test]
    fn forwarded_without_proto_needs_default_scheme() {
        let headers = [("forwarded", "host=app.example.com")];
        assert!(matches!(
            forwarded(&headers),
            Err(ForwardedError::MissingScheme)
        ));
        assert_eq!(
            ForwardedHeader::new()
                .with_default_scheme(Scheme::HTTPS)
                .origin(&parts(&headers))
                .unwrap()
                .to_string(),
            "https://app.example.com/"
        );
    }

    #[test]
    fn forwarded_rejects_bad_input() {
        assert!(matches!(
            forwarded(&[]),
            Err(ForwardedError::Missing("forwarded"))
        ));
        assert!(matches!(
            forwarded(&[("forwarded", "proto=https;proto=http;host=a.example.com")]),
            Err(ForwardedError::MalformedForwarded(_))
        ));
        assert!(matches!(
            forwarded(&[("forwarded", "proto=ftp;host=app.example.com")]),
            Err(ForwardedError::UnsupportedScheme(_))
        ));
    }

    #[test]
    fn x_forwarded_proto_and_host() {
        assert_eq!(
            x_forwarded(&[
                ("x-forwarded-proto", "https"),
                ("x-forwarded-host", "app.example.com"),
            ])
            .unwrap(),
            "https://app.example.com/"
        );
    }

    #[test]
    fn x_forwarded_uses_rightmost_value() {
        assert_eq!(
            x_forwarded(&[
                ("x-forwarded-proto", "http, https"),
                ("x-forwarded-host", "spoofed.example.com"),
                ("x-forwarded-host", "app.example.com"),
            ])
            .unwrap(),
            "https://app.example.com/"
        );
    }

    #[test]
    fn x_forwarded_without_host_uses_request_host() {
        assert_eq!(
            x_forwarded(&[
                ("x-forwarded-proto", "https"),
                ("host", "app.example.com:8443")
            ])
            .unwrap(),
            "https://app.example.com:8443/"
        );
    }

    #[test]
    fn x_forwarded_port() {
        let base = [
            ("x-forwarded-proto", "https"),
            ("x-forwarded-host", "app.example.com"),
        ];
        let with = |port: &'static str| {
            let mut headers = base.to_vec();
            headers.push(("x-forwarded-port", port));
            x_forwarded(&headers)
        };
        assert_eq!(with("8443").unwrap(), "https://app.example.com:8443/");
        assert_eq!(with("443").unwrap(), "https://app.example.com/");
        assert!(matches!(
            with("not-a-port"),
            Err(ForwardedError::MalformedXForwarded { .. })
        ));

        // A port already on the host wins.
        assert_eq!(
            x_forwarded(&[
                ("x-forwarded-proto", "https"),
                ("x-forwarded-host", "app.example.com:9000"),
                ("x-forwarded-port", "8443"),
            ])
            .unwrap(),
            "https://app.example.com:9000/"
        );
    }

    #[test]
    fn x_forwarded_rejects_bad_input() {
        assert!(matches!(
            x_forwarded(&[("host", "app.example.com")]),
            Err(ForwardedError::Missing(_))
        ));
        assert!(matches!(
            x_forwarded(&[("x-forwarded-host", "app.example.com")]),
            Err(ForwardedError::MissingScheme)
        ));
        assert!(matches!(
            x_forwarded(&[
                ("x-forwarded-proto", "gopher"),
                ("x-forwarded-host", "app.example.com"),
            ]),
            Err(ForwardedError::UnsupportedScheme(_))
        ));
    }
}
