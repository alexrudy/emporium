//! Configurable source for the request's public origin.
//!
//! The gateway serves several hostnames behind one reverse proxy, so each
//! provider's redirect URI is built from the origin the request arrived on
//! (see [`oath::server::ExtractRedirect`]). Which headers carry that origin
//! depends on the proxy, so it's chosen in configuration.

use std::str::FromStr as _;

use eyre::Context as _;
use http::Uri;
use http::request::Parts;
use http::uri::Scheme;
use oath::server::{
    ExtractRedirect, ForwardedHeader, ServerError, TrustedHeader, XForwardedHeaders,
};
use serde::{Deserialize, Serialize};

/// Where to read the request's public origin from.
///
/// ```toml
/// [server.origin]
/// kind = "x-forwarded"      # or "forwarded", or "trusted-header"
/// default_scheme = "https"  # forwarded / x-forwarded only, optional
/// # header = "X-Gateway-Callback"   # trusted-header only
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum OriginConfig {
    /// A custom header containing the origin, e.g. Caddy's
    /// `header_up X-Gateway-Callback {scheme}://{host}`.
    TrustedHeader {
        /// The header name.
        header: String,
    },

    /// The standard `Forwarded` header (RFC 7239).
    Forwarded {
        /// Scheme to assume when the header has no `proto`.
        #[serde(default)]
        default_scheme: Option<DefaultScheme>,
    },

    /// The `X-Forwarded-Proto` / `-Host` / `-Port` headers. Caddy's
    /// `reverse_proxy` sets these by default.
    XForwarded {
        /// Scheme to assume when `X-Forwarded-Proto` is absent.
        #[serde(default)]
        default_scheme: Option<DefaultScheme>,
    },
}

/// Scheme assumed when the forwarding headers don't say.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultScheme {
    /// `http`
    Http,
    /// `https`
    Https,
}

impl From<DefaultScheme> for Scheme {
    fn from(value: DefaultScheme) -> Self {
        match value {
            DefaultScheme::Http => Scheme::HTTP,
            DefaultScheme::Https => Scheme::HTTPS,
        }
    }
}

/// Runtime extractor built from an [`OriginConfig`].
#[derive(Debug, Clone)]
pub enum OriginExtractor {
    /// See [`OriginConfig::TrustedHeader`].
    TrustedHeader(TrustedHeader),
    /// See [`OriginConfig::Forwarded`].
    Forwarded(ForwardedHeader),
    /// See [`OriginConfig::XForwarded`].
    XForwarded(XForwardedHeaders),
}

impl TryFrom<&OriginConfig> for OriginExtractor {
    type Error = eyre::Report;

    fn try_from(config: &OriginConfig) -> Result<Self, Self::Error> {
        Ok(match config {
            OriginConfig::TrustedHeader { header } => Self::TrustedHeader(TrustedHeader::from(
                http::HeaderName::from_str(header)
                    .with_context(|| format!("invalid trusted header name {header:?}"))?,
            )),
            OriginConfig::Forwarded { default_scheme } => {
                let mut extractor = ForwardedHeader::new();
                if let Some(scheme) = default_scheme {
                    extractor = extractor.with_default_scheme((*scheme).into());
                }
                Self::Forwarded(extractor)
            }
            OriginConfig::XForwarded { default_scheme } => {
                let mut extractor = XForwardedHeaders::new();
                if let Some(scheme) = default_scheme {
                    extractor = extractor.with_default_scheme((*scheme).into());
                }
                Self::XForwarded(extractor)
            }
        })
    }
}

impl ExtractRedirect for OriginExtractor {
    async fn from_request_parts(&self, request: &mut Parts) -> Result<Uri, ServerError> {
        match self {
            Self::TrustedHeader(extractor) => extractor.from_request_parts(request).await,
            Self::Forwarded(extractor) => extractor.from_request_parts(request).await,
            Self::XForwarded(extractor) => extractor.from_request_parts(request).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn origin(config: OriginConfig, headers: &[(&str, &str)]) -> String {
        let mut builder = http::Request::builder().uri("/auth/login");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let mut parts = builder.body(()).unwrap().into_parts().0;
        OriginExtractor::try_from(&config)
            .unwrap()
            .from_request_parts(&mut parts)
            .await
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn dispatches_to_each_extractor() {
        assert_eq!(
            origin(
                OriginConfig::TrustedHeader {
                    header: "X-Gateway-Callback".into()
                },
                &[("x-gateway-callback", "https://a.example.com")],
            )
            .await,
            "https://a.example.com/"
        );
        assert_eq!(
            origin(
                OriginConfig::Forwarded {
                    default_scheme: None
                },
                &[("forwarded", "proto=https;host=b.example.com")],
            )
            .await,
            "https://b.example.com/"
        );
        assert_eq!(
            origin(
                OriginConfig::XForwarded {
                    default_scheme: Some(DefaultScheme::Https)
                },
                &[("x-forwarded-host", "c.example.com")],
            )
            .await,
            "https://c.example.com/"
        );
    }

    #[test]
    fn invalid_header_name_is_rejected() {
        assert!(
            OriginExtractor::try_from(&OriginConfig::TrustedHeader {
                header: "not a header".into()
            })
            .is_err()
        );
    }
}
