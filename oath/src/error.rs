//! OAuth2 error types.
//!
//! [`Error`] is the crate-wide error returned by most fallible operations.
//! [`TokenErrorResponse`] models the structured error body defined by
//! RFC 6749 §5.2.

use std::fmt;

use serde::Deserialize;
use thiserror::Error;

/// Errors produced by the `oath` crate.
#[derive(Debug, Error)]
pub enum Error {
    /// An error from the underlying HTTP client.
    #[error(transparent)]
    Transport(#[from] api_client::Error),

    /// The server returned a non-success status without a recognizable
    /// OAuth2 error body.
    #[error("OAuth2 endpoint returned HTTP {status}: {body}")]
    BadResponse {
        /// HTTP status code returned by the server.
        status: http::StatusCode,
        /// Raw response body, included for debugging.
        body: String,
    },

    /// The server returned an OAuth2 error response per RFC 6749 §5.2.
    #[error(transparent)]
    TokenError(#[from] TokenErrorResponse),

    /// The response body was present but could not be deserialized into
    /// the expected schema. The raw body is included for debugging.
    #[error("failed to deserialize OAuth2 response: {source}")]
    Deserialize {
        /// Underlying serde error.
        #[source]
        source: serde_json::Error,
        /// Raw response body that failed to deserialize.
        body: String,
    },

    /// The access token has expired and no refresh path is available
    /// (no refresh token stored, or the refresh attempt was rejected).
    #[error("OAuth2 token expired and could not be refreshed")]
    Expired,
}

/// An OAuth2 error response body (RFC 6749 §5.2).
///
/// The `error` field carries one of the well-known codes, with a free-form
/// `Other` variant for forward compatibility with provider-specific codes.
#[derive(Debug, Clone, Deserialize, Error)]
pub struct TokenErrorResponse {
    /// The error code returned by the server.
    #[serde(rename = "error")]
    pub code: TokenErrorCode,

    /// Optional human-readable description.
    #[serde(default)]
    pub error_description: Option<String>,

    /// Optional URI pointing to a page with more information about the error.
    #[serde(default)]
    pub error_uri: Option<String>,
}

impl fmt::Display for TokenErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code)?;
        if let Some(desc) = &self.error_description {
            write!(f, ": {desc}")?;
        }
        Ok(())
    }
}

/// OAuth2 token error codes defined in RFC 6749 §5.2, plus an `Other`
/// variant for codes not enumerated by the spec.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(from = "String")]
pub enum TokenErrorCode {
    /// `invalid_request`
    InvalidRequest,
    /// `invalid_client`
    InvalidClient,
    /// `invalid_grant`
    InvalidGrant,
    /// `unauthorized_client`
    UnauthorizedClient,
    /// `unsupported_grant_type`
    UnsupportedGrantType,
    /// `invalid_scope`
    InvalidScope,
    /// Any error code not recognized by this crate.
    Other(String),
}

impl From<String> for TokenErrorCode {
    fn from(value: String) -> Self {
        match value.as_str() {
            "invalid_request" => Self::InvalidRequest,
            "invalid_client" => Self::InvalidClient,
            "invalid_grant" => Self::InvalidGrant,
            "unauthorized_client" => Self::UnauthorizedClient,
            "unsupported_grant_type" => Self::UnsupportedGrantType,
            "invalid_scope" => Self::InvalidScope,
            _ => Self::Other(value),
        }
    }
}

impl fmt::Display for TokenErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::InvalidScope => "invalid_scope",
            Self::Other(s) => s,
        };
        f.write_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_known_codes() {
        for (s, expected) in [
            ("invalid_request", TokenErrorCode::InvalidRequest),
            ("invalid_client", TokenErrorCode::InvalidClient),
            ("invalid_grant", TokenErrorCode::InvalidGrant),
            ("unauthorized_client", TokenErrorCode::UnauthorizedClient),
            (
                "unsupported_grant_type",
                TokenErrorCode::UnsupportedGrantType,
            ),
            ("invalid_scope", TokenErrorCode::InvalidScope),
        ] {
            let json = format!("\"{s}\"");
            let parsed: TokenErrorCode = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, expected);
        }
    }

    #[test]
    fn deserialize_unknown_code_falls_into_other() {
        let parsed: TokenErrorCode = serde_json::from_str("\"vendor_specific_error\"").unwrap();
        assert_eq!(
            parsed,
            TokenErrorCode::Other("vendor_specific_error".into())
        );
    }

    #[test]
    fn deserialize_full_response() {
        let body = r#"{
            "error": "invalid_grant",
            "error_description": "refresh token expired",
            "error_uri": "https://example.com/docs/errors#invalid_grant"
        }"#;
        let parsed: TokenErrorResponse = serde_json::from_str(body).unwrap();
        assert_eq!(parsed.code, TokenErrorCode::InvalidGrant);
        assert_eq!(
            parsed.error_description.as_deref(),
            Some("refresh token expired")
        );
        assert_eq!(
            parsed.error_uri.as_deref(),
            Some("https://example.com/docs/errors#invalid_grant"),
        );
    }

    #[test]
    fn deserialize_minimal_response() {
        let parsed: TokenErrorResponse =
            serde_json::from_str(r#"{"error":"invalid_scope"}"#).unwrap();
        assert_eq!(parsed.code, TokenErrorCode::InvalidScope);
        assert!(parsed.error_description.is_none());
        assert!(parsed.error_uri.is_none());
    }

    #[test]
    fn display_includes_description_when_present() {
        let resp = TokenErrorResponse {
            code: TokenErrorCode::InvalidGrant,
            error_description: Some("token expired".into()),
            error_uri: None,
        };
        assert_eq!(resp.to_string(), "invalid_grant: token expired");
    }

    #[test]
    fn display_without_description() {
        let resp = TokenErrorResponse {
            code: TokenErrorCode::InvalidGrant,
            error_description: None,
            error_uri: None,
        };
        assert_eq!(resp.to_string(), "invalid_grant");
    }
}
