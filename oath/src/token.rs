//! OAuth2 token types.
//!
//! - [`AccessToken`] is the live credential that implements
//!   [`api_client::Authentication`]. It carries an optional expiry so the
//!   higher-level client can decide whether to refresh before sending.
//! - [`RefreshToken`] is a separate newtype to avoid mixing access and
//!   refresh tokens in signatures.
//! - [`TokenResponse`] models the wire shape returned by an OAuth2 token
//!   endpoint (RFC 6749 §5.1).
//! - [`TokenSet`] is the convenience bundle produced from a `TokenResponse`,
//!   with the relative `expires_in` resolved into an absolute `expires_at`.

use std::collections::BTreeMap;

use api_client::Authentication;
use chrono::{DateTime, Duration, Utc};
use http::HeaderValue;
use secret::Secret;
use serde::{Deserialize, Serialize};

use crate::scope::ScopeSet;

/// Seconds subtracted from a token's stated expiry to account for clock
/// drift between client and server. Matches the offset used by
/// `services/octocat`.
pub const CLOCK_DRIFT_OFFSET_SECS: i64 = 60;

/// An OAuth2 access token.
///
/// This is the credential that gets attached to outgoing requests as a
/// `Bearer` header. It carries an optional `expires_at` so callers can
/// decide whether to refresh before using it.
#[derive(Debug, Clone)]
pub struct AccessToken {
    token: Secret,
    expires_at: Option<DateTime<Utc>>,
}

impl AccessToken {
    /// Construct a new access token with an optional absolute expiry.
    ///
    /// `expires_at` should already include any clock-drift offset the
    /// caller wants applied. To build from a relative `expires_in` value
    /// returned by an OAuth2 token endpoint, prefer
    /// [`AccessToken::from_response_at`] or `TokenSet::from(response)`.
    pub fn new(token: Secret, expires_at: Option<DateTime<Utc>>) -> Self {
        Self { token, expires_at }
    }

    /// Build an access token from the raw response fields, resolving
    /// `expires_in` against `received_at` and applying the clock-drift
    /// offset. Returns `expires_at = received_at + expires_in - offset`
    /// when `expires_in` is provided, otherwise `None`.
    pub fn from_response_at(
        token: Secret,
        expires_in: Option<u64>,
        received_at: DateTime<Utc>,
    ) -> Self {
        let expires_at = expires_in.map(|secs| {
            received_at + Duration::seconds(secs as i64)
                - Duration::seconds(CLOCK_DRIFT_OFFSET_SECS)
        });
        Self { token, expires_at }
    }

    /// Inspect the absolute expiry time, if known.
    pub fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.expires_at
    }

    /// Whether this token should be considered expired at `now`.
    ///
    /// Returns `false` if the token has no recorded expiry — by RFC 6749
    /// §5.1 `expires_in` is RECOMMENDED but not REQUIRED, and a missing
    /// value means the server did not provide a lifetime hint.
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        matches!(self.expires_at, Some(exp) if exp <= now)
    }

    /// Reveal the underlying token text. Use sparingly.
    pub fn revealed(&self) -> &str {
        self.token.revealed()
    }
}

impl Authentication for AccessToken {
    fn authenticate<B>(&self, mut req: http::Request<B>) -> http::Request<B> {
        if req.headers().contains_key(http::header::AUTHORIZATION) {
            tracing::warn!("{} header already set", http::header::AUTHORIZATION);
            return req;
        }
        let value: HeaderValue = self
            .token
            .bearer()
            .expect("bearer token is a valid HTTP header value");
        req.headers_mut().append(http::header::AUTHORIZATION, value);
        req
    }
}

/// An OAuth2 refresh token.
///
/// Kept separate from [`AccessToken`] to prevent accidental swaps in
/// function signatures.
#[derive(Debug, Clone)]
pub struct RefreshToken(Secret);

impl RefreshToken {
    /// Wrap a [`Secret`] as a refresh token.
    pub fn new(secret: impl Into<Secret>) -> Self {
        Self(secret.into())
    }

    /// Reveal the underlying token text. Use only when emitting the value
    /// as part of an outbound request body.
    pub fn revealed(&self) -> &str {
        self.0.revealed()
    }
}

/// The `token_type` field of an OAuth2 token response (RFC 6749 §7.1).
///
/// `oath` only supports `Bearer` semantics today; unknown types are
/// recorded but treated like `Bearer` when used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenType {
    /// `Bearer` per RFC 6750.
    Bearer,
    /// Any token type not recognized by this crate.
    Other(String),
}

impl<'de> Deserialize<'de> for TokenType {
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(de)?;
        Ok(if raw.eq_ignore_ascii_case("bearer") {
            TokenType::Bearer
        } else {
            TokenType::Other(raw)
        })
    }
}

impl Serialize for TokenType {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        match self {
            TokenType::Bearer => ser.serialize_str("Bearer"),
            TokenType::Other(s) => ser.serialize_str(s),
        }
    }
}

/// A token endpoint response (RFC 6749 §5.1).
///
/// Unknown fields are captured in [`TokenResponse::extra`] so
/// provider-specific extensions remain inspectable.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TokenResponse {
    /// The access token issued by the server.
    pub access_token: Secret,

    /// The type of the token (`Bearer` by convention).
    pub token_type: TokenType,

    /// Lifetime of the access token in seconds.
    #[serde(default)]
    pub expires_in: Option<u64>,

    /// A refresh token that can be used to obtain new access tokens.
    #[serde(default)]
    pub refresh_token: Option<Secret>,

    /// The scopes actually granted, as a space-separated string.
    #[serde(default)]
    pub scope: Option<ScopeSet>,

    /// An OIDC ID token, if returned. Not validated by this crate.
    #[serde(default)]
    pub id_token: Option<String>,

    /// Any additional fields returned by the server.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// A processed view of a [`TokenResponse`] with an absolute expiry.
#[derive(Debug, Clone)]
pub struct TokenSet {
    /// The access token to attach to outgoing requests.
    pub access_token: AccessToken,
    /// The refresh token, if the server returned one.
    pub refresh_token: Option<RefreshToken>,
    /// The granted scopes, if the server returned them.
    pub scope: Option<ScopeSet>,
    /// The OIDC ID token, if returned. Unvalidated.
    pub id_token: Option<String>,
}

impl TokenSet {
    /// Convert a [`TokenResponse`] into a [`TokenSet`], resolving
    /// `expires_in` against the supplied reception time.
    pub fn from_response_at(response: TokenResponse, received_at: DateTime<Utc>) -> Self {
        let TokenResponse {
            access_token,
            expires_in,
            refresh_token,
            scope,
            id_token,
            // `token_type` is dropped here — see TokenType docs.
            token_type: _,
            extra: _,
        } = response;

        Self {
            access_token: AccessToken::from_response_at(access_token, expires_in, received_at),
            refresh_token: refresh_token.map(RefreshToken::new),
            scope,
            id_token,
        }
    }
}

impl From<TokenResponse> for TokenSet {
    fn from(response: TokenResponse) -> Self {
        Self::from_response_at(response, Utc::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn epoch() -> DateTime<Utc> {
        Utc.timestamp_opt(0, 0).unwrap()
    }

    #[test]
    fn access_token_with_no_expiry_is_never_expired() {
        let tok = AccessToken::new(Secret::from("abc"), None);
        assert!(!tok.is_expired(Utc::now()));
    }

    #[test]
    fn access_token_expires_at_offset_subtracts_drift() {
        let received = epoch();
        let tok = AccessToken::from_response_at(Secret::from("abc"), Some(3600), received);
        let expected = received + Duration::seconds(3600 - CLOCK_DRIFT_OFFSET_SECS);
        assert_eq!(tok.expires_at(), Some(expected));
    }

    #[test]
    fn access_token_is_expired_after_expires_at() {
        let received = epoch();
        let tok = AccessToken::from_response_at(Secret::from("abc"), Some(60), received);
        // 60s lifetime minus 60s drift = 0s effective; receiver == expiry.
        assert!(tok.is_expired(received));
        // And of course any time later than that.
        assert!(tok.is_expired(received + Duration::seconds(1)));
    }

    #[test]
    fn access_token_is_fresh_before_expires_at() {
        let received = epoch();
        let tok = AccessToken::from_response_at(Secret::from("abc"), Some(3600), received);
        assert!(!tok.is_expired(received));
        assert!(!tok.is_expired(received + Duration::seconds(60)));
    }

    #[test]
    fn access_token_missing_expires_in_yields_no_expiry() {
        let tok = AccessToken::from_response_at(Secret::from("abc"), None, epoch());
        assert!(tok.expires_at().is_none());
    }

    #[test]
    fn authentication_attaches_bearer_header() {
        let tok = AccessToken::new(Secret::from("my-token"), None);
        let req = http::Request::builder()
            .uri("https://example.com/")
            .body(())
            .unwrap();
        let req = tok.authenticate(req);
        let header = req.headers().get(http::header::AUTHORIZATION).unwrap();
        assert_eq!(header.to_str().unwrap(), "Bearer my-token");
        assert!(header.is_sensitive());
    }

    #[test]
    fn authentication_does_not_clobber_existing_header() {
        let tok = AccessToken::new(Secret::from("my-token"), None);
        let req = http::Request::builder()
            .uri("https://example.com/")
            .header(http::header::AUTHORIZATION, "Basic preset")
            .body(())
            .unwrap();
        let req = tok.authenticate(req);
        assert_eq!(
            req.headers().get(http::header::AUTHORIZATION).unwrap(),
            "Basic preset",
        );
    }

    #[test]
    fn token_type_bearer_case_insensitive() {
        let bearer: TokenType = serde_json::from_str("\"Bearer\"").unwrap();
        assert_eq!(bearer, TokenType::Bearer);
        let lowercase: TokenType = serde_json::from_str("\"bearer\"").unwrap();
        assert_eq!(lowercase, TokenType::Bearer);
    }

    #[test]
    fn token_type_unknown_falls_into_other() {
        let other: TokenType = serde_json::from_str("\"MAC\"").unwrap();
        assert_eq!(other, TokenType::Other("MAC".into()));
    }

    #[test]
    fn token_response_minimal() {
        let body = r#"{
            "access_token": "abc",
            "token_type": "Bearer"
        }"#;
        let resp: TokenResponse = serde_json::from_str(body).unwrap();
        assert_eq!(resp.access_token.revealed(), "abc");
        assert_eq!(resp.token_type, TokenType::Bearer);
        assert!(resp.expires_in.is_none());
        assert!(resp.refresh_token.is_none());
        assert!(resp.scope.is_none());
        assert!(resp.id_token.is_none());
        assert!(resp.extra.is_empty());
    }

    #[test]
    fn token_response_full() {
        let body = r#"{
            "access_token": "atok",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "rtok",
            "scope": "read write",
            "id_token": "header.payload.sig",
            "vendor_field": "vendor_value"
        }"#;
        let resp: TokenResponse = serde_json::from_str(body).unwrap();
        assert_eq!(resp.access_token.revealed(), "atok");
        assert_eq!(resp.expires_in, Some(3600));
        assert_eq!(resp.refresh_token.unwrap().revealed(), "rtok");
        assert_eq!(resp.scope.unwrap().to_string(), "read write");
        assert_eq!(resp.id_token.as_deref(), Some("header.payload.sig"));
        assert_eq!(
            resp.extra.get("vendor_field"),
            Some(&serde_json::Value::String("vendor_value".into())),
        );
    }

    #[test]
    fn tokenset_from_response_applies_offset() {
        let resp = TokenResponse {
            access_token: Secret::from("a"),
            token_type: TokenType::Bearer,
            expires_in: Some(120),
            refresh_token: Some(Secret::from("r")),
            scope: None,
            id_token: None,
            extra: BTreeMap::new(),
        };
        let received = epoch();
        let set = TokenSet::from_response_at(resp, received);

        let expected = received + Duration::seconds(120 - CLOCK_DRIFT_OFFSET_SECS);
        assert_eq!(set.access_token.expires_at(), Some(expected));
        assert!(set.refresh_token.is_some());
    }

    #[test]
    fn tokenset_from_response_no_expiry() {
        let resp = TokenResponse {
            access_token: Secret::from("a"),
            token_type: TokenType::Bearer,
            expires_in: None,
            refresh_token: None,
            scope: None,
            id_token: None,
            extra: BTreeMap::new(),
        };
        let set = TokenSet::from(resp);
        assert!(set.access_token.expires_at().is_none());
        assert!(set.refresh_token.is_none());
    }
}
