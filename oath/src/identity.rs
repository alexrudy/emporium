//! Validates identity claims from OpenID Connect tokens.
//!
//! Includes signature validation of the token against the provider's public key.

use std::collections::BTreeMap;

use jaws::{
    Token,
    key::{JWKSetVerifyErrorKind, VerifyJWKSet as _},
    token::Unverified,
};
use serde::{Deserialize, Serialize};

use crate::{TokenEndpoint, nonce::Nonce};

/// Reasons identity resolution can fail.
#[derive(Debug, thiserror::Error)]
pub enum OIDCTokenError {
    /// The [`TokenEndpoint`] has no public key set.
    #[error("no public key set")]
    NoPublicKeySet,

    /// The `nonce` was not provided to the validator
    #[error("no nonce provided")]
    NoNonce,

    /// The [`TokenSet`] carried no `id_token` to parse.
    #[error("token set did not include an id_token")]
    MissingIdToken,
    /// The `id_token` was not three dot-separated segments.
    #[error("id_token did not have three base64url-encoded segments")]
    MalformedIdToken,
    /// The payload segment did not base64url-decode.
    #[error("id_token payload base64 decode failed: {0}")]
    DecodeFailed(#[source] base64::DecodeError),
    /// The decoded payload was not valid JSON for [`IdClaims`].
    #[error("id_token claims JSON parse failed: {0}")]
    InvalidJson(#[source] serde_json::Error),
    /// The `sub` claim was missing or empty.
    #[error("id_token had no `sub` claim")]
    MissingSubject,
    /// The `iss` claim doesn't match the provider's issuer.
    #[error("id_token issuer {actual:?} does not match the provider's issuer {expected:?}")]
    IssuerMismatch {
        /// The provider's issuer identifier.
        expected: String,
        /// The token's `iss` claim, if any.
        actual: Option<String>,
    },
    /// The `aud` claim doesn't include this client.
    #[error("id_token audience {actual:?} does not include client {expected:?}")]
    AudienceMismatch {
        /// This client's `client_id`.
        expected: String,
        /// The token's `aud` claim values.
        actual: Vec<String>,
    },
    /// The `azp` claim names a different client.
    #[error("id_token authorized party {actual:?} is not client {expected:?}")]
    AuthorizedPartyMismatch {
        /// This client's `client_id`.
        expected: String,
        /// The token's `azp` claim.
        actual: String,
    },

    /// The id token's `nonce` claim does not match the expected value.
    #[error("id_token nonce {actual:?} does not match the expected nonce {expected:?}")]
    NonceMismatch {
        /// The expected nonce value.
        expected: String,
        /// The token's `nonce` claim.
        actual: String,
    },

    /// The id token's `exp` claim indicates it is expired.
    #[error("id_token expired")]
    TokenExpired,

    /// The id token's signature verification failed.
    #[error("id_token verification failed: {source}")]
    VerificationError {
        /// The error that occurred during signature verification.
        #[from]
        source: JWKSetVerifyErrorKind,
    },
}

/// The audience of the token, either a single string or a list of strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    /// A single audience string.
    One(String),

    /// A list of audience strings.
    Many(Vec<String>),
}

/// A minimal subset of OIDC ID Token claims.
///
/// Unknown claims are captured in [`IdClaims::extra`] so
/// provider-specific fields remain inspectable.
///
/// This object is only available when the OIDC ID token
/// has been validated against the provider's public key.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IdClaims {
    /// Subject — the stable per-provider user identifier.
    #[serde(default)]
    pub sub: String,

    /// The expiration time of the token.
    #[serde(default, with = "jaws::claims::jiff_jwt_serde::opt")]
    pub exp: Option<jiff::Timestamp>,

    /// The issuer of the token.
    #[serde(default)]
    pub iss: Option<String>,

    /// The audience of the token.
    #[serde(default)]
    pub aud: Option<Audience>,

    /// The authorized party of the token.
    #[serde(default)]
    pub azp: Option<String>,

    /// The nonce of the token.
    #[serde(default)]
    pub nonce: Option<String>,

    /// User's email address, if disclosed.
    #[serde(default)]
    pub email: Option<String>,

    /// Whether the email has been verified by the provider.
    #[serde(default)]
    pub email_verified: Option<bool>,

    /// User's display name.
    #[serde(default)]
    pub name: Option<String>,

    /// Provider's notion of a shorter username (e.g., GitHub login).
    #[serde(default)]
    pub preferred_username: Option<String>,

    /// URL to a profile picture.
    #[serde(default)]
    pub picture: Option<String>,

    /// Any additional claims the provider returned.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// Configures the validation of identity claims.
#[derive(Debug, Clone)]
pub struct IdClaimValidator<'e, 'n> {
    endpoint: &'e TokenEndpoint,
    nonce: Option<&'n Nonce>,
    now: jiff::Timestamp,
    validate_issuer: bool,
}

impl<'e, 'n> IdClaimValidator<'e, 'n> {
    /// Creates a new validator with the given endpoint.
    pub fn new(endpoint: &'e TokenEndpoint) -> Self {
        Self {
            endpoint,
            nonce: None,
            now: jiff::Timestamp::now(),
            validate_issuer: true,
        }
    }

    /// Sets the timestamp to use as the current time when validating the token.
    pub fn with_now(mut self, timestamp: jiff::Timestamp) -> Self {
        self.now = timestamp;
        self
    }

    /// Validates the issuer claim when validating the token.
    pub fn with_nonce(mut self, nonce: Option<&'n Nonce>) -> Self {
        self.nonce = nonce;
        self
    }

    /// Ignores the issuer claim when validating the token.
    pub fn ignore_issuer(mut self) -> Self {
        self.validate_issuer = false;
        self
    }

    /// Validates the token using the configured endpoint and nonce.
    pub fn validate(self, token: &str) -> Result<IdClaims, OIDCTokenError> {
        let Some(keys) = self.endpoint.keys() else {
            return Err(OIDCTokenError::NoPublicKeySet);
        };

        if self.endpoint.validate_nonce() && self.nonce.is_none() {
            return Err(OIDCTokenError::NoNonce);
        }

        let id_token: Token<IdClaims, Unverified<()>> = token
            .parse::<Token<_, _>>()
            .map_err(|_| OIDCTokenError::MalformedIdToken)?;

        let algorithm = *id_token.header().algorithm();
        if !algorithm.is_asymmetric() {
            return Err(JWKSetVerifyErrorKind::UnsupportedAlgorithm(algorithm.into()).into());
        }

        let claims = keys
            .verify_token(id_token)
            .map_err(|err| err.kind)?
            .payload()
            .cloned()
            .ok_or(OIDCTokenError::MalformedIdToken)?;

        if claims.sub.is_empty() {
            return Err(OIDCTokenError::MissingSubject);
        }

        validate_claims(
            &claims,
            self.endpoint.client_id(),
            self.validate_issuer
                .then(|| self.endpoint.issuer())
                .flatten(),
            self.nonce,
            jiff::Timestamp::now(),
        )?;
        Ok(claims)
    }
}

/// Validates an ID token against the given endpoint and nonce.
///
/// Check that the `id_token` was issued by the expected provider, for
/// this client (OIDC Core §3.1.3.7, steps 2–5):
///
/// - `iss` must exactly equal `expected_issuer`, when one is given
///   (e.g. from discovery; see [`crate::TokenEndpoint::issuer`]);
/// - `aud` must be present and include `client_id`;
/// - `azp`, if present, must equal `client_id`.
///
/// With several providers configured, this catches tokens minted by
/// one provider (or for another client) arriving through another's
/// flow.
pub fn validate(
    token: &str,
    endpoint: &TokenEndpoint,
    nonce: Option<&Nonce>,
) -> Result<IdClaims, OIDCTokenError> {
    IdClaimValidator::new(endpoint)
        .with_nonce(nonce)
        .validate(token)
}

/// Check that the `id_token` was issued by the expected provider, for
/// this client (OIDC Core §3.1.3.7, steps 2–5):
///
/// - `iss` must exactly equal `expected_issuer`, when one is given
///   (e.g. from discovery; see [`crate::TokenEndpoint::issuer`]);
/// - `aud` must be present and include `client_id`;
/// - `azp`, if present, must equal `client_id`.
///
/// With several providers configured, this catches tokens minted by
/// one provider (or for another client) arriving through another's
/// flow.
fn validate_claims(
    claims: &IdClaims,
    client_id: &str,
    expected_issuer: Option<&str>,
    nonce: Option<&Nonce>,
    now: jiff::Timestamp,
) -> Result<(), OIDCTokenError> {
    if let Some(expected) = expected_issuer
        && claims.iss.as_deref() != Some(expected)
    {
        return Err(OIDCTokenError::IssuerMismatch {
            expected: expected.to_owned(),
            actual: claims.iss.clone(),
        });
    }

    let audience = match claims.aud.clone() {
        Some(Audience::One(aud)) => vec![aud],
        Some(Audience::Many(aud)) => aud,
        None => Vec::new(),
    };
    if !audience.iter().any(|aud| aud == client_id) {
        return Err(OIDCTokenError::AudienceMismatch {
            expected: client_id.to_owned(),
            actual: audience,
        });
    }

    if let Some(azp) = claims.azp.as_deref()
        && azp != client_id
    {
        return Err(OIDCTokenError::AuthorizedPartyMismatch {
            expected: client_id.to_owned(),
            actual: azp.to_owned(),
        });
    }

    if let Some(exp) = claims.exp
        && exp < now
    {
        return Err(OIDCTokenError::TokenExpired);
    }

    if !nonce.is_none_or(|n| {
        claims
            .nonce
            .as_deref()
            .is_some_and(|recieved| n.verify(recieved))
    }) {
        return Err(OIDCTokenError::NonceMismatch {
            expected: nonce.map(|n| n.revealed()).unwrap_or_default().to_owned(),
            actual: claims.nonce.clone().unwrap_or_default(),
        });
    }

    Ok(())
}

#[cfg(false)]
/// Parses an ID token without verifying its signature.
///
/// Must only be used with trusted tokens from the same provider, received via
/// a secure source (e.g. over TLS).
pub fn dangerous_parse_id_token(token: &str) -> Result<IdClaims, OIDCTokenError> {
    use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};

    let mut parts = token.split('.');
    let Some(_) = parts.next() else {
        return Err(OIDCTokenError::MalformedIdToken);
    };
    let Some(payload) = parts.next() else {
        return Err(OIDCTokenError::MalformedIdToken);
    };

    let raw = BASE64_URL_SAFE_NO_PAD
        .decode(payload.as_bytes())
        .map_err(|error| {
            eprintln!("Unable to decode b64 URL Safe payload: {error:?}");
            OIDCTokenError::MalformedIdToken
        })?;

    serde_json::from_slice(&raw).map_err(|error| OIDCTokenError::InvalidJson(error))
}

#[cfg(test)]
mod tests {
    use super::*;

    use jaws::{
        Token,
        crypto::rsa::{self, Generate as _},
        key::{Identified, JwkSet, PublicWebKey},
    };
    use serde::Serialize;
    use serde_json::json;

    fn rsa() -> rsa::pkcs1v15::SigningKey<sha2::Sha256> {
        rsa::PrivateKey::generate().into()
    }

    fn keyset(key: &rsa::pkcs1v15::SigningKey<sha2::Sha256>) -> JwkSet<PublicWebKey> {
        let public_key = PublicWebKey::from(key.as_ref().as_public_key().clone());
        JwkSet::from(vec![
            Identified::unidentified(public_key).with_id("kid".into()),
        ])
    }

    fn jwt<P: Serialize>(payload: P, key: &rsa::pkcs1v15::SigningKey<sha2::Sha256>) -> String {
        let mut token = Token::compact((), payload);
        *token.header_mut().r#type() = Some("JWT".into());
        *token.header_mut().key_id() = Some("kid".into());

        token
            .sign::<_, rsa::pkcs1v15::Signature>(key)
            .unwrap()
            .rendered()
            .unwrap()
    }

    #[test]
    fn malformed_id_token() {
        let key = rsa();
        assert!(matches!(
            validate("only.two", &endpoint(None, &key), None),
            Err(OIDCTokenError::MalformedIdToken)
        ));
    }

    #[test]
    fn missing_sub_claim() {
        let key = rsa();

        let token = jwt(json!({"email":"alice@example.com"}), &key);
        let error = validate(&token, &endpoint(None, &key), None).unwrap_err();

        assert!(
            matches!(error, OIDCTokenError::MissingSubject),
            "got {error:?}"
        );
    }

    fn endpoint(
        issuer: Option<&str>,
        key: &rsa::pkcs1v15::SigningKey<sha2::Sha256>,
    ) -> TokenEndpoint {
        let builder = TokenEndpoint::builder().client_id("client");

        if let Some(iss) = issuer {
            builder.issuer(iss)
        } else {
            builder
        }
        .keys(keyset(key))
        .token_uri("https://idp.example.com/oauth/token".parse().unwrap())
        .build()
        .unwrap()
    }

    fn ve<P: Serialize>(
        payload: P,
        issuer: Option<&str>,
        nonce: Option<&Nonce>,
        key: &rsa::pkcs1v15::SigningKey<sha2::Sha256>,
    ) -> Result<IdClaims, OIDCTokenError> {
        validate(&jwt(payload, key), &endpoint(issuer, key), nonce)
    }

    #[test]
    fn validate_accepts_matching_claims() {
        let iss = Some("https://idp.example.com");
        let key = rsa();

        assert!(
            ve(
                json!({"iss":"https://idp.example.com","aud":"client","sub":"user"}),
                iss,
                None,
                &key
            )
            .is_ok(),
            "validate accepts matching claims"
        );

        assert!(ve(
            json!({"iss":"https://idp.example.com","aud":["other","client"],"azp":"client","sub":"user"}),
            iss,
            None,
            &key,
        ).is_ok(),
        "validate accepts matching claims with array audience"
        );
        // Without an expected issuer, `iss` isn't checked.
        assert!(
            ve(
                json!({"iss":"https://anything","aud":"client","sub":"user"}),
                None,
                None,
                &key,
            )
            .is_ok(),
            "validate ignores issuer when not provided"
        );
    }

    #[test]
    fn validate_rejects_wrong_issuer() {
        let iss = Some("https://idp.example.com");
        let key = rsa();
        for payload in &[
            json!({"iss":"https://evil.example.com","aud":"client","sub":"user"}),
            json!({"iss":"https://idp.example.com/","aud":"client","sub":"user"}),
            json!({"aud":"client","sub":"user"}),
        ] {
            assert!(
                matches!(
                    ve(payload, iss, None, &key),
                    Err(OIDCTokenError::IssuerMismatch { .. })
                ),
                "{payload:?}"
            );
        }
    }

    #[test]
    fn validate_rejects_wrong_audience() {
        let key = rsa();
        for payload in &[
            json!({"aud":"other","sub":"user"}),
            json!({"aud":["other","another"],"sub":"user"}),
            json!({"aud":[],"sub":"user"}),
            json!({"sub":"user"}),
        ] {
            assert!(
                matches!(
                    ve(payload, None, None, &key),
                    Err(OIDCTokenError::AudienceMismatch { .. })
                ),
                "{payload}"
            );
        }
    }

    #[test]
    fn validate_rejects_wrong_authorized_party() {
        let key = rsa();
        assert!(matches!(
            ve(
                json!({"aud":["client","other"],"azp":"other","sub":"user"}),
                None,
                None,
                &key
            ),
            Err(OIDCTokenError::AuthorizedPartyMismatch { .. })
        ));
    }

    #[test]
    fn extra_claims_captured() {
        let key = rsa();
        let claims = ve(
            json!({"sub":"x","aud":"client","provider_specific":"value"}),
            None,
            None,
            &key,
        )
        .unwrap();
        assert_eq!(
            claims.extra.get("provider_specific"),
            Some(&serde_json::Value::String("value".into())),
        );
    }
}
