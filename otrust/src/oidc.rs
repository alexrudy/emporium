use std::{
    collections::BTreeMap,
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use arc_swap::ArcSwapOption;
use bytes::Bytes;
use http_body_util::BodyExt;
use hyperdriver::Body;

use jaws::{
    Compact, Token,
    key::{IntoVerifyingKey, JwkSet, PublicWebKey, VerifyingWebKey},
    token::{Signed, Unverified, formats::TokenParseError},
};
use oath::ProviderMetadata;
use serde::{Deserialize, Serialize};

/// Errors that can occur during OIDC token validation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OIDCError {
    /// Failed to request the JWK Set from the provider.
    #[error("failed to request JWK Set: {0}")]
    KeysRequst(Box<dyn std::error::Error>),

    /// Invalid JWK Set response from the provider.
    #[error("failed to parse JWK Set response: {status} {body}")]
    KeysResponse {
        /// The HTTP status code of the response.
        status: http::StatusCode,

        /// The body of the response that could not be deserialized.
        body: String,
    },

    /// The JWK Set URI is missing from the provider metadata.
    #[error("missing JWK Set URI in provider metadata")]
    MissingJwksUri,

    /// The provided JWK Set URI is invalid.
    #[error("the provided JWK Set URI is invalid")]
    InvalidJwksUri,

    /// Unable to deserialize the JWK Set from the provider's response.
    #[error("unable to deserialize JWK Set: {source}")]
    DeserializeJwkSet {
        /// The error that occurred while deserializing the JWK Set.
        source: serde_json::Error,

        /// The body of the response that could not be deserialized.
        body: String,
    },

    /// Verification failed due to an error during verification.
    #[error("verification failed: {source}")]
    VerificationFailed {
        /// The error that occurred during verification.
        source: Box<dyn std::error::Error>,
    },

    /// The token could not be parsed.
    #[error("invalid token: {source}")]
    InvalidToken {
        /// The error that occurred while parsing the token.
        source: TokenParseError,
    },

    /// The token's parameters do not match the expected parameters.
    #[error("invalid token parameters: {0}")]
    InvalidParameters(#[from] ParameterError),
}

#[derive(Debug, Clone)]
struct OIDCKeys {
    keyset: JwkSet<PublicWebKey>,
    fetched: Instant,
}

/// Validates an OIDC token using the provider's JWK Set.
#[derive(Debug, Clone)]
pub struct OIDCValidator {
    provider: ProviderMetadata,
    keys: Arc<ArcSwapOption<OIDCKeys>>,
    cache_time: Duration,
    transport: hyperdriver::Client,
    parameters: ExpectedParameters,
}

impl OIDCValidator {
    async fn update_keys(&self) -> Result<(), OIDCError> {
        let now = Instant::now();
        if self
            .keys
            .load()
            .as_ref()
            .is_some_and(|keys| now.duration_since(keys.fetched) < self.cache_time)
        {
            return Ok(());
        }

        let Some(jwks_uri) = self.provider.jwks_uri.as_deref() else {
            return Err(OIDCError::MissingJwksUri);
        };

        let resp = self
            .transport
            .clone()
            .get(jwks_uri.parse().map_err(|_| OIDCError::InvalidJwksUri)?)
            .await
            .map_err(|error| OIDCError::KeysRequst(error))?;

        let body = collect_response(resp).await?;
        let keys: JwkSet<PublicWebKey> =
            serde_json::from_slice(&body).map_err(|error| OIDCError::DeserializeJwkSet {
                source: error,
                body: String::from_utf8_lossy(&body).into_owned(),
            })?;

        self.keys.store(Some(Arc::new(OIDCKeys {
            keyset: keys,
            fetched: Instant::now(),
        })));
        Ok(())
    }

    /// Validates a JWT token against the JWK Set.
    pub async fn validate_token<P: Serialize + Clone>(
        &self,
        token: Token<P, Unverified<()>, Compact>,
    ) -> Result<Token<P, Signed<(), VerifyingWebKey>, Compact>, OIDCError> {
        self.update_keys().await?;

        let algorithm = *token.header().algorithm();
        if !algorithm.is_asymmetric() {
            return Err(OIDCError::VerificationFailed {
                source: "Unsupported algorithm".into(),
            });
        }

        if let Some(kid) = token.header().key_id() {
            if let Some(key) = self.keys.load().as_ref().and_then(|k| k.keyset.get(kid))
                && let Ok(verifier) = key.clone().into_verifying_key(algorithm)
            {
                return token
                    .verify(&verifier)
                    .map_err(|error| OIDCError::VerificationFailed {
                        source: error.kind.into(),
                    });
            }
            return Err(OIDCError::VerificationFailed {
                source: "Unable to find matching key by kid".into(),
            });
        }

        if let Some(keys) = self.keys.load().as_ref().map(|k| &k.keyset) {
            for key in keys.iter() {
                if let Ok(verifier) = key.key.clone().into_verifying_key(algorithm)
                    && let Ok(token) = token.clone().verify(&verifier)
                {
                    return Ok(token);
                }
            }
        }

        Err(OIDCError::VerificationFailed {
            source: "Unable verify token with any key".into(),
        })
    }

    /// Validates the given parameters against the expected parameters.
    pub fn validate_parameters(&self, params: &Parameters) -> Result<(), ParameterError> {
        self.parameters.matches(params)
    }

    /// Validates the given token against the expected parameters and the provider's keys.
    pub async fn validate(&self, token: &str) -> Result<(), OIDCError> {
        let token: Token<Parameters, Unverified<()>, Compact> = token
            .parse()
            .map_err(|error| OIDCError::InvalidToken { source: error })?;
        let token = self.validate_token(token).await?;

        let Some(parameters) = token.payload() else {
            return Err(OIDCError::InvalidToken {
                source: TokenParseError::MissingPayload,
            });
        };
        Ok(self.validate_parameters(parameters)?)
    }
}

async fn collect_response(resp: http::Response<Body>) -> Result<Bytes, OIDCError> {
    let (parts, body) = resp.into_parts();
    let status = parts.status;
    let collected = body.collect().await.map_err(|e| OIDCError::KeysRequst(e))?;
    let bytes = collected.to_bytes();

    if !status.is_success() {
        return Err(OIDCError::KeysResponse {
            status,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        });
    }

    Ok(bytes)
}

/// An error that occurs when validating token parameters.
#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
pub enum ParameterError {
    /// A parameter is missing from the token.
    #[error("missing parameter: {0}")]
    Missing(String),

    /// A parameter does not match the expected value.
    #[error("parameter {key}: {actual} does not match {expected:?}")]
    Unexpected {
        /// The key of the parameter that did not match.
        key: String,

        /// The expected value of the parameter.
        expected: ExpectedParameter,

        /// The actual value of the parameter.
        actual: ScalarValue,
    },
}

/// A single expected parameter for a token.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum ExpectedParameter {
    /// A string value that must contain a specific substring.
    Contains(String),

    /// A value that must be equal to a specific scalar value.
    Equals(ScalarValue),
}

impl ExpectedParameter {
    /// Returns whether the given value matches this expected parameter.
    fn matches(&self, value: &ScalarValue) -> bool {
        match self {
            ExpectedParameter::Contains(substr) => {
                value.as_str().is_some_and(|s| s.contains(substr))
            }
            ExpectedParameter::Equals(expected) => expected == value,
        }
    }
}

/// A map of expected parameters for a token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedParameters(BTreeMap<String, ExpectedParameter>);

impl ExpectedParameters {
    /// Returns whether the given parameters match this expected parameters map.
    fn matches(&self, params: &Parameters) -> Result<(), ParameterError> {
        for (name, expected) in self.0.iter() {
            if let Some(value) = params.0.get(name) {
                if !expected.matches(value) {
                    return Err(ParameterError::Unexpected {
                        key: name.clone(),
                        expected: expected.clone(),
                        actual: value.clone(),
                    });
                }
            } else {
                return Err(ParameterError::Missing(name.clone()));
            }
        }
        Ok(())
    }
}

/// A scalar value that can be serialized as a JSON value.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ScalarValue {
    /// A string value.
    String(String),

    /// A numeric value.
    Number(serde_json::Number),

    /// A boolean value.
    Bool(bool),

    /// A null value.
    Null,
}

impl fmt::Display for ScalarValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScalarValue::String(s) => write!(f, "{}", s),
            ScalarValue::Number(n) => write!(f, "{}", n),
            ScalarValue::Bool(b) => write!(f, "{}", b),
            ScalarValue::Null => write!(f, "null"),
        }
    }
}

impl ScalarValue {
    /// Returns the value as a string, if it is a string value.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            ScalarValue::String(s) => Some(s),
            _ => None,
        }
    }
}

impl From<ScalarValue> for serde_json::Value {
    fn from(value: ScalarValue) -> Self {
        match value {
            ScalarValue::String(s) => serde_json::Value::String(s),
            ScalarValue::Number(n) => serde_json::Value::Number(n),
            ScalarValue::Bool(b) => serde_json::Value::Bool(b),
            ScalarValue::Null => serde_json::Value::Null,
        }
    }
}

/// An error indicating a non-scalar value was encountered trying to construct a [`ScalarValue`].
#[derive(Debug, Clone, thiserror::Error)]
#[error("non-scalar value")]
pub struct NonScalarValue;

impl TryFrom<serde_json::Value> for ScalarValue {
    type Error = NonScalarValue;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        match value {
            serde_json::Value::String(s) => Ok(ScalarValue::String(s)),
            serde_json::Value::Number(n) => Ok(ScalarValue::Number(n)),
            serde_json::Value::Bool(b) => Ok(ScalarValue::Bool(b)),
            serde_json::Value::Null => Ok(ScalarValue::Null),
            _ => Err(NonScalarValue),
        }
    }
}

/// A map of actual parameters for a token.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Parameters(BTreeMap<String, ScalarValue>);

impl Parameters {
    /// Returns the value of the parameter with the given name, if it exists.
    pub fn get(&self, name: &str) -> Option<&ScalarValue> {
        self.0.get(name)
    }
}
