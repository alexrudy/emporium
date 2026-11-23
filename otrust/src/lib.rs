//! Tooling for OIDC Trusted Publisher workflows

use std::{collections::BTreeMap, fmt, sync::Arc};

use jaws::{
    Compact, Token,
    key::{JWKSetVerifyErrorKind, JwkSet, PublicWebKey, VerifyJWKSet, VerifyingWebKey},
    token::{Signed, Unverified, formats::TokenParseError},
};
use serde::{Deserialize, Serialize};

/// Errors that can occur during OIDC token validation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OIDCError {
    /// The token failed to parse as a JWT
    #[error("unable to parse token: {0}")]
    TokenParse(#[from] TokenParseError),

    /// The token failed to verify against the set of public JWKs
    #[error("unable to validate token: {0}")]
    InvalidToken(#[from] JWKSetVerifyErrorKind),

    /// There was no payload found in this tokne
    #[error("no payload in token")]
    MissingTokenPayload,

    /// The token's parameters do not match the expected parameters.
    #[error("invalid token parameters: {0}")]
    InvalidParameters(#[from] ParameterError),
}

/// Validates an OIDC token using the provider's JWK Set.
#[derive(Debug, Clone)]
pub struct OIDCValidator {
    keys: Arc<JwkSet<PublicWebKey>>,
    parameters: ExpectedParameters,
}

impl OIDCValidator {
    /// Construct a new OIDC validator
    pub fn new(keys: impl Into<Arc<JwkSet<PublicWebKey>>>, parameters: ExpectedParameters) -> Self {
        Self {
            keys: keys.into(),
            parameters,
        }
    }

    /// Validates a JWT token against the JWK Set.
    pub fn validate_token<P: Serialize + Clone>(
        &self,
        token: Token<P, Unverified<()>, Compact>,
    ) -> Result<Token<P, Signed<(), VerifyingWebKey>, Compact>, OIDCError> {
        let algorithm = *token.header().algorithm();
        if !algorithm.is_asymmetric() {
            return Err(OIDCError::InvalidToken(
                JWKSetVerifyErrorKind::UnsupportedAlgorithm(algorithm.into()),
            ));
        }

        self.keys
            .verify_token_any(token)
            .map_err(|error| error.kind.into())
    }

    /// Validates the given parameters against the expected parameters.
    pub fn validate_parameters(&self, params: &Parameters) -> Result<(), ParameterError> {
        self.parameters.matches(params)
    }

    /// Validates the given token against the expected parameters and the provider's keys.
    pub fn validate(&self, token: &str) -> Result<(), OIDCError> {
        let token: Token<Parameters, Unverified<()>, Compact> = token.parse()?;
        let token = self.validate_token(token)?;

        let Some(parameters) = token.payload() else {
            return Err(OIDCError::MissingTokenPayload);
        };
        Ok(self.validate_parameters(parameters)?)
    }
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
