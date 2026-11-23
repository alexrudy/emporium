//! OAuth2 / OIDC validator for unattended authentication via trusted publishing
//!
//! The trusted publisher mints a token, and we use their OIDC JWK Set to verify it.

mod oidc;
mod server;

pub use oidc::ExpectedParameter;
pub use oidc::ExpectedParameters;
pub use oidc::NonScalarValue;
pub use oidc::OIDCError;
pub use oidc::OIDCValidator;
pub use oidc::ParameterError;
pub use oidc::Parameters;
pub use oidc::ScalarValue;
