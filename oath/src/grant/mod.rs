//! OAuth2 grants supported by [`crate::endpoint::TokenEndpoint`].
//!
//! Each grant has its own builder type that the endpoint accepts via
//! [`TokenRequest`]. Use [`TokenRequest::from`] (or the impls below) to
//! convert a grant builder into the enum variant the endpoint expects.

use http::Uri;

mod authorization_code;
mod authorization_url;
mod client_credentials;
mod device_code;
mod pending;
mod refresh;

pub use self::authorization_code::AuthorizationCodeRequest;
pub use self::authorization_url::AuthorizationUrl;
pub use self::client_credentials::ClientCredentialsRequest;
pub use self::device_code::{DeviceAuthorizationResponse, DeviceCodeRequest};
pub use self::pending::{CallbackError, PendingAuthorization};
pub use self::refresh::RefreshRequest;

/// A token-endpoint request, dispatching to one of the supported grants.
///
/// Use the [`From`] impls on the inner grant types to construct.
#[derive(Debug, Clone)]
pub enum TokenRequest {
    /// Client Credentials grant (RFC 6749 §4.4).
    ClientCredentials(ClientCredentialsRequest),
    /// Authorization Code grant (RFC 6749 §4.1.3), optionally with PKCE.
    AuthorizationCode(AuthorizationCodeRequest),
    /// Refresh Token grant (RFC 6749 §6).
    Refresh(RefreshRequest),
    /// Device Authorization grant (RFC 8628 §3.4).
    DeviceCode(DeviceCodeRequest),
}

impl TokenRequest {
    /// Build the grant-specific form fields. `endpoint_redirect` is the
    /// `redirect_uri` configured on the token endpoint; the
    /// `authorization_code` grant uses it when present.
    pub(crate) fn build_fields(
        self,
        endpoint_redirect: Option<&Uri>,
    ) -> Vec<(&'static str, String)> {
        match self {
            Self::ClientCredentials(r) => r.into_fields(),
            Self::AuthorizationCode(r) => {
                let mut fields = r.into_fields();
                if let Some(uri) = endpoint_redirect {
                    fields.push(("redirect_uri", uri.to_string()));
                }
                fields
            }
            Self::Refresh(r) => r.into_fields(),
            Self::DeviceCode(r) => r.into_fields(),
        }
    }
}

impl From<ClientCredentialsRequest> for TokenRequest {
    fn from(r: ClientCredentialsRequest) -> Self {
        Self::ClientCredentials(r)
    }
}

impl From<AuthorizationCodeRequest> for TokenRequest {
    fn from(r: AuthorizationCodeRequest) -> Self {
        Self::AuthorizationCode(r)
    }
}

impl From<RefreshRequest> for TokenRequest {
    fn from(r: RefreshRequest) -> Self {
        Self::Refresh(r)
    }
}

impl From<DeviceCodeRequest> for TokenRequest {
    fn from(r: DeviceCodeRequest) -> Self {
        Self::DeviceCode(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkce::PkceVerifier;
    use crate::scope::ScopeSet;
    use crate::token::RefreshToken;
    use secret::Secret;

    fn fields_for(request: impl Into<TokenRequest>, redirect: Option<&Uri>) -> String {
        let fields = request.into().build_fields(redirect);
        serde_urlencoded::to_string(&fields).unwrap()
    }

    #[test]
    fn client_credentials_minimal() {
        let body = fields_for(ClientCredentialsRequest::new(), None);
        assert_eq!(body, "grant_type=client_credentials");
    }

    #[test]
    fn client_credentials_with_scope() {
        let scope: ScopeSet = "read write".parse().unwrap();
        let body = fields_for(ClientCredentialsRequest::new().scope(scope), None);
        assert_eq!(body, "grant_type=client_credentials&scope=read+write");
    }

    #[test]
    fn authorization_code_minimal() {
        let body = fields_for(AuthorizationCodeRequest::new("the-code"), None);
        assert_eq!(body, "grant_type=authorization_code&code=the-code");
    }

    #[test]
    fn authorization_code_with_pkce_and_redirect() {
        let verifier =
            PkceVerifier::new("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_owned()).unwrap();
        let redirect: Uri = "https://app.example.com/cb".parse().unwrap();
        let body = fields_for(
            AuthorizationCodeRequest::new("the-code").pkce(verifier),
            Some(&redirect),
        );
        assert_eq!(
            body,
            "grant_type=authorization_code\
             &code=the-code\
             &code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk\
             &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb"
        );
    }

    #[test]
    fn refresh_minimal() {
        let refresh_token = RefreshToken::new(Secret::from("rtok"));
        let body = fields_for(RefreshRequest::new(refresh_token), None);
        assert_eq!(body, "grant_type=refresh_token&refresh_token=rtok");
    }

    #[test]
    fn refresh_with_scope() {
        let refresh_token = RefreshToken::new(Secret::from("rtok"));
        let scope: ScopeSet = "read".parse().unwrap();
        let body = fields_for(RefreshRequest::new(refresh_token).scope(scope), None);
        assert_eq!(
            body,
            "grant_type=refresh_token&refresh_token=rtok&scope=read"
        );
    }
}
