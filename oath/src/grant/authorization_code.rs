//! RFC 6749 §4.1.3 — Authorization Code grant (with optional PKCE).

use crate::pkce::PkceVerifier;

/// Request a token by exchanging an authorization code.
///
/// `redirect_uri` is taken from the [`crate::endpoint::TokenEndpoint`]
/// configuration; the grant struct only carries values specific to the
/// individual exchange.
#[derive(Debug, Clone)]
pub struct AuthorizationCodeRequest {
    pub(crate) code: String,
    pub(crate) pkce_verifier: Option<PkceVerifier>,
}

impl AuthorizationCodeRequest {
    /// Build a new request for the given authorization code.
    pub fn new(code: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            pkce_verifier: None,
        }
    }

    /// Attach a PKCE verifier (RFC 7636).
    ///
    /// Required when the authorization request advertised a
    /// `code_challenge`. The verifier and the original challenge must
    /// match per RFC 7636 §4.6.
    pub fn pkce(mut self, verifier: PkceVerifier) -> Self {
        self.pkce_verifier = Some(verifier);
        self
    }

    pub(crate) fn into_fields(self) -> Vec<(&'static str, String)> {
        let mut fields = Vec::with_capacity(3);
        fields.push(("grant_type", "authorization_code".to_owned()));
        fields.push(("code", self.code));
        if let Some(verifier) = self.pkce_verifier {
            fields.push(("code_verifier", verifier.revealed().to_owned()));
        }
        fields
    }
}
