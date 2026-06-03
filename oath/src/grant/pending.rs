//! The pre-auth bundle carried across the authorization redirect.

use serde::{Deserialize, Serialize};

use crate::endpoint::TokenEndpoint;
use crate::error::Error;
use crate::grant::authorization_code::AuthorizationCodeRequest;
use crate::pkce::PkceVerifier;
use crate::state::StateToken;
use crate::token::TokenSet;

/// State the caller must persist between sending the authorization
/// request and handling the callback redirect.
///
/// Produced by [`crate::grant::AuthorizationUrl::begin`]. Stash this in
/// the pre-auth session store keyed by a short-lived cookie, then load
/// it back when the callback arrives and call
/// [`PendingAuthorization::complete`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingAuthorization {
    /// The CSRF state token sent in the authorization request.
    pub state: StateToken,
    /// The PKCE verifier whose challenge was sent in the authorization
    /// request. Must be presented to the token endpoint at exchange time.
    pub verifier: PkceVerifier,
}

impl PendingAuthorization {
    /// Verify the state returned by the authorization server and
    /// exchange the code for a [`TokenSet`].
    ///
    /// On a state mismatch, returns [`CallbackError::StateMismatch`]
    /// **before** any network call — the suspect callback never touches
    /// the token endpoint.
    pub async fn complete(
        self,
        endpoint: &TokenEndpoint,
        returned_state: &str,
        returned_code: impl Into<String>,
    ) -> Result<TokenSet, CallbackError> {
        if !self.state.verify(returned_state) {
            return Err(CallbackError::StateMismatch);
        }
        let request = AuthorizationCodeRequest::new(returned_code).pkce(self.verifier);
        let response = endpoint.exchange(request).await?;
        Ok(TokenSet::from(response))
    }
}

/// Errors specific to handling the authorization-code callback.
///
/// Split out from [`Error`] so HTTP handlers can map state mismatches
/// (likely CSRF or a stale session) to a 400 with a generic message,
/// while still propagating real exchange failures.
#[derive(Debug, thiserror::Error)]
pub enum CallbackError {
    /// The `state` returned by the authorization server didn't match
    /// the value we sent. Indicates a CSRF attack or a stale callback.
    #[error("OAuth2 state mismatch (possible CSRF or stale callback)")]
    StateMismatch,

    /// The code exchange against the token endpoint failed.
    #[error(transparent)]
    Exchange(#[from] Error),
}
