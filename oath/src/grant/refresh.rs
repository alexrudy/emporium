//! RFC 6749 §6 — Refresh Token grant.

use crate::scope::ScopeSet;
use crate::token::RefreshToken;

/// Request a new access token using a refresh token.
#[derive(Debug, Clone)]
pub struct RefreshRequest {
    refresh_token: RefreshToken,
    scope: Option<ScopeSet>,
}

impl RefreshRequest {
    /// Build a new refresh request from a stored refresh token.
    pub fn new(refresh_token: RefreshToken) -> Self {
        Self {
            refresh_token,
            scope: None,
        }
    }

    /// Optionally narrow the requested scopes.
    ///
    /// Per RFC 6749 §6, the requested scope MUST NOT include any scope
    /// not originally granted; if omitted, the server treats it as
    /// equivalent to the original grant.
    pub fn scope(mut self, scope: ScopeSet) -> Self {
        self.scope = Some(scope);
        self
    }

    pub(crate) fn into_fields(self) -> Vec<(&'static str, String)> {
        let mut fields = Vec::with_capacity(3);
        fields.push(("grant_type", "refresh_token".to_owned()));
        fields.push(("refresh_token", self.refresh_token.revealed().to_owned()));
        if let Some(scope) = self.scope {
            fields.push(("scope", scope.to_string()));
        }
        fields
    }
}
