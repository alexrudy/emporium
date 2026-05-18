//! RFC 6749 §4.4 — Client Credentials grant.

use crate::scope::ScopeSet;

/// Request a token via the Client Credentials grant.
///
/// Used when the client is acting on its own behalf (machine-to-machine)
/// rather than on behalf of a resource owner.
#[derive(Debug, Clone, Default)]
pub struct ClientCredentialsRequest {
    scope: Option<ScopeSet>,
}

impl ClientCredentialsRequest {
    /// Build a request with no scopes.
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach a scope set to the request.
    pub fn scope(mut self, scope: ScopeSet) -> Self {
        self.scope = Some(scope);
        self
    }

    pub(crate) fn into_fields(self) -> Vec<(&'static str, String)> {
        let mut fields = Vec::with_capacity(2);
        fields.push(("grant_type", "client_credentials".to_owned()));
        if let Some(scope) = self.scope {
            fields.push(("scope", scope.to_string()));
        }
        fields
    }
}
