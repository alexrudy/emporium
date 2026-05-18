//! Authorization-code redirect URL builder.

use api_client::uri::UriExtension as _;
use http::Uri;

use crate::endpoint::TokenEndpoint;
use crate::error::Error;
use crate::grant::pending::PendingAuthorization;
use crate::pkce::{PkceMethod, PkceVerifier};
use crate::scope::{Scope, ScopeSet};
use crate::state::StateToken;

/// Builder for the `/authorize` URL the user-agent is redirected to at
/// the start of the authorization-code flow (RFC 6749 §4.1.1).
///
/// Call [`begin`](Self::begin) to materialize the URL and the
/// [`PendingAuthorization`] bundle to persist for the callback.
#[derive(Debug)]
pub struct AuthorizationUrl<'a> {
    endpoint: &'a TokenEndpoint,
    scopes: ScopeSet,
    state: Option<StateToken>,
    verifier: Option<PkceVerifier>,
    pkce_method: PkceMethod,
    extra: Vec<(String, String)>,
}

impl<'a> AuthorizationUrl<'a> {
    /// Start a new authorization-URL builder against `endpoint`.
    pub fn new(endpoint: &'a TokenEndpoint) -> Self {
        Self {
            endpoint,
            scopes: ScopeSet::new(),
            state: None,
            verifier: None,
            pkce_method: PkceMethod::S256,
            extra: Vec::new(),
        }
    }

    /// Append a single scope.
    pub fn scope(mut self, scope: Scope) -> Self {
        self.scopes.push(scope);
        self
    }

    /// Set the full scope list, replacing any previously-appended scopes.
    pub fn scopes(mut self, scopes: ScopeSet) -> Self {
        self.scopes = scopes;
        self
    }

    /// Provide a pre-generated state token (defaults to a fresh
    /// [`StateToken::generate`]).
    pub fn with_state(mut self, state: StateToken) -> Self {
        self.state = Some(state);
        self
    }

    /// Provide a pre-generated PKCE verifier (defaults to a fresh
    /// [`PkceVerifier::generate`]).
    pub fn with_verifier(mut self, verifier: PkceVerifier) -> Self {
        self.verifier = Some(verifier);
        self
    }

    /// Choose the PKCE challenge method. Defaults to
    /// [`PkceMethod::S256`].
    pub fn pkce_method(mut self, method: PkceMethod) -> Self {
        self.pkce_method = method;
        self
    }

    /// Add a custom query parameter to the authorization URL.
    ///
    /// Useful for provider-specific extensions
    /// (`prompt=consent`, `access_type=offline`, etc.).
    pub fn extra(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra.push((key.into(), value.into()));
        self
    }

    /// Build the URL and the bundle of secrets to persist for the callback.
    ///
    /// If a state token or PKCE verifier were not pre-set, fresh ones
    /// are generated; the returned [`PendingAuthorization`] always
    /// carries whichever values were actually used.
    pub fn begin(self) -> Result<(Uri, PendingAuthorization), Error> {
        let auth_uri = self
            .endpoint
            .auth_uri()
            .cloned()
            .ok_or(Error::MissingAuthUri)?;

        let state = self.state.unwrap_or_else(StateToken::generate);
        let verifier = self.verifier.unwrap_or_else(PkceVerifier::generate);
        let challenge = verifier.challenge_with(self.pkce_method);

        let mut params: Vec<(&str, String)> = Vec::with_capacity(7 + self.extra.len());
        params.push(("response_type", "code".to_owned()));
        params.push(("client_id", self.endpoint.client_id().to_owned()));
        if !self.scopes.is_empty() {
            params.push(("scope", self.scopes.to_string()));
        }
        if let Some(redirect) = self.endpoint.redirect_uri() {
            params.push(("redirect_uri", redirect.to_string()));
        }
        params.push(("state", state.revealed().to_owned()));
        params.push(("code_challenge", challenge.value));
        params.push(("code_challenge_method", challenge.method.to_string()));
        for (k, v) in &self.extra {
            params.push((k.as_str(), v.clone()));
        }

        let url = auth_uri
            .append_query(&params)
            .expect("authorization URL must build from validated components");

        Ok((url, PendingAuthorization { state, verifier }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use api_client::mock::MockService;
    use secret::Secret;
    use std::collections::HashMap;

    fn endpoint() -> TokenEndpoint {
        // Inject a no-op transport so we don't pay the cost of building a
        // default TLS stack — and, importantly, avoid the rustls crypto
        // provider panic when both `tls-ring` and `tls-aws-lc` features
        // are enabled (e.g. `cargo test --all-features`).
        TokenEndpoint::builder()
            .client_id("the-client")
            .client_secret(Secret::from("the-secret"))
            .auth_uri(
                "https://accounts.example.com/oauth/authorize"
                    .parse()
                    .unwrap(),
            )
            .token_uri("https://accounts.example.com/oauth/token".parse().unwrap())
            .redirect_uri("https://app.example.com/cb".parse().unwrap())
            .transport(MockService::new())
            .build()
            .unwrap()
    }

    fn query_map(uri: &Uri) -> HashMap<String, String> {
        uri.query()
            .unwrap_or_default()
            .split('&')
            .filter(|s| !s.is_empty())
            .filter_map(|kv| {
                let mut split = kv.splitn(2, '=');
                let k = split.next()?;
                let v = split.next().unwrap_or("");
                Some((percent_decode(k), percent_decode(v)))
            })
            .collect()
    }

    fn percent_decode(s: &str) -> String {
        // serde_urlencoded encodes spaces as `+`, so swap back first.
        let s = s.replace('+', " ");
        let mut out = String::with_capacity(s.len());
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c == '%' {
                let hi = chars.next().unwrap();
                let lo = chars.next().unwrap();
                let byte = u8::from_str_radix(&format!("{hi}{lo}"), 16).unwrap();
                out.push(byte as char);
            } else {
                out.push(c);
            }
        }
        out
    }

    #[test]
    fn missing_auth_uri_errors() {
        let endpoint = TokenEndpoint::builder()
            .client_id("x")
            .token_uri("https://example.com/token".parse().unwrap())
            .transport(MockService::new())
            .build()
            .unwrap();
        let err = AuthorizationUrl::new(&endpoint).begin().unwrap_err();
        assert!(matches!(err, Error::MissingAuthUri));
    }

    #[test]
    fn url_contains_required_oauth2_params() {
        let endpoint = endpoint();
        let scopes: ScopeSet = "openid profile email".parse().unwrap();
        let (url, _pending) = AuthorizationUrl::new(&endpoint)
            .scopes(scopes)
            .begin()
            .unwrap();

        assert!(
            url.to_string()
                .starts_with("https://accounts.example.com/oauth/authorize?")
        );
        let params = query_map(&url);
        assert_eq!(params.get("response_type").unwrap(), "code");
        assert_eq!(params.get("client_id").unwrap(), "the-client");
        assert_eq!(params.get("scope").unwrap(), "openid profile email");
        assert_eq!(
            params.get("redirect_uri").unwrap(),
            "https://app.example.com/cb",
        );
        assert_eq!(params.get("code_challenge_method").unwrap(), "S256");
        assert!(params.contains_key("state"));
        assert!(params.contains_key("code_challenge"));
    }

    #[test]
    fn pending_holds_state_and_verifier_used() {
        let endpoint = endpoint();
        let state = StateToken::generate();
        let verifier = PkceVerifier::generate();
        let state_revealed = state.revealed().to_owned();
        let verifier_revealed = verifier.revealed().to_owned();

        let (url, pending) = AuthorizationUrl::new(&endpoint)
            .with_state(state)
            .with_verifier(verifier)
            .begin()
            .unwrap();

        assert_eq!(pending.state.revealed(), state_revealed);
        assert_eq!(pending.verifier.revealed(), verifier_revealed);

        // The URL must carry the state we provided, not a freshly generated one.
        let params = query_map(&url);
        assert_eq!(params.get("state").unwrap(), &state_revealed);
    }

    #[test]
    fn extra_params_propagate_to_url() {
        let endpoint = endpoint();
        let (url, _pending) = AuthorizationUrl::new(&endpoint)
            .extra("access_type", "offline")
            .extra("prompt", "consent")
            .begin()
            .unwrap();
        let params = query_map(&url);
        assert_eq!(params.get("access_type").unwrap(), "offline");
        assert_eq!(params.get("prompt").unwrap(), "consent");
    }

    #[test]
    fn plain_pkce_emitted_when_chosen() {
        let endpoint = endpoint();
        let (url, _pending) = AuthorizationUrl::new(&endpoint)
            .pkce_method(PkceMethod::Plain)
            .begin()
            .unwrap();
        let params = query_map(&url);
        assert_eq!(params.get("code_challenge_method").unwrap(), "plain");
    }

    #[test]
    fn pending_is_serde_roundtrippable() {
        let endpoint = endpoint();
        let (_url, pending) = AuthorizationUrl::new(&endpoint).begin().unwrap();

        let json = serde_json::to_string(&pending).unwrap();
        let parsed: PendingAuthorization = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.state.revealed(), pending.state.revealed());
        assert_eq!(parsed.verifier.revealed(), pending.verifier.revealed());
    }
}
