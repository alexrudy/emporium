//! An OAuth2 client built on top of the workspace `api-client` crate.
//!
//! `oath` is a building block for *consuming* OAuth2-protected APIs. It
//! is not an authorization server, an OIDC provider, or a session
//! library — it focuses on the bits between the user-agent redirect and
//! the bearer header on the outgoing API request.
//!
//! # Grants
//!
//! All four grant types defined by RFC 6749 / RFC 8628 that consumers
//! actually need are supported:
//!
//! | Grant                                       | Builder type                       | Use when                                  |
//! |---------------------------------------------|------------------------------------|-------------------------------------------|
//! | Client Credentials (RFC 6749 §4.4)          | [`ClientCredentialsRequest`]       | Machine-to-machine, no end user           |
//! | Authorization Code + PKCE (RFC 6749, 7636)  | [`AuthorizationCodeRequest`]       | User-delegated, with a browser redirect   |
//! | Refresh Token (RFC 6749 §6)                 | [`RefreshRequest`]                 | Long-lived sessions, rotates tokens       |
//! | Device Authorization (RFC 8628)             | [`DeviceCodeRequest`]              | CLIs and headless clients                 |
//!
//! # Layers
//!
//! The crate is layered so you can drop down when you need to:
//!
//! 1. [`TokenEndpoint`] is the low-level handle on `/token`. It accepts
//!    any [`TokenRequest`] (via [`From`] on the per-grant builder
//!    types), POSTs a form-encoded body with the configured client
//!    auth, and returns a [`TokenResponse`].
//! 2. [`AuthorizationUrl`] builds the user-agent redirect URL for the
//!    auth-code flow, returning a [`PendingAuthorization`] bundle to
//!    persist across the redirect. [`PendingAuthorization::complete`]
//!    verifies the returned state and exchanges the code.
//! 3. [`OAuth2Client`] is the refresh-aware HTTP wrapper. It mirrors
//!    `api_client::ApiClient`'s `get`/`post`/etc. surface, but
//!    proactively refreshes the access token before each request when
//!    it's past expiry. Concurrent calls collapse to one `/token`
//!    round-trip.
//!
//! # Quick start: authorization-code + PKCE
//!
//! ```
//! use oath::{AuthorizationUrl, ScopeSet, TokenEndpoint};
//! use secret::Secret;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let endpoint = TokenEndpoint::builder()
//!     .client_id("my-app")
//!     .client_secret(Secret::from("super-secret"))
//!     .auth_uri("https://provider.example.com/oauth/authorize".parse()?)
//!     .token_uri("https://provider.example.com/oauth/token".parse()?)
//!     .redirect_uri("https://app.example.com/auth/callback".parse()?)
//! #   .transport(api_client::mock::MockService::new())
//!     .build()?;
//!
//! // /auth/login: build the redirect URL plus the bundle to persist.
//! let scopes: ScopeSet = "openid profile email".parse()?;
//! let (url, pending) = AuthorizationUrl::new(&endpoint)
//!     .scopes(scopes)
//!     .begin()?;
//!
//! assert!(url.to_string().contains("response_type=code"));
//! assert!(url.to_string().contains("code_challenge_method=S256"));
//!
//! // Stash `pending` in your session store (it serializes via serde).
//! let stashed = serde_json::to_string(&pending)?;
//! # let _ = stashed;
//! # Ok(())
//! # }
//! ```
//!
//! When the provider redirects back to `/auth/callback`, load `pending`
//! and finish the exchange:
//!
//! ```no_run
//! # use oath::{PendingAuthorization, TokenEndpoint};
//! # async fn callback(
//! #     endpoint: &TokenEndpoint,
//! #     pending: PendingAuthorization,
//! #     returned_state: &str,
//! #     returned_code: &str,
//! # ) -> Result<oath::TokenSet, oath::CallbackError> {
//! let token_set = pending
//!     .complete(endpoint, returned_state, returned_code)
//!     .await?;
//! # Ok(token_set)
//! # }
//! ```
//!
//! # Quick start: refresh-aware client
//!
//! ```no_run
//! # use oath::{OAuth2Client, TokenEndpoint, TokenSet};
//! # async fn use_oauth_client(endpoint: TokenEndpoint, tokens: TokenSet) -> Result<(), oath::Error> {
//! let oauth = OAuth2Client::from_authorization_code(
//!     endpoint,
//!     "https://api.example.com/".parse().unwrap(),
//!     tokens,
//! )?;
//!
//! // Calls read exactly like normal api-client code; oauth keeps the
//! // bearer fresh.
//! let _response = oauth.get("/widgets").send().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Security notes
//!
//! - All token-bearing types wrap [`secret::Secret`], so they don't
//!   appear in `Debug` output and are zeroed on drop.
//! - Authorization-code flows always use PKCE (RFC 7636) with `S256` by
//!   default. The verifier and challenge are generated from
//!   `rand::rngs::OsRng`.
//! - [`StateToken::verify`] uses a constant-time compare to dodge
//!   timing oracles, even though state tokens are short-lived and
//!   single-use.
//! - [`OAuth2Client`] refreshes *proactively*: the expiry check happens
//!   before each request, so a near-expired token doesn't slip past
//!   into a 401. There's a 60-second clock-drift offset built in.

pub mod client;
pub mod endpoint;
pub mod error;
pub mod grant;
pub mod pkce;
pub mod scope;
#[cfg(feature = "server")]
pub mod server;
pub mod state;
pub mod token;

pub use crate::client::{OAuth2Client, OAuth2RequestBuilder, RefreshStrategy};
pub use crate::endpoint::{ClientAuthStyle, TokenEndpoint};
pub use crate::error::{Error, TokenErrorCode, TokenErrorResponse};
pub use crate::grant::{
    AuthorizationCodeRequest, AuthorizationUrl, CallbackError, ClientCredentialsRequest,
    DeviceAuthorizationResponse, DeviceCodeRequest, PendingAuthorization, RefreshRequest,
    TokenRequest,
};
pub use crate::pkce::{PkceChallenge, PkceMethod, PkceVerifier};
pub use crate::scope::{Scope, ScopeSet};
pub use crate::state::StateToken;
pub use crate::token::{AccessToken, RefreshToken, TokenResponse, TokenSet, TokenType};
