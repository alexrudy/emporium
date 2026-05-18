//! An OAuth2 client built on top of the workspace `api-client` crate.
//!
//! Phase 1 of the crate provides the foundational types:
//!
//! - [`error::Error`] and [`error::TokenErrorResponse`] for surfacing
//!   OAuth2 protocol errors (RFC 6749 §5.2).
//! - [`scope::Scope`] / [`scope::ScopeSet`] for the space-separated scope
//!   wire format (RFC 6749 §3.3).
//! - [`token::AccessToken`] implements [`api_client::Authentication`] so
//!   an `ApiClient<AccessToken>` attaches a `Bearer` header automatically.
//!   [`token::RefreshToken`], [`token::TokenResponse`], and
//!   [`token::TokenSet`] cover the rest of RFC 6749 §5.1.
//! - [`pkce::PkceVerifier`] / [`pkce::PkceChallenge`] for the
//!   authorization-code flow (RFC 7636).
//! - [`state::StateToken`] for CSRF protection on the redirect (RFC 6749
//!   §10.12).
//!
//! Token-endpoint exchange, grant builders, and the refresh-aware client
//! wrapper land in subsequent phases.

pub mod error;
pub mod pkce;
pub mod scope;
pub mod state;
pub mod token;

pub use crate::error::{Error, TokenErrorCode, TokenErrorResponse};
pub use crate::pkce::{PkceChallenge, PkceMethod, PkceVerifier};
pub use crate::scope::{Scope, ScopeSet};
pub use crate::state::StateToken;
pub use crate::token::{AccessToken, RefreshToken, TokenResponse, TokenSet, TokenType};
