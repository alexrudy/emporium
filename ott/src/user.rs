//! Persisted user record + identity resolver.
//!
//! [`AppUser`] is the payload [`oath::server::JsonFileUserStore`]
//! serializes to `users/<provider>:<sub>.json`. The identity resolver
//! maps the OIDC `IdClaims` parsed out of the `id_token` into one of
//! these.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use oath::server::{Identity, IdentityResolver, ProviderId, parse_id_token};
use serde::{Deserialize, Serialize};

/// What ott persists for each user.
///
/// `created_at` and `last_login_at` are bookkeeping the demo computes
/// at callback time; they aren't part of any OIDC spec.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AppUser {
    /// The provider the user signed in with. Records written before
    /// providers were tracked load as [`ProviderId::default`].
    #[serde(default)]
    pub provider: ProviderId,
    /// OIDC `sub` claim — the stable per-provider identifier.
    pub sub: String,
    /// Email address, if disclosed.
    pub email: Option<String>,
    /// Whether the provider has verified the email.
    pub email_verified: bool,
    /// Display name. Falls back to `preferred_username` when `name` is
    /// missing.
    pub display_name: Option<String>,
    /// Time we first issued a session for this user.
    pub created_at: DateTime<Utc>,
    /// Time of the most recent successful login.
    pub last_login_at: DateTime<Utc>,
    /// Any extra claims the provider returned.
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// Default identity resolver: parse the `id_token` and project the
/// claims into an [`AppUser`], keyed by `{provider}:{sub}` since `sub`
/// is only unique per provider.
///
/// Note: `created_at` is overwritten on every login because the
/// resolver doesn't know whether the user already exists. Phase C
/// polish: read the existing record first and preserve `created_at`.
pub fn identity_resolver() -> IdentityResolver<AppUser> {
    IdentityResolver::with_provider(|provider: ProviderId, tokens| async move {
        let claims = parse_id_token(&tokens)?;
        let now = Utc::now();
        let display_name = claims
            .name
            .clone()
            .or_else(|| claims.preferred_username.clone());
        Ok(Identity {
            username: format!("{provider}:{}", claims.sub),
            data: AppUser {
                provider,
                sub: claims.sub,
                email: claims.email,
                email_verified: claims.email_verified.unwrap_or(false),
                display_name,
                created_at: now,
                last_login_at: now,
                extra: claims.extra,
            },
        })
    })
}
