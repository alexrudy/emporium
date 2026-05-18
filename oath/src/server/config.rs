//! Configuration for [`crate::server::OAuth2Router`].

use std::time::Duration;

use cookie::SameSite;

use crate::ScopeSet;

/// Names of the cookies the router sets and reads.
#[derive(Debug, Clone)]
pub struct CookieNames {
    /// Cookie holding the pre-auth session id (short-lived).
    pub preauth: String,
    /// Cookie holding the post-login session id (long-lived).
    pub session: String,
}

impl Default for CookieNames {
    fn default() -> Self {
        Self {
            preauth: "oath_preauth".into(),
            session: "oath_session".into(),
        }
    }
}

/// Per-router configuration. Most fields default to sensible values.
#[derive(Debug, Clone)]
pub struct OAuth2RouterConfig {
    /// Route prefix, default `/auth`. The router exposes
    /// `{prefix}/login`, `{prefix}/callback`, and `{prefix}/logout`.
    pub route_prefix: String,

    /// Cookie names. Use unique names per integration if you run more
    /// than one OAuth2 provider on the same domain.
    pub cookies: CookieNames,

    /// Scopes requested in the authorization URL.
    pub scopes: ScopeSet,

    /// `Max-Age` for the pre-auth cookie.
    pub preauth_ttl: Duration,

    /// `Max-Age` for the post-login session cookie.
    pub session_ttl: Duration,

    /// Where to redirect after a successful login when the original
    /// request didn't ask for a `return_to`.
    pub login_landing: String,

    /// Where to redirect after `/auth/logout`.
    pub logout_landing: String,

    /// Whether to set the `Secure` cookie attribute. Default `true`;
    /// turn off for `http://localhost` dev.
    pub secure_cookies: bool,

    /// `SameSite` attribute on the cookies. Default `Lax` — required so
    /// the cookie survives the provider's cross-site redirect to the
    /// callback.
    pub same_site: SameSite,
}

impl Default for OAuth2RouterConfig {
    fn default() -> Self {
        Self {
            route_prefix: "/auth".into(),
            cookies: CookieNames::default(),
            scopes: ScopeSet::new(),
            preauth_ttl: Duration::from_secs(60 * 10),
            session_ttl: Duration::from_secs(60 * 60 * 24 * 30),
            login_landing: "/".into(),
            logout_landing: "/".into(),
            secure_cookies: true,
            same_site: SameSite::Lax,
        }
    }
}

impl OAuth2RouterConfig {
    pub(crate) fn login_path(&self) -> String {
        format!("{}/login", self.route_prefix)
    }

    pub(crate) fn callback_path(&self) -> String {
        format!("{}/callback", self.route_prefix)
    }

    pub(crate) fn logout_path(&self) -> String {
        format!("{}/logout", self.route_prefix)
    }
}
