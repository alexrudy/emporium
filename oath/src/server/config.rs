//! Configuration for [`crate::server::OAuth2Router`].

use std::time::Duration;

use cookie::SameSite;
use serde::{Deserialize, Serialize};

use crate::ScopeSet;

use super::registry::ProviderId;

/// Names of the cookies the router sets and reads.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OAuth2RouterConfig {
    /// Route prefix, default `/auth`. The router exposes
    /// `{prefix}/login`, `{prefix}/logout`, and per-provider
    /// `{prefix}/{provider}/login` and `{prefix}/{provider}/callback`
    /// routes (see [`crate::server::OAuth2Router`]).
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
    #[serde(with = "serde_samesite")]
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
    /// Returns the login path, e.g. `/auth/login`.
    pub fn login_path(&self) -> String {
        format!("{}/login", self.route_prefix)
    }

    /// Returns the callback path, e.g. `/auth/callback`.
    pub fn callback_path(&self) -> String {
        format!("{}/callback", self.route_prefix)
    }

    /// Returns the logout path, e.g. `/auth/logout`.
    pub fn logout_path(&self) -> String {
        format!("{}/logout", self.route_prefix)
    }

    /// Returns a registered provider's login path, e.g.
    /// `/auth/google/login`.
    pub fn provider_login_path(&self, provider: &ProviderId) -> String {
        format!("{}/{provider}/login", self.route_prefix)
    }

    /// Returns a registered provider's callback path, e.g.
    /// `/auth/google/callback`. Use this to build the provider's
    /// redirect URI.
    pub fn provider_callback_path(&self, provider: &ProviderId) -> String {
        format!("{}/{provider}/callback", self.route_prefix)
    }

    /// Validate a post-login `return_to` target, returning it if it's
    /// safe to redirect to.
    ///
    /// Only same-origin absolute paths are accepted, e.g.
    /// `/profile?tab=1`. Rejected:
    ///
    /// - anything not starting with exactly one `/`: absolute URLs,
    ///   scheme-relative `//host`, relative paths;
    /// - backslashes, ASCII control characters, and whitespace anywhere:
    ///   browsers treat `\` as `/` and strip tabs and newlines, which
    ///   turns `/\host` or `/\t/host` into `//host`;
    /// - `.` / `..` path segments (including `%2e`), which browsers
    ///   resolve before following the redirect;
    /// - paths under [`route_prefix`](Self::route_prefix), which would
    ///   loop back into the login flow;
    /// - values over 2048 bytes, or that aren't a valid URI path and
    ///   query.
    pub fn sanitize_return_to(&self, value: &str) -> Option<String> {
        const MAX_LEN: usize = 2048;

        if value.len() > MAX_LEN || !value.starts_with('/') {
            return None;
        }
        if matches!(value.as_bytes().get(1), Some(b'/' | b'\\')) {
            return None;
        }
        if value
            .bytes()
            .any(|b| b == b'\\' || b.is_ascii_control() || b.is_ascii_whitespace())
        {
            return None;
        }

        let path = value.split(['?', '#']).next().unwrap_or_default();
        let dot_segment = path.split('/').any(|segment| {
            let segment = segment.to_ascii_lowercase().replace("%2e", ".");
            segment == "." || segment == ".."
        });
        if dot_segment {
            return None;
        }

        let prefix = self.route_prefix.trim_end_matches('/');
        if !prefix.is_empty()
            && (path == prefix
                || path
                    .strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with('/')))
        {
            return None;
        }

        value.parse::<http::uri::PathAndQuery>().ok()?;
        Some(value.to_owned())
    }

    /// Append `return_to` to `path` as an encoded query parameter, e.g.
    /// `/auth/login?return_to=%2Fprofile`.
    ///
    /// `return_to` is checked with
    /// [`sanitize_return_to`](Self::sanitize_return_to) first; if it's
    /// absent or rejected, `path` is returned unchanged.
    pub fn with_return_to(&self, path: &str, return_to: Option<&str>) -> String {
        let Some(target) = return_to.and_then(|value| self.sanitize_return_to(value)) else {
            return path.to_owned();
        };
        let query = serde_urlencoded::to_string([("return_to", target)])
            .expect("a single string pair always URL-encodes");
        let separator = if path.contains('?') { '&' } else { '?' };
        format!("{path}{separator}{query}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sanitize(value: &str) -> Option<String> {
        OAuth2RouterConfig::default().sanitize_return_to(value)
    }

    #[test]
    fn accepts_same_origin_paths() {
        for value in [
            "/",
            "/profile",
            "/a/b?c=1&d=2",
            "/authors",
            "/a%2Fb",
            "/x.y/z",
        ] {
            assert_eq!(sanitize(value).as_deref(), Some(value), "{value:?}");
        }
    }

    #[test]
    fn rejects_other_origins_and_relative_paths() {
        for value in [
            "",
            "profile",
            "https://evil.example.com",
            "//evil.example.com/path",
            "/\\evil.example.com",
            "/\t/evil.example.com",
            "/\n/evil.example.com",
            "/a\\b",
            "/a b",
        ] {
            assert!(sanitize(value).is_none(), "{value:?} should be rejected");
        }
    }

    #[test]
    fn rejects_dot_segments() {
        for value in ["/a/../b", "/./b", "/a/%2e%2e/b", "/a/%2E/b", "/a/..?x=1"] {
            assert!(sanitize(value).is_none(), "{value:?} should be rejected");
        }
    }

    #[test]
    fn rejects_auth_routes() {
        for value in ["/auth", "/auth/login", "/auth/google/login?x=1", "/auth/"] {
            assert!(sanitize(value).is_none(), "{value:?} should be rejected");
        }

        let config = OAuth2RouterConfig {
            route_prefix: "/sso/".into(),
            ..Default::default()
        };
        assert!(config.sanitize_return_to("/sso/login").is_none());
        assert!(config.sanitize_return_to("/auth/login").is_some());
    }

    #[test]
    fn rejects_overlong_values() {
        assert!(sanitize(&format!("/{}", "a".repeat(2048))).is_none());
    }

    #[test]
    fn with_return_to_encodes_or_drops() {
        let config = OAuth2RouterConfig::default();
        assert_eq!(
            config.with_return_to("/auth/login", Some("/a?b=1&c=2")),
            "/auth/login?return_to=%2Fa%3Fb%3D1%26c%3D2"
        );
        assert_eq!(
            config.with_return_to("/?tab=x", Some("/p")),
            "/?tab=x&return_to=%2Fp"
        );
        assert_eq!(
            config.with_return_to("/auth/login", Some("//evil.example.com")),
            "/auth/login"
        );
        assert_eq!(config.with_return_to("/auth/login", None), "/auth/login");
    }
}

mod serde_samesite {
    use cookie::SameSite;

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<SameSite, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SameSiteVisitor;

        impl<'de> serde::de::Visitor<'de> for SameSiteVisitor {
            type Value = SameSite;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a valid SameSite value")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match value.to_ascii_lowercase().as_str() {
                    "lax" => Ok(SameSite::Lax),
                    "strict" => Ok(SameSite::Strict),
                    "none" => Ok(SameSite::None),
                    _ => Err(E::invalid_value(serde::de::Unexpected::Str(value), &self)),
                }
            }
        }

        deserializer.deserialize_str(SameSiteVisitor)
    }

    pub(super) fn serialize<S>(value: &SameSite, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&value.to_string().to_ascii_lowercase())
    }
}
