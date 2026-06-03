//! Session cookie reader + `CurrentUser` axum extractor.
//!
//! Mirrors the cookie-signing convention used internally by
//! `oath::server::handlers` — kept inline here so consumers can copy
//! the pattern verbatim. If/when more apps grow the same logic, this
//! is the natural extraction candidate.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::response::Redirect;
use cookie::{Cookie, CookieJar, Key};
use http::HeaderMap;
use oath::server::{SessionData, SessionId, SessionStore as _, UserStore as _};

use crate::state::AppState;
use crate::user::AppUser;

/// Authenticated user, loaded from the session cookie.
///
/// `from_request_parts` redirects to `/` on any miss (no cookie,
/// invalid signature, expired session, missing user record) rather
/// than returning a 401. This is a browser-facing app, so a redirect
/// is friendlier than a JSON error.
#[derive(Debug, Clone)]
pub struct CurrentUser(pub AppUser);

impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = Redirect;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let cookie_name = &state.config.cookie_key_cookie_name();
        let raw = read_signed_cookie(&parts.headers, &state.config.cookie_key, cookie_name)
            .ok_or_else(redirect_home)?;
        let session_id = SessionId::from_string(raw);
        let data = state
            .sessions
            .get(&session_id)
            .await
            .ok()
            .flatten()
            .ok_or_else(redirect_home)?;
        let SessionData::Authenticated { username } = data else {
            return Err(redirect_home());
        };
        let user = state
            .users
            .get(&username)
            .await
            .ok()
            .flatten()
            .ok_or_else(redirect_home)?;
        Ok(CurrentUser(user))
    }
}

fn redirect_home() -> Redirect {
    Redirect::to("/")
}

/// Like [`CurrentUser`] but never rejects: returns `None` when there's
/// no valid session. Use this from handlers that want to branch on auth
/// state without forcing a redirect (e.g. the `/` landing page).
#[derive(Debug, Clone)]
pub struct OptionalCurrentUser(pub Option<AppUser>);

impl FromRequestParts<AppState> for OptionalCurrentUser {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let inner = CurrentUser::from_request_parts(parts, state)
            .await
            .ok()
            .map(|CurrentUser(user)| user);
        Ok(OptionalCurrentUser(inner))
    }
}

/// Read a signed cookie value from request headers using `key`.
///
/// Returns `None` if the cookie is absent, malformed, or has an
/// invalid signature. The HMAC verification happens inside
/// `cookie::SignedJar::get`.
pub fn read_signed_cookie(headers: &HeaderMap, key: &Key, name: &str) -> Option<String> {
    let mut jar = CookieJar::new();
    for hv in headers.get_all(http::header::COOKIE) {
        let Ok(s) = hv.to_str() else { continue };
        for part in s.split(';').map(str::trim) {
            if part.is_empty() {
                continue;
            }
            if let Ok(cookie) = Cookie::parse(part.to_owned()) {
                jar.add_original(cookie);
            }
        }
    }
    jar.signed(key).get(name).map(|c| c.value().to_owned())
}

impl crate::config::Config {
    /// Name of the session cookie. Matches the default in
    /// `oath::server::CookieNames`.
    pub fn cookie_key_cookie_name(&self) -> &'static str {
        "oath_session"
    }
}
