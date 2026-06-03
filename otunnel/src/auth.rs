//! Session cookie reader + `CurrentUser` axum extractor.
//!
//! Mirrors the cookie-signing convention used internally by
//! `oath::server::handlers` — kept inline here so consumers can copy
//! the pattern verbatim. If/when more apps grow the same logic, this
//! is the natural extraction candidate.

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use http::StatusCode;
use oath::server::{SessionData, SessionId, SessionStore as _};

use crate::cookies::CookieJar;
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
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_request_parts(parts, state).await.unwrap();
        let cookie = jar
            .signed(
                &state.config.oath.cookies.session,
                &FromRef::from_ref(state),
            )
            .ok_or(StatusCode::UNAUTHORIZED)
            .inspect_err(|_| tracing::trace!("No session cookie"))?;

        let session_id = SessionId::from_string(cookie.value());
        let data = state
            .sessions
            .get(&session_id)
            .await
            .ok()
            .flatten()
            .ok_or(StatusCode::UNAUTHORIZED)
            .inspect_err(|_| tracing::trace!(session=%session_id.as_str(), "Unknown session"))?;
        let SessionData::Authenticated { username } = data else {
            tracing::trace!("Session data is not authenticated");
            return Err(StatusCode::UNAUTHORIZED);
        };

        Ok(CurrentUser(AppUser::new(username)))
    }
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
