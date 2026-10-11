//! Session cookie reader + `CurrentUser` axum extractor.
//!
//! Mirrors the cookie-signing convention used internally by
//! `oath::server::handlers` — kept inline here so consumers can copy
//! the pattern verbatim. If/when more apps grow the same logic, this
//! is the natural extraction candidate.

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use http::StatusCode;
use oath::server::{SessionData, SessionId, SessionStore as _, UserStore as _};

use crate::cookies::CookieJar;
use crate::state::AppState;
use crate::user::AppUser;

/// Authenticated user, loaded from the session cookie.
///
/// Rejects with `401 Unauthorized` when there's no valid session (no
/// cookie, invalid signature, unknown or expired session). The display
/// name comes from the user store; a missing profile leaves it `None`
/// rather than rejecting, since the session alone proves who the user is.
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
                &state.oauth_router.cookies.session,
                &FromRef::from_ref(state),
            )
            .ok_or(StatusCode::UNAUTHORIZED)
            .inspect_err(|_| tracing::trace!("No session cookie"))?;

        let session_id = SessionId::from_string(cookie.value());
        let data = state
            .sessions_store
            .get(&session_id)
            .await
            .ok()
            .flatten()
            .ok_or(StatusCode::UNAUTHORIZED)
            .inspect_err(|_| tracing::trace!(session=%session_id.as_str(), "Unknown session"))?;
        let SessionData::Authenticated { provider, username } = data else {
            tracing::trace!("Session data is not authenticated");
            return Err(StatusCode::UNAUTHORIZED);
        };

        let display_name = match state.users_store.get(&provider, &username).await {
            Ok(Some(profile)) => profile.display_name,
            Ok(None) | Err(_) => None,
        };

        Ok(CurrentUser(
            AppUser::new(provider, username).with_display_name(display_name),
        ))
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

#[cfg(test)]
mod tests {
    use cookie::{Cookie, Key};
    use oath::server::ProviderId;

    use super::*;
    use crate::config::{ProvidersConfig, SessionsConfig};
    use crate::user::UserProfile;

    async fn state() -> AppState {
        AppState::new(
            Default::default(),
            ProvidersConfig::default(),
            SessionsConfig::default(),
        )
        .await
        .unwrap()
    }

    /// A request carrying a session cookie for `provider`/`username`,
    /// signed with `key`.
    async fn request_for(
        state: &AppState,
        key: &Key,
        provider: &ProviderId,
        username: &str,
    ) -> Parts {
        let id = state
            .sessions_store
            .create(SessionData::Authenticated {
                provider: provider.clone(),
                username: username.into(),
            })
            .await
            .unwrap();
        let mut jar = cookie::CookieJar::new();
        jar.signed_mut(key).add(Cookie::new(
            state.oauth_router.cookies.session.clone(),
            id.as_str().to_owned(),
        ));
        let cookie = jar.get(&state.oauth_router.cookies.session).unwrap();
        let header = format!("{}={}", cookie.name(), cookie.value());
        http::Request::builder()
            .header(http::header::COOKIE, header)
            .body(())
            .unwrap()
            .into_parts()
            .0
    }

    #[tokio::test]
    async fn loads_user_with_display_name() {
        let state = state().await;
        let google = ProviderId::new("google").unwrap();
        state
            .users_store
            .put(
                &google,
                "abc",
                &UserProfile {
                    display_name: Some("Alice".into()),
                },
            )
            .await
            .unwrap();

        let key = Key::from_ref(&state);
        let mut parts = request_for(&state, &key, &google, "abc").await;
        let CurrentUser(user) = CurrentUser::from_request_parts(&mut parts, &state)
            .await
            .unwrap();
        assert_eq!(user.provider, google);
        assert_eq!(user.username, "abc");
        assert_eq!(user.display_name.as_deref(), Some("Alice"));
        assert_eq!(user.to_string(), "Alice (google:abc)");
    }

    #[tokio::test]
    async fn missing_profile_still_authenticates() {
        let state = state().await;
        let google = ProviderId::new("google").unwrap();
        let key = Key::from_ref(&state);
        let mut parts = request_for(&state, &key, &google, "abc").await;
        let CurrentUser(user) = CurrentUser::from_request_parts(&mut parts, &state)
            .await
            .unwrap();
        assert!(user.display_name.is_none());
    }

    #[tokio::test]
    async fn rejects_missing_or_forged_cookie() {
        let state = state().await;
        let mut parts = http::Request::builder().body(()).unwrap().into_parts().0;
        assert_eq!(
            CurrentUser::from_request_parts(&mut parts, &state)
                .await
                .unwrap_err(),
            StatusCode::UNAUTHORIZED
        );

        // Signed with a different key.
        let google = ProviderId::new("google").unwrap();
        let mut parts = request_for(&state, &Key::generate(), &google, "abc").await;
        assert_eq!(
            CurrentUser::from_request_parts(&mut parts, &state)
                .await
                .unwrap_err(),
            StatusCode::UNAUTHORIZED
        );
        let OptionalCurrentUser(user) = OptionalCurrentUser::from_request_parts(&mut parts, &state)
            .await
            .unwrap();
        assert!(user.is_none());
    }
}
