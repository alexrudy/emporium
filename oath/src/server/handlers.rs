//! HTTP handlers and shared state for the OAuth2 router.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Extension, Query};
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Redirect};
use cookie::{Cookie, CookieJar, Key, SameSite};
use serde::Deserialize;

use crate::{AuthorizationUrl, TokenEndpoint, TokenErrorCode};

use super::config::OAuth2RouterConfig;
use super::error::ServerError;
use super::identity::{Identity, IdentityResolver};
use super::session::{SessionData, SessionId, SessionStore};
use super::users::UserStore;

/// Shared state threaded through the router via `Extension`.
pub(crate) struct RouterState<S, U>
where
    U: UserStore,
{
    pub endpoint: TokenEndpoint,
    pub config: OAuth2RouterConfig,
    pub sessions: Arc<S>,
    pub users: Arc<U>,
    pub identity: IdentityResolver<U::Data>,
    pub cookie_key: Key,
}

impl<S, U> std::fmt::Debug for RouterState<S, U>
where
    U: UserStore,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouterState")
            .field("endpoint", &self.endpoint)
            .field("config", &self.config)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct LoginParams {
    /// Where to redirect after a successful callback. Only honored if
    /// it's a same-origin relative path (starts with `/`, no `//`).
    #[serde(default)]
    return_to: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CallbackParams {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

/// `GET {prefix}/login`
pub(crate) async fn login<S, U>(
    Extension(state): Extension<Arc<RouterState<S, U>>>,
    Query(params): Query<LoginParams>,
) -> Result<axum::response::Response, ServerError>
where
    S: SessionStore,
    U: UserStore,
{
    let (url, pending) = AuthorizationUrl::new(&state.endpoint)
        .scopes(state.config.scopes.clone())
        .begin()?;

    let return_to = params.return_to.and_then(|s| sanitize_return_to(&s));
    let session_id = state
        .sessions
        .create(SessionData::Pending { pending, return_to })
        .await
        .map_err(ServerError::session_store)?;

    let cookie = build_signed_cookie(
        &state.cookie_key,
        &state.config.cookies.preauth,
        session_id.as_str(),
        state.config.preauth_ttl,
        state.config.secure_cookies,
        state.config.same_site,
    );

    tracing::debug!("redirecting to oauth provider {url}", url = url.to_string());
    let mut headers = HeaderMap::new();
    headers.append(SET_COOKIE, cookie);

    Ok((headers, Redirect::to(&url.to_string())).into_response())
}

/// `GET {prefix}/callback`
pub(crate) async fn callback<S, U>(
    Extension(state): Extension<Arc<RouterState<S, U>>>,
    Query(params): Query<CallbackParams>,
    headers: HeaderMap,
) -> Result<axum::response::Response, ServerError>
where
    S: SessionStore,
    U: UserStore,
{
    if let Some(code) = params.error {
        return Err(ServerError::ProviderError {
            code,
            description: params.error_description,
        });
    }

    let auth_code = params
        .code
        .ok_or(ServerError::MissingCallbackParam("code"))?;
    let auth_state = params
        .state
        .ok_or(ServerError::MissingCallbackParam("state"))?;

    let preauth_id = read_signed_cookie(&headers, &state.cookie_key, &state.config.cookies.preauth)
        .ok_or(ServerError::PreauthCookieMissing)?;
    let preauth_id = SessionId::from_string(preauth_id);

    let preauth = state
        .sessions
        .get(&preauth_id)
        .await
        .map_err(ServerError::session_store)?
        .ok_or(ServerError::PreauthMissing)?;

    let (pending, return_to) = match preauth {
        SessionData::Pending { pending, return_to } => (pending, return_to),
        SessionData::Authenticated { .. } => return Err(ServerError::PreauthMissing),
    };

    // The pre-auth session is single-use; drop it before we do
    // anything that could fail.
    state
        .sessions
        .delete(&preauth_id)
        .await
        .map_err(ServerError::session_store)?;

    let token_set = pending
        .complete(&state.endpoint, &auth_state, auth_code)
        .await?;

    let Identity { username, data } = state
        .identity
        .resolve(token_set)
        .await
        .map_err(ServerError::identity)?;

    super::sanitize_username(&username)?;

    state
        .users
        .put(&username, &data)
        .await
        .map_err(ServerError::user_store)?;

    let session_id = state
        .sessions
        .create(SessionData::Authenticated {
            username: username.clone(),
        })
        .await
        .map_err(ServerError::session_store)?;

    tracing::trace!("Session created: {}", session_id.as_str());
    let session_cookie = build_signed_cookie(
        &state.cookie_key,
        &state.config.cookies.session,
        session_id.as_str(),
        state.config.session_ttl,
        state.config.secure_cookies,
        state.config.same_site,
    );
    let preauth_clear = build_clear_cookie(
        &state.config.cookies.preauth,
        state.config.secure_cookies,
        state.config.same_site,
    );

    let mut response_headers = HeaderMap::new();
    response_headers.append(SET_COOKIE, preauth_clear);
    response_headers.append(SET_COOKIE, session_cookie);

    let dest = return_to.unwrap_or_else(|| state.config.login_landing.clone());
    Ok((response_headers, Redirect::to(&dest)).into_response())
}

/// `POST {prefix}/logout`
pub(crate) async fn logout<S, U>(
    Extension(state): Extension<Arc<RouterState<S, U>>>,
    headers: HeaderMap,
) -> Result<axum::response::Response, ServerError>
where
    S: SessionStore,
    U: UserStore,
{
    if let Some(raw_id) =
        read_signed_cookie(&headers, &state.cookie_key, &state.config.cookies.session)
    {
        let id = SessionId::from_string(raw_id);
        state
            .sessions
            .delete(&id)
            .await
            .map_err(ServerError::session_store)?;
    }

    let session_clear = build_clear_cookie(
        &state.config.cookies.session,
        state.config.secure_cookies,
        state.config.same_site,
    );

    let mut response_headers = HeaderMap::new();
    response_headers.append(SET_COOKIE, session_clear);

    Ok((response_headers, Redirect::to(&state.config.logout_landing)).into_response())
}

fn sanitize_return_to(value: &str) -> Option<String> {
    if value.starts_with('/') && !value.starts_with("//") {
        Some(value.to_owned())
    } else {
        None
    }
}

fn build_signed_cookie(
    key: &Key,
    name: &str,
    value: &str,
    ttl: Duration,
    secure: bool,
    same_site: SameSite,
) -> HeaderValue {
    let mut cookie = Cookie::new(name.to_owned(), value.to_owned());
    cookie.set_http_only(true);
    cookie.set_secure(secure);
    cookie.set_same_site(same_site);
    cookie.set_path("/");
    cookie.set_max_age(cookie::time::Duration::seconds(ttl.as_secs() as i64));
    let mut jar = CookieJar::new();
    jar.signed_mut(key).add(cookie);
    let rendered = jar
        .get(name)
        .expect("cookie just inserted into the jar")
        .to_string();
    HeaderValue::from_str(&rendered).expect("signed cookie is a valid header value")
}

fn build_clear_cookie(name: &str, secure: bool, same_site: SameSite) -> HeaderValue {
    let mut cookie = Cookie::new(name.to_owned(), "".to_owned());
    cookie.set_http_only(true);
    cookie.set_secure(secure);
    cookie.set_same_site(same_site);
    cookie.set_path("/");
    cookie.set_max_age(cookie::time::Duration::seconds(0));
    HeaderValue::from_str(&cookie.to_string()).expect("clear cookie is a valid header value")
}

fn read_signed_cookie(headers: &HeaderMap, key: &Key, name: &str) -> Option<String> {
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

/// Convenience: classify a [`TokenErrorCode`] returned in the callback.
///
/// Useful when a handler wants to react to RFC 8628's
/// `access_denied`/`expired_token` codes differently from generic
/// RFC 6749 §5.2 errors.
pub fn is_user_denied(code: &TokenErrorCode) -> bool {
    matches!(code, TokenErrorCode::Other(s) if s == "access_denied")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_to_must_be_relative() {
        assert_eq!(sanitize_return_to("/profile").as_deref(), Some("/profile"),);
        assert!(sanitize_return_to("https://evil.example.com").is_none());
        assert!(sanitize_return_to("//evil.example.com/path").is_none());
        assert!(sanitize_return_to("relative-path").is_none());
    }

    #[test]
    fn signed_cookie_roundtrip() {
        let key = Key::generate();
        let header = build_signed_cookie(
            &key,
            "name",
            "value",
            Duration::from_secs(60),
            false,
            SameSite::Lax,
        );
        let mut headers = HeaderMap::new();
        headers.append(http::header::COOKIE, header);
        let got = read_signed_cookie(&headers, &key, "name");
        assert_eq!(got.as_deref(), Some("value"));
    }

    #[test]
    fn signed_cookie_rejects_tampered_value() {
        let key = Key::generate();
        let mut headers = HeaderMap::new();
        headers.append(
            http::header::COOKIE,
            HeaderValue::from_static("name=not-signed-with-this-key"),
        );
        assert!(read_signed_cookie(&headers, &key, "name").is_none());
    }
}
