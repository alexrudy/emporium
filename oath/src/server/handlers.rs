//! HTTP handlers and shared state for the OAuth2 router.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Extension, Query};
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Redirect};
use cookie::{Cookie, CookieJar, Key, SameSite};
use serde::Deserialize;

use crate::{AuthorizationUrl, TokenErrorCode};

use super::config::OAuth2RouterConfig;
use super::error::ServerError;
use super::identity::{Identity, IdentityResolver, validate_id_token};
use super::redirect::ExtractRedirect;
use super::registry::Provider;
use super::session::{SessionData, SessionId, SessionStore};
use super::users::UserStore;

/// Shared state threaded through the router via `Extension`.
///
/// The provider a login/callback route belongs to is not part of this
/// state: each of those routes carries its own `Extension<Arc<Provider>>`.
pub(crate) struct RouterState<S, U>
where
    U: UserStore,
{
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
            .field("config", &self.config)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct LoginParams {
    /// Where to redirect after a successful callback. Only honored if
    /// it passes [`OAuth2RouterConfig::sanitize_return_to`].
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
    /// RFC 9207 issuer identifier.
    #[serde(default)]
    iss: Option<String>,
}

/// `GET {prefix}/{provider}/login` (or `{prefix}/login` for the default
/// provider).
pub(crate) async fn login<S, U, C>(
    Extension(state): Extension<Arc<RouterState<S, U>>>,
    Extension(provider): Extension<Arc<Provider>>,
    Extension(redirect): Extension<Option<Arc<C>>>,
    Query(params): Query<LoginParams>,
    mut parts: http::request::Parts,
) -> Result<axum::response::Response, ServerError>
where
    S: SessionStore,
    U: UserStore,
    C: ExtractRedirect + Send + Sync + 'static,
{
    let mut auth_uri =
        AuthorizationUrl::new(provider.endpoint()).scopes(provider.effective_scopes(&state.config));

    // With an origin extractor, the redirect URI is always this
    // provider's callback route on the request's public host. Otherwise
    // the endpoint's configured redirect URI is used. Either way,
    // `PendingAuthorization` records the value sent so the token
    // exchange can repeat it.
    if let Some(extract) = &redirect {
        let origin = extract.from_request_parts(&mut parts).await?;
        let callback =
            super::redirect::callback_uri(&origin, &provider.callback_path(&state.config))?;
        auth_uri = auth_uri.with_redirect(callback);
    }

    let (url, pending) = auth_uri.begin()?;

    let return_to = params
        .return_to
        .and_then(|value| state.config.sanitize_return_to(&value));
    let session_id = state
        .sessions
        .create(SessionData::Pending {
            provider: provider.id().clone(),
            pending,
            return_to,
        })
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

    tracing::debug!(
        provider = %provider.id(),
        "redirecting to oauth provider {url}",
        url = url.to_string()
    );
    let mut headers = HeaderMap::new();
    headers.append(SET_COOKIE, cookie);

    Ok((headers, Redirect::to(&url.to_string())).into_response())
}

/// `GET {prefix}/{provider}/callback` (or `{prefix}/callback` for a
/// provider registered via [`super::OAuth2Router::new`]).
pub(crate) async fn callback<S, U>(
    Extension(state): Extension<Arc<RouterState<S, U>>>,
    Extension(provider): Extension<Arc<Provider>>,
    Query(params): Query<CallbackParams>,
    headers: HeaderMap,
) -> Result<axum::response::Response, ServerError>
where
    S: SessionStore,
    U: UserStore,
{
    // RFC 9207 §2.4: check `iss` before acting on the response at all,
    // including error responses.
    provider.check_iss_parameter(params.iss.as_deref())?;

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

    let (pending_provider, pending, return_to) = match preauth {
        SessionData::Pending {
            provider,
            pending,
            return_to,
        } => (provider, pending, return_to),
        SessionData::Authenticated { .. } => return Err(ServerError::PreauthMissing),
    };

    // The pre-auth session is single-use; drop it before we do
    // anything that could fail.
    state
        .sessions
        .delete(&preauth_id)
        .await
        .map_err(ServerError::session_store)?;

    // Only exchange the code with the provider the flow was started
    // against, and only when it arrives on that provider's callback
    // route. This is the IdP mix-up defense: a code from provider A must
    // never be sent to provider B's token endpoint.
    if &pending_provider != provider.id() {
        return Err(ServerError::ProviderMismatch {
            expected: pending_provider,
            actual: provider.id().clone(),
        });
    }

    let token_set = pending
        .complete(provider.endpoint(), &auth_state, auth_code)
        .await?;

    // OIDC providers return an id_token; make sure it's from this
    // provider and for this client before the app's resolver sees it.
    if token_set.id_token.is_some() {
        validate_id_token(
            &token_set,
            provider.endpoint().client_id(),
            provider.expected_issuer(),
        )
        .map_err(ServerError::InvalidIdToken)?;
    }

    let Identity { username, data } = state
        .identity
        .resolve(provider.id(), token_set)
        .await
        .map_err(ServerError::identity)?;

    super::sanitize_username(&username)?;

    state
        .users
        .put(provider.id(), &username, &data)
        .await
        .map_err(ServerError::user_store)?;

    let session_id = state
        .sessions
        .create(SessionData::Authenticated {
            provider: provider.id().clone(),
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
