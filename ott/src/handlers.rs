//! HTTP handlers for ott's own routes.

use axum::extract::State;
use axum::response::{Html, IntoResponse, Redirect};
use minijinja::context;

use crate::auth::{CurrentUser, OptionalCurrentUser};
use crate::state::AppState;

/// `GET /` — anonymous landing.
///
/// If the request carries a valid session cookie + user record, we
/// redirect to `/profile`; otherwise render the home template.
pub async fn home(
    State(state): State<AppState>,
    OptionalCurrentUser(user): OptionalCurrentUser,
) -> axum::response::Response {
    if user.is_some() {
        return Redirect::to("/profile").into_response();
    }
    let tmpl = state
        .templates
        .get_template("home.html")
        .expect("home.html template was registered at startup");
    let body = tmpl
        .render(context! {
            provider_name => &state.config.provider_name,
            redirect_uri => state.config.redirect_uri().to_string(),
        })
        .expect("home.html renders cleanly with built-in context");
    Html(body).into_response()
}

/// `GET /profile` — authenticated landing.
///
/// `CurrentUser` redirects to `/` if the session cookie is missing
/// or invalid, so by the time the body runs we have a real user.
pub async fn profile(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
) -> axum::response::Response {
    let user_json = serde_json::to_string_pretty(&user)
        .unwrap_or_else(|e| format!("(failed to serialize user: {e})"));
    let tmpl = state
        .templates
        .get_template("profile.html")
        .expect("profile.html template was registered at startup");
    let body = tmpl
        .render(context! {
            user => &user,
            user_json => user_json,
        })
        .expect("profile.html renders cleanly with built-in context");
    Html(body).into_response()
}

/// `GET /healthz` — reverse-proxy friendly probe.
pub async fn health() -> &'static str {
    "ok\n"
}
