//! HTTP handlers for ott's own routes.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Redirect, Response};
use http::{HeaderName, HeaderValue, StatusCode};
use minijinja::context;
use oath::server::ServerError;

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

/// Header HTMX sets on every request it issues.
const HX_REQUEST: &str = "hx-request";

/// Top-level response-rendering middleware.
///
/// Handlers and extractors return [`ServerError`], whose `IntoResponse` stashes it in
/// the response extensions with only a status code (see
/// `Error::into_response`). This layer removes it and renders the presentation
/// that fits the request:
///
/// * Unauthenticated (`401`) navigation → redirect to `/login` carrying a
///   `return_to`; for HTMX requests an `HX-Redirect` header is used instead so
///   the browser performs a full-page navigation.
/// * Other HTMX requests → a small inline alert fragment, status preserved.
/// * Everything else → the full `error.html` page, status preserved.
///
/// Authenticated-but-forbidden failures use `403` (see `Error::forbidden`) and
/// therefore fall through to the error page rather than bouncing to login.
pub async fn render_errors(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let is_htmx = request.headers().contains_key(HX_REQUEST);

    let mut response = next.run(request).await;

    let Some(error) = response.extensions_mut().remove::<Arc<ServerError>>() else {
        return response;
    };

    let status = error.status_code();
    tracing::error!(error = %error, ?status, is_htmx, "request error");

    // Unauthenticated navigation: send them to log in, then back where they were.
    if status == StatusCode::UNAUTHORIZED {
        let location = "/login";
        if is_htmx {
            let mut response = StatusCode::NO_CONTENT.into_response();
            if let Ok(value) = HeaderValue::from_str(location) {
                response
                    .headers_mut()
                    .insert(HeaderName::from_static("hx-redirect"), value);
            }
            return response;
        }
        return Redirect::to(location).into_response();
    }

    // HTMX swaps responses into a fragment target, so a full page would be wrong.
    if is_htmx {
        let body = format!(
            "<div class=\"alert alert-danger\" role=\"alert\">{}</div>",
            html_escape(&error.to_string())
        );
        return (status, Html(body)).into_response();
    }

    // Default browser presentation: the full error page.
    let tmpl = state
        .templates
        .get_template("error.html")
        .expect("error.html template was registered at startup");

    match tmpl.render(context! { error => error.status_code().canonical_reason(), error_description => &error.to_string() }) {
        Ok(html) => (status, Html(html)).into_response(),
        Err(render_error) => {
            tracing::error!(error = %render_error, "failed to render error.html");
            (
                status,
                Html("An internal server error occurred".to_string()),
            )
                .into_response()
        }
    }
}

/// Minimal HTML-text escaping for values interpolated into an inline fragment.
fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
