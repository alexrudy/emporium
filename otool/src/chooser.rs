//! A minimal "Sign in with …" page for `{prefix}/login`.
//!
//! When several providers are configured and none is the default,
//! [`oath::server::OAuth2Router`] leaves `{prefix}/login` unrouted. This
//! module fills it with a page linking to each provider's login route, so
//! apps can keep redirecting unauthenticated users to `{prefix}/login`.

use std::fmt::Write as _;
use std::sync::Arc;

use axum::Router;
use axum::extract::Query;
use axum::response::Html;
use axum::routing::get;
use oath::server::{OAuth2Router, OAuth2RouterConfig, SessionStore, UserStore};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ChooserParams {
    #[serde(default)]
    return_to: Option<String>,
}

#[derive(Debug)]
struct Choice {
    display_name: String,
    login_path: String,
}

/// A router serving the provider chooser at `{prefix}/login`, or `None`
/// if a default provider already serves that route.
pub fn login_chooser<S, U, C, AxS>(oauth: &OAuth2Router<S, U, C>) -> Option<Router<AxS>>
where
    S: SessionStore,
    U: UserStore,
    AxS: Clone + Send + Sync + 'static,
{
    if oauth.default_login_provider().is_some() {
        return None;
    }

    let choices: Arc<[Choice]> = oauth
        .providers()
        .map(|provider| Choice {
            display_name: provider.display_name().to_owned(),
            login_path: provider.login_path(oauth.router_config()),
        })
        .collect();
    let config = Arc::new(oauth.router_config().clone());

    Some(Router::new().route(
        &oauth.router_config().login_path(),
        get(move |Query(params): Query<ChooserParams>| {
            let choices = choices.clone();
            let config = config.clone();
            async move { Html(render(&choices, &config, params.return_to.as_deref())) }
        }),
    ))
}

/// Build the OAuth2 router, adding the provider chooser at
/// `{prefix}/login` when there's no default provider.
pub fn router_with_chooser<S, U, C, AxS>(oauth: OAuth2Router<S, U, C>) -> Router<AxS>
where
    S: SessionStore,
    U: UserStore,
    C: oath::server::ExtractRedirect + Send + Sync + 'static,
    AxS: Clone + Send + Sync + 'static,
{
    let chooser = login_chooser(&oauth);
    let router = oauth.into_router();
    match chooser {
        Some(chooser) => router.merge(chooser),
        None => router,
    }
}

fn render(choices: &[Choice], config: &OAuth2RouterConfig, return_to: Option<&str>) -> String {
    let mut items = String::new();
    for choice in choices {
        let _ = write!(
            items,
            r#"<li><a href="{href}">Sign in with {name}</a></li>"#,
            href = escape(&config.with_return_to(&choice.login_path, return_to)),
            name = escape(&choice.display_name),
        );
    }

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in</title>
<style>
body {{ font-family: system-ui, sans-serif; display: grid; place-items: center; min-height: 100vh; margin: 0; }}
ul {{ list-style: none; padding: 0; }}
li {{ margin: 0.5rem 0; }}
a {{ display: block; padding: 0.6rem 1.2rem; border: 1px solid currentColor; border-radius: 0.4rem; text-decoration: none; }}
</style>
</head>
<body>
<main>
<h1>Sign in</h1>
<ul>{items}</ul>
</main>
</body>
</html>
"#
    )
}

fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn choices() -> Vec<Choice> {
        vec![
            Choice {
                display_name: "Google".into(),
                login_path: "/auth/google/login".into(),
            },
            Choice {
                display_name: "<Okta & Co>".into(),
                login_path: "/auth/okta/login".into(),
            },
        ]
    }

    #[test]
    fn lists_each_provider() {
        let html = render(&choices(), &OAuth2RouterConfig::default(), None);
        assert!(html.contains(r#"<a href="/auth/google/login">Sign in with Google</a>"#));
        assert!(html.contains("Sign in with &lt;Okta &amp; Co&gt;"));
    }

    #[test]
    fn carries_return_to_encoded() {
        let html = render(
            &choices(),
            &OAuth2RouterConfig::default(),
            Some("/a?b=1&c=2"),
        );
        assert!(html.contains(r#"href="/auth/google/login?return_to=%2Fa%3Fb%3D1%26c%3D2""#));
    }

    #[test]
    fn drops_unsafe_return_to() {
        for return_to in ["//evil.example.com", "/auth/login"] {
            let html = render(&choices(), &OAuth2RouterConfig::default(), Some(return_to));
            assert!(
                html.contains(r#"href="/auth/google/login""#),
                "{return_to}: {html}"
            );
        }
    }
}
