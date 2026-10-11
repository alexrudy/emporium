//! `build_router` + `router_with_chooser` against explicit (non-discovery)
//! provider endpoints.

use axum::Router;
use axum::body::Body;
use http::{Request, StatusCode, header};
use otool::config::{OAuth2RouterConfig, OAuthProviderConfig, ProvidersConfig, SessionsConfig};
use otool::state::AppState;
use otool::{build_router, router_with_chooser};
use tower::ServiceExt as _;

fn provider(name: &str) -> OAuthProviderConfig {
    serde_json::from_value(serde_json::json!({
        "provider_name": name,
        "client_id": format!("{name}-client"),
        "external_origin": "https://gw.example.com",
        "endpoints": {
            "auth_uri": format!("https://{name}.example.com/authorize"),
            "token_uri": format!("https://{name}.example.com/token"),
        },
    }))
    .unwrap()
}

async fn app(providers: ProvidersConfig) -> Router {
    let state = AppState::new(
        OAuth2RouterConfig::default(),
        providers,
        SessionsConfig::default(),
    );
    router_with_chooser(build_router::<http::Uri>(&state).await.unwrap())
}

async fn get(router: &Router, uri: &str) -> (StatusCode, Option<String>, String) {
    let resp = router
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let location = resp
        .headers()
        .get(header::LOCATION)
        .map(|v| v.to_str().unwrap().to_owned());
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        location,
        String::from_utf8_lossy(&body).into_owned(),
    )
}

fn redirect_uri(location: &str) -> String {
    let query = location.split_once('?').unwrap().1;
    let params: Vec<(String, String)> = serde_urlencoded::from_str(query).unwrap();
    params
        .into_iter()
        .find(|(k, _)| k == "redirect_uri")
        .unwrap()
        .1
}

fn multi() -> ProvidersConfig {
    let mut providers = ProvidersConfig::default();
    providers
        .providers
        .insert("google".parse().unwrap(), provider("google"));
    providers
        .providers
        .insert("okta".parse().unwrap(), provider("okta"));
    providers
}

#[tokio::test]
async fn multiple_providers_without_default_get_a_chooser() {
    let router = app(multi()).await;

    let (status, _, body) = get(&router, "/auth/login?return_to=/app").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"href="/auth/google/login?return_to=%2Fapp""#),
        "{body}"
    );
    assert!(
        body.contains(r#"href="/auth/okta/login?return_to=%2Fapp""#),
        "{body}"
    );

    let (status, location, _) = get(&router, "/auth/okta/login").await;
    assert!(status.is_redirection());
    let location = location.unwrap();
    assert!(location.starts_with("https://okta.example.com/authorize?"));
    assert_eq!(
        redirect_uri(&location),
        "https://gw.example.com/auth/okta/callback"
    );
}

#[tokio::test]
async fn default_provider_serves_login() {
    let mut providers = multi();
    providers.default_provider = Some("google".parse().unwrap());
    let router = app(providers).await;

    let (status, location, _) = get(&router, "/auth/login").await;
    assert!(status.is_redirection());
    assert!(
        location
            .unwrap()
            .starts_with("https://google.example.com/authorize?")
    );
}

#[tokio::test]
async fn legacy_provider_keeps_root_callback() {
    let mut providers = multi();
    providers.provider = Some(provider("bastion"));
    let router = app(providers).await;

    let (status, location, _) = get(&router, "/auth/login").await;
    assert!(status.is_redirection());
    let location = location.unwrap();
    assert!(location.starts_with("https://bastion.example.com/authorize?"));
    assert_eq!(
        redirect_uri(&location),
        "https://gw.example.com/auth/callback"
    );

    let (_, location, _) = get(&router, "/auth/google/login").await;
    assert_eq!(
        redirect_uri(&location.unwrap()),
        "https://gw.example.com/auth/google/callback"
    );
}

/// A discovery-configured provider whose issuer refuses connections.
fn unreachable(name: &str) -> OAuthProviderConfig {
    serde_json::from_value(serde_json::json!({
        "provider_name": name,
        "client_id": format!("{name}-client"),
        "external_origin": "https://gw.example.com",
        "endpoints": { "issuer": "http://127.0.0.1:1" },
    }))
    .unwrap()
}

#[tokio::test]
async fn unavailable_default_provider_falls_back() {
    let mut providers = ProvidersConfig::default();
    providers
        .providers
        .insert("down".parse().unwrap(), unreachable("down"));
    providers
        .providers
        .insert("okta".parse().unwrap(), provider("okta"));
    providers.default_provider = Some("down".parse().unwrap());
    let router = app(providers).await;

    // `okta` is the only provider left, so it serves /auth/login.
    let (status, location, _) = get(&router, "/auth/login").await;
    assert!(status.is_redirection(), "{status}");
    assert!(
        location
            .unwrap()
            .starts_with("https://okta.example.com/authorize?")
    );
    let (status, _, _) = get(&router, "/auth/down/login").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn unavailable_root_provider_leaves_the_others() {
    let mut providers = multi();
    providers.provider = Some(unreachable("bastion"));
    let router = app(providers).await;

    // Two providers left and no default: the chooser.
    let (status, _, body) = get(&router, "/auth/login").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("/auth/google/login"), "{body}");
    assert!(!body.contains("bastion"), "{body}");
}

#[tokio::test]
async fn every_provider_unavailable_is_an_error() {
    let mut providers = ProvidersConfig {
        provider: Some(unreachable("bastion")),
        ..Default::default()
    };
    providers
        .providers
        .insert("down".parse().unwrap(), unreachable("down"));
    let state = AppState::new(
        OAuth2RouterConfig::default(),
        providers,
        SessionsConfig::default(),
    );

    let err = build_router::<http::Uri>(&state).await.unwrap_err();
    let message = err.to_string();
    assert!(matches!(err, otool::BuildError::NoProviders(ref f) if f.len() == 2));
    assert!(
        message.contains("default") && message.contains("down"),
        "{message}"
    );
}

#[tokio::test]
async fn invalid_config_is_an_error() {
    let state = AppState::new(
        OAuth2RouterConfig::default(),
        ProvidersConfig::default(),
        SessionsConfig::default(),
    );
    assert!(build_router::<http::Uri>(&state).await.is_err());
}
