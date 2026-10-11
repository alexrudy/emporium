//! Multi-provider behavior of the optional `server` feature: per-provider
//! routes, provider-tagged sessions, default-login resolution, and the
//! IdP mix-up defense on the callback route.

#![cfg(feature = "server")]

mod common;

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::ScriptedMock;
use cookie::Key;
use http::{Request, StatusCode, Uri, header};
use oath::TokenEndpoint;
use oath::server::{
    Identity, IdentityResolver, InMemorySessionStore, OAuth2Router, Provider, ProviderId,
    SessionData, SessionId, SessionStore as _, UserStore, parse_id_token,
};
use secret::Secret;
use tower::ServiceExt as _;

#[derive(Debug, Clone, Default)]
struct MemoryUsers(Arc<Mutex<HashMap<String, String>>>);

#[async_trait::async_trait]
impl UserStore for MemoryUsers {
    type Data = String;
    type Error = Infallible;

    async fn get(&self, username: &str) -> Result<Option<String>, Infallible> {
        Ok(self.0.lock().unwrap().get(username).cloned())
    }

    async fn put(&self, username: &str, data: &String) -> Result<(), Infallible> {
        self.0
            .lock()
            .unwrap()
            .insert(username.to_owned(), data.clone());
        Ok(())
    }
}

fn token_response(sub: &str) -> Vec<u8> {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::json!({ "sub": sub }).to_string());
    let sig = URL_SAFE_NO_PAD.encode(b"sig");
    serde_json::to_vec(&serde_json::json!({
        "access_token": "atok",
        "token_type": "Bearer",
        "expires_in": 3600,
        "id_token": format!("{header}.{payload}.{sig}"),
    }))
    .unwrap()
}

fn endpoint(name: &str, mock: &ScriptedMock) -> TokenEndpoint {
    TokenEndpoint::builder()
        .client_id(format!("{name}-client"))
        .client_secret(Secret::from("secret"))
        .auth_uri(
            format!("https://{name}.example.com/authorize")
                .parse()
                .unwrap(),
        )
        .token_uri(
            format!("https://{name}.example.com/{name}/token")
                .parse()
                .unwrap(),
        )
        .redirect_uri(
            format!("https://app.example.com/auth/{name}/callback")
                .parse()
                .unwrap(),
        )
        .transport(mock.clone())
        .build()
        .unwrap()
}

fn id(s: &str) -> ProviderId {
    ProviderId::new(s).unwrap()
}

struct Setup {
    router: Router,
    mock: ScriptedMock,
    users: MemoryUsers,
    sessions: InMemorySessionStore,
}

fn setup(
    configure: impl FnOnce(
        OAuth2Router<InMemorySessionStore, MemoryUsers>,
    ) -> OAuth2Router<InMemorySessionStore, MemoryUsers>,
) -> Setup {
    let mock = ScriptedMock::new();
    mock.enqueue_json("/google/token", StatusCode::OK, &token_response("g-123"));
    mock.enqueue_json("/okta/token", StatusCode::OK, &token_response("o-456"));

    let users = MemoryUsers::default();
    let sessions = InMemorySessionStore::default();
    let identity = IdentityResolver::with_provider(|provider: ProviderId, tokens| async move {
        let claims = parse_id_token(&tokens)?;
        Ok(Identity {
            username: format!("{provider}:{}", claims.sub),
            data: claims.sub,
        })
    });

    let builder = OAuth2Router::<_, _, Uri>::multi_provider(
        sessions.clone(),
        users.clone(),
        identity,
        Key::generate(),
    )
    .provider(Provider::new(id("google"), endpoint("google", &mock)))
    .provider(
        Provider::new(id("okta"), endpoint("okta", &mock))
            .with_scopes("openid groups".parse().unwrap()),
    )
    .secure_cookies(false);

    Setup {
        router: configure(builder).into_router(),
        mock,
        users,
        sessions,
    }
}

fn cookie_value(headers: &http::HeaderMap, name: &str) -> Option<String> {
    headers.get_all(header::SET_COOKIE).iter().find_map(|hv| {
        let s = hv.to_str().ok()?;
        let (name_value, _) = s.split_once(';').unwrap_or((s, ""));
        let (n, v) = name_value.split_once('=')?;
        (n.trim() == name).then(|| v.trim().to_owned())
    })
}

async fn get(router: &Router, uri: &str, cookie: Option<&str>) -> http::Response<Body> {
    let mut req = Request::builder().uri(uri);
    if let Some(cookie) = cookie {
        req = req.header(header::COOKIE, cookie);
    }
    router
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

/// Drive a provider's login route; returns (authorize URL, preauth cookie).
async fn begin_login(router: &Router, path: &str) -> (url::Url, String) {
    let resp = get(router, path, None).await;
    assert!(
        resp.status().is_redirection(),
        "{path} -> {}",
        resp.status()
    );
    let location: url::Url = resp.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let preauth = format!(
        "oath_preauth={}",
        cookie_value(resp.headers(), "oath_preauth").unwrap()
    );
    (location, preauth)
}

fn query(url: &url::Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

#[tokio::test]
async fn each_provider_has_its_own_login_and_callback() {
    let setup = setup(|b| b);

    let (google_url, _) = begin_login(&setup.router, "/auth/google/login").await;
    assert_eq!(google_url.host_str(), Some("google.example.com"));
    assert_eq!(
        query(&google_url, "client_id").as_deref(),
        Some("google-client")
    );

    let (okta_url, preauth) = begin_login(&setup.router, "/auth/okta/login").await;
    assert_eq!(okta_url.host_str(), Some("okta.example.com"));
    assert_eq!(query(&okta_url, "scope").as_deref(), Some("openid groups"));

    let state = query(&okta_url, "state").unwrap();
    let resp = get(
        &setup.router,
        &format!("/auth/okta/callback?code=c&state={state}"),
        Some(&preauth),
    )
    .await;
    assert!(
        resp.status().is_redirection(),
        "callback -> {}",
        resp.status()
    );

    // Only okta's token endpoint was used, and the resolver saw the provider.
    assert_eq!(setup.mock.count_for("/okta/token"), 1);
    assert_eq!(setup.mock.count_for("/google/token"), 0);
    assert_eq!(
        setup.users.get("okta:o-456").await.unwrap().as_deref(),
        Some("o-456")
    );

    // The authenticated session records the provider.
    let session = cookie_value(resp.headers(), "oath_session").unwrap();
    // Signed cookie values are `<signature><value>`; the session id is the
    // trailing 43 base64url chars.
    let session_id = SessionId::from_string(&session[session.len() - 43..]);
    match setup.sessions.get(&session_id).await.unwrap().unwrap() {
        SessionData::Authenticated { provider, username } => {
            assert_eq!(provider, id("okta"));
            assert_eq!(username, "okta:o-456");
        }
        other => panic!("expected authenticated session, got {other:?}"),
    }
}

#[tokio::test]
async fn callback_on_wrong_provider_route_is_rejected() {
    let setup = setup(|b| b);

    let (google_url, preauth) = begin_login(&setup.router, "/auth/google/login").await;
    let state = query(&google_url, "state").unwrap();

    let resp = get(
        &setup.router,
        &format!("/auth/okta/callback?code=c&state={state}"),
        Some(&preauth),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(setup.mock.count_for("/okta/token"), 0);
    assert_eq!(setup.mock.count_for("/google/token"), 0);

    // The pre-auth session is single-use, so the legitimate callback
    // can't be replayed afterwards either.
    let resp = get(
        &setup.router,
        &format!("/auth/google/callback?code=c&state={state}"),
        Some(&preauth),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(setup.mock.count_for("/google/token"), 0);
}

#[tokio::test]
async fn default_login_is_unrouted_without_a_default() {
    let setup = setup(|b| b);
    let resp = get(&setup.router, "/auth/login", None).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn default_login_uses_explicit_default_provider() {
    let setup = setup(|b| b.default_provider(id("okta")));
    let (url, preauth) = begin_login(&setup.router, "/auth/login").await;
    assert_eq!(url.host_str(), Some("okta.example.com"));

    // The flow completes on okta's own callback route.
    let state = query(&url, "state").unwrap();
    let resp = get(
        &setup.router,
        &format!("/auth/okta/callback?code=c&state={state}"),
        Some(&preauth),
    )
    .await;
    assert!(resp.status().is_redirection());
}

#[tokio::test]
async fn new_keeps_root_paths_alongside_added_providers() {
    let mock = ScriptedMock::new();
    mock.enqueue_json("/legacy/token", StatusCode::OK, &token_response("l-1"));

    let users = MemoryUsers::default();
    let identity = IdentityResolver::with_provider(|provider: ProviderId, tokens| async move {
        let claims = parse_id_token(&tokens)?;
        Ok(Identity {
            username: format!("{provider}:{}", claims.sub),
            data: claims.sub,
        })
    });
    let router: Router = OAuth2Router::<_, _, Uri>::new(
        endpoint("legacy", &mock),
        InMemorySessionStore::default(),
        users.clone(),
        identity,
        Key::generate(),
    )
    .provider(Provider::new(id("google"), endpoint("google", &mock)))
    .secure_cookies(false)
    .into_router();

    let (url, preauth) = begin_login(&router, "/auth/login").await;
    assert_eq!(url.host_str(), Some("legacy.example.com"));
    let state = query(&url, "state").unwrap();
    let resp = get(
        &router,
        &format!("/auth/callback?code=c&state={state}"),
        Some(&preauth),
    )
    .await;
    assert!(
        resp.status().is_redirection(),
        "callback -> {}",
        resp.status()
    );
    assert!(users.get("default:l-1").await.unwrap().is_some());

    let (url, _) = begin_login(&router, "/auth/google/login").await;
    assert_eq!(url.host_str(), Some("google.example.com"));
}

#[test]
#[should_panic(expected = "registered twice")]
fn duplicate_provider_panics() {
    setup(|b| {
        let mock = ScriptedMock::new();
        b.provider(Provider::new(id("google"), endpoint("google", &mock)))
    });
}

#[test]
#[should_panic(expected = "not a registered provider")]
fn unknown_default_provider_panics() {
    setup(|b| b.default_provider(id("github")));
}
