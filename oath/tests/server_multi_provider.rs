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
use http::{HeaderName, Request, StatusCode, Uri, header};
use oath::TokenEndpoint;
use oath::server::{
    Identity, IdentityResolver, InMemorySessionStore, OAuth2Router, Provider, ProviderId,
    SessionData, SessionId, SessionStore as _, TrustedHeader, UserStore, parse_id_token,
};
use secret::Secret;
use tower::ServiceExt as _;

#[derive(Debug, Clone, Default)]
struct MemoryUsers(Arc<Mutex<HashMap<(ProviderId, String), String>>>);

impl MemoryUsers {
    fn record(&self, provider: &str, username: &str) -> Option<String> {
        self.0
            .lock()
            .unwrap()
            .get(&(id(provider), username.to_owned()))
            .cloned()
    }
}

#[async_trait::async_trait]
impl UserStore for MemoryUsers {
    type Data = String;
    type Error = Infallible;

    async fn get(
        &self,
        provider: &ProviderId,
        username: &str,
    ) -> Result<Option<String>, Infallible> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .get(&(provider.clone(), username.to_owned()))
            .cloned())
    }

    async fn put(
        &self,
        provider: &ProviderId,
        username: &str,
        data: &String,
    ) -> Result<(), Infallible> {
        self.0
            .lock()
            .unwrap()
            .insert((provider.clone(), username.to_owned()), data.clone());
        Ok(())
    }
}

/// Username is the bare `sub`; the record notes which provider the
/// resolver was told about.
fn resolver() -> IdentityResolver<String> {
    IdentityResolver::with_provider(|provider: ProviderId, tokens| async move {
        let claims = parse_id_token(&tokens)?;
        Ok(Identity {
            data: format!("{provider}:{}", claims.sub),
            username: claims.sub,
        })
    })
}

/// A token response for provider `name`, whose id_token carries that
/// provider's issuer and client id.
fn token_response(name: &str, sub: &str) -> Vec<u8> {
    token_response_with(
        sub,
        &format!("https://{name}.example.com"),
        &format!("{name}-client"),
    )
}

fn token_response_with(sub: &str, iss: &str, aud: &str) -> Vec<u8> {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD
        .encode(serde_json::json!({ "sub": sub, "iss": iss, "aud": aud }).to_string());
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
        .issuer(format!("https://{name}.example.com"))
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
    mock.enqueue_json(
        "/google/token",
        StatusCode::OK,
        &token_response("google", "g-123"),
    );
    mock.enqueue_json(
        "/okta/token",
        StatusCode::OK,
        &token_response("okta", "o-456"),
    );

    let users = MemoryUsers::default();
    let sessions = InMemorySessionStore::default();
    let identity = resolver();

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

/// Run a full login + callback against `provider`'s routes.
async fn complete_login(router: &Router, provider: &str) {
    let (url, preauth) = begin_login(router, &format!("/auth/{provider}/login")).await;
    let state = query(&url, "state").unwrap();
    let resp = get(
        router,
        &format!("/auth/{provider}/callback?code=c&state={state}"),
        Some(&preauth),
    )
    .await;
    assert!(
        resp.status().is_redirection(),
        "{provider} callback -> {}",
        resp.status()
    );
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
        setup.users.record("okta", "o-456").as_deref(),
        Some("okta:o-456")
    );

    // The authenticated session records the provider.
    let session = cookie_value(resp.headers(), "oath_session").unwrap();
    // Signed cookie values are `<signature><value>`; the session id is the
    // trailing 43 base64url chars.
    let session_id = SessionId::from_string(&session[session.len() - 43..]);
    match setup.sessions.get(&session_id).await.unwrap().unwrap() {
        SessionData::Authenticated { provider, username } => {
            assert_eq!(provider, id("okta"));
            assert_eq!(username, "o-456");
        }
        other => panic!("expected authenticated session, got {other:?}"),
    }
}

#[tokio::test]
async fn same_sub_at_two_providers_is_two_users() {
    let setup = setup(|b| b);
    // Both providers issue the same `sub`.
    setup.mock.enqueue_json(
        "/google/token",
        StatusCode::OK,
        &token_response("google", "same"),
    );
    setup.mock.enqueue_json(
        "/okta/token",
        StatusCode::OK,
        &token_response("okta", "same"),
    );

    // `setup` queued one response per provider (g-123 / o-456) ahead of
    // the shared `sub`, so log in twice with each.
    for provider in ["google", "okta", "google", "okta"] {
        complete_login(&setup.router, provider).await;
    }

    assert_eq!(
        setup.users.record("google", "same").as_deref(),
        Some("google:same")
    );
    assert_eq!(
        setup.users.record("okta", "same").as_deref(),
        Some("okta:same")
    );
}

/// Log in at `provider` with an id_token from `iss` for `aud`; return the
/// callback status.
async fn callback_status_for_token(
    configure: impl FnOnce(
        OAuth2Router<InMemorySessionStore, MemoryUsers>,
    ) -> OAuth2Router<InMemorySessionStore, MemoryUsers>,
    iss: &str,
    aud: &str,
) -> (StatusCode, MemoryUsers) {
    let setup = setup(configure);
    // Use up okta's default response so ours is next.
    complete_login(&setup.router, "okta").await;
    setup.mock.enqueue_json(
        "/okta/token",
        StatusCode::OK,
        &token_response_with("intruder", iss, aud),
    );

    let (url, preauth) = begin_login(&setup.router, "/auth/okta/login").await;
    let state = query(&url, "state").unwrap();
    let resp = get(
        &setup.router,
        &format!("/auth/okta/callback?code=c&state={state}"),
        Some(&preauth),
    )
    .await;
    (resp.status(), setup.users)
}

#[tokio::test]
async fn id_token_from_another_issuer_is_rejected() {
    let (status, users) =
        callback_status_for_token(|b| b, "https://google.example.com", "okta-client").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(users.record("okta", "intruder").is_none());
}

#[tokio::test]
async fn id_token_for_another_client_is_rejected() {
    let (status, users) =
        callback_status_for_token(|b| b, "https://okta.example.com", "google-client").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(users.record("okta", "intruder").is_none());
}

#[tokio::test]
async fn issuer_check_can_be_skipped_but_audience_still_applies() {
    let mock = ScriptedMock::new();
    let skip = |b: OAuth2Router<InMemorySessionStore, MemoryUsers>| {
        b.provider(Provider::new(id("entra"), endpoint("entra", &mock)).skip_issuer_validation())
    };

    let setup = setup(skip);
    mock.enqueue_json(
        "/entra/token",
        StatusCode::OK,
        &token_response_with(
            "u1",
            "https://login.example.com/tenant-a/v2.0",
            "entra-client",
        ),
    );
    complete_login(&setup.router, "entra").await;
    assert!(setup.users.record("entra", "u1").is_some());

    mock.enqueue_json(
        "/entra/token",
        StatusCode::OK,
        &token_response_with(
            "u2",
            "https://login.example.com/tenant-a/v2.0",
            "other-client",
        ),
    );
    let (url, preauth) = begin_login(&setup.router, "/auth/entra/login").await;
    let state = query(&url, "state").unwrap();
    let resp = get(
        &setup.router,
        &format!("/auth/entra/callback?code=c&state={state}"),
        Some(&preauth),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert!(setup.users.record("entra", "u2").is_none());
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
    mock.enqueue_json(
        "/legacy/token",
        StatusCode::OK,
        &token_response("legacy", "l-1"),
    );

    let users = MemoryUsers::default();
    let identity = resolver();
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
    assert!(users.record("default", "l-1").is_some());

    let (url, _) = begin_login(&router, "/auth/google/login").await;
    assert_eq!(url.host_str(), Some("google.example.com"));
}

fn trusted_header_router(mock: &ScriptedMock, users: MemoryUsers) -> Router {
    let identity = resolver();
    OAuth2Router::<_, _, TrustedHeader>::new(
        endpoint("legacy", mock),
        InMemorySessionStore::default(),
        users,
        identity,
        Key::generate(),
    )
    .provider(Provider::new(id("google"), endpoint("google", mock)))
    .provider(Provider::new(id("okta"), endpoint("okta", mock)))
    .redirect(Arc::new(TrustedHeader::from(HeaderName::from_static(
        "x-gateway-origin",
    ))))
    .secure_cookies(false)
    .into_router()
}

async fn login_via_header(router: &Router, path: &str, origin: &str) -> (url::Url, String) {
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .header("x-gateway-origin", origin)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
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

#[tokio::test]
async fn trusted_header_gives_each_provider_and_host_its_own_callback() {
    let mock = ScriptedMock::new();
    let router = trusted_header_router(&mock, MemoryUsers::default());

    let cases = [
        // Bare origin, as recommended.
        (
            "/auth/google/login",
            "https://app1.example.com",
            "https://app1.example.com/auth/google/callback",
        ),
        // A full callback URL (the old header format) is reduced to its origin.
        (
            "/auth/okta/login",
            "http://app2.example.com:8080/auth/callback",
            "http://app2.example.com:8080/auth/okta/callback",
        ),
        // The provider from `new` keeps the root callback path.
        (
            "/auth/login",
            "https://app2.example.com",
            "https://app2.example.com/auth/callback",
        ),
    ];
    for (path, origin, expected) in cases {
        let (url, _) = login_via_header(&router, path, origin).await;
        assert_eq!(
            query(&url, "redirect_uri").as_deref(),
            Some(expected),
            "{path} via {origin}"
        );
    }
}

#[tokio::test]
async fn exchange_repeats_the_redirect_uri_sent_to_the_provider() {
    let mock = ScriptedMock::new();
    mock.enqueue_json(
        "/google/token",
        StatusCode::OK,
        &token_response("google", "g-1"),
    );
    mock.enqueue_json(
        "/google/token",
        StatusCode::OK,
        &token_response("google", "g-2"),
    );
    let users = MemoryUsers::default();
    let router = trusted_header_router(&mock, users.clone());

    for (origin, sub) in [
        ("https://app1.example.com", "g-1"),
        ("https://app2.example.com", "g-2"),
    ] {
        let (url, preauth) = login_via_header(&router, "/auth/google/login", origin).await;
        let sent = query(&url, "redirect_uri").unwrap();
        assert_eq!(sent, format!("{origin}/auth/google/callback"));

        let state = query(&url, "state").unwrap();
        let resp = get(
            &router,
            &format!("/auth/google/callback?code=c&state={state}"),
            Some(&preauth),
        )
        .await;
        assert!(
            resp.status().is_redirection(),
            "callback -> {}",
            resp.status()
        );
        assert!(users.record("google", sub).is_some());

        let exchange = mock
            .requests()
            .into_iter()
            .rfind(|r| r.path == "/google/token")
            .unwrap();
        assert_eq!(exchange.form().get("redirect_uri"), Some(&sent));
    }
}

#[tokio::test]
async fn trusted_header_missing_is_400() {
    let mock = ScriptedMock::new();
    let router = trusted_header_router(&mock, MemoryUsers::default());
    let resp = get(&router, "/auth/google/login", None).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
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
