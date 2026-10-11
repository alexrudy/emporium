//! End-to-end tests of the proxy: authentication, redirects, forwarding,
//! header handling, upstream failures, and connection upgrades.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use cookie::{Cookie, Key};
use http::uri::Authority;
use http::{HeaderMap, Request, StatusCode, header};
use oath::server::{ProviderId, SessionData, SessionStore as _};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tower::ServiceExt as _;

use crate::config::Config;
use crate::state::AppState;

/// What the fake upstream received.
#[derive(Debug, Clone)]
struct Seen {
    uri: String,
    headers: HeaderMap,
}

#[derive(Debug, Clone, Default)]
struct Recorder(Arc<Mutex<Vec<Seen>>>);

impl Recorder {
    fn requests(&self) -> Vec<Seen> {
        self.0.lock().unwrap().clone()
    }
}

/// An HTTP upstream that records each request and answers `upstream ok`.
async fn upstream() -> (Authority, Recorder) {
    let recorder = Recorder::default();
    let seen = recorder.clone();
    let app = Router::new().fallback(move |request: Request<Body>| {
        let seen = seen.clone();
        async move {
            seen.0.lock().unwrap().push(Seen {
                uri: request.uri().to_string(),
                headers: request.headers().clone(),
            });
            "upstream ok"
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let authority = listener.local_addr().unwrap().to_string().parse().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (authority, recorder)
}

fn config() -> Config {
    config::Config::builder()
        .add_source(config::File::from_str(
            r#"
            [oath]
            secure_cookies = false

            [provider]
            client_id = "otunnel"
            provider_name = "Bastion"
            external_origin = "https://tunnel.example.com"
            [provider.endpoints]
            auth_uri = "https://idp.example.com/authorize"
            token_uri = "https://idp.example.com/token"

            [sessions]
            key = "a-test-session-signing-key-that-is-long-enough-to-satisfy-cookie-0123456789"
            "#,
            config::FileFormat::Toml,
        ))
        .build()
        .unwrap()
        .try_deserialize()
        .unwrap()
}

async fn otunnel(upstream: Authority) -> (Router, AppState) {
    let config = config();
    let state = AppState::new(config.clone(), upstream);
    let router = crate::app::build(&state, &config).await.unwrap();
    (router, state)
}

/// A `Cookie` header value for a fresh signed-in session.
async fn session_cookie(state: &AppState) -> String {
    let id = state
        .inner
        .sessions_store
        .create(SessionData::Authenticated {
            provider: ProviderId::default(),
            username: "alice".into(),
        })
        .await
        .unwrap();
    let key = Key::from(state.inner.sessions.key.revealed().as_bytes());
    let name = state.inner.oauth_router.cookies.session.clone();
    let mut jar = cookie::CookieJar::new();
    jar.signed_mut(&key)
        .add(Cookie::new(name.clone(), id.as_str().to_owned()));
    let cookie = jar.get(&name).unwrap();
    format!("{}={}", cookie.name(), cookie.value())
}

async fn send(router: &Router, request: Request<Body>) -> (StatusCode, HeaderMap, String) {
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, headers, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn unauthenticated_requests_redirect_to_login() {
    let (authority, upstream) = upstream().await;
    let (router, _) = otunnel(authority).await;

    let (status, headers, _) = send(
        &router,
        Request::get("/app/page?x=1&y=2")
            .body(Body::empty())
            .unwrap(),
    )
    .await;

    assert!(status.is_redirection(), "{status}");
    assert_eq!(
        headers[header::LOCATION],
        "/auth/login?return_to=%2Fapp%2Fpage%3Fx%3D1%26y%3D2"
    );
    assert!(upstream.requests().is_empty());
}

#[tokio::test]
async fn forged_session_cookie_is_not_trusted() {
    let (authority, upstream) = upstream().await;
    let (router, state) = otunnel(authority).await;
    let name = &state.inner.oauth_router.cookies.session;

    let (status, _, _) = send(
        &router,
        Request::get("/app")
            .header(header::COOKIE, format!("{name}=not-a-signed-session"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;

    assert!(status.is_redirection(), "{status}");
    assert!(upstream.requests().is_empty());
}

#[tokio::test]
async fn signed_in_requests_are_forwarded() {
    let (authority, upstream) = upstream().await;
    let (router, state) = otunnel(authority).await;
    let cookie = session_cookie(&state).await;

    let (status, _, body) = send(
        &router,
        Request::get("/app/page?x=1&y=2")
            .header(header::COOKIE, cookie)
            .header("x-app-header", "kept")
            .header(header::TE, "trailers")
            .header(header::PROXY_AUTHORIZATION, "Basic c2VjcmV0")
            .header(header::CONNECTION, "x-hop")
            .header("x-hop", "this hop only")
            .header("keep-alive", "timeout=5")
            .body(Body::empty())
            .unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "upstream ok");

    let seen = upstream.requests();
    assert_eq!(seen.len(), 1);
    let request = &seen[0];
    assert!(
        request.uri.ends_with("/app/page?x=1&y=2"),
        "{}",
        request.uri
    );

    // End-to-end headers pass through; hop-by-hop ones (including the
    // proxy credential) don't.
    assert_eq!(request.headers["x-app-header"], "kept");
    for hop_by_hop in ["te", "proxy-authorization", "x-hop", "keep-alive"] {
        assert!(
            !request.headers.contains_key(hop_by_hop),
            "{hop_by_hop} was forwarded"
        );
    }
    // The client's `Connection: x-hop` is gone; hyper may add its own.
    if let Some(connection) = request.headers.get(header::CONNECTION) {
        assert!(!connection.to_str().unwrap().contains("x-hop"));
    }

    // otunnel identifies itself, and tags the request.
    let via = request.headers[header::VIA].to_str().unwrap();
    assert!(via.contains("otunnel"), "{via}");
    let request_id = request.headers["x-proxy-request-id"].to_str().unwrap();
    assert!(uuid::Uuid::parse_str(request_id).is_ok(), "{request_id}");
}

#[tokio::test]
async fn auth_routes_are_served_locally() {
    let (authority, upstream) = upstream().await;
    let (router, _) = otunnel(authority).await;

    let (status, headers, _) = send(
        &router,
        Request::get("/auth/login").body(Body::empty()).unwrap(),
    )
    .await;

    assert!(status.is_redirection(), "{status}");
    let location = headers[header::LOCATION].to_str().unwrap();
    assert!(
        location.starts_with("https://idp.example.com/authorize?"),
        "{location}"
    );
    assert!(upstream.requests().is_empty());
}

#[tokio::test]
async fn upstream_failure_is_a_500() {
    // Bind and drop a listener to get a port nothing is listening on.
    let closed: Authority = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().to_string().parse().unwrap()
    };
    let (router, state) = otunnel(closed).await;
    let cookie = session_cookie(&state).await;

    let (status, _, body) = send(
        &router,
        Request::get("/app")
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!body.contains("127.0.0.1"), "error details leaked: {body}");
}

/// A raw TCP upstream that answers one upgrade request with `101` and
/// then echoes whatever it receives.
async fn echo_upgrade_upstream() -> Authority {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let authority = listener.local_addr().unwrap().to_string().parse().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_head(&mut stream).await;
        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\n\
                  Connection: Upgrade\r\n\
                  Upgrade: echo\r\n\r\n",
            )
            .await
            .unwrap();
        let mut buf = [0u8; 1024];
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            stream.write_all(&buf[..n]).await.unwrap();
        }
    });
    authority
}

/// Read an HTTP message head (through the blank line).
async fn read_head(stream: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
    }
    String::from_utf8(head).unwrap()
}

/// Open an upgraded connection through otunnel, sending `connection` as
/// the `Connection` header, and check bytes are relayed both ways.
async fn upgrade_round_trip(connection: &str) {
    let upstream = echo_upgrade_upstream().await;
    let (router, state) = otunnel(upstream).await;
    let cookie = session_cookie(&state).await;

    // Upgrades need a real connection, so serve otunnel over TCP.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    tokio::time::timeout(Duration::from_secs(5), async move {
        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(
                format!(
                    "GET /socket HTTP/1.1\r\n\
                     Host: {addr}\r\n\
                     Cookie: {cookie}\r\n\
                     Connection: {connection}\r\n\
                     Upgrade: echo\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();

        let head = read_head(&mut client).await;
        assert!(head.starts_with("HTTP/1.1 101"), "{head}");

        client.write_all(b"ping").await.unwrap();
        let mut echoed = [0u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");
    })
    .await
    .expect("upgrade round-trip timed out");
}

#[tokio::test]
async fn connection_upgrades_are_proxied() {
    // As browsers send it.
    upgrade_round_trip("Upgrade").await;
}

#[tokio::test]
async fn connection_upgrades_with_other_connection_options() {
    upgrade_round_trip("keep-alive, upgrade").await;
}
