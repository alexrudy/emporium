//! End-to-end test of the optional `server` feature.
//!
//! Drives a built `OAuth2Router` through the full
//! `/auth/login` → `/auth/callback` → `/auth/logout` round-trip,
//! using `ScriptedMock` as the OAuth2 transport and `MemoryStorage` as
//! the `Driver` behind `JsonFileUserStore`.

#![cfg(feature = "server")]

mod common;

use axum::Router;
use axum::body::Body;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::ScriptedMock;
use cookie::Key;
use http::{Request, StatusCode, header};
use oath::server::{
    Identity, IdentityResolver, InMemorySessionStore, JsonFileUserStore, OAuth2Router,
    parse_id_token,
};
use oath::{ScopeSet, TokenEndpoint};
use secret::Secret;
use serde::{Deserialize, Serialize};
use storage::MemoryStorage;
use storage_driver::Driver as _;
use tower::ServiceExt as _;

const APP_BUCKET: &str = "users";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct AppUser {
    email: String,
    sub: String,
}

fn id_token(sub: &str, email: &str) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    let payload =
        serde_json::json!({"sub": sub, "email": email, "email_verified": true}).to_string();
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());
    let sig = URL_SAFE_NO_PAD.encode(b"unverified-signature-bytes");
    format!("{header}.{payload_b64}.{sig}")
}

fn token_response_bytes(id_tok: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "access_token": "atok",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "rtok",
        "id_token": id_tok,
    }))
    .unwrap()
}

struct Setup {
    router: Router,
    mock: ScriptedMock,
    storage: std::sync::Arc<MemoryStorage>,
    #[allow(dead_code)]
    sessions: InMemorySessionStore,
}

async fn setup_router(id_tok_sub: &str, id_tok_email: &str) -> Setup {
    let mock = ScriptedMock::new();
    mock.enqueue_json(
        "/oauth/token",
        StatusCode::OK,
        &token_response_bytes(&id_token(id_tok_sub, id_tok_email)),
    );

    let endpoint = TokenEndpoint::builder()
        .client_id("the-client")
        .client_secret(Secret::from("the-secret"))
        .auth_uri(
            "https://provider.example.com/oauth/authorize"
                .parse()
                .unwrap(),
        )
        .token_uri("https://provider.example.com/oauth/token".parse().unwrap())
        .redirect_uri("https://app.example.com/auth/callback".parse().unwrap())
        .transport(mock.clone())
        .build()
        .unwrap();

    let storage = std::sync::Arc::new(MemoryStorage::with_buckets(&[APP_BUCKET]));

    let storage_for_users = storage.clone();
    let users: JsonFileUserStore<_, AppUser> =
        JsonFileUserStore::new(SharedStorage(storage_for_users), APP_BUCKET);

    let identity = IdentityResolver::new(|tokens| async move {
        let claims = parse_id_token(&tokens)?;
        Ok(Identity {
            username: claims.sub.clone(),
            data: AppUser {
                email: claims.email.clone().unwrap_or_default(),
                sub: claims.sub,
            },
        })
    });

    let sessions = InMemorySessionStore::default();
    let scopes: ScopeSet = "openid email".parse().unwrap();

    let router = OAuth2Router::new(endpoint, sessions.clone(), users, identity, Key::generate())
        .scopes(scopes)
        .secure_cookies(false)
        .into_router();

    Setup {
        router,
        mock,
        storage,
        sessions,
    }
}

// SharedStorage is a thin newtype that lets us hand the MemoryStorage to
// the UserStore by value while still keeping a handle for assertions.
#[derive(Debug)]
struct SharedStorage(std::sync::Arc<MemoryStorage>);

#[async_trait::async_trait]
impl storage_driver::Driver for SharedStorage {
    fn name(&self) -> &'static str {
        self.0.name()
    }
    fn scheme(&self) -> &str {
        self.0.scheme()
    }
    async fn delete(
        &self,
        bucket: &str,
        remote: &camino::Utf8Path,
    ) -> Result<(), storage_driver::StorageError> {
        self.0.delete(bucket, remote).await
    }
    async fn metadata(
        &self,
        bucket: &str,
        remote: &camino::Utf8Path,
    ) -> Result<storage_driver::Metadata, storage_driver::StorageError> {
        self.0.metadata(bucket, remote).await
    }
    async fn upload(
        &self,
        bucket: &str,
        remote: &camino::Utf8Path,
        reader: &mut storage_driver::Reader<'_>,
    ) -> Result<(), storage_driver::StorageError> {
        self.0.upload(bucket, remote, reader).await
    }
    async fn download(
        &self,
        bucket: &str,
        remote: &camino::Utf8Path,
        writer: &mut storage_driver::Writer<'_>,
    ) -> Result<(), storage_driver::StorageError> {
        self.0.download(bucket, remote, writer).await
    }
    async fn list(
        &self,
        bucket: &str,
        prefix: Option<&camino::Utf8Path>,
    ) -> Result<Vec<String>, storage_driver::StorageError> {
        self.0.list(bucket, prefix).await
    }
}

fn extract_cookie_value(headers: &http::HeaderMap, cookie_name: &str) -> Option<String> {
    headers.get_all(header::SET_COOKIE).iter().find_map(|hv| {
        let s = hv.to_str().ok()?;
        let (name_value, _) = s.split_once(';').unwrap_or((s, ""));
        let (name, value) = name_value.split_once('=')?;
        if name.trim() == cookie_name {
            Some(value.trim().to_owned())
        } else {
            None
        }
    })
}

#[tokio::test]
async fn login_callback_logout_round_trip() {
    let setup = setup_router("user-sub-123", "alice@example.com").await;
    let router = setup.router.clone();

    // --- GET /auth/login -------------------------------------------------
    let login_resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/auth/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(
        login_resp.status().is_redirection(),
        "login should redirect, got {}",
        login_resp.status(),
    );

    let location = login_resp
        .headers()
        .get(header::LOCATION)
        .expect("login response must include Location")
        .to_str()
        .unwrap()
        .to_owned();
    assert!(
        location.starts_with("https://provider.example.com/oauth/authorize?"),
        "Location was {location}",
    );

    // Parse state out of the redirect URL — the provider would echo it back.
    let url: url::Url = location.parse().unwrap();
    let echoed_state = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.into_owned())
        .expect("authorize URL must carry a state param");

    let preauth_value = extract_cookie_value(login_resp.headers(), "oath_preauth")
        .expect("login response must set the preauth cookie");
    let preauth_cookie = format!("oath_preauth={preauth_value}");

    // --- GET /auth/callback ---------------------------------------------
    let callback_resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/auth/callback?code=the-code&state={echoed_state}"))
                .header(header::COOKIE, &preauth_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(
        callback_resp.status().is_redirection(),
        "callback should redirect, got {}",
        callback_resp.status(),
    );
    let dest = callback_resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(dest, "/");

    // Session cookie is set, preauth cookie is cleared (Max-Age=0).
    let session_value = extract_cookie_value(callback_resp.headers(), "oath_session")
        .expect("callback must set the session cookie");
    let cleared_preauth: Vec<_> = callback_resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter(|hv| {
            let s = hv.to_str().unwrap_or("");
            s.starts_with("oath_preauth=") && s.contains("Max-Age=0")
        })
        .collect();
    assert_eq!(
        cleared_preauth.len(),
        1,
        "preauth cookie should be cleared on callback",
    );

    // User should be persisted in storage.
    let mut buf = Vec::<u8>::new();
    setup
        .storage
        .download(APP_BUCKET, "users/user-sub-123.json".into(), &mut buf)
        .await
        .expect("user file should exist after callback");
    let user: AppUser = serde_json::from_slice(&buf).unwrap();
    assert_eq!(
        user,
        AppUser {
            email: "alice@example.com".into(),
            sub: "user-sub-123".into(),
        }
    );

    // --- POST /auth/logout ----------------------------------------------
    let session_cookie = format!("oath_session={session_value}");
    let logout_resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method(http::Method::POST)
                .uri("/auth/logout")
                .header(header::COOKIE, &session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(logout_resp.status().is_redirection());
    let cleared_session: Vec<_> = logout_resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter(|hv| {
            let s = hv.to_str().unwrap_or("");
            s.starts_with("oath_session=") && s.contains("Max-Age=0")
        })
        .collect();
    assert_eq!(cleared_session.len(), 1);

    // The token endpoint mock should have been hit exactly once.
    assert_eq!(setup.mock.count_for("/oauth/token"), 1);
}

#[tokio::test]
async fn callback_without_preauth_cookie_is_400() {
    let setup = setup_router("anything", "anything").await;
    let response = setup
        .router
        .oneshot(
            Request::builder()
                .uri("/auth/callback?code=x&state=y")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn callback_with_state_mismatch_is_400() {
    let setup = setup_router("user-sub", "user@example.com").await;
    let router = setup.router.clone();

    // Drive login to capture a real preauth cookie.
    let login = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/auth/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let preauth = format!(
        "oath_preauth={}",
        extract_cookie_value(login.headers(), "oath_preauth").unwrap()
    );

    let response = router
        .oneshot(
            Request::builder()
                .uri("/auth/callback?code=x&state=wrong-state-value")
                .header(header::COOKIE, &preauth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    // Nothing should have been written to user storage.
    assert!(
        setup
            .storage
            .list(APP_BUCKET, None)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn callback_with_provider_error_query_is_400() {
    let setup = setup_router("user-sub", "user@example.com").await;
    let response = setup
        .router
        .oneshot(
            Request::builder()
                .uri("/auth/callback?error=access_denied&error_description=user%20said%20no")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
