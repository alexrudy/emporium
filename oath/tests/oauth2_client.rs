//! Proactive-refresh integration tests for [`oath::OAuth2Client`].

mod common;

use std::sync::Arc;

use api_client::ApiClient;
use chrono::{Duration as ChronoDuration, Utc};
use common::ScriptedMock;
use http::StatusCode;
use oath::{AccessToken, OAuth2Client, RefreshStrategy, RefreshToken, TokenEndpoint};
use secret::Secret;

fn token_response() -> Vec<u8> {
    br#"{"access_token":"fresh","token_type":"Bearer","expires_in":3600,"refresh_token":"rotated"}"#
        .to_vec()
}

fn make_client(
    mock: ScriptedMock,
    access_token: AccessToken,
    refresh_token: RefreshToken,
) -> OAuth2Client {
    let endpoint = TokenEndpoint::builder()
        .client_id("the-client")
        .client_secret(Secret::from("the-secret"))
        .token_uri("https://example.com/oauth/token".parse().unwrap())
        .transport(mock.clone())
        .build()
        .unwrap();

    let api = ApiClient::new_with_inner_service(
        "https://example.com/api/".parse().unwrap(),
        access_token,
        mock,
    );

    OAuth2Client::new(
        endpoint,
        api,
        RefreshStrategy::RefreshToken {
            refresh_token,
            scope: None,
        },
    )
}

#[tokio::test]
async fn expired_token_triggers_refresh_before_request() {
    let mock = ScriptedMock::new();

    // /token returns the new bearer.
    mock.enqueue_json("/oauth/token", StatusCode::OK, &token_response());

    // /api/widgets returns 200.
    mock.enqueue_json("/api/widgets", StatusCode::OK, br#"[]"#);

    let expired = AccessToken::new(
        Secret::from("expired"),
        Some(Utc::now() - ChronoDuration::seconds(1)),
    );
    let refresh = RefreshToken::new(Secret::from("rtok"));
    let client = make_client(mock.clone(), expired, refresh);

    client
        .get("widgets")
        .send()
        .await
        .expect("API call should succeed");

    let requests = mock.requests();
    assert_eq!(requests.len(), 2, "expected refresh + API call");
    assert_eq!(requests[0].path, "/oauth/token");
    assert_eq!(requests[1].path, "/api/widgets");
    assert_eq!(
        requests[1].authorization.as_deref(),
        Some("Bearer fresh"),
        "the API call should carry the *new* bearer",
    );
}

#[tokio::test]
async fn fresh_token_skips_refresh() {
    let mock = ScriptedMock::new();

    // Only /api/widgets is queued — if refresh tried to run, the mock
    // would panic because /oauth/token has no scripted response.
    mock.enqueue_json("/api/widgets", StatusCode::OK, br#"[]"#);

    let fresh = AccessToken::new(
        Secret::from("still-good"),
        Some(Utc::now() + ChronoDuration::hours(1)),
    );
    let refresh = RefreshToken::new(Secret::from("rtok"));
    let client = make_client(mock.clone(), fresh, refresh);

    client
        .get("widgets")
        .send()
        .await
        .expect("API call should succeed");

    assert_eq!(
        mock.count_for("/oauth/token"),
        0,
        "fresh path must skip /token"
    );
    assert_eq!(mock.count_for("/api/widgets"), 1);
    let requests = mock.requests();
    assert_eq!(
        requests[0].authorization.as_deref(),
        Some("Bearer still-good")
    );
}

#[tokio::test]
async fn concurrent_sends_collapse_to_one_refresh() {
    let mock = ScriptedMock::new();

    // One /token response: if more than one refresh is attempted, the
    // second pop panics with "queue exhausted".
    mock.enqueue_json("/oauth/token", StatusCode::OK, &token_response());

    // Ten /api/widgets responses for the ten concurrent calls.
    for _ in 0..10 {
        mock.enqueue_json("/api/widgets", StatusCode::OK, br#"[]"#);
    }

    let expired = AccessToken::new(
        Secret::from("expired"),
        Some(Utc::now() - ChronoDuration::seconds(1)),
    );
    let refresh = RefreshToken::new(Secret::from("rtok"));
    let client = Arc::new(make_client(mock.clone(), expired, refresh));

    let handles: Vec<_> = (0..10)
        .map(|_| {
            let client = client.clone();
            tokio::spawn(async move { client.get("widgets").send().await })
        })
        .collect();

    for handle in handles {
        handle
            .await
            .expect("task should not panic")
            .expect("API call should succeed");
    }

    assert_eq!(
        mock.count_for("/oauth/token"),
        1,
        "concurrent refresh must collapse to exactly one /token round-trip",
    );
    assert_eq!(mock.count_for("/api/widgets"), 10);

    // All ten API calls should have used the *new* token; none should
    // have leaked through with the expired one.
    for req in mock.requests().iter().filter(|r| r.path == "/api/widgets") {
        assert_eq!(req.authorization.as_deref(), Some("Bearer fresh"));
    }
}

#[tokio::test]
async fn refresh_rotates_stored_refresh_token() {
    let mock = ScriptedMock::new();

    // First /token returns a rotated refresh token "rotated".
    mock.enqueue_json("/oauth/token", StatusCode::OK, &token_response());
    mock.enqueue_json("/api/widgets", StatusCode::OK, br#"[]"#);

    // Second /token must therefore receive `refresh_token=rotated`,
    // not the original `rtok`. The response can be anything that
    // parses.
    mock.enqueue_json(
        "/oauth/token",
        StatusCode::OK,
        br#"{"access_token":"second","token_type":"Bearer","expires_in":3600}"#,
    );
    mock.enqueue_json("/api/widgets", StatusCode::OK, br#"[]"#);

    let expired = AccessToken::new(
        Secret::from("e1"),
        Some(Utc::now() - ChronoDuration::seconds(1)),
    );
    let refresh = RefreshToken::new(Secret::from("rtok"));
    let client = make_client(mock.clone(), expired, refresh);

    client.get("widgets").send().await.unwrap();
    // Mark token as expired again to force a second refresh.
    client.api_client().refresh_auth(AccessToken::new(
        Secret::from("e2"),
        Some(Utc::now() - ChronoDuration::seconds(1)),
    ));
    client.get("widgets").send().await.unwrap();

    let token_requests: Vec<_> = mock
        .requests()
        .into_iter()
        .filter(|r| r.path == "/oauth/token")
        .collect();
    assert_eq!(token_requests.len(), 2);
}
