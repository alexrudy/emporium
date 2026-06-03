//! End-to-end webserver-style login round-trip.
//!
//! Exercises [`oath::AuthorizationUrl::begin`] →
//! session-store round-trip →
//! [`oath::PendingAuthorization::complete`] against a mocked token
//! endpoint, matching the flow described in the worked example in
//! `oath/PLAN.md`.

use api_client::mock::MockService;
use http::{HeaderMap, HeaderValue, StatusCode};
use oath::{
    AuthorizationUrl, CallbackError, PendingAuthorization, ScopeSet, StateToken, TokenEndpoint,
};
use secret::Secret;

fn json_body() -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    (
        StatusCode::OK,
        headers,
        br#"{"access_token":"final","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh"}"#
            .to_vec(),
    )
}

fn endpoint(mock: MockService) -> TokenEndpoint {
    TokenEndpoint::builder()
        .client_id("the-client")
        .client_secret(Secret::from("the-secret"))
        .auth_uri(
            "https://provider.example.com/oauth/authorize"
                .parse()
                .unwrap(),
        )
        .token_uri("https://provider.example.com/oauth/token".parse().unwrap())
        .redirect_uri("https://app.example.com/auth/callback".parse().unwrap())
        .transport(mock)
        .build()
        .unwrap()
}

#[tokio::test]
async fn end_to_end_login_round_trip() {
    let mut mock = MockService::new();
    let (status, headers, body) = json_body();
    mock.add("/oauth/token", status, headers, body);
    let endpoint = endpoint(mock);

    // /auth/login: pin the state so we can simulate the provider echoing it.
    let state = StateToken::generate();
    let echoed_state = state.revealed().to_owned();
    let scopes: ScopeSet = "openid profile email".parse().unwrap();
    let (url, pending) = AuthorizationUrl::new(&endpoint)
        .scopes(scopes)
        .with_state(state)
        .begin()
        .expect("authorization URL should build");

    // The URL must be on the provider's authorize endpoint and carry
    // every parameter the spec requires for a PKCE auth-code request.
    assert!(
        url.to_string()
            .starts_with("https://provider.example.com/oauth/authorize?")
    );
    let query = url.query().unwrap();
    assert!(query.contains("response_type=code"));
    assert!(query.contains("client_id=the-client"));
    assert!(query.contains("code_challenge_method=S256"));
    assert!(query.contains(&format!("state={echoed_state}")));

    // The webserver stashes `pending` in its pre-auth session store.
    let stashed = serde_json::to_string(&pending).expect("PendingAuthorization is serde-able");

    // ...user authenticates at the provider, gets redirected back...

    // /auth/callback: the webserver pulls `pending` out of the session.
    let pending: PendingAuthorization =
        serde_json::from_str(&stashed).expect("PendingAuthorization round-trips");
    let token_set = pending
        .complete(&endpoint, &echoed_state, "the-auth-code")
        .await
        .expect("complete should succeed");

    assert_eq!(token_set.access_token.revealed(), "final");
    assert!(token_set.access_token.expires_at().is_some());
    let refresh = token_set
        .refresh_token
        .expect("server returned a refresh_token");
    assert_eq!(refresh.revealed(), "refresh");
}

#[tokio::test]
async fn callback_with_wrong_state_short_circuits_before_exchange() {
    // No `mock.add` for "/oauth/token" — if `complete` tries to exchange,
    // the mock will panic, proving the state check happens *before* any
    // network call.
    let endpoint = endpoint(MockService::new());

    let (_url, pending) = AuthorizationUrl::new(&endpoint)
        .begin()
        .expect("authorization URL should build");

    let err = pending
        .complete(&endpoint, "definitely-not-the-state", "code")
        .await
        .expect_err("state mismatch should error");

    assert!(matches!(err, CallbackError::StateMismatch));
}

#[tokio::test]
async fn callback_propagates_token_endpoint_errors() {
    let mut mock = MockService::new();
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    mock.add(
        "/oauth/token",
        StatusCode::BAD_REQUEST,
        headers,
        br#"{"error":"invalid_grant","error_description":"stale code"}"#.to_vec(),
    );
    let endpoint = endpoint(mock);

    let state = StateToken::generate();
    let echoed = state.revealed().to_owned();
    let (_url, pending) = AuthorizationUrl::new(&endpoint)
        .with_state(state)
        .begin()
        .expect("authorization URL should build");

    let err = pending
        .complete(&endpoint, &echoed, "the-auth-code")
        .await
        .expect_err("invalid_grant should error");

    match err {
        CallbackError::Exchange(oath::Error::TokenError(resp)) => {
            assert_eq!(resp.code, oath::TokenErrorCode::InvalidGrant);
        }
        other => panic!("expected Exchange(TokenError), got {other:?}"),
    }
}
