//! Device-authorization grant integration tests (RFC 8628).

mod common;

use common::ScriptedMock;

use http::StatusCode;
use oath::TokenEndpoint;
use secret::Secret;

fn endpoint(mock: ScriptedMock) -> TokenEndpoint {
    TokenEndpoint::builder()
        .client_id("the-client")
        .client_secret(Secret::from("the-secret"))
        .token_uri("https://example.com/oauth/token".parse().unwrap())
        .device_uri(
            "https://example.com/oauth/device_authorization"
                .parse()
                .unwrap(),
        )
        .transport(mock)
        .build()
        .unwrap()
}

#[tokio::test(start_paused = true)]
async fn polling_handles_pending_slow_down_then_success() {
    let mock = ScriptedMock::new();

    // /device → DeviceAuthorizationResponse with a 1s interval.
    mock.enqueue_json(
        "/oauth/device_authorization",
        StatusCode::OK,
        br#"{
            "device_code": "dev-abc",
            "user_code": "WDJB-MJHT",
            "verification_uri": "https://example.com/device",
            "expires_in": 60,
            "interval": 1
        }"#,
    );

    // /token: three responses scripted in order:
    //   1. authorization_pending → keep polling
    //   2. slow_down → bump interval, keep polling
    //   3. success → return token
    mock.enqueue_json(
        "/oauth/token",
        StatusCode::BAD_REQUEST,
        br#"{"error":"authorization_pending"}"#,
    );
    mock.enqueue_json(
        "/oauth/token",
        StatusCode::BAD_REQUEST,
        br#"{"error":"slow_down"}"#,
    );
    mock.enqueue_json(
        "/oauth/token",
        StatusCode::OK,
        br#"{"access_token":"granted","token_type":"Bearer","expires_in":3600}"#,
    );

    let endpoint = endpoint(mock.clone());

    let auth = endpoint
        .start_device_flow(None)
        .await
        .expect("device authorization request should succeed");
    assert_eq!(auth.user_code, "WDJB-MJHT");
    assert_eq!(auth.interval, 1);

    let token = endpoint
        .poll_device_token(&auth)
        .await
        .expect("polling should eventually succeed");
    assert_eq!(token.access_token.revealed(), "granted");

    // Three /token polls total: pending, slow_down, success.
    assert_eq!(mock.count_for("/oauth/token"), 3);
}

#[tokio::test(start_paused = true)]
async fn polling_propagates_access_denied() {
    let mock = ScriptedMock::new();
    mock.enqueue_json(
        "/oauth/device_authorization",
        StatusCode::OK,
        br#"{
            "device_code": "dev-abc",
            "user_code": "WDJB-MJHT",
            "verification_uri": "https://example.com/device",
            "expires_in": 60,
            "interval": 1
        }"#,
    );
    mock.enqueue_json(
        "/oauth/token",
        StatusCode::BAD_REQUEST,
        br#"{"error":"access_denied"}"#,
    );

    let endpoint = endpoint(mock);
    let auth = endpoint.start_device_flow(None).await.unwrap();

    let err = endpoint
        .poll_device_token(&auth)
        .await
        .expect_err("access_denied should surface");

    match err {
        oath::Error::TokenError(resp) => {
            assert_eq!(
                resp.code,
                oath::TokenErrorCode::Other("access_denied".into()),
            );
        }
        other => panic!("expected TokenError, got {other:?}"),
    }
}

#[tokio::test]
async fn missing_device_uri_errors() {
    let endpoint = TokenEndpoint::builder()
        .client_id("c")
        .token_uri("https://example.com/oauth/token".parse().unwrap())
        .transport(ScriptedMock::new())
        .build()
        .unwrap();

    let err = endpoint.start_device_flow(None).await.unwrap_err();
    assert!(matches!(err, oath::Error::MissingDeviceUri));
}
