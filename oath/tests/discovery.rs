//! End-to-end test: fetch a `.well-known` metadata document and use
//! it to populate a `TokenEndpoint`.

mod common;

use common::ScriptedMock;
use http::{HeaderMap, HeaderValue, StatusCode};
use oath::{ClientCredentialsRequest, ProviderMetadata, TokenEndpoint};
use secret::Secret;

fn json_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers
}

const METADATA_BODY: &str = r#"{
    "issuer": "https://example.com",
    "authorization_endpoint": "https://example.com/oauth/authorize",
    "token_endpoint": "https://example.com/oauth/token",
    "device_authorization_endpoint": "https://example.com/oauth/device",
    "userinfo_endpoint": "https://example.com/oauth/userinfo",
    "jwks_uri": "https://example.com/.well-known/jwks.json",
    "response_types_supported": ["code"],
    "code_challenge_methods_supported": ["S256"]
}"#;

#[tokio::test]
async fn fetches_and_parses_well_known_document() {
    let mock = ScriptedMock::new();
    mock.enqueue(
        "/.well-known/openid-configuration",
        StatusCode::OK,
        json_headers(),
        METADATA_BODY.as_bytes().to_vec(),
    );

    let url: http::Uri = "https://example.com/.well-known/openid-configuration"
        .parse()
        .unwrap();
    let metadata = ProviderMetadata::fetch_with_transport(url, mock.clone())
        .await
        .expect("fetch succeeds");

    assert_eq!(metadata.issuer, "https://example.com");
    assert_eq!(
        metadata.token_uri().unwrap().to_string(),
        "https://example.com/oauth/token",
    );
    assert_eq!(
        metadata
            .device_authorization_uri()
            .unwrap()
            .unwrap()
            .to_string(),
        "https://example.com/oauth/device",
    );
    assert_eq!(mock.count_for("/.well-known/openid-configuration"), 1);
}

#[tokio::test]
async fn builder_populates_endpoints_from_metadata() {
    let mock = ScriptedMock::new();
    mock.enqueue(
        "/.well-known/openid-configuration",
        StatusCode::OK,
        json_headers(),
        METADATA_BODY.as_bytes().to_vec(),
    );
    // The token endpoint we'll hit *after* building.
    mock.enqueue(
        "/oauth/token",
        StatusCode::OK,
        json_headers(),
        br#"{"access_token":"atok","token_type":"Bearer","expires_in":3600}"#.to_vec(),
    );

    let url: http::Uri = "https://example.com/.well-known/openid-configuration"
        .parse()
        .unwrap();
    let metadata = ProviderMetadata::fetch_with_transport(url, mock.clone())
        .await
        .unwrap();

    let endpoint = TokenEndpoint::builder()
        .from_metadata(&metadata)
        .expect("builder populates from metadata")
        .client_id("the-client")
        .client_secret(Secret::from("the-secret"))
        .transport(mock.clone())
        .build()
        .expect("builder yields TokenEndpoint");

    assert_eq!(
        endpoint.token_uri().to_string(),
        "https://example.com/oauth/token",
    );
    assert_eq!(
        endpoint.auth_uri().unwrap().to_string(),
        "https://example.com/oauth/authorize",
    );
    assert_eq!(
        endpoint.device_uri().unwrap().to_string(),
        "https://example.com/oauth/device",
    );

    // Sanity: exchange against the discovered token endpoint works.
    let response = endpoint
        .exchange(ClientCredentialsRequest::new())
        .await
        .expect("exchange against discovered token endpoint");
    assert_eq!(response.access_token.revealed(), "atok");

    // The mock saw exactly one /.well-known fetch and one /oauth/token call.
    assert_eq!(mock.count_for("/.well-known/openid-configuration"), 1);
    assert_eq!(mock.count_for("/oauth/token"), 1);
}

#[tokio::test]
async fn fetch_propagates_4xx_as_bad_response() {
    let mock = ScriptedMock::new();
    mock.enqueue(
        "/.well-known/openid-configuration",
        StatusCode::NOT_FOUND,
        json_headers(),
        br#"{"error":"not found"}"#.to_vec(),
    );

    let url: http::Uri = "https://example.com/.well-known/openid-configuration"
        .parse()
        .unwrap();
    let err = ProviderMetadata::fetch_with_transport(url, mock)
        .await
        .expect_err("404 is propagated");

    match err {
        oath::Error::BadResponse { status, .. } => assert_eq!(status, StatusCode::NOT_FOUND),
        other => panic!("expected BadResponse, got {other:?}"),
    }
}
