//! Integration tests for the OCI registry

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use bytes::Bytes;
use registry::RegistryBuilder;
use sha2::{Digest, Sha256};
use storage::MemoryStorage;
use tower::ServiceExt;

/// Helper to create a test registry
fn test_registry() -> axum::Router {
    let storage = MemoryStorage::with_buckets(&["test-registry"]);
    RegistryBuilder::new()
        .storage(storage.into())
        .bucket("test-registry")
        .build()
}

#[tokio::test]
async fn test_api_version_check() {
    let app = test_registry();

    let response = app
        .oneshot(Request::builder().uri("/v2/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_blob_upload_and_download() {
    let app = test_registry();

    // Test data
    let data = b"Hello, OCI Registry!";
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(data)));

    // Start blob upload
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v2/test-repo/blobs/uploads/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let location = response.headers().get(header::LOCATION).unwrap();
    let upload_url = location.to_str().unwrap();

    // Complete blob upload
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("{}?digest={}", upload_url, digest))
                .header("digest", &digest)
                .body(Body::from(Bytes::from_static(data)))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    // Download blob
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v2/test-repo/blobs/{}", digest))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&body[..], data);
}

#[tokio::test]
async fn test_blob_head() {
    let app = test_registry();

    // Upload a blob first
    let data = b"test blob data";
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(data)));

    // Start and complete upload
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v2/test-repo/blobs/uploads/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let location = response.headers().get(header::LOCATION).unwrap();
    let upload_url = location.to_str().unwrap();

    let _response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("{}?digest={}", upload_url, digest))
                .header("digest", &digest)
                .body(Body::from(Bytes::from_static(data)))
                .unwrap(),
        )
        .await
        .unwrap();

    // Check blob exists with HEAD
    let response = app
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri(format!("/v2/test-repo/blobs/{}", digest))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_manifest_upload_and_download() {
    let app = test_registry();

    // Create a simple manifest
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 1234,
            "digest": "sha256:1234567890abcdef"
        },
        "layers": []
    });

    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();

    // Upload manifest
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v2/test-repo/manifests/latest")
                .header(
                    header::CONTENT_TYPE,
                    "application/vnd.docker.distribution.manifest.v2+json",
                )
                .body(Body::from(manifest_bytes.clone()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let digest = response
        .headers()
        .get("docker-content-digest")
        .unwrap()
        .to_str()
        .unwrap();

    // Download manifest by tag
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v2/test-repo/manifests/latest")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&body[..], &manifest_bytes[..]);

    // Download manifest by digest
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v2/test-repo/manifests/{}", digest))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&body[..], &manifest_bytes[..]);
}

#[tokio::test]
async fn test_list_tags() {
    let app = test_registry();

    // Upload manifests with different tags
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 1234,
            "digest": "sha256:1234567890abcdef"
        },
        "layers": []
    });

    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();

    for tag in &["v1.0", "v1.1", "latest"] {
        let _response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/v2/test-repo/manifests/{}", tag))
                    .header(
                        header::CONTENT_TYPE,
                        "application/vnd.docker.distribution.manifest.v2+json",
                    )
                    .body(Body::from(manifest_bytes.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    // List tags
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v2/test-repo/tags/list")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let tag_list: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(tag_list["name"], "test-repo");
    let tags = tag_list["tags"].as_array().unwrap();
    assert_eq!(tags.len(), 3);
}

#[tokio::test]
async fn test_blob_not_found() {
    let app = test_registry();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v2/test-repo/blobs/sha256:nonexistent")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_manifest_not_found() {
    let app = test_registry();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v2/test-repo/manifests/nonexistent")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_invalid_digest() {
    let app = test_registry();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v2/test-repo/blobs/invalid-digest")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
