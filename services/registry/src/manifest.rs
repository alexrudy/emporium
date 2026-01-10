//! Manifest operations for the registry

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use bytes::Bytes;
use sha2::Digest;

use crate::error::{RegistryError, RegistryResult};
use crate::storage::RegistryStorage;

/// Router for manifest operations
pub fn router() -> Router<RegistryStorage> {
    Router::new()
        .route(
            "/v2/:name/manifests/:reference",
            get(get_manifest)
                .head(head_manifest)
                .put(put_manifest)
                .delete(delete_manifest),
        )
        .route("/v2/:name/tags/list", get(list_tags))
}

/// Get a manifest
async fn get_manifest(
    State(storage): State<RegistryStorage>,
    Path((name, reference)): Path<(String, String)>,
) -> RegistryResult<Response> {
    validate_repository(&name)?;

    let data = storage.get_manifest(&name, &reference).await?;

    // Detect manifest type from content
    let content_type = detect_manifest_type(&data);

    // Calculate digest for Docker-Content-Digest header
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&data)));

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type),
            (
                header::HeaderName::from_static("docker-content-digest"),
                digest,
            ),
        ],
        data,
    )
        .into_response())
}

/// Check if a manifest exists
async fn head_manifest(
    State(storage): State<RegistryStorage>,
    Path((name, reference)): Path<(String, String)>,
) -> RegistryResult<Response> {
    validate_repository(&name)?;

    let data = storage.get_manifest(&name, &reference).await?;
    let content_type = detect_manifest_type(&data);
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&data)));

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type),
            (
                header::HeaderName::from_static("docker-content-digest"),
                digest,
            ),
            (header::CONTENT_LENGTH, data.len().to_string()),
        ],
    )
        .into_response())
}

/// Put a manifest
async fn put_manifest(
    State(storage): State<RegistryStorage>,
    Path((name, reference)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> RegistryResult<Response> {
    validate_repository(&name)?;

    // Get content type
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/vnd.docker.distribution.manifest.v2+json");

    // Validate manifest type
    validate_manifest_type(content_type)?;

    // Store the manifest
    let digest = storage.put_manifest(&name, &reference, &body).await?;

    let location = format!("/v2/{}/manifests/{}", name, digest);

    Ok((
        StatusCode::CREATED,
        [
            (header::LOCATION, location),
            (
                header::HeaderName::from_static("docker-content-digest"),
                digest,
            ),
        ],
    )
        .into_response())
}

/// Delete a manifest
async fn delete_manifest(
    State(storage): State<RegistryStorage>,
    Path((name, reference)): Path<(String, String)>,
) -> RegistryResult<StatusCode> {
    validate_repository(&name)?;

    storage.delete_manifest(&name, &reference).await?;
    Ok(StatusCode::ACCEPTED)
}

/// List tags for a repository
async fn list_tags(
    State(storage): State<RegistryStorage>,
    Path(name): Path<String>,
) -> RegistryResult<Json<TagList>> {
    validate_repository(&name)?;

    let tags = storage.list_tags(&name).await?;

    Ok(Json(TagList { name, tags }))
}

/// Tag list response
#[derive(Debug, serde::Serialize)]
struct TagList {
    name: String,
    tags: Vec<String>,
}

/// Validate repository name
fn validate_repository(name: &str) -> RegistryResult<()> {
    if name.is_empty() || name.contains("..") {
        return Err(RegistryError::InvalidRepository(name.to_string()));
    }
    Ok(())
}

/// Detect manifest type from content
fn detect_manifest_type(data: &[u8]) -> String {
    // Try to parse as JSON and detect the schemaVersion or mediaType
    if let Ok(json) = serde_json::from_slice::<serde_json::Value>(data) {
        if let Some(media_type) = json.get("mediaType").and_then(|v| v.as_str()) {
            return media_type.to_string();
        }

        if let Some(schema_version) = json.get("schemaVersion").and_then(|v| v.as_u64()) {
            return match schema_version {
                1 => "application/vnd.docker.distribution.manifest.v1+json".to_string(),
                2 => {
                    // Check if it's a manifest list
                    if json.get("manifests").is_some() {
                        "application/vnd.docker.distribution.manifest.list.v2+json".to_string()
                    } else {
                        "application/vnd.docker.distribution.manifest.v2+json".to_string()
                    }
                }
                _ => "application/vnd.oci.image.manifest.v1+json".to_string(),
            };
        }
    }

    // Default to OCI manifest
    "application/vnd.oci.image.manifest.v1+json".to_string()
}

/// Validate manifest type
fn validate_manifest_type(content_type: &str) -> RegistryResult<()> {
    match content_type {
        "application/vnd.docker.distribution.manifest.v1+json"
        | "application/vnd.docker.distribution.manifest.v1+prettyjws"
        | "application/vnd.docker.distribution.manifest.v2+json"
        | "application/vnd.docker.distribution.manifest.list.v2+json"
        | "application/vnd.oci.image.manifest.v1+json"
        | "application/vnd.oci.image.index.v1+json" => Ok(()),
        _ => Err(RegistryError::UnsupportedManifestType(
            content_type.to_string(),
        )),
    }
}
