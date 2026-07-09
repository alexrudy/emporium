//! Blob operations for the registry

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use bytes::Bytes;
use serde::Deserialize;
use uuid::Uuid;

use crate::Repository;
use crate::error::{RegistryError, RegistryResult};
use crate::storage::RegistryStorage;

/// Router for blob operations
pub fn router() -> Router<RegistryStorage> {
    use axum::routing::put;

    Router::new()
        .route(
            "/v2/{name}/blobs/{digest}",
            get(get_blob).head(head_blob).delete(delete_blob),
        )
        .route(
            "/v2/{org}/{name}/blobs/{digest}",
            get(get_blob).head(head_blob).delete(delete_blob),
        )
        .route("/v2/{name}/blobs/uploads/", post(start_blob_upload))
        .route("/v2/{org}/{name}/blobs/uploads/", post(start_blob_upload))
        .route(
            "/v2/{name}/blobs/uploads/{uuid}",
            put(complete_blob_upload).delete(cancel_blob_upload),
        )
        .route(
            "/v2/{org}/{name}/blobs/uploads/{uuid}",
            put(complete_blob_upload).delete(cancel_blob_upload),
        )
}

#[derive(Debug, Deserialize)]
struct BlobPath {
    #[serde(flatten)]
    repo: Repository,
    digest: String,
}

/// Get a blob
async fn get_blob(
    State(storage): State<RegistryStorage>,
    Path(BlobPath { repo, digest }): Path<BlobPath>,
) -> RegistryResult<Response> {
    repo.validate()?;
    validate_digest(&digest)?;

    let data = storage.get_blob(&digest).await?;

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/octet-stream")],
        data,
    )
        .into_response())
}

/// Check if a blob exists
async fn head_blob(
    State(storage): State<RegistryStorage>,
    Path(BlobPath { repo, digest }): Path<BlobPath>,
) -> RegistryResult<Response> {
    repo.validate()?;
    validate_digest(&digest)?;

    if storage.blob_exists(&digest).await? {
        Ok((
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/octet-stream")],
        )
            .into_response())
    } else {
        Err(RegistryError::BlobNotFound(digest))
    }
}

/// Delete a blob
async fn delete_blob(
    State(storage): State<RegistryStorage>,
    Path(BlobPath { repo, digest }): Path<BlobPath>,
) -> RegistryResult<StatusCode> {
    repo.validate()?;
    validate_digest(&digest)?;

    storage.delete_blob(&digest).await?;
    Ok(StatusCode::ACCEPTED)
}

/// Start a blob upload session
async fn start_blob_upload(Path(repo): Path<Repository>) -> RegistryResult<Response> {
    let fullname = repo.validate()?;
    // Generate a UUID for the upload session
    let session_id = Uuid::new_v4();
    let location = format!("/v2/{}/blobs/uploads/{}", fullname, session_id);

    Ok((
        StatusCode::ACCEPTED,
        [
            (header::LOCATION, location),
            (header::RANGE, "0-0".to_string()),
        ],
    )
        .into_response())
}

#[derive(Debug, Deserialize)]
struct BlobUploadComplete {
    #[serde(flatten)]
    repo: Repository,

    #[expect(dead_code)]
    uuid: Uuid,
}

/// Complete a blob upload
async fn complete_blob_upload(
    State(storage): State<RegistryStorage>,
    Path(BlobUploadComplete { repo, .. }): Path<BlobUploadComplete>,
    headers: HeaderMap,
    body: Bytes,
) -> RegistryResult<Response> {
    let fullname = repo.validate()?;

    // Get the digest from query parameter or header
    let digest = headers
        .get("digest")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| RegistryError::BlobUploadInvalid("missing digest".to_string()))?;

    validate_digest(digest)?;

    // Store the blob
    storage.put_blob(digest, &body).await?;

    let location = format!("/v2/{}/blobs/{}", fullname, digest);

    Ok((
        StatusCode::CREATED,
        [
            (header::LOCATION, location),
            (header::CONTENT_LENGTH, "0".to_string()),
        ],
    )
        .into_response())
}

/// Cancel a blob upload
async fn cancel_blob_upload(
    Path(BlobUploadComplete { repo, .. }): Path<BlobUploadComplete>,
) -> RegistryResult<StatusCode> {
    repo.validate()?;
    Ok(StatusCode::NO_CONTENT)
}

/// Validate digest format
fn validate_digest(digest: &str) -> RegistryResult<()> {
    if !digest.contains(':') {
        return Err(RegistryError::InvalidDigest(digest.to_string()));
    }

    let parts: Vec<&str> = digest.splitn(2, ':').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        return Err(RegistryError::InvalidDigest(digest.to_string()));
    }

    Ok(())
}
