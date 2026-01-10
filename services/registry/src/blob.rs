//! Blob operations for the registry

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use bytes::Bytes;

use crate::error::{RegistryError, RegistryResult};
use crate::storage::RegistryStorage;

/// Router for blob operations
pub fn router() -> Router<RegistryStorage> {
    use axum::routing::put;

    Router::new()
        .route(
            "/v2/:name/blobs/:digest",
            get(get_blob).head(head_blob).delete(delete_blob),
        )
        .route("/v2/:name/blobs/uploads/", post(start_blob_upload))
        .route(
            "/v2/:name/blobs/uploads/:uuid",
            put(complete_blob_upload).delete(cancel_blob_upload),
        )
}

/// Get a blob
async fn get_blob(
    State(storage): State<RegistryStorage>,
    Path((name, digest)): Path<(String, String)>,
) -> RegistryResult<Response> {
    validate_repository(&name)?;
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
    Path((name, digest)): Path<(String, String)>,
) -> RegistryResult<Response> {
    validate_repository(&name)?;
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
    Path((name, digest)): Path<(String, String)>,
) -> RegistryResult<StatusCode> {
    validate_repository(&name)?;
    validate_digest(&digest)?;

    storage.delete_blob(&digest).await?;
    Ok(StatusCode::ACCEPTED)
}

/// Start a blob upload session
async fn start_blob_upload(Path(name): Path<String>) -> RegistryResult<Response> {
    validate_repository(&name)?;

    // Generate a UUID for the upload session
    let uuid = uuid::Uuid::new_v4().to_string();
    let location = format!("/v2/{}/blobs/uploads/{}", name, uuid);

    Ok((
        StatusCode::ACCEPTED,
        [
            (header::LOCATION, location),
            (header::RANGE, "0-0".to_string()),
        ],
    )
        .into_response())
}

/// Complete a blob upload
async fn complete_blob_upload(
    State(storage): State<RegistryStorage>,
    Path((name, _uuid)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> RegistryResult<Response> {
    validate_repository(&name)?;

    // Get the digest from query parameter or header
    let digest = headers
        .get("digest")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| RegistryError::BlobUploadInvalid("missing digest".to_string()))?;

    validate_digest(digest)?;

    // Store the blob
    storage.put_blob(digest, &body).await?;

    let location = format!("/v2/{}/blobs/{}", name, digest);

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
    Path((name, _uuid)): Path<(String, String)>,
) -> RegistryResult<StatusCode> {
    validate_repository(&name)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Validate repository name
fn validate_repository(name: &str) -> RegistryResult<()> {
    if name.is_empty() || name.contains("..") {
        return Err(RegistryError::InvalidRepository(name.to_string()));
    }
    Ok(())
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

/// UUID type for blob uploads (simplified)
mod uuid {
    pub struct Uuid;

    impl Uuid {
        pub fn new_v4() -> Self {
            Self
        }

        pub fn to_string(&self) -> String {
            // Simple UUID generation using random hex
            use sha2::{Digest, Sha256};
            let random_data = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
                .to_string();
            let hash = Sha256::digest(random_data.as_bytes());
            format!("{:x}", hash)
        }
    }
}
