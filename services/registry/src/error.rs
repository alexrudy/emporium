//! Error types for the registry

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Result type for registry operations
pub type RegistryResult<T> = Result<T, RegistryError>;

/// Error types for registry operations
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// Blob not found
    #[error("blob not found: {0}")]
    BlobNotFound(String),

    /// Manifest not found
    #[error("manifest not found: {0}")]
    ManifestNotFound(String),

    /// Invalid digest format
    #[error("invalid digest: {0}")]
    InvalidDigest(String),

    /// Storage error
    #[error("storage error: {0}")]
    Storage(#[from] storage::StorageError),

    /// Invalid manifest
    #[error("invalid manifest: {0}")]
    InvalidManifest(String),

    /// Unsupported manifest media type
    #[error("unsupported manifest type: {0}")]
    UnsupportedManifestType(String),

    /// Digest mismatch
    #[error("digest mismatch: expected {expected}, got {actual}")]
    DigestMismatch {
        /// Expected digest
        expected: String,
        /// Actual digest
        actual: String,
    },

    /// Invalid repository name
    #[error("invalid repository name: {0}")]
    InvalidRepository(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Range not satisfiable
    #[error("range not satisfiable")]
    RangeNotSatisfiable,

    /// Blob upload invalid
    #[error("blob upload invalid: {0}")]
    BlobUploadInvalid(String),
}

impl RegistryError {
    /// Get the HTTP status code for this error
    pub fn status_code(&self) -> StatusCode {
        match self {
            RegistryError::BlobNotFound(_) | RegistryError::ManifestNotFound(_) => {
                StatusCode::NOT_FOUND
            }
            RegistryError::InvalidDigest(_)
            | RegistryError::InvalidManifest(_)
            | RegistryError::InvalidRepository(_)
            | RegistryError::DigestMismatch { .. }
            | RegistryError::BlobUploadInvalid(_) => StatusCode::BAD_REQUEST,
            RegistryError::UnsupportedManifestType(_) => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            RegistryError::RangeNotSatisfiable => StatusCode::RANGE_NOT_SATISFIABLE,
            RegistryError::Storage(_) | RegistryError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Get the error code for OCI error responses
    pub fn error_code(&self) -> &'static str {
        match self {
            RegistryError::BlobNotFound(_) => "BLOB_UNKNOWN",
            RegistryError::ManifestNotFound(_) => "MANIFEST_UNKNOWN",
            RegistryError::InvalidDigest(_) => "DIGEST_INVALID",
            RegistryError::InvalidManifest(_) => "MANIFEST_INVALID",
            RegistryError::UnsupportedManifestType(_) => "MANIFEST_INVALID",
            RegistryError::DigestMismatch { .. } => "DIGEST_INVALID",
            RegistryError::InvalidRepository(_) => "NAME_INVALID",
            RegistryError::RangeNotSatisfiable => "BLOB_UNKNOWN",
            RegistryError::BlobUploadInvalid(_) => "BLOB_UPLOAD_INVALID",
            RegistryError::Storage(_) | RegistryError::Io(_) => "UNKNOWN",
        }
    }
}

/// OCI error response format
#[derive(Debug, serde::Serialize)]
struct ErrorResponse {
    errors: Vec<ErrorDetail>,
}

#[derive(Debug, serde::Serialize)]
struct ErrorDetail {
    code: &'static str,
    message: String,
}

impl IntoResponse for RegistryError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let code = self.error_code();
        let message = self.to_string();

        let body = ErrorResponse {
            errors: vec![ErrorDetail { code, message }],
        };

        (status, axum::Json(body)).into_response()
    }
}
