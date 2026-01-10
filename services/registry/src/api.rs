//! API server builder and router

use axum::Router;
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::get;
use serde_json::json;

use crate::storage::RegistryStorage;

/// Registry builder for configuring and creating the OCI registry service
#[derive(Debug)]
pub struct RegistryBuilder {
    storage: Option<storage::Storage>,
    bucket: Option<String>,
}

impl Default for RegistryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl RegistryBuilder {
    /// Create a new registry builder
    pub fn new() -> Self {
        Self {
            storage: None,
            bucket: None,
        }
    }

    /// Set the storage backend
    pub fn storage(mut self, storage: storage::Storage) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Set the bucket name for storage
    pub fn bucket(mut self, bucket: impl Into<String>) -> Self {
        self.bucket = Some(bucket.into());
        self
    }

    /// Build the registry service
    ///
    /// Returns a Router that can be served with any tower-compatible server
    pub fn build(self) -> Router {
        let storage = self.storage.expect("storage backend must be configured");
        let bucket = self.bucket.unwrap_or_else(|| "registry".to_string());

        let registry_storage = RegistryStorage::new(storage, bucket);

        // Build the router
        Router::new()
            .route("/v2/", get(api_version_check))
            .merge(crate::blob::router())
            .merge(crate::manifest::router())
            .with_state(registry_storage)
    }
}

/// API version check endpoint
///
/// Returns 200 OK to indicate the registry is available
async fn api_version_check() -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::OK, Json(json!({})))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder() {
        let storage = storage::MemoryStorage::with_buckets(&["test"]);
        let _registry = RegistryBuilder::new()
            .storage(storage.into())
            .bucket("test")
            .build();
    }
}
