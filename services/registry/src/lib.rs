//! # OCI Container Registry
//!
//! This module implements an OCI-compliant container registry server following
//! the [OCI Distribution Specification](https://github.com/opencontainers/distribution-spec).
//!
//! ## Features
//!
//! - Full OCI registry API support
//! - Blob storage and retrieval
//! - Manifest operations (upload, download, delete)
//! - Pluggable storage backend via the `storage` crate
//! - Builder pattern for configuration
//!
//! ## Example
//!
//! ```no_run
//! use registry::RegistryBuilder;
//! use storage::MemoryStorage;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let storage = MemoryStorage::with_buckets(&["registry"]);
//! let registry = RegistryBuilder::new()
//!     .storage(storage.into())
//!     .bucket("registry")
//!     .build();
//!
//! // Use the registry service with axum or any tower-compatible server
//! # Ok(())
//! # }
//! ```

mod api;
mod blob;
mod error;
mod manifest;
mod storage;

pub use ::axum::Router;
pub use api::RegistryBuilder;
pub use error::{RegistryError, RegistryResult};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Repository {
    #[serde(default)]
    pub org: Option<String>,
    pub name: String,
}

impl Repository {
    pub fn validate(&self) -> RegistryResult<String> {
        let full_name = if let Some(org) = &self.org {
            format!("{}/{}", org, self.name)
        } else {
            self.name.clone()
        };

        if self.name.is_empty() || self.name.contains("/") || self.name.contains("..") {
            return Err(RegistryError::InvalidRepository(full_name));
        }
        if let Some(org) = &self.org
            && (org.contains("/") || org.contains(".."))
        {
            return Err(RegistryError::InvalidRepository(full_name));
        }

        Ok(full_name)
    }
}
