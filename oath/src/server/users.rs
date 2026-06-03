//! User-store abstraction for the `server` feature.

use serde::{Serialize, de::DeserializeOwned};

/// Storage abstraction for persisted user records.
///
/// One concrete implementation ships with the crate
/// ([`crate::server::JsonFileUserStore`]). Apps with their own user
/// database implement this trait against their existing types.
#[async_trait::async_trait]
pub trait UserStore: Send + Sync + 'static {
    /// The user payload type. Serialized to / from the backing store.
    type Data: Serialize + DeserializeOwned + Send + Sync + 'static;
    /// The error type produced by store operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Load the record for `username`. Returns `None` if absent.
    async fn get(&self, username: &str) -> Result<Option<Self::Data>, Self::Error>;

    /// Insert or replace the record for `username`.
    async fn put(&self, username: &str, data: &Self::Data) -> Result<(), Self::Error>;
}
