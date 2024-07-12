//! Access to B2 using separate credentials per bucket.
//!
//! B2 doesn't allow keys to access multiple specific buckets, they either access
//! all buckets, or just a single bucket.

use std::collections::HashMap;
use std::sync::Arc;

use camino::Utf8Path;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use eyre::Context;
use serde::Deserialize;

use storage_driver::StorageError;
use storage_driver::{Driver, Metadata, Reader, Writer};

use crate::application::AuthenticationError;
use crate::application::AuthenticationErrorKind;
use crate::application::B2ApplicationKey;
use crate::client::B2Client;

use super::B2_STORAGE_NAME;
use super::B2_STORAGE_SCHEME;

/// Implements a client-per-bucket caching scheme.
#[derive(Debug, Clone)]
enum B2BucketStatus {
    Authorized(B2Client),
    Key(B2ApplicationKey),
}

/// Configuration for a multi-client which uses a separate key per bucket.
#[derive(Debug, Clone, Deserialize)]
pub struct B2MultiConfig {
    /// Map of bucket names to application keys.
    #[serde(flatten)]
    pub buckets: HashMap<Box<str>, B2ApplicationKey>,
}

impl B2MultiConfig {
    /// Create a new multi-client from a configuration.
    pub fn client(self) -> B2MultiClient {
        if self.buckets.is_empty() {
            tracing::warn!("No buckets configured for B2 client");
        }
        B2MultiClient::new(self.buckets)
    }
}

/// API Client for accessing B2 with a separate key per bucket
///
/// B2 doesn't allow keys to access multiple specific buckets, they either access
/// all buckets, or just a single bucket. This client is really a meta-client
/// which supports access to many buckets, each with their own key. Clients
/// are created on-demand, and then used to access B2 APIs. The underlying transport
/// usese Reqwest, and is shared among all clients.
#[derive(Debug, Clone)]
pub struct B2MultiClient {
    client: hyperdriver::client::SharedClientService<hyperdriver::Body>,
    buckets: Arc<DashMap<Box<str>, B2BucketStatus>>,
}

impl B2MultiClient {
    /// Create a new multiclient, by providing a configuration map.
    ///
    /// The map should map bucket names to application keys. This client will then implement
    /// the `Driver` trait, and can be used to access B2 across multiple keys. Authorization
    /// and re-authentication will be handled transparently.
    pub fn new(buckets: HashMap<Box<str>, B2ApplicationKey>) -> Self {
        B2MultiClient {
            client: hyperdriver::Client::build_tcp_http().build_service(),
            buckets: Arc::new(
                buckets
                    .into_iter()
                    .map(|(b, k)| (b, B2BucketStatus::Key(k)))
                    .collect(),
            ),
        }
    }

    /// Get a client for a given bucket.
    async fn get_bucket_client(&self, bucket: &str) -> Result<B2Client, AuthenticationError> {
        let bucket: Box<str> = bucket.into();
        match &mut self.buckets.entry(bucket.clone()) {
            Entry::Occupied(entry) => match entry.get() {
                B2BucketStatus::Authorized(client) => Ok(client.clone()),
                B2BucketStatus::Key(key) => {
                    let client = B2Client::from_client_and_authorization(
                        self.client.clone(),
                        key.fetch_authorization(&mut self.client.clone()).await?,
                        key.clone(),
                    );

                    *entry.get_mut() = B2BucketStatus::Authorized(client.clone());
                    Ok(client)
                }
            },
            Entry::Vacant(_) => {
                Err(AuthenticationErrorKind::UnauthorizedBucket(bucket.clone()).into())
            }
        }
    }
}

#[async_trait::async_trait]
impl Driver for B2MultiClient {
    fn name(&self) -> &'static str {
        B2_STORAGE_NAME
    }

    fn scheme(&self) -> &str {
        B2_STORAGE_SCHEME
    }

    async fn metadata(&self, bucket: &str, remote: &Utf8Path) -> Result<Metadata, StorageError> {
        let client = self
            .get_bucket_client(bucket)
            .await
            .context("authorize bucket key")
            .map_err(StorageError::with(self::B2_STORAGE_NAME))?;
        client.metadata(bucket, remote).await
    }

    async fn delete(&self, bucket: &str, remote: &Utf8Path) -> Result<(), StorageError> {
        let client = self
            .get_bucket_client(bucket)
            .await
            .context("authorize bucket key")
            .map_err(StorageError::with(self::B2_STORAGE_NAME))?;
        client.delete(bucket, remote).await
    }

    async fn upload(
        &self,
        bucket: &str,
        remote: &Utf8Path,
        local: &mut Reader<'_>,
    ) -> Result<(), StorageError> {
        let client = self
            .get_bucket_client(bucket)
            .await
            .context("authorize bucket key")
            .map_err(StorageError::with(self::B2_STORAGE_NAME))?;
        client.upload(bucket, remote, local).await
    }

    async fn download(
        &self,
        bucket: &str,
        remote: &Utf8Path,
        local: &mut Writer<'_>,
    ) -> Result<(), StorageError> {
        let client = self
            .get_bucket_client(bucket)
            .await
            .context("authorize bucket key")
            .map_err(StorageError::with(self::B2_STORAGE_NAME))?;
        client.download(bucket, remote, local).await
    }

    async fn list(
        &self,
        bucket: &str,
        prefix: Option<&Utf8Path>,
    ) -> Result<Vec<String>, StorageError> {
        let client = self
            .get_bucket_client(bucket)
            .await
            .context("authorize bucket key")
            .map_err(StorageError::with(self::B2_STORAGE_NAME))?;
        client.list(bucket, prefix).await
    }
}
