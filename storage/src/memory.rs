use std::collections::HashMap;

use camino::{Utf8Path, Utf8PathBuf};
use chrono::{DateTime, Utc};
use eyre::{eyre, Context};
use tokio::{io::AsyncWriteExt, sync::RwLock};

use storage_driver::{Driver, Metadata, Reader, StorageError, Writer};

#[derive(Debug)]
struct MemoryFileItem {
    created: DateTime<Utc>,
    data: Vec<u8>,
}

impl AsRef<[u8]> for MemoryFileItem {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl From<Vec<u8>> for MemoryFileItem {
    fn from(data: Vec<u8>) -> Self {
        Self {
            created: Utc::now(),
            data,
        }
    }
}

impl From<&MemoryFileItem> for Metadata {
    fn from(value: &MemoryFileItem) -> Self {
        Self {
            created: value.created,
            size: value.data.len() as u64,
        }
    }
}

/// Storage driver that stores files in memory.
#[derive(Debug, Default)]
pub struct MemoryStorage {
    buckets: RwLock<HashMap<String, HashMap<Utf8PathBuf, MemoryFileItem>>>,
}

impl MemoryStorage {
    /// Create a new `MemoryStorage` instance, with no buckets.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new `MemoryStorage` instance, with the given buckets.
    pub fn with_buckets(buckets: &[&str]) -> Self {
        let mut map = HashMap::new();
        for bucket in buckets {
            map.insert(bucket.to_string(), HashMap::new());
        }

        Self {
            buckets: RwLock::new(map),
        }
    }

    /// Create a new bucket in the storage.
    pub async fn create_bucket(&self, bucket: String) {
        let mut buckets = self.buckets.write().await;
        buckets.insert(bucket, HashMap::new());
    }
}

#[async_trait::async_trait]
impl Driver for MemoryStorage {
    fn name(&self) -> &'static str {
        "memory"
    }

    fn scheme(&self) -> &str {
        "memory"
    }

    async fn metadata(&self, bucket: &str, remote: &Utf8Path) -> Result<Metadata, StorageError> {
        let buckets = self.buckets.read().await;
        let bucket = buckets
            .get(bucket)
            .ok_or(eyre!("Bucket Not found: {bucket}"))
            .map_err(|err| StorageError::new(self.name(), err))?;
        Ok(bucket
            .get(remote)
            .ok_or(eyre!("Path Not found: {remote}"))
            .map_err(|err| StorageError::new(self.name(), err))?
            .into())
    }

    async fn delete(&self, bucket: &str, remote: &Utf8Path) -> Result<(), StorageError> {
        let mut buckets = self.buckets.write().await;
        let bucket = buckets
            .get_mut(bucket)
            .ok_or(eyre!("Bucket Not found: {bucket}"))
            .map_err(|err| StorageError::new(self.name(), err))?;
        bucket.remove(remote);

        Ok(())
    }

    async fn upload(
        &self,
        bucket: &str,
        remote: &Utf8Path,
        local: &mut Reader<'_>,
    ) -> Result<(), StorageError> {
        let mut buf = Vec::new();

        tokio::io::copy(local, &mut buf)
            .await
            .context("copy")
            .map_err(|err| StorageError::new(self.name(), err))?;

        buf.shutdown()
            .await
            .context("shutdown writer")
            .map_err(|err| StorageError::new(self.name(), err))?;

        let mut buckets = self.buckets.write().await;
        let bucket = buckets.entry(bucket.to_string()).or_default();
        bucket.insert(remote.to_owned(), buf.into());

        Ok(())
    }

    async fn download(
        &self,
        bucket: &str,
        remote: &Utf8Path,
        local: &mut Writer<'_>,
    ) -> Result<(), StorageError> {
        let buckets = self.buckets.read().await;
        let bucket = buckets
            .get(bucket)
            .ok_or(eyre!("Bucket Not found: {bucket}"))
            .map_err(|err| StorageError::new(self.name(), err))?;
        let mut buf = bucket
            .get(remote)
            .ok_or(eyre!("Path Not found: {remote}"))
            .map_err(|err| StorageError::new(self.name(), err))?
            .as_ref();

        tokio::io::copy(&mut buf, local)
            .await
            .context("copy")
            .map_err(|err| StorageError::new(self.name(), err))?;

        local
            .flush()
            .await
            .context("flush")
            .map_err(|err| StorageError::new(self.name(), err))?;

        Ok(())
    }

    async fn list(
        &self,
        bucket: &str,
        prefix: Option<&Utf8Path>,
    ) -> Result<Vec<String>, StorageError> {
        tracing::trace!(%bucket, ?prefix, "list memory bucket");

        let buckets = self.buckets.read().await;
        let bucket = buckets
            .get(bucket)
            .ok_or(eyre!("Bucket Not found: {bucket}"))
            .map_err(|err| StorageError::new(self.name(), err))?;

        let mut paths = Vec::new();
        for path in bucket.keys() {
            if let Some(prefix) = prefix {
                if path.starts_with(prefix) {
                    paths.push(path.to_string());
                }
            } else {
                paths.push(path.to_string());
            }
        }

        Ok(paths)
    }
}
