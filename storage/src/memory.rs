use std::collections::HashMap;

use camino::{Utf8Path, Utf8PathBuf};
use chrono::{DateTime, Utc};
use tokio::{io::AsyncWriteExt, sync::RwLock};

use storage_driver::{Driver, Metadata, Reader, StorageError, StorageErrorKind, Writer};

/// Helper to convert io::Error to StorageError with appropriate kind detection
fn io_error_to_storage(engine: &'static str, err: std::io::Error) -> StorageError {
    let kind = match err.kind() {
        std::io::ErrorKind::NotFound => StorageErrorKind::NotFound,
        std::io::ErrorKind::PermissionDenied => StorageErrorKind::PermissionDenied,
        _ => StorageErrorKind::Io,
    };
    StorageError::new(engine, kind, err)
}

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
        let bucket_map = buckets.get(bucket).ok_or_else(|| {
            StorageError::builder()
                .kind(StorageErrorKind::NotFound)
                .engine(self.name())
                .bucket(bucket)
                .context("bucket not found")
                .error(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("Bucket not found: {bucket}"),
                ))
                .build()
        })?;
        Ok(bucket_map
            .get(remote)
            .ok_or_else(|| {
                StorageError::builder()
                    .kind(StorageErrorKind::NotFound)
                    .engine(self.name())
                    .bucket(bucket)
                    .path(remote.as_str())
                    .context("path not found")
                    .error(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("Path not found: {remote}"),
                    ))
                    .build()
            })?
            .into())
    }

    async fn delete(&self, bucket: &str, remote: &Utf8Path) -> Result<(), StorageError> {
        let mut buckets = self.buckets.write().await;
        let bucket_map = buckets.get_mut(bucket).ok_or_else(|| {
            StorageError::builder()
                .kind(StorageErrorKind::NotFound)
                .engine(self.name())
                .bucket(bucket)
                .context("bucket not found")
                .error(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("Bucket not found: {bucket}"),
                ))
                .build()
        })?;
        bucket_map.remove(remote);

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
            .map_err(|err| io_error_to_storage(self.name(), err))?;

        buf.shutdown()
            .await
            .map_err(|err| io_error_to_storage(self.name(), err))?;

        let mut buckets = self.buckets.write().await;
        let bucket_map = buckets.entry(bucket.to_string()).or_default();
        bucket_map.insert(remote.to_owned(), buf.into());

        Ok(())
    }

    async fn download(
        &self,
        bucket: &str,
        remote: &Utf8Path,
        local: &mut Writer<'_>,
    ) -> Result<(), StorageError> {
        let buckets = self.buckets.read().await;
        let bucket_map = buckets.get(bucket).ok_or_else(|| {
            StorageError::builder()
                .kind(StorageErrorKind::NotFound)
                .engine(self.name())
                .bucket(bucket)
                .context("bucket not found")
                .error(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("Bucket not found: {bucket}"),
                ))
                .build()
        })?;
        let mut buf = bucket_map
            .get(remote)
            .ok_or_else(|| {
                StorageError::builder()
                    .kind(StorageErrorKind::NotFound)
                    .engine(self.name())
                    .bucket(bucket)
                    .path(remote.as_str())
                    .context("path not found")
                    .error(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("Path not found: {remote}"),
                    ))
                    .build()
            })?
            .as_ref();

        tokio::io::copy(&mut buf, local)
            .await
            .map_err(|err| io_error_to_storage(self.name(), err))?;

        local
            .flush()
            .await
            .map_err(|err| io_error_to_storage(self.name(), err))?;

        Ok(())
    }

    async fn list(
        &self,
        bucket: &str,
        prefix: Option<&Utf8Path>,
    ) -> Result<Vec<String>, StorageError> {
        tracing::trace!(%bucket, ?prefix, "list memory bucket");

        let buckets = self.buckets.read().await;
        let bucket_map = buckets.get(bucket).ok_or_else(|| {
            StorageError::builder()
                .kind(StorageErrorKind::NotFound)
                .engine(self.name())
                .bucket(bucket)
                .context("bucket not found")
                .error(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("Bucket not found: {bucket}"),
                ))
                .build()
        })?;

        let mut paths = Vec::new();
        for path in bucket_map.keys() {
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
