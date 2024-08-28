//! # Storage backends
//!
//! Configuration and unification for the storage backends.

use std::sync::Arc;

use camino::Utf8Path;
#[cfg(feature = "local")]
use camino::Utf8PathBuf;
#[cfg(feature = "b2")]
use eyre::Context;
use serde::Deserialize;

#[cfg(feature = "local")]
pub(crate) mod local;

pub mod multi;

pub(crate) mod memory;
#[cfg(feature = "tmp")]
pub(crate) mod temp;

#[cfg(feature = "local")]
#[doc(inline)]
pub use local::LocalDriver;

#[doc(inline)]
pub use memory::MemoryStorage;

use storage_driver::DriverUri;
#[cfg(feature = "tmp")]
#[doc(inline)]
pub use temp::TempDriver;

#[doc(inline)]
pub use storage_driver::{Driver, Metadata, StorageError};

/// Configuration for the storage backend, used to create a [`Storage`] instance.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageConfig {
    /// In-memory storage backend.
    Memory {
        /// The name of the bucket.
        bucket: String,
    },

    /// Local storage backend.
    #[cfg(feature = "local")]
    Local {
        /// The path to the local storage directory.
        path: Utf8PathBuf,
    },

    /// Temporary storage backend.
    #[cfg(feature = "tmp")]
    Temp,

    /// Backblaze B2 storage backend.
    #[cfg(feature = "b2")]
    B2(b2_client::B2ApplicationKey),

    /// Backblaze B2 storage backend, using environment variables for configuration.
    #[cfg(feature = "b2")]
    #[serde(alias = "b2env")]
    B2Env,

    /// Backblaze B2 storage backend, using multiple accounts to access multiple buckets.
    #[cfg(feature = "b2")]
    B2Multi(b2_client::B2MultiConfig),
}

impl StorageConfig {
    /// Build a [`Storage`] instance from the configuration.
    #[tracing::instrument]
    pub async fn build(self) -> Result<Storage, StorageError> {
        let client: Storage = match self {
            StorageConfig::Memory { bucket } => MemoryStorage::with_buckets(&[&bucket]).into(),
            #[cfg(feature = "local")]
            StorageConfig::Local { path } => LocalDriver::new(path).into(),
            #[cfg(feature = "tmp")]
            StorageConfig::Temp => TempDriver::new()
                .map_err(StorageError::with("Temp"))?
                .into(),
            #[cfg(feature = "b2")]
            StorageConfig::B2(app) => app
                .client()
                .await
                .context("authenticating b2 client")
                .map_err(StorageError::with("B2"))?
                .into(),
            #[cfg(feature = "b2")]
            StorageConfig::B2Env => b2_client::B2ApplicationKey::from_env()
                .context("creating b2 client from env")
                .map_err(StorageError::with("B2"))?
                .client()
                .await
                .context("authenticating b2 client from env")
                .map_err(StorageError::with("B2"))?
                .into(),
            #[cfg(feature = "b2")]
            StorageConfig::B2Multi(config) => config.client().into(),
        };
        Ok(client)
    }
}

use tokio::io;

pub(crate) type ArcDriver = Arc<dyn Driver + Send + Sync>;

/// Storage API client, wrapping a [`Driver`] implementation.
#[derive(Debug, Clone)]
pub struct Storage {
    driver: ArcDriver,
}

impl<D> From<D> for Storage
where
    D: Driver + Send + Sync + 'static,
{
    fn from(value: D) -> Self {
        Storage::new(value)
    }
}

impl Storage {
    /// Directly create a new storage client from a driver.
    pub fn new<D: Driver + Send + Sync + 'static>(driver: D) -> Self {
        Self {
            driver: Arc::new(driver),
        }
    }

    /// Get the name of the driver.
    pub fn name(&self) -> &'static str {
        self.driver.name()
    }

    /// Get a bucket-specific storage client.
    pub fn bucket<S: Into<String>>(&self, bucket: S) -> StorageBucket {
        StorageBucket {
            driver: self.driver.clone(),
            bucket: bucket.into(),
        }
    }

    /// Get file metadata.
    #[tracing::instrument(skip(self), fields(driver=self.driver.name()))]
    pub async fn metadata(
        &self,
        bucket: &str,
        remote: &Utf8Path,
    ) -> Result<Metadata, StorageError> {
        self.driver.metadata(bucket, remote).await
    }

    /// Download a file to a writer.
    #[tracing::instrument(skip(self, writer), fields(driver=self.driver.name()))]
    pub async fn download<'d, W>(
        &'d self,
        bucket: &str,
        remote: &Utf8Path,
        writer: &mut W,
    ) -> Result<(), StorageError>
    where
        W: io::AsyncWrite + Unpin + Send + Sync + 'd,
    {
        tracing::trace!(%remote, "Downloading from: {bucket}/{remote}");
        self.driver.download(bucket, remote, writer).await?;
        Ok(())
    }

    /// Upload a file from a reader.
    #[tracing::instrument(skip(self, reader), fields(driver=self.driver.name(), bucket))]
    pub async fn upload<'d, R>(
        &'d self,
        bucket: &str,
        remote: &Utf8Path,
        reader: &mut R,
    ) -> Result<(), StorageError>
    where
        R: io::AsyncBufRead + Unpin + Send + Sync + 'd,
    {
        tracing::trace!(%remote, "Uploading to: {bucket}/{remote}");
        self.driver.upload(bucket, remote, reader).await?;
        Ok(())
    }

    /// Upload a file from a local path.
    pub async fn upload_file(
        &self,
        bucket: &str,
        remote: &Utf8Path,
        local: &Utf8Path,
    ) -> Result<(), StorageError> {
        tracing::trace!(%remote, %local, "Uploading to: {bucket}/{remote}");
        self.driver.upload_file(bucket, remote, local).await
    }

    /// Download a file to a local path.
    pub async fn download_file(
        &self,
        bucket: &str,
        remote: &Utf8Path,
        local: &Utf8Path,
    ) -> Result<(), StorageError> {
        tracing::trace!(%remote, %local, "Downloading from: {bucket}/{remote}");
        self.driver.download_file(bucket, remote, local).await
    }

    /// List files in a bucket.
    #[tracing::instrument(skip(self), fields(driver=self.driver.name(), bucket))]
    pub async fn list(
        &self,
        bucket: &str,
        prefix: Option<&Utf8Path>,
    ) -> Result<Vec<String>, StorageError> {
        self.driver.list(bucket, prefix).await
    }

    /// Delete a file.
    #[tracing::instrument(skip(self), fields(driver=self.driver.name()))]
    pub async fn delete(&self, bucket: &str, path: &Utf8Path) -> Result<(), StorageError> {
        self.driver.delete(bucket, path).await
    }

    /// Get a storage driver which accepts URIs.
    pub fn uri(&self) -> DriverUri<ArcDriver> {
        DriverUri::new(self.driver.clone())
    }
}

/// Bucket-specific storage client, wrapping a [`Driver`] implementation.
#[derive(Debug, Clone)]
pub struct StorageBucket {
    /// The bucket name.
    pub bucket: String,
    driver: Arc<dyn Driver + Send + Sync + 'static>,
}

impl StorageBucket {
    /// Get file metadata.
    #[tracing::instrument(skip(self), fields(driver=self.driver.name()))]
    pub async fn metadata(&self, remote: &Utf8Path) -> Result<Metadata, StorageError> {
        self.driver.metadata(&self.bucket, remote).await
    }

    /// Download a file to a writer.
    #[tracing::instrument(skip(self, writer), fields(driver=self.driver.name()))]
    pub async fn download<'d, W>(
        &'d self,
        remote: &Utf8Path,
        writer: &mut W,
    ) -> Result<(), StorageError>
    where
        W: io::AsyncWrite + Unpin + Send + Sync + 'd,
    {
        tracing::trace!(%remote, "Downloading from: {}/{remote}", self.bucket);
        self.driver.download(&self.bucket, remote, writer).await?;
        Ok(())
    }

    /// Upload a file from a reader.
    #[tracing::instrument(skip(self, reader), fields(driver=self.driver.name(), bucket=self.bucket))]
    pub async fn upload<'d, R>(
        &'d self,
        remote: &Utf8Path,
        reader: &mut R,
    ) -> Result<(), StorageError>
    where
        R: io::AsyncBufRead + Unpin + Send + Sync + 'd,
    {
        tracing::trace!(%remote, "Uploading to: {}/{remote}", self.bucket);
        self.driver.upload(&self.bucket, remote, reader).await?;
        Ok(())
    }

    /// Upload a file from a local path.
    pub async fn upload_file(
        &self,
        remote: &Utf8Path,
        local: &Utf8Path,
    ) -> Result<(), StorageError> {
        self.driver.upload_file(&self.bucket, remote, local).await
    }

    /// Download a file to a local path.
    pub async fn download_file(
        &self,
        remote: &Utf8Path,
        local: &Utf8Path,
    ) -> Result<(), StorageError> {
        self.driver.download_file(&self.bucket, remote, local).await
    }

    /// List files in a bucket.
    #[tracing::instrument(skip(self), fields(driver=self.driver.name(), bucket=self.bucket))]
    pub async fn list(&self, prefix: Option<&Utf8Path>) -> Result<Vec<String>, StorageError> {
        self.driver.list(&self.bucket, prefix).await
    }

    /// Delete a file.
    #[tracing::instrument(skip(self), fields(driver=self.driver.name(), bucket=self.bucket))]
    pub async fn delete(&self, path: &Utf8Path) -> Result<(), StorageError> {
        self.driver.delete(&self.bucket, path).await
    }
}
