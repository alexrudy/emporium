#![allow(clippy::needless_pass_by_ref_mut)]

use http::Uri;
use std::{fmt, fs::DirEntry, ops::Deref, os::unix::prelude::MetadataExt, path::Path, sync::Arc};
use tokio::io::{self, AsyncWriteExt};
use tracing::Instrument;

use crate::error::{StorageError, StorageErrorKind};
use camino::Utf8Path;
use chrono::{DateTime, Utc};

/// Helper to convert io::Error to StorageError with appropriate kind detection
fn io_error_to_storage(engine: &'static str, err: io::Error) -> StorageError {
    let kind = match err.kind() {
        io::ErrorKind::NotFound => StorageErrorKind::NotFound,
        io::ErrorKind::PermissionDenied => StorageErrorKind::PermissionDenied,
        _ => StorageErrorKind::Io,
    };
    StorageError::new(engine, kind, err)
}

/// A reader stream for file contents.
pub type Reader<'r> = dyn io::AsyncBufRead + Unpin + Send + Sync + 'r;

/// A writer stream for file contents.
pub type Writer<'w> = dyn io::AsyncWrite + Unpin + Send + Sync + 'w;

/// File object metadata, which will be generically provided by the driver.
///
/// This struct only provides common metadata fields, and drivers may provide more specific
/// metadata fields directly.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Metadata {
    /// The size of the file in bytes.
    pub size: u64,

    /// The creation timestamp of the file.
    pub created: DateTime<Utc>,
}

/// A storage driver, which provides the ability to interact with a storage backend.
#[async_trait::async_trait]
pub trait Driver: fmt::Debug {
    /// The name of the driver.
    fn name(&self) -> &'static str;

    /// The Uri of the driver.
    fn scheme(&self) -> &str;

    /// Delete a file from the storage, by path.
    async fn delete(&self, bucket: &str, remote: &Utf8Path) -> Result<(), StorageError>;

    /// Get the metadata for a file, by path.
    async fn metadata(&self, bucket: &str, remote: &Utf8Path) -> Result<Metadata, StorageError>;

    /// Upload a file to the storage, using a reader stream to provide the contents.
    async fn upload(
        &self,
        bucket: &str,
        remote: &Utf8Path,
        reader: &mut Reader<'_>,
    ) -> Result<(), StorageError>;

    /// Download a file from storage, into a writer stream.
    async fn download(
        &self,
        bucket: &str,
        remote: &Utf8Path,
        writer: &mut Writer<'_>,
    ) -> Result<(), StorageError>;

    /// Donwload a file from storage, into a local file.
    async fn download_file(
        &self,
        bucket: &str,
        remote: &Utf8Path,
        local: &Utf8Path,
    ) -> Result<(), StorageError> {
        tracing::trace!(%remote, %local, "Downloading to file: {local}");

        if let Some(parent) = local.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| io_error_to_storage("tokio::fs", e))?;
        }
        let mut file = tokio::io::BufWriter::new(
            tokio::fs::File::create(local)
                .await
                .map_err(|e| io_error_to_storage("tokio::fs", e))?,
        );
        self.download(bucket, remote, &mut file).await?;
        file.shutdown()
            .await
            .map_err(|e| io_error_to_storage("tokio::fs", e))?;
        Ok(())
    }

    /// Upload a file to storage, from a local file.
    async fn upload_file(
        &self,
        bucket: &str,
        remote: &Utf8Path,
        local: &Utf8Path,
    ) -> Result<(), StorageError> {
        tracing::trace!(%remote, %local, "Uploading from file: {local}");
        let mut file = tokio::io::BufReader::new(
            tokio::fs::File::open(local)
                .await
                .map_err(|e| io_error_to_storage("tokio::fs", e))?,
        );

        self.upload(bucket, remote, &mut file).await
    }

    /// List the files in a bucket, optionally filtered by a prefix.
    async fn list(
        &self,
        bucket: &str,
        prefix: Option<&Utf8Path>,
    ) -> Result<Vec<String>, StorageError>;

    /// Get an adaptor which accepts Uri objects instead of explicit
    /// bucket and path pairs, and forwards those on to the underlying
    /// driver using `Driver::parse_url` to identify the bucket and
    /// path components.
    fn uri<'d>(&'d self) -> DriverUri<&'d Self>
    where
        Self: Sized + 'd,
    {
        DriverUri { driver: self }
    }

    /// Parse a Uri object to extract the bucket and remote path.
    fn parse_url<'u>(&self, url: &'u Uri) -> Result<(&'u str, &'u Utf8Path), StorageError> {
        if url.scheme_str() != Some(self.scheme()) {
            let err = std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Invalid scheme: expected {}, got {}",
                    self.scheme(),
                    url.scheme_str().unwrap_or_default()
                ),
            );
            return Err(StorageError::new(
                self.name(),
                StorageErrorKind::InvalidRequest,
                err,
            ));
        }

        let bucket = url.host().ok_or_else(|| {
            StorageError::new(
                self.name(),
                StorageErrorKind::InvalidRequest,
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Missing host: invalid Uri {url}"),
                ),
            )
        })?;
        let remote = url.path().trim_start_matches('/').into();

        Ok((bucket, remote))
    }
}

/// An adaptor which accepts Uri objects instead of explicit
/// bucket and path pairs, and forwards those on to the underlying
/// driver using `Driver::parse_url` to identify the bucket and
/// path components.
#[derive(Debug)]
pub struct DriverUri<D> {
    driver: D,
}

macro_rules! forward_uri {
    ($here:ident.$driver:ident.$method:ident($url:expr)) => {
        async {
            let (bucket, remote) = $here.$driver.parse_url($url)?;
            $here.$driver.$method(bucket, remote).await
        }
    };
    ($here:ident.$driver:ident.$method:ident($url:expr,$($args:expr),+)) => {
        async {
            let (bucket, remote) = $here.$driver.parse_url($url)?;
            $here.$driver.$method(bucket, remote, $($args),+).await
        }
    };
}

/// An adaptor which accepts Uri objects instead of explicit
/// bucket and path pairs, and forwards those on to the underlying
/// driver using `Driver::parse_url` to identify the bucket and
/// path components.
impl<D> DriverUri<D>
where
    D: Driver + Send + Sync + 'static,
{
    /// Create a new driver URI adaptor.
    pub fn new(driver: D) -> Self {
        Self { driver }
    }

    /// Delete a file from the storage, by path.
    pub async fn delete(&self, url: &Uri) -> Result<(), StorageError> {
        forward_uri!(self.driver.delete(url)).await
    }

    /// Get the metadata for a file, by path.
    pub async fn metadata(&self, url: &Uri) -> Result<Metadata, StorageError> {
        forward_uri!(self.driver.metadata(url)).await
    }

    /// Upload a file to the storage, using a reader stream to provide the contents.
    pub async fn upload(&self, url: &Uri, reader: &mut Reader<'_>) -> Result<(), StorageError> {
        forward_uri!(self.driver.upload(url, reader)).await
    }

    /// Download a file from storage, into a writer stream.
    pub async fn download(&self, url: &Uri, writer: &mut Writer<'_>) -> Result<(), StorageError> {
        forward_uri!(self.driver.download(url, writer)).await
    }

    /// Donwload a file from storage, into a local file.
    pub async fn download_file(&self, url: &Uri, local: &Utf8Path) -> Result<(), StorageError> {
        forward_uri!(self.driver.download_file(url, local)).await
    }

    /// Upload a file to storage, from a local file.
    pub async fn upload_file(&self, url: &Uri, local: &Utf8Path) -> Result<(), StorageError> {
        forward_uri!(self.driver.upload_file(url, local)).await
    }

    /// List the files in a bucket, optionally filtered by a prefix.
    pub async fn list(&self, url: &Uri) -> Result<Vec<String>, StorageError> {
        let (bucket, prefix) = self.driver.parse_url(url)?;
        self.driver.list(bucket, Some(prefix)).await
    }
}

impl DriverUri<()> {
    /// Create a new driver for the file system.
    pub fn file() -> Self {
        Self { driver: () }
    }

    /// Delete a file from the storage, by path.
    pub async fn delete(&self, url: &Uri) -> Result<(), StorageError> {
        assert_eq!(url.scheme_str(), Some("file"));
        let path = url.path();
        tokio::fs::remove_file(path)
            .await
            .map_err(|e| io_error_to_storage("tokio::fs", e))?;
        Ok(())
    }

    /// Get the metadata for a file, by path.
    pub async fn metadata(&self, url: &Uri) -> Result<Metadata, StorageError> {
        assert_eq!(url.scheme_str(), Some("file"));
        let path = url.path();
        let metadata = tokio::fs::metadata(path)
            .await
            .map_err(|e| io_error_to_storage("tokio::fs", e))?;
        Ok(Metadata {
            size: metadata.size(),
            created: metadata
                .created()
                .map_err(|e| io_error_to_storage("tokio::fs", e))?
                .into(),
        })
    }

    /// Upload a file to the storage, using a reader stream to provide the contents.
    pub async fn upload(&self, url: &Uri, reader: &mut Reader<'_>) -> Result<(), StorageError> {
        assert_eq!(url.scheme_str(), Some("file"));
        let path = url.path();
        let mut file = tokio::fs::File::create(path)
            .await
            .map_err(|e| io_error_to_storage("tokio::fs", e))?;
        tokio::io::copy(reader, &mut file)
            .await
            .map_err(|e| io_error_to_storage("tokio::fs", e))?;
        Ok(())
    }

    /// Download a file from storage, into a writer stream.
    pub async fn download(&self, url: &Uri, writer: &mut Writer<'_>) -> Result<(), StorageError> {
        assert_eq!(url.scheme_str(), Some("file"));
        let path = url.path();
        let mut file = tokio::fs::File::open(path)
            .await
            .map_err(|e| io_error_to_storage("tokio::fs", e))?;
        tokio::io::copy(&mut file, writer)
            .await
            .map_err(|e| io_error_to_storage("tokio::fs", e))?;
        Ok(())
    }

    /// Donwload a file from storage, into a local file.
    pub async fn download_file(&self, url: &Uri, local: &Utf8Path) -> Result<(), StorageError> {
        assert_eq!(url.scheme_str(), Some("file"));
        let path = url.path();
        let mut src = tokio::fs::File::open(path)
            .await
            .map_err(|e| io_error_to_storage("tokio::fs", e))?;
        let mut dst = tokio::fs::File::create(local)
            .await
            .map_err(|e| io_error_to_storage("tokio::fs", e))?;
        tokio::io::copy(&mut src, &mut dst)
            .await
            .map_err(|e| io_error_to_storage("tokio::fs", e))?;
        Ok(())
    }

    /// Upload a file to storage, from a local file.
    pub async fn upload_file(&self, url: &Uri, local: &Utf8Path) -> Result<(), StorageError> {
        assert_eq!(url.scheme_str(), Some("file"));
        let path = url.path();
        let mut src = tokio::fs::File::open(local)
            .await
            .map_err(|e| io_error_to_storage("tokio::fs", e))?;
        let mut dst = tokio::fs::File::create(path)
            .await
            .map_err(|e| io_error_to_storage("tokio::fs", e))?;
        tokio::io::copy(&mut src, &mut dst)
            .await
            .map_err(|e| io_error_to_storage("tokio::fs", e))?;
        Ok(())
    }

    /// List the files in a bucket, optionally filtered by a prefix.
    pub async fn list(&self, uri: &Uri) -> Result<Vec<String>, StorageError> {
        assert_eq!(uri.scheme_str(), Some("file"));
        let path = uri.path().to_owned();

        let files = tokio::task::spawn_blocking(move || {
            let mut files: Vec<_> = Vec::new();
            fn visit_dirs(dir: &Path, cb: &mut dyn FnMut(&DirEntry)) -> io::Result<()> {
                if dir.is_dir() {
                    for entry in std::fs::read_dir(dir)? {
                        let entry = entry?;
                        let path = entry.path();
                        if path.is_dir() {
                            visit_dirs(&path, cb)?;
                        } else {
                            cb(&entry);
                        }
                    }
                }
                Ok(())
            }

            visit_dirs(
                Path::new(&path),
                &mut (|entry| files.push(entry.path().to_string_lossy().to_string())),
            )
            .map_err(|e| io_error_to_storage("tokio::fs", e))?;

            Ok::<_, StorageError>(files)
        })
        .in_current_span()
        .await
        .map_err(|e| StorageError::new("tokio::fs", StorageErrorKind::Other, e))??;
        Ok(files)
    }
}

#[async_trait::async_trait]
impl<D> Driver for Arc<D>
where
    D: ?Sized + Driver + Sync + Send + 'static,
{
    fn name(&self) -> &'static str {
        self.deref().name()
    }

    fn scheme(&self) -> &str {
        self.deref().scheme()
    }

    async fn delete(&self, bucket: &str, remote: &Utf8Path) -> Result<(), StorageError> {
        self.deref().delete(bucket, remote).await
    }

    async fn metadata(&self, bucket: &str, remote: &Utf8Path) -> Result<Metadata, StorageError> {
        self.deref().metadata(bucket, remote).await
    }

    async fn upload(
        &self,
        bucket: &str,
        remote: &Utf8Path,
        reader: &mut Reader<'_>,
    ) -> Result<(), StorageError> {
        self.deref().upload(bucket, remote, reader).await
    }

    async fn download(
        &self,
        bucket: &str,
        remote: &Utf8Path,
        writer: &mut Writer<'_>,
    ) -> Result<(), StorageError> {
        self.deref().download(bucket, remote, writer).await
    }

    async fn list(
        &self,
        bucket: &str,
        prefix: Option<&Utf8Path>,
    ) -> Result<Vec<String>, StorageError> {
        self.deref().list(bucket, prefix).await
    }
}

#[async_trait::async_trait]
impl<D> Driver for &D
where
    D: ?Sized + Driver + Sync + Send + 'static,
{
    fn name(&self) -> &'static str {
        (*self).name()
    }

    /// The Uri of the driver.
    fn scheme(&self) -> &str {
        (*self).scheme()
    }

    async fn delete(&self, bucket: &str, remote: &Utf8Path) -> Result<(), StorageError> {
        self.delete(bucket, remote).await
    }

    async fn metadata(&self, bucket: &str, remote: &Utf8Path) -> Result<Metadata, StorageError> {
        self.metadata(bucket, remote).await
    }

    async fn upload(
        &self,
        bucket: &str,
        remote: &Utf8Path,
        reader: &mut Reader<'_>,
    ) -> Result<(), StorageError> {
        self.upload(bucket, remote, reader).await
    }

    async fn download(
        &self,
        bucket: &str,
        remote: &Utf8Path,
        writer: &mut Writer<'_>,
    ) -> Result<(), StorageError> {
        self.download(bucket, remote, writer).await
    }

    async fn list(
        &self,
        bucket: &str,
        prefix: Option<&Utf8Path>,
    ) -> Result<Vec<String>, StorageError> {
        self.list(bucket, prefix).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static_assertions::assert_obj_safe!(Driver);
}
