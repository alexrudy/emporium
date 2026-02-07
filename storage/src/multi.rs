//! A storage backend that can use multiple drivers based on the URI scheme,
//! and possibly the bucket.

#![allow(clippy::needless_pass_by_ref_mut)]
use std::collections::HashMap;

use camino::Utf8Path;
use http::Uri;
use storage_driver::{Driver, DriverUri, Metadata, StorageError, StorageErrorKind};
use tokio::io;

use crate::Storage;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    scheme: String,
    bucket: Option<String>,
}

/// A storage backend that can use multiple drivers based on the URI scheme,
/// and possibly the bucket.
#[derive(Debug, Default)]
pub struct MultiStorage {
    drivers: HashMap<Key, Storage>,
}

macro_rules! forward_driver {
    ($this:ident.$method:ident($url:expr)) => {
        async {
            let _span = tracing::trace_span!("multi", method=%stringify!($method));
            if $url.scheme_str() == Some("file") {
                tracing::trace!(method=%stringify!($method), "Using file driver");
                return DriverUri::file().$method($url).await;
            }
            let driver = $this
                .get($url)?
                .ok_or_else(|| {
                    StorageError::new(
                        "multi driver",
                        StorageErrorKind::InvalidRequest,
                        std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            format!("Driver for {}:// not found", $url.scheme_str().unwrap_or_default())
                        )
                    )
                })?;
            tracing::trace!(method=%stringify!($method), driver=%driver.name(), "Using {} driver", driver.name());

            driver.uri().$method($url).await
        }
    };


    ($this:ident.$method:ident($url:expr, $($args:expr),+)) => {
        async {
            if $url.scheme_str() == Some("file") {
                return DriverUri::file().$method($url,$($args),+).await;
            }
            let driver = $this
                .get($url)?
                .ok_or_else(|| {
                    StorageError::new(
                        "multi driver",
                        StorageErrorKind::InvalidRequest,
                        std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            format!("Driver for {}:// not found", $url.scheme_str().unwrap_or_default())
                        )
                    )
                })?;

            driver.uri().$method($url,$($args),+).await
        }
    };


}

impl MultiStorage {
    /// Create a new `MultiStorage` instance, with no drivers.
    pub fn new() -> Self {
        Self {
            drivers: HashMap::new(),
        }
    }

    /// Add a new driver to the storage backend, applicable to all URIs with the
    /// same scheme.
    pub fn add<D>(&mut self, driver: D)
    where
        D: Driver + Send + Sync + 'static,
    {
        assert_ne!(driver.scheme(), "file");
        self.drivers.insert(
            Key {
                scheme: driver.scheme().into(),
                bucket: None,
            },
            driver.into(),
        );
    }

    /// Get a driver for the given URI.
    pub fn get(&self, uri: &Uri) -> Result<Option<&Storage>, StorageError> {
        let bucket = uri.host();

        if let Some(s) = self.drivers.get(&Key {
            scheme: uri.scheme_str().unwrap_or_default().to_owned(),
            bucket: bucket.map(|s| s.to_owned()),
        }) {
            return Ok(Some(s));
        }

        if let Some(s) = self.drivers.get(&Key {
            scheme: uri.scheme_str().unwrap_or_default().to_owned(),
            bucket: None,
        }) {
            return Ok(Some(s));
        }

        Ok(None)
    }

    /// Get file metadata.
    pub async fn metadata(&self, uri: &Uri) -> Result<Metadata, StorageError> {
        forward_driver!(self.metadata(uri)).await
    }

    /// Download a file to a writer.
    pub async fn download<'d, W>(&'d self, uri: &Uri, writer: &mut W) -> Result<(), StorageError>
    where
        W: io::AsyncWrite + Unpin + Send + Sync + 'd,
    {
        forward_driver!(self.download(uri, writer)).await
    }

    /// Upload a file from a reader.
    pub async fn upload<'d, R>(&'d self, uri: &Uri, reader: &mut R) -> Result<(), StorageError>
    where
        R: io::AsyncBufRead + Unpin + Send + Sync + 'd,
    {
        forward_driver!(self.upload(uri, reader)).await
    }

    /// Upload a file from a reader.
    pub async fn upload_file(&self, uri: &Uri, local: &Utf8Path) -> Result<(), StorageError> {
        forward_driver!(self.upload_file(uri, local)).await
    }

    /// Download a file to a local path.
    pub async fn download_file(&self, uri: &Uri, local: &Utf8Path) -> Result<(), StorageError> {
        forward_driver!(self.download_file(uri, local)).await
    }

    /// List files in a directory.
    pub async fn list(&self, uri: &Uri) -> Result<Vec<String>, StorageError> {
        forward_driver!(self.list(uri)).await
    }

    /// Delete a file.
    pub async fn delete(&self, uri: &Uri) -> Result<(), StorageError> {
        forward_driver!(self.delete(uri)).await
    }
}

#[cfg(test)]
mod tests {
    use http::Uri;

    #[test]
    fn parse_b2_url() {
        let url = "b2://bucket/path/to/file";
        let uri = url.parse::<Uri>().unwrap();
        assert_eq!(uri.scheme_str(), Some("b2"));
        assert_eq!(uri.host(), Some("bucket"));
        assert_eq!(uri.path(), "/path/to/file");
    }

    #[test]
    fn parse_s3_url() {
        let url = "s3://bucket/path/to/file";
        let uri = url.parse::<Uri>().unwrap();
        assert_eq!(uri.scheme_str(), Some("s3"));
        assert_eq!(uri.host(), Some("bucket"));
        assert_eq!(uri.path(), "/path/to/file");
    }

    #[test]
    fn parse_local_url() {
        let url = "local://bucket/path/to/file";
        let uri = url.parse::<Uri>().unwrap();
        assert_eq!(uri.scheme_str(), Some("local"));
        assert_eq!(uri.host(), Some("bucket"));
        assert_eq!(uri.path(), "/path/to/file");
    }

    #[test]
    fn parse_tmp_url() {
        let url = "tmp://bucket/path/to/file";
        let uri = url.parse::<Uri>().unwrap();
        assert_eq!(uri.scheme_str(), Some("tmp"));
        assert_eq!(uri.host(), Some("bucket"));
        assert_eq!(uri.path(), "/path/to/file");
    }

    #[test]
    fn parse_memory_url() {
        let url = "memory://bucket/path/to/file";
        let uri = url.parse::<Uri>().unwrap();
        assert_eq!(uri.scheme_str(), Some("memory"));
        assert_eq!(uri.host(), Some("bucket"));
        assert_eq!(uri.path(), "/path/to/file");
    }

    // #[test]
    // fn parse_file_url() {
    //     let url = "file:///path/to/file";
    //     let uri = url.parse::<Uri>().unwrap();
    //     assert_eq!(uri.scheme_str(), Some("file"));
    //     assert_eq!(uri.host(), None);
    //     assert_eq!(uri.path(), "/path/to/file");
    // }
}
