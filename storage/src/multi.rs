#![allow(clippy::needless_pass_by_ref_mut)]
use std::collections::HashMap;

use camino::Utf8Path;
use eyre::eyre;
use http::Uri;
use storage_driver::{Driver, DriverUri, Metadata, StorageError};
use tokio::io;

use crate::Storage;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    scheme: String,
    bucket: Option<String>,
}

#[derive(Debug, Default)]
pub struct MultiStorage {
    drivers: HashMap<Key, Storage>,
}

macro_rules! file {
    ($this:ident,$method:ident($url:expr)) => {
        async {
            if $url.scheme_str() == Some("file") {
                return DriverUri::file().$method($url).await;
            }
            let driver = $this
                .get($url)?
                .ok_or_else(|| eyre!("Driver for {}:// not found", $url.scheme_str().unwrap_or_default())).map_err(|err| StorageError::new("multi driver", err))?;

            driver.uri().$method($url).await
        }
    };


    ($this:ident,$method:ident($url:expr, $($args:expr),+)) => {
        async {
            if $url.scheme_str() == Some("file") {
                return DriverUri::file().$method($url,$($args),+).await;
            }
            let driver = $this
                .get($url)?
                .ok_or_else(|| eyre!("Driver for {}:// not found", $url.scheme_str().unwrap_or_default())).map_err(|err| StorageError::new("multi driver", err))?;

            driver.uri().$method($url,$($args),+).await
        }
    };


}

impl MultiStorage {
    pub fn new() -> Self {
        Self {
            drivers: HashMap::new(),
        }
    }

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

    pub async fn metadata(&self, uri: &Uri) -> Result<Metadata, StorageError> {
        file!(self, metadata(uri)).await
    }

    pub async fn download<'d, W>(&'d self, uri: &Uri, writer: &mut W) -> Result<(), StorageError>
    where
        W: io::AsyncWrite + Unpin + Send + Sync + 'd,
    {
        file!(self, download(uri, writer)).await
    }

    pub async fn upload<'d, R>(&'d self, uri: &Uri, reader: &mut R) -> Result<(), StorageError>
    where
        R: io::AsyncBufRead + Unpin + Send + Sync + 'd,
    {
        file!(self, upload(uri, reader)).await
    }

    pub async fn upload_file(&self, uri: &Uri, local: &Utf8Path) -> Result<(), StorageError> {
        file!(self, upload_file(uri, local)).await
    }

    pub async fn download_file(&self, uri: &Uri, local: &Utf8Path) -> Result<(), StorageError> {
        file!(self, download_file(uri, local)).await
    }

    pub async fn list(&self, uri: &Uri) -> Result<Vec<String>, StorageError> {
        file!(self, list(uri)).await
    }

    pub async fn delete(&self, uri: &Uri) -> Result<(), StorageError> {
        file!(self, delete(uri)).await
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
