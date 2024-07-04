use camino::Utf8Path;
use eyre::WrapErr;
use tempfile::TempDir;

use crate::local::LocalDriver;
use storage_driver::{Driver, Metadata, Reader, StorageError, Writer};

#[derive(Debug)]
pub struct TempDriver {
    #[allow(unused)]
    dir: TempDir,
    driver: LocalDriver,
}

impl Default for TempDriver {
    fn default() -> Self {
        TempDriver::new().unwrap()
    }
}

impl TempDriver {
    pub fn new() -> eyre::Result<Self> {
        let tmp = TempDir::new().wrap_err("create temporary directory")?;
        let root = Utf8Path::from_path(tmp.path())
            .expect("utf-8 path")
            .to_owned();

        Ok(Self {
            dir: tmp,
            driver: LocalDriver::new(root),
        })
    }
}

#[async_trait::async_trait]
impl Driver for TempDriver {
    fn name(&self) -> &'static str {
        "temp"
    }

    fn scheme(&self) -> &str {
        "tmp"
    }

    async fn metadata(&self, bucket: &str, remote: &Utf8Path) -> Result<Metadata, StorageError> {
        self.driver.metadata(bucket, remote).await
    }

    async fn delete(&self, bucket: &str, remote: &Utf8Path) -> Result<(), StorageError> {
        self.driver.delete(bucket, remote).await
    }

    async fn upload(
        &self,
        bucket: &str,
        remote: &Utf8Path,
        local: &mut Reader<'_>,
    ) -> Result<(), StorageError> {
        self.driver.upload(bucket, remote, local).await
    }
    async fn download(
        &self,
        bucket: &str,
        remote: &Utf8Path,
        local: &mut Writer<'_>,
    ) -> Result<(), StorageError> {
        self.driver.download(bucket, remote, local).await
    }

    async fn list(
        &self,
        bucket: &str,
        prefix: Option<&Utf8Path>,
    ) -> Result<Vec<String>, StorageError> {
        self.driver.list(bucket, prefix).await
    }
}
