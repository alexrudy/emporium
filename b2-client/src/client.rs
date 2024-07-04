//! Core client for access files on B2 using the storage driver API.

use std::sync::Arc;

use camino::Utf8Path;
use dashmap::DashMap;
use eyre::{eyre, Context};
use futures::StreamExt;
use hyperdriver::Body;
use tokio::io;
use tokio::io::AsyncWriteExt;

use echocache::Cached;
use storage_driver::{Driver, Metadata, Reader, StorageError, Writer};

use crate::application::B2ApplicationKey;
use crate::application::{AuthenticationError, B2Authorization};
use crate::errors::B2ErrorCode;
use crate::errors::B2RequestError;

use super::B2_DEFAULT_CONCURRENCY;
use super::B2_STORAGE_NAME;
use super::B2_STORAGE_SCHEME;
use super::B2_UPLOAD_RETRIES;

type BucketResult = Result<crate::bucket::Bucket, Arc<B2RequestError>>;
type ArcLockMap<K, V> = Arc<DashMap<K, V>>;

#[derive(Debug, Clone)]
pub(crate) struct UploadSettings {
    pub(crate) concurrency: usize,
    pub(crate) retries: usize,
}

impl Default for UploadSettings {
    fn default() -> Self {
        UploadSettings {
            concurrency: B2_DEFAULT_CONCURRENCY,
            retries: B2_UPLOAD_RETRIES,
        }
    }
}

/// API client for accessing B2 with a single application key.
///
/// Create a single client from a B2ApplicationKey.
#[derive(Debug, Clone)]
pub struct B2Client {
    pub(crate) client: api_client::ApiClient<B2Authorization>,
    keys: Arc<B2ApplicationKey>,
    pub(crate) buckets: ArcLockMap<String, Cached<BucketResult>>,

    /// Upload settings for this client.
    pub(crate) uploads: UploadSettings,
}

impl B2Client {
    #[cfg(test)]
    pub(crate) fn test() -> Self {
        let client = hyperdriver::Client::build_tcp_http().build_service();
        let authorization = B2Authorization::test();
        let keys = B2ApplicationKey::test();
        B2Client::from_client_and_authorization(client, authorization, keys)
    }

    pub(crate) fn from_client_and_authorization(
        client: hyperdriver::client::SharedClientService<Body>,
        authorization: B2Authorization,
        keys: B2ApplicationKey,
    ) -> Self {
        B2Client {
            client: api_client::ApiClient::new_with_inner_service(
                authorization.api_url.clone(),
                authorization,
                client,
            ),
            keys: Arc::new(keys),
            buckets: Default::default(),
            uploads: Default::default(),
        }
    }

    pub(crate) fn authorization(&self) -> arc_swap::Guard<Arc<B2Authorization>> {
        self.client.auth()
    }

    pub(crate) async fn refresh_authorization(&self) -> Result<(), AuthenticationError> {
        tracing::debug!(
            key = self.keys.key_id.revealed(),
            "Refreshing B2 authorization"
        );

        let mut service = self.client.inner().clone();
        let auth = self.keys.fetch_authorization(&mut service).await?;
        {
            self.client.refresh_auth(auth);
        }
        Ok(())
    }
}

macro_rules! auth {
($driver:ident.$method:ident($($args:expr),+)) => {
    async {
        let mut result = $driver.$method($($args),+).await;
        if let Err(err) = &result {
            if let Some(err) = err.b2() {
                if matches!(err.kind(), B2ErrorCode::ExpiredAuthToken) {
                    if let Err(error) = $driver.refresh_authorization().await {
                        tracing::error!("Encountered an error refreshing credentials: {error}");
                    } else {
                        tracing::debug!("Refreshed B2 Authorization credentials");
                        result = $driver.$method($($args),+).await;
                    }
                }
            }
        }
        result
    }
};
}

impl B2Client {
    async fn impl_download(
        &self,
        bucket: &str,
        remote: &Utf8Path,
        local: &mut Writer<'_>,
    ) -> Result<(), StorageError> {
        let stream = auth!(self.b2_download_file_by_name(bucket, remote))
            .await
            .context("open download stream")
            .map_err(StorageError::with(B2_STORAGE_NAME))?;

        let mut src = tokio_util::io::StreamReader::new(
            stream.map(|s| s.map_err(|err| io::Error::new(io::ErrorKind::Other, err))),
        );
        tokio::io::copy(&mut src, local)
            .await
            .context("copy file to upload stream")
            .map_err(StorageError::with(B2_STORAGE_NAME))?;

        local
            .flush()
            .await
            .context("flush file stream")
            .map_err(StorageError::with(B2_STORAGE_NAME))?;

        Ok(())
    }
}

#[async_trait::async_trait]
impl Driver for B2Client {
    fn name(&self) -> &'static str {
        B2_STORAGE_NAME
    }

    fn scheme(&self) -> &str {
        B2_STORAGE_SCHEME
    }

    async fn metadata(&self, bucket: &str, remote: &Utf8Path) -> Result<Metadata, StorageError> {
        let mut buckets = auth!(self.b2_list_buckets(String::from(bucket), None))
            .await
            .with_context(|| format!("list bucket {bucket}"))
            .map_err(StorageError::with(B2_STORAGE_NAME))?;

        assert_eq!(buckets.len(), 1);
        let bucket = buckets.pop().unwrap();

        let mut infos = auth!(self.b2_list_file_names(bucket.id(), Some(remote.to_string()), None))
            .await
            .with_context(|| format!("list files in {}:{remote:?}", bucket.name()))
            .map_err(StorageError::with(B2_STORAGE_NAME))?;

        if infos.len() != 1 {
            return Err(eyre!("{} files found with name {remote}", infos.len()))
                .map_err(StorageError::with(B2_STORAGE_NAME));
        }
        let info = infos.pop().unwrap();
        Ok(info.into())
    }

    async fn delete(&self, bucket: &str, remote: &Utf8Path) -> Result<(), StorageError> {
        let bucket_id = auth!(self.get_bucket(bucket))
            .await
            .with_context(|| format!("get {bucket} id"))
            .map_err(StorageError::with(B2_STORAGE_NAME))?
            .id()
            .clone();

        self.delete_file(&bucket_id, remote)
            .await
            .with_context(|| format!("delete b2://{bucket}:{remote}"))
            .map_err(StorageError::with(B2_STORAGE_NAME))?;
        Ok(())
    }

    async fn upload(
        &self,
        bucket: &str,
        remote: &Utf8Path,
        local: &mut Reader<'_>,
    ) -> Result<(), StorageError> {
        let bucket_id = auth!(self.get_bucket(bucket))
            .await
            .with_context(|| format!("get {bucket} id"))
            .map_err(StorageError::with(B2_STORAGE_NAME))?
            .id()
            .clone();

        auth!(self.upload_reader(bucket_id.clone(), local, remote, None))
            .await
            .with_context(|| format!("upload to b2://{bucket}:{remote}"))
            .map_err(StorageError::with(B2_STORAGE_NAME))?;
        Ok(())
    }

    async fn upload_file(
        &self,
        bucket: &str,
        remote: &Utf8Path,
        local: &Utf8Path,
    ) -> Result<(), StorageError> {
        let bucket_id = auth!(self.get_bucket(bucket))
            .await
            .with_context(|| format!("get {bucket} id"))
            .map_err(StorageError::with(B2_STORAGE_NAME))?
            .id()
            .clone();

        auth!(self.upload_file_from_disk(bucket_id.clone(), local, remote, None))
            .await
            .with_context(|| format!("upload to b2://{bucket}:{remote}"))
            .map_err(StorageError::with(B2_STORAGE_NAME))?;
        Ok(())
    }

    async fn download(
        &self,
        bucket: &str,
        remote: &Utf8Path,
        local: &mut Writer<'_>,
    ) -> Result<(), StorageError> {
        self.impl_download(bucket, remote, local)
            .await
            .with_context(|| format!("download from b2://{bucket}:{remote}"))
            .map_err(StorageError::with(B2_STORAGE_NAME))?;
        Ok(())
    }

    async fn list(
        &self,
        bucket: &str,
        prefix: Option<&Utf8Path>,
    ) -> Result<Vec<String>, StorageError> {
        let mut buckets = auth!(self.b2_list_buckets(String::from(bucket), None))
            .await
            .with_context(|| format!("list bucket {bucket}"))
            .map_err(StorageError::with(B2_STORAGE_NAME))?;

        assert_eq!(buckets.len(), 1);
        let bucket = buckets.pop().unwrap();

        let infos =
            auth!(self.b2_list_file_names(bucket.id(), prefix.map(|p| p.to_string()), None))
                .await
                .with_context(|| format!("list files in {}:{prefix:?}", bucket.name()))
                .map_err(StorageError::with(B2_STORAGE_NAME))?;

        Ok(infos.into_iter().map(|f| f.path().to_string()).collect())
    }
}
