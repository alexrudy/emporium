use std::sync::Arc;
use std::{fmt, ops::Deref};

use api_client::Secret;
use camino::Utf8PathBuf;
use echocache::Cached;
use serde::{Deserialize, Serialize};

use crate::{errors::B2ResponseExt, file::FileInfo, B2Client, B2RequestError};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub struct BucketID(Arc<str>);

impl BucketID {
    pub fn new<S>(id: S) -> Self
    where
        S: Into<String>,
    {
        BucketID(Arc::from(id.into()))
    }
}

impl From<String> for BucketID {
    fn from(value: String) -> Self {
        BucketID(value.into())
    }
}

impl From<BucketID> for String {
    fn from(value: BucketID) -> Self {
        value.0.deref().to_owned()
    }
}

impl fmt::Display for BucketID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<Bucket> for BucketID {
    fn from(value: Bucket) -> Self {
        value.bucket_id
    }
}

impl AsRef<BucketID> for BucketID {
    fn as_ref(&self) -> &BucketID {
        self
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bucket {
    bucket_name: String,
    bucket_id: BucketID,
    bucket_type: BucketType,
}

impl Bucket {
    #[allow(unused)]
    pub fn name(&self) -> &str {
        &self.bucket_name
    }

    pub fn id(&self) -> &BucketID {
        &self.bucket_id
    }

    pub fn kind(&self) -> &BucketType {
        &self.bucket_type
    }
}

impl AsRef<BucketID> for Bucket {
    fn as_ref(&self) -> &BucketID {
        &self.bucket_id
    }
}

pub(crate) enum SelectBucket {
    All,
    ByID(BucketID),
    ByName(String),
}

impl From<BucketID> for SelectBucket {
    fn from(value: BucketID) -> Self {
        SelectBucket::ByID(value)
    }
}

impl From<String> for SelectBucket {
    fn from(value: String) -> Self {
        SelectBucket::ByName(value)
    }
}

impl From<Bucket> for SelectBucket {
    fn from(value: Bucket) -> Self {
        SelectBucket::ByID(value.bucket_id)
    }
}

impl From<()> for SelectBucket {
    fn from(_: ()) -> Self {
        SelectBucket::All
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BucketType {
    AllPrivate,
    AllPublic,
    Snapshot,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct BucketListBody {
    account_id: Secret,
    #[serde(skip_serializing_if = "Option::is_none")]
    bucket_id: Option<BucketID>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bucket_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bucket_types: Option<Vec<BucketType>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BucketListResponse {
    buckets: Vec<Bucket>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct FileListBody {
    bucket_id: BucketID,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_file_name: Option<Utf8PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_file_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delimiter: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FileListResponse {
    files: Vec<FileInfo>,
    next_file_name: Option<Utf8PathBuf>,
}

impl B2Client {
    #[tracing::instrument(skip(self))]
    pub async fn get_bucket(&self, name: &str) -> Result<Bucket, Arc<B2RequestError>> {
        let cache = if let Some(cache) = { self.buckets.get(name).map(|r| r.value().clone()) } {
            cache
        } else {
            let cache = self
                .buckets
                .entry(name.into())
                .or_insert(Cached::new(Some(std::time::Duration::from_secs(300))));
            cache.clone()
        };

        if cache.map_cached(Result::is_err).unwrap_or(false) {
            cache.clear();
        }

        let name = name.to_owned();
        let client = self.clone();
        cache
            .get(move || {
                Box::pin(async move {
                    client
                        .b2_list_buckets(SelectBucket::ByName(name), None)
                        .await
                        .map(|mut v| v.pop().unwrap())
                        .map_err(Arc::new)
                })
            })
            .await
    }

    #[tracing::instrument(skip_all)]
    pub(crate) async fn b2_list_buckets<L: Into<SelectBucket>>(
        &self,
        select: L,
        filter: Option<&[BucketType]>,
    ) -> Result<Vec<Bucket>, B2RequestError> {
        tracing::trace!("request");

        let bucket_select: SelectBucket = select.into();

        let (bucket_id, bucket_name) = match bucket_select {
            SelectBucket::All => (None, None),
            SelectBucket::ByID(id) => (Some(id), None),
            SelectBucket::ByName(name) => (None, Some(name)),
        };

        let body = BucketListBody {
            account_id: self.authorization().account_id.clone(),
            bucket_id,
            bucket_name,
            bucket_types: filter.map(|f| f.to_vec()),
        };

        tracing::trace!("body: {body:?}");

        let request = self.authorization().post("b2_list_buckets", &body);

        let buckets: BucketListResponse = self
            .client
            .execute(request)
            .await
            .map_err(B2RequestError::Client)?
            .deserialize()
            .await?;

        Ok(buckets.buckets)
    }

    #[tracing::instrument(skip_all, fields(bucket=%bucket.as_ref()))]
    pub(crate) async fn b2_list_file_names<B: AsRef<BucketID>>(
        &self,
        bucket: B,
        prefix: Option<String>,
        delimiter: Option<String>,
    ) -> Result<Vec<FileInfo>, B2RequestError> {
        tracing::trace!("starting request");

        let mut body = FileListBody {
            bucket_id: bucket.as_ref().clone(),
            start_file_name: None,
            max_file_count: Some(1000),
            prefix,
            delimiter,
        };
        let mut infos = Vec::new();

        loop {
            let request = self.authorization().post("b2_list_file_names", &body);
            let resp = self.client.execute(request).await?;

            let file_list: FileListResponse = resp.deserialize().await?;

            infos.extend(file_list.files);

            match file_list.next_file_name {
                Some(name) => body.start_file_name = Some(name),
                None => break,
            };
        }

        Ok(infos)
    }
}

#[cfg(test)]
mod tests {
    use hyperdriver::client::DowncastError;
    use hyperdriver::service::SharedService;
    use serde_json::json;

    use crate::application::B2Authorization;
    use crate::B2ApplicationKey;

    use super::*;

    #[tokio::test]
    async fn cache_get_bucket() {
        let mut mock = api_client::mock::MockService::new();
        mock.add(
            "/b2api/v2/b2_list_buckets",
            http::StatusCode::OK,
            http::HeaderMap::new(),
            serde_json::to_vec(&json! {
                {
                    "buckets": [
                        {
                            "bucketId": "test",
                            "bucketName": "test",
                            "bucketType": "allPrivate"
                        }
                    ]
                }
            })
            .unwrap(),
        );

        let client = B2Client::from_client_and_authorization(
            SharedService::new(DowncastError::new(mock)),
            B2Authorization::test(),
            B2ApplicationKey::test(),
        );

        let bucket = client.get_bucket("test").await.unwrap();
        assert_eq!(bucket.name(), "test");

        let bucket = client.get_bucket("test").await.unwrap();
        assert_eq!(bucket.name(), "test");
    }
}
