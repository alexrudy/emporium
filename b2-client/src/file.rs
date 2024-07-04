use std::fmt;
use std::ops::Deref;
use std::sync::Arc;

use api_client::Secret;
use camino::{Utf8Path, Utf8PathBuf};
use chrono::{TimeZone, Utc};
use serde::{Deserialize, Serialize};
use storage_driver::Metadata;

use crate::bucket::BucketID;
use crate::{errors::B2ResponseExt, B2Client, B2RequestError};

pub use self::mime::BzMime;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(from = "String", into = "String")]
pub struct FileID(Arc<str>);

impl fmt::Display for FileID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<String> for FileID {
    fn from(value: String) -> Self {
        FileID(value.into())
    }
}

impl From<FileID> for String {
    fn from(value: FileID) -> Self {
        value.0.deref().to_owned()
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Start,
    Upload,
    Hide,
    Folder,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(unused)]
#[serde(rename_all = "camelCase")]
pub struct FileInfo {
    account_id: Secret,
    action: Action,
    bucket_id: BucketID,
    content_length: usize,
    // content_sha1: Option<Sha1>,
    content_type: BzMime,
    file_id: FileID,
    file_name: Utf8PathBuf,
    upload_timestamp: u64,
}

impl FileInfo {
    pub fn path(&self) -> &Utf8Path {
        &self.file_name
    }

    #[allow(unused)]
    pub fn id(&self) -> &FileID {
        &self.file_id
    }
}

impl From<FileInfo> for Metadata {
    fn from(value: FileInfo) -> Self {
        Metadata {
            size: value
                .content_length
                .try_into()
                .expect("File size larger than u64"),
            created: Utc
                .timestamp_millis_opt(
                    value
                        .upload_timestamp
                        .try_into()
                        .expect("timestamp overflow"),
                )
                .single()
                .expect("Invalid timestamp"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[allow(unused)]
#[serde(rename_all = "camelCase")]
struct FileDeleteRequest<'f> {
    file_name: &'f Utf8Path,
    file_id: &'f FileID,
    #[serde(skip_serializing_if = "Option::is_none")]
    bypass_governance: Option<bool>,
}

impl B2Client {
    #[tracing::instrument(skip_all, fields(%name))]
    pub(crate) async fn b2_delete_file_version(
        &self,
        name: &Utf8Path,
        id: &FileID,
    ) -> Result<(), B2RequestError> {
        let body = FileDeleteRequest {
            file_name: name,
            file_id: id,
            bypass_governance: None,
        };

        let req = self.authorization().post("b2_delete_file_version", &body);

        self.client.execute(req).await?.handle_errors().await?;

        Ok(())
    }

    #[tracing::instrument(skip(self, bucket), fields(bucket=%bucket.as_ref()))]
    pub async fn delete_file<B: AsRef<BucketID>>(
        &self,
        bucket: B,
        name: &Utf8Path,
    ) -> Result<(), B2RequestError> {
        let files = self
            .b2_list_file_names(bucket, Some(name.to_string()), Some("/".into()))
            .await?;

        if files.is_empty() {
            tracing::warn!("No files found to delete");
        }
        //TODO: Consider parallelizing this?
        for file in files.into_iter().filter(|file| file.path() == name) {
            tracing::trace!(id = ?file.id(), "Deleting file");
            self.b2_delete_file_version(file.path(), file.id()).await?;
        }

        Ok(())
    }
}

mod mime {

    use std::fmt;
    use std::str::FromStr;

    use serde::{de, ser};
    use thiserror::Error;

    #[derive(Debug, Clone, Error)]
    #[error("Invalid MIME type: {0}")]
    pub struct Invalid(String);

    #[derive(Debug, Clone)]
    pub enum BzMime {
        Auto,
        Hide,
        Mime(mime::Mime),
        Custom(String),
    }

    impl fmt::Display for BzMime {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                BzMime::Auto => write!(f, "b2/x-auto"),
                BzMime::Hide => write!(f, "application/x-bz-hide-marker"),
                BzMime::Mime(mime) => write!(f, "{}", mime),
                BzMime::Custom(s) => write!(f, "{}", s),
            }
        }
    }

    impl FromStr for BzMime {
        type Err = Invalid;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            if let Ok(mime) = mime::Mime::from_str(s) {
                return Ok(BzMime::Mime(mime));
            }

            match s {
                "application/x-bz-hide-marker" => return Ok(BzMime::Hide),
                "b2/x-auto" => return Ok(BzMime::Auto),
                _ => {
                    if s.contains('/') {
                        return Ok(BzMime::Custom(s.into()));
                    }
                }
            }

            Err(Invalid(s.into()))
        }
    }

    impl ser::Serialize for BzMime {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_str(&self.to_string())
        }
    }

    impl<'de> de::Deserialize<'de> for BzMime {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            struct Visitor;

            impl<'de> de::Visitor<'de> for Visitor {
                type Value = BzMime;

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("a sha1 hex digest")
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    BzMime::from_str(v).map_err(|e| de::Error::custom(e))
                }
            }

            deserializer.deserialize_str(Visitor)
        }
    }
}
