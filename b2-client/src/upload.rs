use std::io;
use std::ops::Deref;
use std::sync::Arc;

use bytes::Bytes;
use camino::Utf8PathBuf;
use futures::FutureExt;
use http::StatusCode;
use storage_driver::Reader;
use tokio::io::AsyncReadExt;
use tokio::task::JoinHandle;

use api_client::Secret;
use camino::Utf8Path;
use http::Uri;
use hyperdriver::Body;
use percent_encoding::utf8_percent_encode;
use serde::{Deserialize, Serialize};
use sha1::Digest as _;
use tracing::Instrument;

use crate::application::B2Authorization;
use crate::file::FileID;
use crate::file::{BzMime, FileInfo};
use crate::{bucket::BucketID, errors::B2ResponseExt, B2Client, B2RequestError};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GetUploadUrlBody {
    bucket_id: BucketID,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct StartLargeFileBody {
    bucket_id: BucketID,
    file_name: Utf8PathBuf,
    content_type: BzMime,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GetUploadPartUrlBody {
    file_id: FileID,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BucketUploadInfo {
    #[serde(with = "api_client::uri::serde")]
    upload_url: Uri,
    authorization_token: Secret,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Action {
    Start,
    Upload,
    Hide,
    Folder,
}

#[derive(Debug, Clone, Deserialize)]
struct UploadFileResponse {
    action: Action,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct FinishLargeFileBody<'s> {
    file_id: FileID,
    part_sha1_array: &'s [[u8; 20]],
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct CancelLargeFileBody {
    file_id: FileID,
}

pub struct FileDigest {
    digest: [u8; 20],
    content_length: usize,
}

impl FileDigest {
    pub fn new(digest: [u8; 20], content_length: usize) -> Self {
        Self {
            digest,
            content_length,
        }
    }

    pub fn content_length(&self) -> usize {
        self.content_length
    }
}

impl FileDigest {
    pub fn digest(&self) -> &[u8] {
        &self.digest
    }
}

pub fn digest<R: io::Read>(mut rdr: R) -> io::Result<FileDigest> {
    let mut digest = sha1::Sha1::new();
    let mut length = 0;
    loop {
        let mut buf = [0; 1024];
        let to_consume = rdr.read(&mut buf)?;
        if to_consume == 0 {
            break;
        }
        length += to_consume;
        digest.update(&buf[..to_consume]);
    }

    let d: [u8; 20] = digest.finalize().into();

    Ok(FileDigest::new(d, length))
}

/// Upload state for a single upload request.
///
/// B2 uploads are a multi-step process, this struct tracks the URL and authorization
/// token which should be used for a single upload.
#[derive(Debug)]
pub struct B2Uploader {
    client: api_client::ApiClient<B2Authorization>,
    info: BucketUploadInfo,
}

impl B2Uploader {
    pub(crate) async fn b2_upload_file(
        &self,
        file: Body,
        filename: &Utf8Path,
        content_type: Option<mime::Mime>,
        content_length: usize,
        content_sha: &[u8],
    ) -> Result<(), B2RequestError> {
        let encoded_name =
            utf8_percent_encode(filename.as_str(), percent_encoding::NON_ALPHANUMERIC);

        tracing::trace!("sending upload post request");
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri(self.info.upload_url.clone())
            .header(
                http::header::AUTHORIZATION,
                self.info.authorization_token.to_header().unwrap(),
            )
            .header("X-Bz-File-Name", encoded_name.to_string())
            .header(
                http::header::CONTENT_TYPE,
                content_type
                    .as_ref()
                    .map(|m| m.as_ref())
                    .unwrap_or_else(|| "b2/x-auto"),
            )
            .header(http::header::CONTENT_LENGTH, content_length)
            .header("X-Bz-Content-Sha1", hex::encode(content_sha))
            .body(file)
            .expect("Failed to build upload request");

        let response = self.client.execute(request).await?;

        let info: UploadFileResponse = response.deserialize().await?;

        assert!(
            matches!(info.action, Action::Upload),
            "Unexpected action returned: {info:?}"
        );

        Ok(())
    }

    pub(crate) async fn b2_upload_part<P>(
        &self,
        part: P,
        part_number: usize,
        content_length: usize,
        content_sha: &[u8],
    ) -> Result<(), B2RequestError>
    where
        P: Into<Body>,
    {
        tracing::trace!("sending upload_part post request");

        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri(self.info.upload_url.clone())
            .header(
                http::header::AUTHORIZATION,
                self.info.authorization_token.to_header().unwrap(),
            )
            .header(http::header::CONTENT_LENGTH, content_length)
            .header("X-Bz-Part-Number", part_number)
            .header("X-Bz-Content-Sha1", hex::encode(content_sha))
            .body(part.into())
            .expect("Failed to build upload request");

        let _ = self.client.execute(request).await?;

        Ok(())
    }
}

impl B2Client {
    #[tracing::instrument(skip(self))]
    async fn b2_get_upload_url(&self, bucket: BucketID) -> Result<B2Uploader, B2RequestError> {
        tracing::trace!("requesting uploader");

        let body = GetUploadUrlBody { bucket_id: bucket };

        let req = self.authorization().post("b2_get_upload_url", &body);
        let resp = self.client.execute(req).await?;

        let info: BucketUploadInfo = resp.deserialize().await?;
        Ok(B2Uploader {
            client: self.client.clone(),
            info,
        })
    }

    #[tracing::instrument(skip_all, fields(file=%file))]
    async fn b2_get_upload_part_url(&self, file: FileID) -> Result<B2Uploader, B2RequestError> {
        tracing::trace!("requesting part uploader");

        let body = GetUploadPartUrlBody { file_id: file };

        let req = self.authorization().post("b2_get_upload_part_url", &body);
        let resp = self.client.execute(req).await?;

        let info: BucketUploadInfo = resp.deserialize().await?;
        Ok(B2Uploader {
            client: self.client.clone(),
            info,
        })
    }

    #[tracing::instrument(skip(self))]
    async fn b2_start_large_file(
        &self,
        bucket: BucketID,
        filename: &Utf8Path,
        mime: Option<mime::Mime>,
    ) -> Result<FileInfo, B2RequestError> {
        let body = StartLargeFileBody {
            bucket_id: bucket,
            file_name: filename.to_owned(),
            content_type: mime.map_or(BzMime::Auto, BzMime::Mime),
        };

        let req = self.authorization().post("b2_start_large_file", &body);
        let resp = self.client.execute(req).await?;

        let info: FileInfo = resp.deserialize().await?;

        Ok(info)
    }

    #[tracing::instrument(skip_all, fields(file=%info.id()))]
    async fn b2_finish_large_file(
        &self,
        info: &FileInfo,
        shas: &[[u8; 20]],
    ) -> Result<(), B2RequestError> {
        let body = FinishLargeFileBody {
            file_id: info.id().clone(),
            part_sha1_array: shas,
        };

        let req = self.authorization().post("b2_finish_large_file", &body);
        let resp = self.client.execute(req).await?;

        let info: FileInfo = resp.deserialize().await?;
        tracing::debug!(file=?info.id(), "finished large file upload");

        Ok(())
    }

    #[tracing::instrument(skip_all, fields(file=%info.id()))]
    async fn b2_cancel_large_file(&self, info: &FileInfo) -> Result<(), B2RequestError> {
        let body = CancelLargeFileBody {
            file_id: info.id().clone(),
        };

        let req = self.authorization().post("b2_cancel_large_file", &body);
        let resp = self.client.execute(req).await?;

        let info: FileInfo = resp.deserialize().await?;
        tracing::debug!(file=?info.id(), "cancelled large file upload");

        Ok(())
    }

    #[tracing::instrument("part", skip_all, fields(part=%part))]
    async fn upload_part_inner(
        &self,
        semaphore: Arc<tokio::sync::Semaphore>,
        mut file: &mut Reader<'_>,
        part: usize,
        part_size: usize,
        info: &FileInfo,
    ) -> Result<Option<JoinHandle<Result<FileDigest, B2RequestError>>>, B2RequestError> {
        let permit = semaphore.clone().acquire_owned().await.unwrap();

        tracing::trace!("Gathering chunk");
        let mut buffer = Vec::with_capacity(part_size);
        let mut chunk = (&mut file).take(part_size as u64);

        tokio::io::copy_buf(&mut chunk, &mut buffer).await?;

        while buffer.len() < part_size {
            if chunk.read_buf(&mut buffer).await? == 0 {
                break;
            }
        }

        if buffer.is_empty() {
            tracing::trace!("Empty buffer, breaking");
            return Ok(None);
        }

        tracing::trace!("Preparing upload");
        let retries = self.uploads.retries;
        let file_id = info.id().clone();
        let mut uploader = self.b2_get_upload_part_url(file_id.clone()).await?;
        let client = self.clone();
        tracing::trace!("Spawning upload");
        let handle = tokio::spawn(
            async move {
                tracing::trace!("digesting");
                let buffer = bytes::Bytes::from(buffer);
                let digest = tokio::task::spawn_blocking({
                    let buffer = buffer.clone();
                    move || digest(&buffer as &[u8])
                })
                .in_current_span()
                .await
                .expect("blocking thread")?;

                for attempt in 1..=retries {
                    tracing::trace!(%attempt, "uploading part");
                    let body = hyperdriver::Body::from(buffer.clone());
                    match uploader
                        .b2_upload_part(body, part, digest.content_length(), digest.digest())
                        .await
                    {
                        Ok(()) => {
                            return Ok::<_, B2RequestError>(digest);
                        }
                        // Err(B2RequestError::Request(error)) if error.is_timeout() => {
                        //     uploader.increase_timeout();
                        // }
                        Err(B2RequestError::B2(error))
                            if error.status_code() == StatusCode::SERVICE_UNAVAILABLE =>
                        {
                            tokio::time::sleep(std::time::Duration::from_secs(attempt as u64))
                                .await;
                            uploader = client.b2_get_upload_part_url(file_id.clone()).await?;
                        }
                        Err(error) => return Err(error),
                    };
                }

                drop(permit);
                Err(B2RequestError::RetriesExhausted)
            }
            .in_current_span(),
        );
        Ok(Some(handle))
    }

    async fn upload_multipart_inner(
        &self,
        file: &mut Reader<'_>,
        filename: &Utf8Path,
        part_size: usize,
        info: &FileInfo,
        content_length: usize,
    ) -> Result<(), B2RequestError> {
        tracing::debug!("File {filename} is larger than 1GB, using large file upload");

        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.uploads.concurrency));
        let parts = (content_length / part_size) + 1;

        let mut handles = Vec::with_capacity(parts);

        for part in 1..=parts {
            let handle = self
                .upload_part_inner(semaphore.clone(), file, part, part_size, info)
                .await?;
            if let Some(handle) = handle {
                handles.push(handle.map(|r| match r {
                    Ok(Ok(sha)) => Ok(sha),
                    Ok(Err(error)) => Err(error),
                    Err(_) => panic!("upload task paniced"),
                }));
            }
        }

        semaphore.close();

        tracing::trace!("Waiting for uploads to complete");
        let digests = futures::future::try_join_all(handles).await?;
        let parts_uploaded = digests.len();
        tracing::debug!("Uploaded {filename} in {parts_uploaded} parts");

        let shas: Vec<[u8; 20]> = digests.iter().map(|d| d.digest).collect();

        self.b2_finish_large_file(info, &shas).await?;

        Ok(())
    }

    pub(crate) async fn upload_inner(
        &self,
        bucket: BucketID,
        file: &mut Reader<'_>,
        filename: &Utf8Path,
        content_type: Option<mime::Mime>,
        content_length: usize,
        content_sha: &[u8],
    ) -> Result<(), B2RequestError> {
        let part_size = self.authorization().recommended_part_size();
        let parts = (content_length / part_size) + 1;

        if content_length >= crate::B2_LARGE_FILE_SIZE && parts > 1 {
            self.upload_large_file(bucket, file, filename, content_type, content_length)
                .await
        } else {
            tracing::trace!("upload as single part");

            let mut uploader = self.b2_get_upload_url(bucket.clone()).await?;

            let body: Bytes = {
                let mut body = Vec::with_capacity(content_length);
                file.read_to_end(&mut body).await?;
                body.into()
            };

            for attempt in 1..=self.uploads.retries {
                tracing::trace!(%attempt, "uploading");

                match uploader
                    .b2_upload_file(
                        body.clone().into(),
                        filename,
                        content_type.clone(),
                        content_length,
                        content_sha,
                    )
                    .await
                {
                    Ok(()) => {
                        return Ok(());
                    }
                    Err(B2RequestError::B2(error))
                        if error.status_code() == StatusCode::SERVICE_UNAVAILABLE =>
                    {
                        tracing::debug!("Re-trying upload, service was not available");
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        uploader = self.b2_get_upload_url(bucket.clone()).await?;
                    }
                    Err(error) => {
                        return Err(error);
                    }
                }
            }
            Err(B2RequestError::RetriesExhausted)
        }
    }

    #[tracing::instrument(skip_all, fields(%bucket, remote=%filename.file_name().unwrap()))]
    pub(crate) async fn upload_reader(
        &self,
        bucket: BucketID,
        reader: &mut Reader<'_>,
        filename: &Utf8Path,
        content_type: Option<mime::Mime>,
    ) -> Result<(), B2RequestError> {
        let buffer = {
            let mut buffer = Vec::new();
            reader.read_to_end(&mut buffer).await?;
            bytes::Bytes::from(buffer)
        };

        let digest = tokio::task::spawn_blocking({
            let buffer = buffer.clone();
            move || digest(&buffer as &[u8])
        })
        .in_current_span()
        .await
        .expect("blocking thread")?;

        let mut reader = tokio::io::BufReader::new(buffer.deref());

        self.upload_inner(
            bucket,
            &mut reader,
            filename,
            content_type,
            digest.content_length(),
            digest.digest(),
        )
        .await
    }

    #[tracing::instrument(skip_all, fields(%bucket, local=%local.file_name().unwrap(), remote=%remote.file_name().unwrap()))]
    pub(crate) async fn upload_file_from_disk(
        &self,
        bucket: BucketID,
        local: &Utf8Path,
        remote: &Utf8Path,
        content_type: Option<mime::Mime>,
    ) -> Result<(), B2RequestError> {
        tracing::trace!("Computing SHA1 file digest");
        let filename = local.to_owned();
        let digest = tokio::task::spawn_blocking(move || {
            let file = std::fs::File::open(filename).expect("open file");
            let mut rdr = io::BufReader::new(file);
            digest(&mut rdr).expect("digest")
        })
        .in_current_span()
        .await
        .expect("blocking thread");

        tracing::trace!("Preparing reader stream for send");
        let mut file = tokio::io::BufReader::new(tokio::fs::File::open(local).await.unwrap());

        tracing::trace!("uploading");
        self.upload_inner(
            bucket,
            &mut file,
            remote,
            content_type,
            digest.content_length(),
            digest.digest(),
        )
        .await?;

        Ok(())
    }

    /// Upload a large file using the B2 API
    #[tracing::instrument(skip_all, fields(%bucket, remote=%filename.file_name().unwrap()))]
    pub async fn upload_large_file(
        &self,
        bucket: BucketID,
        file: &mut Reader<'_>,
        filename: &Utf8Path,
        content_type: Option<mime::Mime>,
        content_length: usize,
    ) -> Result<(), B2RequestError> {
        tracing::trace!("Multi-part upload");

        let info = self
            .b2_start_large_file(bucket, filename, content_type)
            .await?;

        tracing::info!(file=?info.id(), "Multi-part upload");

        match self
            .upload_multipart_inner(
                file,
                filename,
                self.authorization().recommended_part_size(),
                &info,
                content_length,
            )
            .await
        {
            Ok(_) => {
                tracing::info!(file=?info.id(), "Finished multi-part upload");
                Ok(())
            }
            Err(error) => {
                tracing::error!(file=?info.id(), "Error during multi-part upload: {error}");

                let _ = self.b2_cancel_large_file(&info).await;

                Err(error)
            }
        }
    }
}
