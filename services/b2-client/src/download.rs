use api_client::uri::UriExtension as _;
use camino::{Utf8Path, Utf8PathBuf};
use http_body_util::BodyExt as _;
use hyperdriver::Body;

use crate::{B2Client, B2RequestError, errors::B2ResponseExt};
const B2_FILE_URL_BASE: &str = "file";

type BoxError = Box<dyn std::error::Error + Send + Sync>;

impl B2Client {
    #[tracing::instrument(level = "trace", skip(self))]
    pub(crate) async fn b2_download_file_by_name(
        &self,
        bucket: &str,
        filename: &Utf8Path,
    ) -> Result<impl futures::stream::Stream<Item = Result<bytes::Bytes, BoxError>>, B2RequestError>
    {
        let url = self.b2_download_file_by_name_url(bucket, filename);
        tracing::trace!("GET {}", url);

        let key = self
            .authorization()
            .authorization_token
            .revealed()
            .to_owned();

        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri(url)
            .header(http::header::AUTHORIZATION, key.clone())
            .body(Body::empty())
            .unwrap();

        let resp = self.client.execute(request).await?.handle_errors().await?;

        Ok(resp.into_response().into_body().into_data_stream())
    }

    pub(crate) fn b2_download_file_by_name_url(
        &self,
        bucket: &str,
        filename: &Utf8Path,
    ) -> http::Uri {
        let mut path = Utf8PathBuf::from(B2_FILE_URL_BASE);
        path.push(bucket);
        path.extend(filename);

        let url = self.authorization().download_url.clone();
        url.join(path.as_str())
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn download_url() {
        let client = B2Client::test();
        let url = client.b2_download_file_by_name_url("bucket", "path/to/my/stuff.txt".into());
        assert_eq!(
            &url.to_string(),
            "https://f999.backblazeb2.test/file/bucket/path/to/my/stuff.txt"
        );
    }
}
