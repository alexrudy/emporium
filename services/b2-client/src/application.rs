use std::env::VarError;
use std::fmt;

use api_client::response::ResponseBodyExt as _;
use api_client::uri::UriExtension as _;
use api_client::{RequestExt as _, Secret};
use http::{HeaderValue, Method};
use http::{Request, StatusCode, Uri};
use hyperdriver::service::ServiceExt;
use hyperdriver::Body;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::errors::B2Error;
use crate::{B2Client, B2RequestError};

const B2_APPLICATION_URL: &str = "https://api.backblazeb2.com/b2api/v2/b2_authorize_account";
const B2_KEY_ID_ENV: &str = "B2_KEY_ID";
const B2_KEY_ENV: &str = "B2_KEY";

#[derive(Debug, Error)]
pub enum AuthenticationErrorKind {
    #[error(transparent)]
    Client(#[from] api_client::Error),

    #[error("deserialization error: {0}")]
    Deserialization(#[source] serde_json::Error, String),

    #[error("body error: {0}")]
    Body(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error(transparent)]
    BadRequest(B2Error),

    #[error(transparent)]
    Unauthorized(B2Error),

    #[error("Unauthorized for bucket {0}")]
    UnauthorizedBucket(Box<str>),
}

#[derive(Debug, Error)]
#[error("{kind}")]
pub struct AuthenticationError {
    #[from]
    pub(crate) kind: AuthenticationErrorKind,
}

impl AuthenticationError {
    pub fn kind(&self) -> &AuthenticationErrorKind {
        &self.kind
    }
}

impl From<B2RequestError> for AuthenticationErrorKind {
    fn from(value: B2RequestError) -> Self {
        match value {
            B2RequestError::Serde(_, _) => panic!("{value}"),
            B2RequestError::B2(error) => error.into(),
            B2RequestError::NoCredentials(bucket) => {
                AuthenticationErrorKind::UnauthorizedBucket(bucket.into())
            }
            _ => panic!("{value}"),
        }
    }
}

impl From<B2Error> for AuthenticationErrorKind {
    fn from(value: B2Error) -> Self {
        match value.status_code() {
            StatusCode::BAD_REQUEST => AuthenticationErrorKind::BadRequest(value),
            StatusCode::UNAUTHORIZED => AuthenticationErrorKind::Unauthorized(value),
            _ => panic!("Unexpected error status code: {value}"),
        }
    }
}

/// B2 Application Key, which consists of an ID and a secret key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct B2ApplicationKey {
    key_id: Secret,
    key: Secret,
}

impl B2ApplicationKey {
    /// Create a new B2 Application Key.
    pub fn new(key_id: Secret, key: Secret) -> Self {
        if !key_id.revealed().starts_with('0') {
            tracing::warn!("B2 key id does not start with 0");
        }

        if !key.revealed().starts_with('K') {
            tracing::warn!("B2 key does not start with K");
        }

        Self { key_id, key }
    }

    /// Load the B2 Application Key from the environment.
    pub fn from_env() -> Result<Self, VarError> {
        let key_id = Secret::from_env(B2_KEY_ID_ENV)?;
        let key = Secret::from_env(B2_KEY_ENV)?;

        Ok(B2ApplicationKey::new(key_id, key))
    }

    #[cfg(test)]
    pub(crate) fn test() -> Self {
        B2ApplicationKey::new(
            Secret::from("001B2-key-id-test"),
            Secret::from("K001B2-key-test"),
        )
    }

    /// Get the Key, this is the secret part of the authentication pair.
    pub fn key(&self) -> &Secret {
        &self.key
    }

    /// Get the key ID, this is the less secret part of the authentication pair.
    pub fn key_id(&self) -> &Secret {
        &self.key_id
    }
}

/// Represents the authorization response from the B2 API.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct B2Authorization {
    pub(crate) account_id: Secret,
    pub(crate) authorization_token: Secret,

    #[serde(with = "api_client::uri::serde")]
    pub(crate) api_url: Uri,
    #[serde(with = "api_client::uri::serde")]
    pub(crate) download_url: Uri,
    pub(crate) recommended_part_size: u64,
}

impl fmt::Debug for B2Authorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("B2Authorization")
            .field("account_id", &self.account_id)
            .field("authorization_token", &self.authorization_token)
            .field("api_url", &self.api_url.clone().to_string())
            .field("download_url", &self.download_url.clone().to_string())
            .finish()
    }
}

impl B2Authorization {
    #[cfg(test)]
    pub(crate) fn test() -> Self {
        B2Authorization {
            account_id: Secret::from("b2_account_id"),
            authorization_token: Secret::from("b2_authorization_token"),
            api_url: "https://api.backblazeb2.test".parse().unwrap(),
            download_url: "https://f999.backblazeb2.test".parse().unwrap(),
            recommended_part_size: 1024 * 1024 * 100, // 100MB
        }
    }

    fn endpoint(&self, name: &str) -> Uri {
        self.api_url.clone().join(format!("b2api/v2/{name}"))
    }

    fn authorize(&self, req: &mut Request<Body>) {
        if !req.headers().contains_key(http::header::AUTHORIZATION) {
            let hdrs = req.headers_mut();
            let mut value: HeaderValue = self
                .authorization_token
                .revealed()
                .try_into()
                .expect("authorization should be a valid http header value");

            value.set_sensitive(true);

            hdrs.insert(http::header::AUTHORIZATION, value);
        }
    }

    pub(crate) fn recommended_part_size(&self) -> usize {
        self.recommended_part_size as usize
    }

    #[allow(dead_code)]
    pub(crate) fn get(&self, name: &str) -> Request<Body> {
        let url = self.endpoint(name);
        tracing::trace!("GET {}", url);

        let mut req = Request::builder()
            .method(Method::GET)
            .version(http::Version::HTTP_11)
            .uri(url)
            .body(Body::empty())
            .unwrap();
        self.authorize(&mut req);

        req
    }

    pub(crate) fn post<T: Serialize>(&self, name: &str, body: &T) -> Request<Body> {
        let url = self.endpoint(name);
        tracing::trace!("POST {}", url);

        let mut req = Request::builder()
            .method(Method::POST)
            .version(http::Version::HTTP_11)
            .uri(url)
            .body(
                serde_json::to_string(body)
                    .expect("Serialize body to JSON")
                    .into(),
            )
            .unwrap();
        self.authorize(&mut req);

        req
    }
}

impl api_client::Authentication for B2Authorization {
    fn authenticate<B>(&self, mut req: http::Request<B>) -> http::Request<B> {
        if !req.headers().contains_key(http::header::AUTHORIZATION) {
            let hdrs = req.headers_mut();
            let mut value: HeaderValue = self
                .authorization_token
                .revealed()
                .try_into()
                .expect("authorization should be a valid http header value");

            value.set_sensitive(true);

            hdrs.insert(http::header::AUTHORIZATION, value);
        }

        req
    }
}

impl B2ApplicationKey {
    async fn client_inner(self) -> Result<B2Client, AuthenticationErrorKind> {
        let mut builder = hyperdriver::Client::build_tcp_http();
        let tcp = builder.transport();

        tcp.config_mut().connect_timeout = Some(crate::B2_DEFAULT_CONNECT_TIMEOUT);

        let mut client = builder
            .with_timeout(crate::B2_DEFAULT_TIMEOUT)
            .build_service();

        let auth = self.fetch_authorization(&mut client).await?;
        Ok(B2Client::from_client_and_authorization(client, auth, self))
    }

    pub(crate) async fn fetch_authorization<S>(
        &self,
        client: &mut S,
    ) -> Result<B2Authorization, AuthenticationErrorKind>
    where
        S: tower::Service<
                http::Request<Body>,
                Response = http::Response<Body>,
                Error = hyperdriver::client::Error,
            > + Clone
            + Send
            + 'static,
        S::Future: Send + 'static,
    {
        if !self.key_id.revealed().starts_with("001") {
            tracing::warn!("B2 key id does not start with 001");
        }

        if !self.key.revealed().starts_with("K001") {
            tracing::warn!("B2 key does not start with K001");
        }

        let request = http::Request::builder()
            .method(Method::GET)
            .version(http::Version::HTTP_11)
            .uri(B2_APPLICATION_URL)
            .basic_auth(self.key_id.revealed(), Some(self.key.revealed()))
            .body(Body::empty())
            .unwrap();

        let resp = client
            .oneshot(request)
            .await
            .map_err(api_client::Error::Request)?;

        let text = resp.text().await.map_err(AuthenticationErrorKind::Body)?;
        let auth = serde_json::from_str(&text)
            .map_err(|error| AuthenticationErrorKind::Deserialization(error, text))?;

        tracing::trace!("Got B2 Authorization: {:#?}", auth);
        Ok(auth)
    }

    /// Fetch a new authorization and create a client which can use that authorization
    /// to make API calls.
    pub async fn client(self) -> Result<B2Client, AuthenticationError> {
        let client = self.client_inner().await?;
        Ok(client)
    }
}
