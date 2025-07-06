//! Simple client for using oAuth applications with the Github API.

use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;
use std::process::Output;
use std::sync::{Arc, RwLock};

use api_client::response::ResponseBodyExt;
use api_client::{ApiClient, RequestExt, Secret};

use http::HeaderValue;
use hyperdriver::client::conn::transport::tcp::TcpTransportConfig;
use hyperdriver::service::ServiceExt as _;
use jaws::claims::{Claims, RegisteredClaims};
use jaws::crypto::{rsa, signature};
use jaws::token::{Token, TokenFormattingError, TokenSigningError};

use http::header;
use hyperdriver::{Body, Client};
use models::InstallationAccess;
use rsa::sha2::Sha256;
use thiserror::Error;

pub mod config;
pub mod models;

pub use crate::config::GithubAppConfig;

const CLOCK_DRIFT_OFFSET_SECONDS: i64 = 60;
const TOKEN_DURATION_SECONDS: i64 = 5 * 60;
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
const GITHUB_ACCEPT: &str = "application/vnd.github+json";
const GITHUB_API_VERSION: &str = "2022-11-28";
const GITHUB_API_VERSION_HEADER: &str = "X-GitHub-Api-Version";
const GITHUB_BASE: &str = "https://api.github.com/";
const GITHUB_LIST_INSTALLATIONS: &str = "https://api.github.com/app/installations";

/// Errors that can occur when using the Github client.
#[derive(Debug, Error)]
pub enum Error {
    /// An error that occurs when sending a request.
    #[error("Sending request: {0}")]
    Request(#[from] hyperdriver::client::Error),

    /// An error that occurs when signing or verifying a JWT token.
    #[error("Signature: {0}")]
    Signature(#[from] signature::Error),

    /// An error that occurs when serializing or deserializing a model.
    #[error("Model: {0}")]
    Serde(#[from] serde_json::Error),

    /// A response not in the 200-299 range.
    #[error("Response: {0}")]
    Response(#[from] ResponseError),

    /// An error that occurs when receiving a response body.
    #[error("Receiving body: {0}")]
    Body(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// An error occured when interacting with the filesystem.
    #[error("IO: {0}")]
    IO(#[from] std::io::Error),

    /// An error occured when encoding or decoding data from the OS
    #[error("Encoding: {0}")]
    OsEncoding(#[from] std::string::FromUtf8Error),
}

impl From<TokenSigningError> for Error {
    fn from(err: TokenSigningError) -> Self {
        match err {
            TokenSigningError::Signing(err) => err.into(),
            TokenSigningError::Serialization(err) => err.into(),
        }
    }
}

impl From<TokenFormattingError> for Error {
    fn from(value: TokenFormattingError) -> Self {
        match value {
            TokenFormattingError::Serialization(error) => error.into(),
            TokenFormattingError::IO(_) => panic!("a formatting error occured"),
        }
    }
}

/// An error that occurs when a response is not successful.
#[derive(Debug, Clone, Error)]
#[error("Response error: {status:?} {body}")]
pub struct ResponseError {
    status: http::StatusCode,
    body: String,
}

impl ResponseError {
    async fn from_response(response: http::Response<Body>) -> Self {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        Self { status, body }
    }
}

#[derive(Clone)]
struct GithubCredentialHelperSettings {
    credentials: PathBuf,
    existing_global_setting: Option<String>,
}

/// A guard struct to restore git credentials when dropped.
pub struct GithubCredentialsHelper {
    settings: GithubCredentialHelperSettings,
    tx: Option<tokio::sync::oneshot::Sender<()>>,
}

async fn run(command: &mut tokio::process::Command) -> Result<Output, std::io::Error> {
    let output = command.output().await?;
    if !output.status.success() {
        tracing::error!("Git command failed: {:?}", output);
    }

    Ok(output)
}

impl GithubCredentialsHelper {
    /// Set the current credenetials to be used by git.
    pub async fn new(path: impl Into<PathBuf>, credential: &Secret) -> Result<Self, Error> {
        let path = path.into();
        let contents = format!(
            "https://x-access-token:{}@github.com\n",
            credential.revealed()
        );

        tokio::fs::write(&path, contents).await?;
        run(tokio::process::Command::new("chmod").arg("600").arg(&path)).await?;

        let output = tokio::process::Command::new("git")
            .args(["config", "get", "--global", "credential.helper"])
            .output()
            .await?;

        let credential_helper = if output.status.success() {
            Some(String::from_utf8(output.stdout)?.trim().to_owned())
        } else {
            None
        };

        let mut setting = OsString::from("store --file ".to_string());
        setting.push(&path);

        run(tokio::process::Command::new("git")
            .args(["config", "--global", "credential.helper"])
            .arg(setting))
        .await?;

        let (tx, rx) = tokio::sync::oneshot::channel();

        let settings = GithubCredentialHelperSettings {
            credentials: path,
            existing_global_setting: credential_helper,
        };

        let guard = GithubCredentialsHelper {
            settings: settings.clone(),
            tx: Some(tx),
        };

        tokio::task::spawn(async move {
            if rx.await.is_err() {
                tracing::error!("No signal to restore git credentials, connection dropped");
            }

            if let Err(error) = tokio::fs::remove_file(&settings.credentials).await {
                tracing::error!("Failed to remove github app git credentials: {}", error);
            }

            let output = if let Some(existing) = &settings.existing_global_setting {
                tokio::process::Command::new("git")
                    .args(["config", "--global", "credential.helper"])
                    .arg(existing)
                    .output()
                    .await
            } else {
                tokio::process::Command::new("git")
                    .args(["config", "--global", "--unset", "credential.helper"])
                    .output()
                    .await
            };

            match output {
                Err(error) => {
                    tracing::error!(?settings.existing_global_setting, "Failed to restore git credentials config: {}", error)
                }
                Ok(output) if !output.status.success() => {
                    tracing::error!(?settings.existing_global_setting, "Failed to restore git credentials config: {:?}", output)
                }
                _ => {}
            }
        });

        Ok(guard)
    }
}

impl fmt::Debug for GithubCredentialsHelper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GithubCredentialsHelper")
            .field("credentials", &self.settings.credentials)
            .field(
                "existing_global_setting",
                &self.settings.existing_global_setting,
            )
            .finish()
    }
}

impl Drop for GithubCredentialsHelper {
    fn drop(&mut self) {
        if self
            .tx
            .take()
            .expect("drop called twice?")
            .send(())
            .is_err()
        {
            tracing::error!("Failed to send signal to restore git credentials");
        }
    }
}

/// A Github client that can be used to make requests against the Github API
/// using an oAuth application and a specific installation.
#[derive(Debug, Clone)]
pub struct GithubClient {
    app: GithubApp,
    client: ApiClient<InstallationAccess>,
    id: u64,
}

impl GithubClient {
    fn new(
        app: GithubApp,
        client: hyperdriver::client::SharedClientService<Body, Body>,
        installation: InstallationAccess,
        id: u64,
    ) -> Self {
        Self {
            app,
            client: ApiClient::new_with_inner_service(
                GITHUB_BASE.parse().unwrap(),
                installation,
                client,
            ),
            id,
        }
    }

    fn from_app(app: GithubApp, installation: InstallationAccess, id: u64) -> Self {
        let client = app.client.clone();
        Self::new(app, client, installation, id)
    }

    /// Build a GET request against a Github endpoint.
    pub fn get(&self, endpoint: &str) -> api_client::RequestBuilder {
        self.client.get(endpoint).version(http::Version::HTTP_2)
    }

    /// Build a POST request against a Github endpoint.
    pub fn post(&self, endpoint: &str) -> api_client::RequestBuilder {
        self.client.post(endpoint).version(http::Version::HTTP_2)
    }

    /// Check if the authentication token is expired.
    pub fn is_expired(&self) -> bool {
        self.client.auth().is_expired()
    }

    /// Get the authentication token.
    pub fn token(&self) -> Secret {
        self.client.auth().token.clone()
    }

    /// Set up git credentials for this installation with a token.
    pub async fn install_credentials(&self) -> Result<GithubCredentialsHelper, Error> {
        let path = format!("/etc/octocat/credentials/{}", self.id);
        GithubCredentialsHelper::new(path, &self.token()).await
    }

    /// refresh the authentication token.
    pub async fn refresh(&self) -> Result<(), Error> {
        let installation = self.app.installation_token(self.id).await?;
        self.client.refresh_auth(installation);
        Ok(())
    }
}

#[derive(Debug)]
struct TokenCache {
    secret: Secret,
    expires: chrono::DateTime<chrono::Utc>,
}

impl TokenCache {
    fn new(secret: Secret, expires: chrono::DateTime<chrono::Utc>) -> Self {
        Self { secret, expires }
    }

    fn is_expired(&self) -> bool {
        self.expires < chrono::Utc::now()
    }
}

/// A Github App client that can be used to authenticate and make requests against the Github API.
///
/// This represents the high level oAuth application, not an individual installation.
#[derive(Debug, Clone)]
pub struct GithubApp {
    app_id: String,
    secret: Arc<rsa::RsaPrivateKey>,
    token: Arc<RwLock<Option<TokenCache>>>,
    client: hyperdriver::client::SharedClientService<Body, Body>,
}

impl GithubApp {
    /// Create a new Github App client
    pub fn new(app_id: String, secret: Arc<rsa::RsaPrivateKey>) -> Self {
        let mut tcp = TcpTransportConfig::default();
        tcp.connect_timeout = Some(CONNECT_TIMEOUT);

        let client = Client::builder()
            .layer(
                tower_http::set_header::SetRequestHeaderLayer::if_not_present(
                    header::ACCEPT,
                    GITHUB_ACCEPT.parse::<HeaderValue>().unwrap(),
                ),
            )
            .layer(
                tower_http::set_header::SetRequestHeaderLayer::if_not_present(
                    GITHUB_API_VERSION_HEADER.parse().unwrap(),
                    GITHUB_API_VERSION.parse::<HeaderValue>().unwrap(),
                ),
            )
            .with_tcp(tcp)
            .with_default_tls()
            .with_auto_http()
            .with_user_agent("automoton-octocat/0.1.0".to_owned())
            .with_timeout(TIMEOUT)
            .build_service();

        Self {
            app_id,
            secret,
            token: Default::default(),
            client,
        }
    }

    /// List all installations for this app
    pub async fn installations(&self) -> Result<Vec<crate::models::Installation>, Error> {
        let req = http::Request::get(GITHUB_LIST_INSTALLATIONS)
            .version(http::Version::HTTP_2)
            .bearer_auth(self.authentication_token(None)?.revealed())
            .body(Body::empty())
            .unwrap();

        let resp = self.client.clone().oneshot(req).await?;

        if !resp.status().is_success() {
            let error = ResponseError::from_response(resp).await;
            return Err(Error::Response(error));
        }

        let contents: Vec<crate::models::Installation> = resp.json().await.map_err(Error::Body)?;

        tracing::debug!(app = self.app_id, "Found {} installations", contents.len());

        Ok(contents)
    }

    /// Get an authentication token for an installation
    pub(crate) async fn installation_token(
        &self,
        installation_id: u64,
    ) -> Result<InstallationAccess, Error> {
        let req = http::Request::post(format!(
            "https://api.github.com/app/installations/{installation_id}/access_tokens"
        ))
        .version(http::Version::HTTP_2)
        .bearer_auth(self.authentication_token(None)?.revealed())
        .body(Body::empty())
        .unwrap();

        let resp = self.client.clone().oneshot(req).await?;

        if !resp.status().is_success() {
            let error = ResponseError::from_response(resp).await;
            return Err(Error::Response(error));
        }

        let body = resp.text().await.map_err(Error::Body)?;
        tracing::trace!(id=%installation_id, "Got response for installation: {:?}", body);
        let access: InstallationAccess = serde_json::from_str(&body)?;
        tracing::debug!(
            expires=%access.expires_at,
            id=%installation_id,
            "Got authentication token for installation",
        );
        Ok(access)
    }

    /// Get a github client with an installation token for a repository.
    #[tracing::instrument(level = "trace", skip(self))]
    pub async fn installation_for_repo(
        self,
        user: &str,
        repository: &str,
    ) -> Result<GithubClient, Error> {
        let req = http::Request::get(format!(
            "https://api.github.com/repos/{user}/{repository}/installation"
        ))
        .version(http::Version::HTTP_2)
        .bearer_auth(self.authentication_token(None)?.revealed())
        .body(Body::empty())
        .unwrap();

        let resp = self.client.clone().oneshot(req).await?;

        if !resp.status().is_success() {
            let error = ResponseError::from_response(resp).await;
            return Err(Error::Response(error));
        }

        let body = resp.text().await.map_err(Error::Body)?;
        let installation: crate::models::Installation = serde_json::from_str(&body)?;
        tracing::debug!(id=%installation.id, "Got installation for repo {user}/{repository}");

        let token = self.installation_token(installation.id).await?;

        Ok(GithubClient::from_app(self, token, installation.id))
    }

    /// Get a github client with an installation token.
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn installation(self, installation_id: u64) -> Result<GithubClient, Error> {
        let access = self.installation_token(installation_id).await?;
        Ok(GithubClient::from_app(self, access, installation_id))
    }

    /// Get an authentication token for the Github App specific to an installation
    fn authentication_token(
        &self,
        now: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Secret, Error> {
        let now = now.unwrap_or_else(chrono::Utc::now);

        {
            let guard = self.token.read().unwrap();
            if let Some(cache) = &*guard {
                if !cache.is_expired() {
                    return Ok(cache.secret.clone());
                }
            }
        }

        // Grab the lock now so that only one cache update occurs
        let mut guard = self.token.write().unwrap();

        let issued_at = now - chrono::Duration::seconds(CLOCK_DRIFT_OFFSET_SECONDS);
        let expire_at = now + chrono::Duration::seconds(TOKEN_DURATION_SECONDS);

        let claims: Claims<(), &str> = Claims {
            registered: RegisteredClaims {
                issuer: Some(&self.app_id),
                issued_at: Some(issued_at),
                expiration: Some(expire_at),
                ..Default::default()
            },
            claims: (),
        };

        let jwt = Token::compact((), claims);
        let algorihm: rsa::pkcs1v15::SigningKey<Sha256> =
            rsa::pkcs1v15::SigningKey::new((*self.secret).clone());
        let token =
            jwt.sign::<rsa::pkcs1v15::SigningKey<Sha256>, rsa::pkcs1v15::Signature>(&algorihm)?;

        let encoded_token: Secret = token.rendered()?.into();
        tracing::debug!(app = self.app_id, "Created a new Github App",);
        tracing::trace!(app = self.app_id, jwt=%encoded_token.revealed(), "Github App JWT");
        let cache = TokenCache::new(
            encoded_token.clone(),
            expire_at - chrono::Duration::seconds(CLOCK_DRIFT_OFFSET_SECONDS),
        );
        *guard = Some(cache);

        Ok(encoded_token)
    }
}

#[cfg(test)]
mod tests {

    use rsa::pkcs8::DecodePrivateKey;

    use super::*;

    impl GithubApp {
        fn test() -> Self {
            let key = {
                include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/test/rsa-2048-private-key.pk8"
                ))
            };

            GithubApp {
                app_id: "1235".into(),
                secret: Arc::new(rsa::RsaPrivateKey::from_pkcs8_der(key).unwrap()),
                token: Default::default(),
                client: Client::builder()
                    .with_auto_http()
                    .with_tcp(Default::default())
                    .build_service(),
            }
        }
    }

    #[test]
    fn create_authentication_token() {
        use chrono::TimeZone;
        let now = chrono::Utc.with_ymd_and_hms(2014, 7, 8, 9, 10, 11).unwrap();
        let app = GithubApp::test();

        let token = GithubApp::authentication_token(&app, Some(now)).unwrap();
        assert_eq!(
            token.revealed(),
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/test/expected_token.txt"
            ))
            .trim()
        )
    }
}
