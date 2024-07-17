use std::{io, sync::Arc};

use camino::{Utf8Path, Utf8PathBuf};
use jaws::crypto::rsa;
use rsa::pkcs8::Error as Pkcs8Error;
use rsa::{pkcs1::DecodeRsaPrivateKey, pkcs8::DecodePrivateKey};
use serde::Deserialize;
use storage::Storage;

use super::GithubApp;

#[derive(Debug, thiserror::Error)]
pub enum ErrorKind {
    #[error("IO: {0}")]
    Io(#[from] io::Error),

    #[error("PKCS8: {0}")]
    Pkcs8(#[from] Pkcs8Error),

    #[error("PKCS1: {0}")]
    Pkcs1(#[from] rsa::pkcs1::Error),
}

#[derive(Debug, thiserror::Error)]
#[error("Reading Github Key in PEM format from {path:?}")]
pub struct FileError {
    path: Utf8PathBuf,
    source: ErrorKind,
}

#[derive(Debug, thiserror::Error)]
pub enum AppKeyError {
    #[error("App Key from file")]
    File(#[from] FileError),
    #[error("App Key from b2 storage")]
    Storage(#[from] StorageError),
}

impl TryFrom<GithubAppConfig> for GithubApp {
    type Error = FileError;

    fn try_from(config: GithubAppConfig) -> Result<Self, Self::Error> {
        let key = match config.signing_key {
            GithubAppKey::File(path) => Arc::new(rsa_key_from_file(&path)?),
            GithubAppKey::B2 { .. } => panic!("B2 storage not implemented in try-from"),
        };

        Ok(GithubApp::new(config.app_id, key))
    }
}

impl GithubApp {
    /// Create a new GithubApp from a GithubAppConfig
    ///
    /// This method is async to support downloading the key from a cloud storage provider.
    pub async fn from_config(
        config: &GithubAppConfig,
        storage: &Storage,
    ) -> Result<Self, AppKeyError> {
        match &config.signing_key {
            GithubAppKey::File(path) => {
                let key = rsa_key_from_file(path).map_err(AppKeyError::File)?;
                Ok(GithubApp::new(config.app_id.clone(), Arc::new(key)))
            }
            GithubAppKey::B2 { path, bucket } => {
                let key = rsa_key_from_storage(storage, bucket, path).await?;
                Ok(GithubApp::new(config.app_id.clone(), Arc::new(key)))
            }
        }
    }
}

fn rsa_key_from_file(path: &Utf8Path) -> Result<rsa::RsaPrivateKey, FileError> {
    match rsa::RsaPrivateKey::read_pkcs1_pem_file(path).map_err(|err| FileError {
        path: path.to_path_buf(),
        source: err.into(),
    }) {
        Ok(key) => Ok(key),
        Err(pkcs1_error) => {
            let key = match rsa::RsaPrivateKey::read_pkcs8_pem_file(path).map_err(|err| FileError {
                path: path.to_path_buf(),
                source: err.into(),
            }) {
                Ok(key) => key,
                Err(pkcs8_error) => {
                    tracing::error!("Error reading as PKCS1: {}", pkcs1_error);
                    tracing::error!("Error reading as PKCS8: {}", pkcs8_error);
                    return Err(pkcs8_error);
                }
            };
            Ok(key)
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StorageErrorKind {
    #[error("IO: {0}")]
    Io(#[from] io::Error),

    #[error("Storage: {0}")]
    Storage(#[from] storage::StorageError),

    #[error("Encoding: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    #[error("PKCS8: {0}")]
    Pkcs8(#[from] Pkcs8Error),

    #[error("PKCS1: {0}")]
    Pkcs1(#[from] rsa::pkcs1::Error),
}

#[derive(Debug, thiserror::Error)]
#[error("Reading Github Key in PEM format from b2://{bucket}/{path}")]
pub struct StorageError {
    path: Utf8PathBuf,
    bucket: String,
    source: StorageErrorKind,
}

async fn rsa_key_from_storage(
    storage: &Storage,
    bucket: &str,
    path: &Utf8Path,
) -> Result<rsa::RsaPrivateKey, StorageError> {
    let mut buf = Vec::new();
    storage
        .download(bucket, path, &mut buf)
        .await
        .map_err(|err| StorageError {
            path: path.to_path_buf(),
            bucket: bucket.to_string(),
            source: err.into(),
        })?;

    let contents = String::from_utf8(buf).map_err(|err| StorageError {
        path: path.to_path_buf(),
        bucket: bucket.to_string(),
        source: err.into(),
    })?;

    rsa::RsaPrivateKey::from_pkcs1_pem(&contents).map_err(|err| StorageError {
        bucket: bucket.to_string(),
        path: path.to_path_buf(),
        source: err.into(),
    })
}

/// Configuration for a Github App
#[derive(Debug, Clone, Deserialize)]
pub struct GithubAppConfig {
    /// Key used to sign JWTs
    pub signing_key: GithubAppKey,

    /// App ID from Github
    pub app_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GithubAppKey {
    File(Utf8PathBuf),
    B2 { path: Utf8PathBuf, bucket: String },
}
