//! Configuration for Github Apps

use std::{io, sync::Arc};

use camino::{Utf8Path, Utf8PathBuf};
use jaws::crypto::rsa;
use rsa::pkcs8::Error as Pkcs8Error;
use rsa::{pkcs1::DecodeRsaPrivateKey, pkcs8::DecodePrivateKey};
use serde::Deserialize;
use storage::Storage;

use super::GithubApp;

/// Errors that can occur when reading a key from a file
#[derive(Debug, thiserror::Error)]
pub enum ErrorKind {
    /// Error reading the key.
    #[error("IO: {0}")]
    Io(#[from] io::Error),

    /// Error decoding the key as PKCS8
    #[error("PKCS8: {0}")]
    Pkcs8(#[from] Pkcs8Error),

    /// Error decoding the key as PKCS1
    #[error("PKCS1: {0}")]
    Pkcs1(#[from] rsa::pkcs1::Error),
}

/// Error reading the key from a file
#[derive(Debug, thiserror::Error)]
#[error("Reading Github Key in PEM format from {path:?}")]
pub struct FileError {
    path: Utf8PathBuf,
    source: ErrorKind,
}

/// Error reading the key from a file or storage provider
#[derive(Debug, thiserror::Error)]
pub enum AppKeyError {
    /// Error reading the key from a file
    #[error("App Key from file")]
    File(#[from] FileError),

    /// Error reading the key from a storage provider
    #[error("App Key from storage provider")]
    Storage(#[from] StorageError),
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

/// Errors that can occur when reading a key from a storage provider
#[derive(Debug, thiserror::Error)]
pub enum StorageErrorKind {
    /// Error accessing the key
    #[error("IO: {0}")]
    Io(#[from] io::Error),

    /// Errro from the storage provider
    #[error("Storage: {0}")]
    Storage(#[from] storage::StorageError),

    /// Error decoding the key as utf8
    #[error("Encoding: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    /// Error decoding the key as PKCS8
    #[error("PKCS8: {0}")]
    Pkcs8(#[from] Pkcs8Error),

    /// Error decoding the key as PKCS1
    #[error("PKCS1: {0}")]
    Pkcs1(#[from] rsa::pkcs1::Error),
}

/// Error from a storage provider
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

/// Configuration for a Github App Key source
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GithubAppKey {
    /// Read the key from disk at this path
    File(Utf8PathBuf),

    /// Read the key from B2 storage
    B2 {
        /// Path to the key in the storage provider
        path: Utf8PathBuf,

        /// Bucket containing the key
        bucket: String,
    },
}
