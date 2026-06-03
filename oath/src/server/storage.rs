//! `Driver`-backed [`UserStore`] implementation.

use std::marker::PhantomData;
use std::sync::Arc;

use camino::Utf8PathBuf;
use serde::{Serialize, de::DeserializeOwned};
use storage_driver::{Driver, StorageError, StorageErrorKind};

use crate::server::error::ServerError;
use crate::server::users::UserStore;

/// [`UserStore`] backed by any [`storage_driver::Driver`].
///
/// Reads and writes `{prefix}/{username}.json` in the configured
/// bucket. The user payload type `T` round-trips through
/// `serde_json::to_vec` / `serde_json::from_slice`.
///
/// Username sanitization is enforced on both [`UserStore::get`] and
/// [`UserStore::put`] — slashes, NULs, control characters, leading
/// dots, and embedded `..` are rejected before any path is constructed.
pub struct JsonFileUserStore<D, T> {
    driver: Arc<D>,
    bucket: String,
    prefix: Utf8PathBuf,
    _marker: PhantomData<fn() -> T>,
}

impl<D, T> std::fmt::Debug for JsonFileUserStore<D, T>
where
    D: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsonFileUserStore")
            .field("driver", &self.driver)
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .finish()
    }
}

impl<D, T> Clone for JsonFileUserStore<D, T> {
    fn clone(&self) -> Self {
        Self {
            driver: self.driver.clone(),
            bucket: self.bucket.clone(),
            prefix: self.prefix.clone(),
            _marker: PhantomData,
        }
    }
}

impl<D, T> JsonFileUserStore<D, T>
where
    D: Driver + Send + Sync + 'static,
    T: Serialize + DeserializeOwned + Send + Sync + 'static,
{
    /// Create a new user store on `bucket` of `driver`. Defaults the
    /// path prefix to `users`.
    pub fn new(driver: D, bucket: impl Into<String>) -> Self {
        Self {
            driver: Arc::new(driver),
            bucket: bucket.into(),
            prefix: Utf8PathBuf::from("users"),
            _marker: PhantomData,
        }
    }

    /// Override the path prefix (`users` by default).
    pub fn with_prefix(mut self, prefix: impl Into<Utf8PathBuf>) -> Self {
        self.prefix = prefix.into();
        self
    }

    fn path_for(&self, username: &str) -> Result<Utf8PathBuf, ServerError> {
        super::sanitize_username(username)?;
        let file = format!("{username}.json");
        Ok(self.prefix.join(file))
    }
}

#[async_trait::async_trait]
impl<D, T> UserStore for JsonFileUserStore<D, T>
where
    D: Driver + Send + Sync + 'static,
    T: Serialize + DeserializeOwned + Send + Sync + 'static,
{
    type Data = T;
    type Error = ServerError;

    async fn get(&self, username: &str) -> Result<Option<T>, ServerError> {
        let path: Utf8PathBuf = self.path_for(username)?;
        let mut buf = Vec::<u8>::new();
        match self.driver.download(&self.bucket, &path, &mut buf).await {
            Ok(()) => {
                let value = serde_json::from_slice::<T>(&buf).map_err(|e| {
                    ServerError::user_store(StorageError::new(
                        self.driver.name(),
                        StorageErrorKind::SerializationError,
                        e,
                    ))
                })?;
                Ok(Some(value))
            }
            Err(e) if matches!(e.kind(), StorageErrorKind::NotFound) => Ok(None),
            Err(e) => Err(ServerError::user_store(e)),
        }
    }

    async fn put(&self, username: &str, data: &T) -> Result<(), ServerError> {
        let path: Utf8PathBuf = self.path_for(username)?;
        let bytes = serde_json::to_vec(data).map_err(|e| {
            ServerError::user_store(StorageError::new(
                self.driver.name(),
                StorageErrorKind::SerializationError,
                e,
            ))
        })?;
        let mut reader: &[u8] = &bytes;
        self.driver
            .upload(&self.bucket, &path, &mut reader)
            .await
            .map_err(ServerError::user_store)?;
        let _ = path; // silence unused if release-build optimizer thinks so
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::server::sanitize_username;

    use super::*;

    #[test]
    fn empty_rejected() {
        assert!(matches!(
            sanitize_username(""),
            Err(ServerError::InvalidUsername("empty"))
        ));
    }

    #[test]
    fn too_long_rejected() {
        let long = "a".repeat(256);
        assert!(matches!(
            sanitize_username(&long),
            Err(ServerError::InvalidUsername("too long"))
        ));
    }

    #[test]
    fn path_separators_rejected() {
        for bad in ["a/b", "a\\b", "a\0b"] {
            assert!(
                matches!(
                    sanitize_username(bad),
                    Err(ServerError::InvalidUsername("path separator")),
                ),
                "expected reject for {bad:?}"
            );
        }
    }

    #[test]
    fn control_chars_rejected() {
        assert!(matches!(
            sanitize_username("a\nb"),
            Err(ServerError::InvalidUsername("control character"))
        ));
        assert!(matches!(
            sanitize_username("a\tb"),
            Err(ServerError::InvalidUsername("control character"))
        ));
    }

    #[test]
    fn path_traversal_rejected() {
        for bad in [".", "..", "a..b", "../etc/passwd"] {
            let result = sanitize_username(bad);
            assert!(
                matches!(
                    result,
                    Err(ServerError::InvalidUsername("path traversal"))
                        | Err(ServerError::InvalidUsername("embedded `..`"))
                        | Err(ServerError::InvalidUsername("path separator")),
                ),
                "expected reject for {bad:?} but got {result:?}",
            );
        }
    }

    #[test]
    fn typical_usernames_accepted() {
        for ok in [
            "alice",
            "bob123",
            "user.name",
            "user-name",
            "user_name",
            "sub_abc123",
        ] {
            sanitize_username(ok).unwrap_or_else(|e| panic!("{ok:?} should be valid: {e:?}"));
        }
    }
}
