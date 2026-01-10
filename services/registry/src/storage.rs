//! Storage layer for the registry

use camino::{Utf8Path, Utf8PathBuf};
use sha2::{Digest, Sha256};
use std::io::Cursor;
use tokio::io::BufReader;

use crate::error::{RegistryError, RegistryResult};

/// Registry storage backend
#[derive(Clone, Debug)]
pub struct RegistryStorage {
    storage: storage::Storage,
    bucket: String,
}

impl RegistryStorage {
    /// Create a new registry storage
    pub fn new(storage: storage::Storage, bucket: String) -> Self {
        Self { storage, bucket }
    }

    /// Get the path for a blob
    fn blob_path(&self, digest: &str) -> Utf8PathBuf {
        // Store blobs as: blobs/<algorithm>/<digest>
        // e.g., blobs/sha256/abc123...
        let parts: Vec<&str> = digest.splitn(2, ':').collect();
        if parts.len() == 2 {
            Utf8PathBuf::from(format!("blobs/{}/{}", parts[0], parts[1]))
        } else {
            Utf8PathBuf::from(format!("blobs/sha256/{}", digest))
        }
    }

    /// Get the path for a manifest
    fn manifest_path(&self, repository: &str, reference: &str) -> Utf8PathBuf {
        // Store manifests as: manifests/<repository>/<reference>
        Utf8PathBuf::from(format!("manifests/{}/{}", repository, reference))
    }

    /// Get the path for a tag
    fn tag_path(&self, repository: &str, tag: &str) -> Utf8PathBuf {
        // Store tag references as: tags/<repository>/<tag>
        Utf8PathBuf::from(format!("tags/{}/{}", repository, tag))
    }

    /// Check if a blob exists
    pub async fn blob_exists(&self, digest: &str) -> RegistryResult<bool> {
        let path = self.blob_path(digest);
        match self.storage.metadata(&self.bucket, &path).await {
            Ok(_) => Ok(true),
            Err(e) => {
                // Check if error message contains "Not found"
                if e.to_string().to_lowercase().contains("not found") {
                    Ok(false)
                } else {
                    Err(e.into())
                }
            }
        }
    }

    /// Get a blob
    pub async fn get_blob(&self, digest: &str) -> RegistryResult<Vec<u8>> {
        let path = self.blob_path(digest);
        let mut data = Vec::new();
        let mut cursor = Cursor::new(&mut data);

        self.storage
            .download(&self.bucket, &path, &mut cursor)
            .await
            .map_err(|e| {
                if e.to_string().to_lowercase().contains("not found") {
                    RegistryError::BlobNotFound(digest.to_string())
                } else {
                    e.into()
                }
            })?;

        Ok(data)
    }

    /// Store a blob with verification
    pub async fn put_blob(&self, digest: &str, data: &[u8]) -> RegistryResult<()> {
        // Verify the digest
        let computed = format!("sha256:{}", hex::encode(Sha256::digest(data)));
        if computed != digest {
            return Err(RegistryError::DigestMismatch {
                expected: digest.to_string(),
                actual: computed,
            });
        }

        let path = self.blob_path(digest);
        let mut reader = BufReader::new(data);

        self.storage
            .upload(&self.bucket, &path, &mut reader)
            .await?;

        Ok(())
    }

    /// Delete a blob
    pub async fn delete_blob(&self, digest: &str) -> RegistryResult<()> {
        let path = self.blob_path(digest);
        self.storage.delete(&self.bucket, &path).await.map_err(|e| {
            if e.to_string().to_lowercase().contains("not found") {
                RegistryError::BlobNotFound(digest.to_string())
            } else {
                e.into()
            }
        })
    }

    /// Get a manifest
    pub async fn get_manifest(&self, repository: &str, reference: &str) -> RegistryResult<Vec<u8>> {
        // First try as a tag
        let tag_path = self.tag_path(repository, reference);
        let digest = match self.read_tag(&tag_path).await {
            Ok(d) => d,
            Err(_) if reference.starts_with("sha256:") => reference.to_string(),
            Err(_) => {
                return Err(RegistryError::ManifestNotFound(format!(
                    "{}/{}",
                    repository, reference
                )));
            }
        };

        // Get the manifest by digest
        let path = self.manifest_path(repository, &digest);
        let mut data = Vec::new();
        let mut cursor = Cursor::new(&mut data);

        self.storage
            .download(&self.bucket, &path, &mut cursor)
            .await
            .map_err(|e| {
                if e.to_string().to_lowercase().contains("not found") {
                    RegistryError::ManifestNotFound(format!("{}/{}", repository, reference))
                } else {
                    e.into()
                }
            })?;

        Ok(data)
    }

    /// Put a manifest
    pub async fn put_manifest(
        &self,
        repository: &str,
        reference: &str,
        data: &[u8],
    ) -> RegistryResult<String> {
        // Calculate the digest
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(data)));

        // Store the manifest by digest
        let path = self.manifest_path(repository, &digest);
        let mut reader = BufReader::new(data);
        self.storage
            .upload(&self.bucket, &path, &mut reader)
            .await?;

        // If reference is a tag, create a tag reference
        if !reference.starts_with("sha256:") {
            let tag_path = self.tag_path(repository, reference);
            let mut reader = BufReader::new(digest.as_bytes());
            self.storage
                .upload(&self.bucket, &tag_path, &mut reader)
                .await?;
        }

        Ok(digest)
    }

    /// Delete a manifest
    pub async fn delete_manifest(&self, repository: &str, reference: &str) -> RegistryResult<()> {
        // First try to resolve the reference to a digest
        let digest = if reference.starts_with("sha256:") {
            reference.to_string()
        } else {
            let tag_path = self.tag_path(repository, reference);
            match self.read_tag(&tag_path).await {
                Ok(d) => {
                    // Delete the tag
                    let _ = self.storage.delete(&self.bucket, &tag_path).await;
                    d
                }
                Err(_) => {
                    return Err(RegistryError::ManifestNotFound(format!(
                        "{}/{}",
                        repository, reference
                    )));
                }
            }
        };

        // Delete the manifest
        let path = self.manifest_path(repository, &digest);
        self.storage.delete(&self.bucket, &path).await.map_err(|e| {
            if e.to_string().to_lowercase().contains("not found") {
                RegistryError::ManifestNotFound(format!("{}/{}", repository, reference))
            } else {
                e.into()
            }
        })
    }

    /// Read a tag reference
    async fn read_tag(&self, path: &Utf8Path) -> RegistryResult<String> {
        let mut data = Vec::new();
        let mut cursor = Cursor::new(&mut data);
        self.storage
            .download(&self.bucket, path, &mut cursor)
            .await?;
        Ok(String::from_utf8_lossy(&data).to_string())
    }

    /// List tags for a repository
    pub async fn list_tags(&self, repository: &str) -> RegistryResult<Vec<String>> {
        let prefix = Utf8PathBuf::from(format!("tags/{}/", repository));
        let files = self
            .storage
            .list(&self.bucket, Some(&prefix))
            .await
            .unwrap_or_default();

        let tags = files
            .into_iter()
            .filter_map(|f| {
                let path = Utf8Path::new(&f);
                path.strip_prefix(&prefix)
                    .ok()
                    .and_then(|p| p.file_name())
                    .map(|s| s.to_string())
            })
            .collect();

        Ok(tags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use storage::MemoryStorage;

    fn test_storage() -> RegistryStorage {
        let storage = MemoryStorage::with_buckets(&["test"]);
        RegistryStorage::new(storage.into(), "test".to_string())
    }

    #[tokio::test]
    async fn test_blob_storage() {
        let storage = test_storage();
        let data = b"test data";
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(data)));

        // Store blob
        storage.put_blob(&digest, data).await.unwrap();

        // Check it exists
        assert!(storage.blob_exists(&digest).await.unwrap());

        // Retrieve blob
        let retrieved = storage.get_blob(&digest).await.unwrap();
        assert_eq!(&retrieved[..], data);

        // Delete blob
        storage.delete_blob(&digest).await.unwrap();

        // Check it no longer exists
        assert!(!storage.blob_exists(&digest).await.unwrap());
    }

    #[tokio::test]
    async fn test_blob_digest_verification() {
        let storage = test_storage();
        let data = b"test data";
        let wrong_digest =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000";

        // Attempt to store blob with wrong digest
        let result = storage.put_blob(wrong_digest, data).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_manifest_storage() {
        let storage = test_storage();
        let manifest = b"test manifest";

        // Store manifest
        let digest = storage
            .put_manifest("test-repo", "latest", manifest)
            .await
            .unwrap();

        // Retrieve by tag
        let retrieved = storage.get_manifest("test-repo", "latest").await.unwrap();
        assert_eq!(&retrieved[..], manifest);

        // Retrieve by digest
        let retrieved = storage.get_manifest("test-repo", &digest).await.unwrap();
        assert_eq!(&retrieved[..], manifest);
    }

    #[tokio::test]
    async fn test_list_tags() {
        let storage = test_storage();
        let manifest = b"test manifest";

        // Store multiple tags
        storage
            .put_manifest("test-repo", "v1.0", manifest)
            .await
            .unwrap();
        storage
            .put_manifest("test-repo", "v1.1", manifest)
            .await
            .unwrap();
        storage
            .put_manifest("test-repo", "latest", manifest)
            .await
            .unwrap();

        // List tags
        let tags = storage.list_tags("test-repo").await.unwrap();
        assert_eq!(tags.len(), 3);
        assert!(tags.contains(&"v1.0".to_string()));
        assert!(tags.contains(&"v1.1".to_string()));
        assert!(tags.contains(&"latest".to_string()));
    }

    #[tokio::test]
    async fn test_blob_paths() {
        let storage = test_storage();
        let path = storage.blob_path("sha256:abcdef123456");
        assert_eq!(path.as_str(), "blobs/sha256/abcdef123456");
    }

    #[tokio::test]
    async fn test_manifest_paths() {
        let storage = test_storage();
        let path = storage.manifest_path("myrepo", "sha256:abcdef123456");
        assert_eq!(path.as_str(), "manifests/myrepo/sha256:abcdef123456");
    }

    #[tokio::test]
    async fn test_tag_paths() {
        let storage = test_storage();
        let path = storage.tag_path("myrepo", "latest");
        assert_eq!(path.as_str(), "tags/myrepo/latest");
    }
}
