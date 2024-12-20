use camino::{Utf8Path, Utf8PathBuf};
use eyre::Context;
use tokio::io::AsyncWriteExt;
use tracing::instrument;

use storage_driver::{Driver, Metadata, Reader, StorageError, Writer};

/// A storage driver that stores files on the local filesystem.
#[derive(Debug)]
pub struct LocalDriver {
    root: Utf8PathBuf,
}

impl LocalDriver {
    /// Create a new `LocalDriver` instance, storing files in the given directory.
    pub fn new(root: Utf8PathBuf) -> Self {
        Self { root }
    }

    fn path(&self, bucket: &str, remote: &Utf8Path) -> Utf8PathBuf {
        let mut path = self.root.join(bucket);
        path.push("b");
        path.push(remote);
        path
    }
}

#[async_trait::async_trait]
impl Driver for LocalDriver {
    fn name(&self) -> &'static str {
        "local"
    }

    fn scheme(&self) -> &str {
        "local"
    }

    async fn metadata(&self, bucket: &str, remote: &Utf8Path) -> Result<Metadata, StorageError> {
        let remote = self.path(bucket, remote);
        let metadata = tokio::fs::metadata(remote)
            .await
            .wrap_err("local driver: metadata")
            .map_err(|err| StorageError::new(self.name(), err))?;
        Ok(Metadata {
            size: metadata.len(),
            created: metadata
                .created()
                .wrap_err("metadata")
                .map_err(|err| StorageError::new(self.name(), err))?
                .into(),
        })
    }

    async fn delete(&self, bucket: &str, remote: &Utf8Path) -> Result<(), StorageError> {
        let remote = self.path(bucket, remote);
        tokio::fs::remove_file(remote)
            .await
            .wrap_err("remove_file")
            .map_err(|err| StorageError::new(self.name(), err))?;
        Ok(())
    }

    async fn upload(
        &self,
        bucket: &str,
        remote: &Utf8Path,
        local: &mut Reader<'_>,
    ) -> Result<(), StorageError> {
        let remote = self.path(bucket, remote);

        tokio::fs::create_dir_all(&remote.parent().unwrap())
            .await
            .context("create_dir_all")
            .map_err(|err| StorageError::new(self.name(), err))?;

        let mut writer = tokio::io::BufWriter::new(
            tokio::fs::File::create(&remote)
                .await
                .context("local: open remote file")
                .map_err(|err| StorageError::new(self.name(), err))?,
        );

        tokio::io::copy(local, &mut writer)
            .await
            .context("copy")
            .map_err(|err| StorageError::new(self.name(), err))?;

        writer
            .shutdown()
            .await
            .context("shutdown writer")
            .map_err(|err| StorageError::new(self.name(), err))?;
        Ok(())
    }
    async fn download(
        &self,
        bucket: &str,
        remote: &Utf8Path,
        local: &mut Writer<'_>,
    ) -> Result<(), StorageError> {
        let remote = self.path(bucket, remote);

        let mut reader = tokio::io::BufReader::new(
            tokio::fs::File::open(&remote)
                .await
                .context(" open remote file")
                .map_err(|err| StorageError::new(self.name(), err))?,
        );

        tokio::io::copy(&mut reader, local)
            .await
            .context("copy")
            .map_err(|err| StorageError::new(self.name(), err))?;

        local
            .flush()
            .await
            .context("flush writer")
            .map_err(|err| StorageError::new(self.name(), err))?;

        Ok(())
    }

    #[instrument(skip(self), "local::list", level = "debug", fields(bucket=%bucket, prefix=%prefix.as_ref().map(|p| p.as_str()).unwrap_or("")))]
    async fn list(
        &self,
        bucket: &str,
        prefix: Option<&Utf8Path>,
    ) -> Result<Vec<String>, StorageError> {
        let mut path = self.root.join(bucket);
        path.push("b");
        if let Some(part) = prefix {
            path.push(part);
        }

        tokio::fs::create_dir_all(path.parent().unwrap())
            .await
            .context("create_dir_all")
            .map_err(|err| StorageError::new(self.name(), err))?;

        tracing::trace!(%path, "Searching directory tree");

        let span = tracing::Span::current();

        let items = tokio::task::spawn_blocking(move || span.in_scope(|| collect_list(&path)))
            .await
            .wrap_err("local driver")
            .map_err(|err| StorageError::new(self.name(), err))?
            .map_err(|err| StorageError::new(self.name(), err))?;

        if items.is_empty() {
            tracing::trace!("No remote entries found");
            return Ok(Vec::new());
        }

        tracing::debug!("Found {} entries", items.len());

        if let Some(part) = prefix {
            Ok(items
                .into_iter()
                .map(|p| part.join(p).to_string())
                .collect())
        } else {
            Ok(items.into_iter().map(|p| p.to_string()).collect())
        }
    }
}

fn collect_list(path: &Utf8Path) -> eyre::Result<Vec<Utf8PathBuf>> {
    let mut files = Vec::new();

    let target = path.parent().unwrap();
    visit(target, &mut files)?;

    Ok(files
        .into_iter()
        .filter_map(|p| {
            tracing::trace!(path=%p, prefix=%path, "processing path");
            p.strip_prefix(path).ok().map(|p| p.to_owned())
        })
        .collect())
}

fn visit(path: &Utf8Path, files: &mut Vec<Utf8PathBuf>) -> eyre::Result<()> {
    tracing::trace!(%path, "Visiting {}", path);
    for entry in path.read_dir_utf8()? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            visit(entry.path(), files)?;
        } else {
            tracing::trace!("Found file: {}", entry.path());
            files.push(entry.path().to_owned())
        }
    }

    Ok(())
}
