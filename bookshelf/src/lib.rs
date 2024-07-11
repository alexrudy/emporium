use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use camino::{Utf8Path, Utf8PathBuf};
use storage::Storage;
use thiserror::Error;

mod epoch;
pub mod expiration;

pub use epoch::{Epoch, EpochSelector, InvalidEpoch};
use tokio::io;
use tracing::instrument;

pub type Date = chrono::NaiveDate;
type Paths = BTreeMap<Epoch, Vec<Utf8PathBuf>>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Volume {0} not found")]
    NotFound(String),

    #[error("Storage error: {0}")]
    Storage(#[from] storage::StorageError),
}

/// A set of volume objects that share a common prefix, storage
/// and bucket.
#[derive(Debug, Clone)]
pub struct Bookshelf {
    storage: Storage,
    bucket: String,
    prefix: Option<Utf8PathBuf>,
}

impl Bookshelf {
    pub fn new(storage: Storage, bucket: String, prefix: Option<Utf8PathBuf>) -> Self {
        Self {
            storage,
            bucket,
            prefix,
        }
    }

    pub fn with_prefix(mut self, prefix: Utf8PathBuf) -> Self {
        self.prefix = Some(prefix);
        self
    }

    pub fn join<P: AsRef<Utf8Path>>(mut self, path: P) -> Self {
        if let Some(prefix) = self.prefix.as_mut() {
            prefix.push(path);
        } else {
            self.prefix = Some(path.as_ref().to_owned());
        }
        self
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    pub fn storage(&self) -> &Storage {
        &self.storage
    }

    pub fn prefix(&self) -> Option<&Utf8Path> {
        self.prefix.as_deref()
    }

    pub async fn list(&self) -> Result<Vec<Volume>, Error> {
        let mut list = self
            .storage
            .list(&self.bucket, self.prefix.as_deref())
            .await?
            .into_iter()
            .map(Utf8PathBuf::from)
            .collect::<Vec<_>>();
        list.sort();
        let shelves = self.process_list(list.as_slice())?;

        Ok(shelves)
    }

    fn process_list(&self, list: &[Utf8PathBuf]) -> Result<Vec<Volume>, Error> {
        tracing::trace!(paths=%list.len(), "Processing paths for bookshelves");

        let mut shelves: BTreeMap<Utf8PathBuf, BTreeMap<Epoch, Vec<Utf8PathBuf>>> = BTreeMap::new();

        let candidates = list.iter().filter_map(|path| {
            // Find the part of the path with the prefix stripped.
            let mut path = Utf8PathBuf::from(path);
            if let Some(base) = self.prefix.as_deref() {
                path = path.strip_prefix(base).ok()?.to_path_buf();
            }

            // Find the first valid epoch.
            let (i, epoch) = path
                .components()
                .enumerate()
                .find(|(_, c)| {
                    if let camino::Utf8Component::Normal(s) = c {
                        s.parse::<Epoch>().is_ok()
                    } else {
                        false
                    }
                })
                .and_then(|(i, c)| c.as_str().parse::<Epoch>().ok().map(|e| (i, e)))?;

            let name = path.components().take(i).collect::<Utf8PathBuf>();

            // The remainder is the suffix.
            let suffix: Utf8PathBuf = path
                .components()
                .skip_while(|c| !matches!(c, camino::Utf8Component::Normal(_)))
                .skip(1)
                .collect();

            Some((name, epoch, suffix))
        });

        for (name, epoch, path) in candidates {
            shelves
                .entry(name)
                .or_default()
                .entry(epoch)
                .or_default()
                .push(path);
        }

        Ok(shelves
            .into_iter()
            .map(|(name, paths)| {
                Volume::new(
                    self.storage.clone(),
                    self.bucket.clone(),
                    self.prefix.clone(),
                    name,
                    paths,
                )
            })
            .collect())
    }

    #[instrument(level="debug", skip(self), fields(bucket = %self.bucket, prefix = ?self.prefix))]
    pub async fn bookshelf(&self, name: &str) -> Result<Volume, Error> {
        let shelves = self.list().await?;

        Ok(shelves
            .into_iter()
            .find(|s| s.name() == name)
            .unwrap_or_else(|| {
                tracing::trace!("Creating new bookshelf: {}", name);
                Volume::new(
                    self.storage.clone(),
                    self.bucket.clone(),
                    self.prefix.clone(),
                    name.into(),
                    BTreeMap::new(),
                )
            }))
    }
}

#[derive(Debug)]
struct VolumeConfig {
    storage: Storage,
    bucket: String,
    prefix: Option<Utf8PathBuf>,
}

impl PartialEq for VolumeConfig {
    fn eq(&self, other: &Self) -> bool {
        self.bucket == other.bucket && self.prefix == other.prefix
    }
}

impl Eq for VolumeConfig {}

#[derive(Debug, PartialEq, Eq)]
struct InnerVolume {
    config: VolumeConfig,
    paths: Paths,
    name: Utf8PathBuf,
    path: Utf8PathBuf,
}

impl InnerVolume {
    fn new(config: VolumeConfig, paths: Paths, name: Utf8PathBuf) -> Self {
        let path = config
            .prefix
            .as_deref()
            .map(|p| p.join(&name))
            .unwrap_or_else(|| name.clone());

        Self {
            config,
            paths,
            name,
            path,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Volume {
    inner: Arc<InnerVolume>,
}

impl Volume {
    fn new(
        storage: Storage,
        bucket: String,
        prefix: Option<Utf8PathBuf>,
        name: Utf8PathBuf,
        paths: Paths,
    ) -> Self {
        let config = VolumeConfig {
            storage,
            bucket,
            prefix,
        };

        let inner = InnerVolume::new(config, paths, name);

        Self {
            inner: Arc::new(inner),
        }
    }

    pub fn list(&self) -> BTreeSet<Epoch> {
        self.inner.paths.keys().cloned().collect()
    }

    pub fn name(&self) -> &Utf8Path {
        &self.inner.name
    }

    pub fn path(&self) -> &Utf8Path {
        &self.inner.path
    }

    /// Inner storage driver, which can be used to perform arbitrary
    /// operations on the underlying storage backend.
    pub fn storage(&self) -> &Storage {
        &self.inner.config.storage
    }

    pub fn bucket(&self) -> &str {
        &self.inner.config.bucket
    }

    pub fn prefix(&self) -> Option<&Utf8Path> {
        self.inner.config.prefix.as_deref()
    }

    fn paths(&self) -> &BTreeMap<Epoch, Vec<Utf8PathBuf>> {
        &self.inner.paths
    }

    pub fn exists(&self, epoch: Epoch) -> bool {
        self.inner.paths.contains_key(&epoch)
    }

    pub fn get<E: Into<EpochSelector>>(&self, epoch: E) -> Option<Book> {
        let selector = epoch.into();
        let epoch = selector.find(self.paths());
        tracing::trace!("Selected epoch {epoch:?} as {selector}");
        epoch.map(|epoch| Book::new(self.clone(), epoch))
    }

    pub fn book(&self, epoch: Epoch) -> Book {
        Book::new(self.clone(), epoch)
    }

    pub fn today(&self) -> Book {
        self.book(Epoch::today())
    }

    pub fn earliest(&self) -> Option<Book> {
        let epoch = self.paths().keys().next().cloned();
        epoch.map(|epoch| Book::new(self.clone(), epoch))
    }

    pub fn latest(&self) -> Option<Book> {
        let epoch = self.paths().keys().last().cloned();
        epoch.map(|epoch| Book::new(self.clone(), epoch))
    }
}

#[derive(Debug, Clone)]
pub struct Book {
    bookshelf: Volume,
    epoch: Epoch,
}

impl PartialEq for Book {
    fn eq(&self, other: &Self) -> bool {
        self.epoch == other.epoch && self.bookshelf == other.bookshelf
    }
}

impl Book {
    pub fn new(bookshelf: Volume, epoch: Epoch) -> Self {
        Self { bookshelf, epoch }
    }

    pub fn exists(&self) -> bool {
        self.bookshelf.exists(self.epoch)
    }

    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub fn list(&self) -> Vec<Utf8PathBuf> {
        self.bookshelf
            .paths()
            .get(&self.epoch)
            .cloned()
            .unwrap_or_default()
    }

    pub async fn contains<P: AsRef<Utf8Path>>(&self, path: P) -> bool {
        self.bookshelf
            .paths()
            .get(&self.epoch)
            .map_or(false, |paths| paths.iter().any(|p| p == path.as_ref()))
    }

    pub fn entry<P: AsRef<Utf8Path>>(&self, path: P) -> Entry {
        Entry::new(self.bookshelf.clone(), self.epoch, path.as_ref())
    }

    pub async fn delete(&self) -> Result<(), Error> {
        let paths = self
            .bookshelf
            .paths()
            .get(&self.epoch)
            .cloned()
            .unwrap_or_default();

        let mut futures = Vec::with_capacity(paths.len());
        for path in paths {
            let path = self.bookshelf.path().join(path);
            futures.push(async move {
                self.bookshelf
                    .storage()
                    .delete(&self.bookshelf.inner.config.bucket, &path)
                    .await
            });
        }

        let _ = futures::future::try_join_all(futures).await?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Entry {
    bookshelf: Volume,
    epoch: Epoch,
    path: Utf8PathBuf,
}

impl Entry {
    pub fn new(bookshelf: Volume, epoch: Epoch, suffix: &Utf8Path) -> Self {
        let mut path = bookshelf.prefix().map(|p| p.to_owned()).unwrap_or_default();
        path.push(bookshelf.name());
        path.push(epoch.to_path());
        path.push(suffix);

        Self {
            bookshelf,
            epoch,
            path,
        }
    }

    pub fn path(&self) -> &Utf8Path {
        &self.path
    }

    pub fn exists(&self) -> bool {
        self.bookshelf
            .paths()
            .get(&self.epoch)
            .map_or(false, |paths| paths.iter().any(|p| self.path.ends_with(p)))
    }

    pub async fn download<'s, W>(&'s self, destination: &mut W) -> Result<(), Error>
    where
        W: io::AsyncWrite + Unpin + Send + Sync + 's,
    {
        let remote = self.path();

        self.bookshelf
            .storage()
            .download(&self.bookshelf.inner.config.bucket, remote, destination)
            .await
            .map_err(Error::from)
    }

    pub async fn upload<'s, R>(&'s self, source: &mut R) -> Result<(), Error>
    where
        R: io::AsyncBufRead + Unpin + Send + Sync + 's,
    {
        let remote = self.path();

        self.bookshelf
            .storage()
            .upload(&self.bookshelf.inner.config.bucket, remote, source)
            .await?;
        Ok(())
    }

    pub async fn upload_file(&self, source: &Utf8Path) -> Result<(), Error> {
        let remote = self.path();

        self.bookshelf
            .storage()
            .upload_file(&self.bookshelf.inner.config.bucket, remote, source)
            .await?;
        Ok(())
    }

    pub async fn delete(&self) -> Result<(), Error> {
        let remote = self.path();

        self.bookshelf
            .storage()
            .delete(&self.bookshelf.inner.config.bucket, remote)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use chrono::NaiveDate;
    use std::collections::BTreeSet;
    use storage::MemoryStorage;

    macro_rules! epoch {
        ($year:tt / $month:tt / $day:tt) => {
            Epoch::from(NaiveDate::from_ymd_opt($year, $month, $day).unwrap())
        };
    }

    #[tokio::test]
    async fn test_empty_bookshelf() {
        let bucket = "bucket";
        let prefix = Some(Utf8PathBuf::from("prefix"));

        let memory = MemoryStorage::new();
        memory.create_bucket(bucket.to_string()).await;
        let storage = Storage::new(memory);

        let case = Bookshelf::new(storage.clone(), bucket.to_string(), prefix.clone());
        let bookshelf = case.bookshelf("shelf/parts").await.unwrap();

        assert_eq!(bookshelf.list(), BTreeSet::new());
        assert_eq!(bookshelf.bucket(), "bucket");
        assert_eq!(
            bookshelf.prefix(),
            Some(Utf8PathBuf::from("prefix").as_path())
        );

        let epoch = epoch!(2020 / 1 / 1);
        assert_eq!(bookshelf.get(epoch), None);
        assert!(!bookshelf.exists(epoch));

        let remote = "prefix/shelf/parts/20200101/foo";
        let mut reader = std::io::Cursor::new("foo");
        storage
            .upload(bucket, Utf8Path::new(remote), &mut reader)
            .await
            .unwrap();

        let shelf = bookshelf.book(epoch);
        assert_eq!(shelf.epoch(), epoch);

        let entry = shelf.entry("foo");
        assert_eq!(
            entry.path(),
            Utf8Path::new("prefix/shelf/parts/20200101/foo")
        );
        assert!(!entry.exists());
    }

    #[tokio::test]
    async fn bookshelf() {
        let bucket = "bucket";
        let prefix = Some(Utf8PathBuf::from("prefix"));

        let memory = MemoryStorage::new();
        memory.create_bucket(bucket.to_string()).await;
        let storage = Storage::new(memory);

        let case = Bookshelf::new(storage.clone(), bucket.to_string(), prefix.clone());

        let remote = "prefix/shelf/parts/20200101/foo";
        let mut reader = std::io::Cursor::new("foo");
        storage
            .upload(bucket, Utf8Path::new(remote), &mut reader)
            .await
            .unwrap();

        eprintln!("paths: {:#?}", storage.list(bucket, None).await.unwrap());

        let bookshelf = case.bookshelf("shelf/parts").await.unwrap();
        eprintln!("paths: {:#?}", bookshelf.inner.paths);

        let epoch = epoch!(2020 / 1 / 1);

        let shelf = bookshelf.book(epoch);
        assert_eq!(shelf.epoch(), epoch);
        assert!(shelf.exists());

        let entry = shelf.entry("foo");
        assert_eq!(
            entry.path(),
            Utf8Path::new("prefix/shelf/parts/20200101/foo")
        );
        assert!(entry.exists());

        let entry = shelf.entry("bar");
        assert_eq!(
            entry.path(),
            Utf8Path::new("prefix/shelf/parts/20200101/bar")
        );
        assert!(!entry.exists());

        let shelf = bookshelf.earliest().unwrap();
        assert_eq!(shelf.epoch(), epoch);

        let shelf = bookshelf.book(epoch!(2023 / 2 / 28));
        assert_eq!(shelf.epoch(), epoch!(2023 / 2 / 28));
        assert!(!shelf.exists());

        let shelf = bookshelf.latest().unwrap();
        assert_eq!(shelf.epoch(), epoch);

        shelf.entry("foo").delete().await.unwrap();
        assert!(storage.list(bucket, None).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn bookshelf_no_prefix() {
        let bucket = "bucket";
        let prefix = None;

        let memory = MemoryStorage::new();
        memory.create_bucket(bucket.to_string()).await;
        let storage = Storage::new(memory);

        let case = Bookshelf::new(storage.clone(), bucket.to_string(), prefix.clone());

        let remote = "shelf/deep/parts/20200101/foo";
        let mut reader = std::io::Cursor::new("foo");
        storage
            .upload(bucket, Utf8Path::new(remote), &mut reader)
            .await
            .unwrap();

        eprintln!("paths: {:#?}", storage.list(bucket, None).await.unwrap());

        let bookshelf = case.bookshelf("shelf/deep/parts").await.unwrap();
        eprintln!("paths: {:#?}", bookshelf.inner.paths);

        let epoch = epoch!(2020 / 1 / 1);

        let shelf = bookshelf.book(epoch);
        assert_eq!(shelf.epoch(), epoch);
        assert!(shelf.exists());

        let entry = shelf.entry("foo");
        assert_eq!(entry.path(), Utf8Path::new("shelf/deep/parts/20200101/foo"));
        assert!(entry.exists());

        let entry = shelf.entry("bar");
        assert_eq!(entry.path(), Utf8Path::new("shelf/deep/parts/20200101/bar"));
        assert!(!entry.exists());

        let shelf = bookshelf.book(epoch!(2023 / 2 / 28));
        assert_eq!(shelf.epoch(), epoch!(2023 / 2 / 28));
        assert!(!shelf.exists());

        let shelf = bookshelf.earliest().unwrap();
        assert_eq!(shelf.epoch(), epoch);

        let shelf = bookshelf.latest().unwrap();
        assert_eq!(shelf.epoch(), epoch);

        shelf.entry("foo").delete().await.unwrap();
        assert!(storage.list(bucket, None).await.unwrap().is_empty());
    }
}
