use eyre::Report;
use thiserror::Error;

/// Generic error returned from a downstream
/// implementation.
#[derive(Debug, Error)]
#[error("Storage error from {engine}")]
pub struct StorageError {
    engine: &'static str,

    #[source]
    error: Report,
}

impl StorageError {
    /// Create a new storage error from a downstream error and the name of the
    /// storage engine.
    pub fn new<E: Into<Report>>(engine: &'static str, error: E) -> Self {
        Self {
            engine,
            error: error.into(),
        }
    }

    /// Return a boxed closure that creates a new storage error from a downstream
    /// error, using the provided storage engine name.
    pub fn with<E>(engine: &'static str) -> Box<dyn FnOnce(E) -> StorageError>
    where
        E: Into<Report>,
    {
        Box::new(move |error: E| StorageError {
            engine,
            error: error.into(),
        })
    }
}
