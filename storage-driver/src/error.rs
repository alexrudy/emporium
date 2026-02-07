use std::backtrace::Backtrace;
use std::error::Error as StdError;
use std::fmt;

use tracing_error::SpanTrace;

/// Categorizes storage errors by their semantic meaning, independent of
/// the underlying storage backend implementation.
///
/// This enum helps callers understand what went wrong and how to respond,
/// without needing to inspect error messages or know backend-specific details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageErrorKind {
    /// The requested resource (file, object, bucket) was not found.
    ///
    /// **Retryable:** No - the resource doesn't exist.
    /// **Caller action:** Check the path/bucket name, or handle as a missing resource.
    NotFound,

    /// The caller lacks permission to perform the requested operation.
    ///
    /// **Retryable:** No - unless credentials are updated.
    /// **Caller action:** Check authentication, authorization, or file permissions.
    PermissionDenied,

    /// The operation failed due to I/O errors (network, disk, etc.).
    ///
    /// **Retryable:** Maybe - depends on whether the I/O issue is transient.
    /// **Caller action:** Consider retrying with backoff for transient failures.
    Io,

    /// The backing storage service is temporarily unavailable.
    ///
    /// **Retryable:** Yes - the service should recover.
    /// **Caller action:** Retry with exponential backoff.
    ServiceUnavailable,

    /// Authentication credentials have expired and need refresh.
    ///
    /// **Retryable:** Yes - after refreshing credentials.
    /// **Caller action:** Refresh auth tokens and retry.
    AuthExpired,

    /// The request was invalid (bad parameters, malformed data, etc.).
    ///
    /// **Retryable:** No - the request itself is invalid.
    /// **Caller action:** Fix the request parameters.
    InvalidRequest,

    /// The operation was retried multiple times but continued to fail.
    ///
    /// **Retryable:** No - retries were already attempted.
    /// **Caller action:** Investigate the underlying cause or escalate.
    RetriesExhausted,

    /// Data serialization or deserialization failed.
    ///
    /// **Retryable:** No - indicates a data format mismatch.
    /// **Caller action:** Check data format compatibility.
    SerializationError,

    /// An unexpected or uncategorized error occurred.
    ///
    /// **Retryable:** Unknown - inspect the underlying error.
    /// **Caller action:** Check error details for specific guidance.
    Other,
}

impl StorageErrorKind {
    /// Returns whether this error kind typically indicates a retryable condition.
    ///
    /// Note: This is advisory only. Callers should consider context like:
    /// - How many retries have already occurred
    /// - Whether retry logic exists at a higher level
    /// - The criticality of the operation
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            StorageErrorKind::ServiceUnavailable
                | StorageErrorKind::AuthExpired
                | StorageErrorKind::Io // May be transient
        )
    }

    /// Returns whether this error indicates a client-side fault (bad request, invalid params).
    pub fn is_client_fault(&self) -> bool {
        matches!(
            self,
            StorageErrorKind::InvalidRequest
                | StorageErrorKind::PermissionDenied
                | StorageErrorKind::SerializationError
        )
    }

    /// Returns whether this error indicates a server-side fault (service issues).
    pub fn is_server_fault(&self) -> bool {
        matches!(
            self,
            StorageErrorKind::ServiceUnavailable | StorageErrorKind::RetriesExhausted
        )
    }
}

impl fmt::Display for StorageErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageErrorKind::NotFound => write!(f, "not found"),
            StorageErrorKind::PermissionDenied => write!(f, "permission denied"),
            StorageErrorKind::Io => write!(f, "I/O error"),
            StorageErrorKind::ServiceUnavailable => write!(f, "service unavailable"),
            StorageErrorKind::AuthExpired => write!(f, "authentication expired"),
            StorageErrorKind::InvalidRequest => write!(f, "invalid request"),
            StorageErrorKind::RetriesExhausted => write!(f, "retries exhausted"),
            StorageErrorKind::SerializationError => write!(f, "serialization error"),
            StorageErrorKind::Other => write!(f, "other error"),
        }
    }
}

#[derive(Debug)]
struct ErrorTrace {
    /// Captured backtrace for debugging.
    ///
    /// Note: Backtrace capture is controlled by RUST_BACKTRACE environment variable.
    backtrace: Backtrace,

    /// Captured span trace from tracing for async context.
    ///
    /// This provides the span context at the point where the error was created,
    /// allowing you to see the logical async call stack.
    span_trace: SpanTrace,
}

impl ErrorTrace {
    /// Captures the current backtrace and span trace.
    #[track_caller]
    fn capture() -> Self {
        ErrorTrace {
            backtrace: Backtrace::capture(),
            span_trace: SpanTrace::capture(),
        }
    }
}

/// Comprehensive storage error with rich context and diagnostic capabilities.
///
/// This error type provides:
/// - **Semantic categorization** via `StorageErrorKind`
/// - **Operation context** (bucket, path, engine)
/// - **Error chain preservation** via `Box<dyn Error + Send + Sync>`
/// - **Backtrace capture** for debugging
/// - **Spantrace support** via `tracing_error::SpanTrace`
/// - **Retry guidance** via `StorageErrorKind` methods
///
/// # Example
///
/// ```rust
/// use storage_driver::{StorageError, StorageErrorKind};
///
/// fn download_file() -> Result<(), StorageError> {
///     let result = std::fs::File::open("missing.txt");
///
///     match result {
///         Err(err) => Err(StorageError::builder("local", StorageErrorKind::NotFound, err)
///             .bucket("my-bucket")
///             .path("path/to/missing.txt")
///             .build()),
///         Ok(_) => Ok(()),
///     }
/// }
/// ```
#[derive(Debug)]
pub struct StorageError {
    /// The semantic category of this error.
    kind: StorageErrorKind,

    /// The name of the storage engine that produced this error.
    engine: &'static str,

    /// The bucket/container name, if applicable.
    bucket: Option<String>,

    /// The file path within the bucket, if applicable.
    path: Option<String>,

    /// Additional context or metadata about the error.
    context: Option<String>,

    /// The underlying error.
    source: Box<dyn StdError + Send + Sync + 'static>,

    /// Traces
    traces: Box<ErrorTrace>,
}

impl StdError for StorageError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.source.as_ref())
    }
}

impl StorageError {
    /// Create a new storage error with the minimum required information.
    ///
    /// For more control, use `StorageError::builder()`.
    pub fn new<E>(engine: &'static str, kind: StorageErrorKind, error: E) -> Self
    where
        E: Into<Box<dyn StdError + Send + Sync + 'static>>,
    {
        Self {
            kind,
            engine,
            bucket: None,
            path: None,
            context: None,
            source: error.into(),
            traces: Box::new(ErrorTrace::capture()),
        }
    }

    /// Create a builder for constructing a storage error with full context.
    ///
    /// The builder requires the three essential pieces of information upfront:
    /// - `engine`: The storage engine name
    /// - `kind`: The error kind
    /// - `error`: The underlying error
    ///
    /// Additional optional context (bucket, path, context) can be added via builder methods.
    ///
    /// # Example
    ///
    /// ```rust
    /// use storage_driver::{StorageError, StorageErrorKind};
    ///
    /// let error = StorageError::builder("s3", StorageErrorKind::NotFound,
    ///     std::io::Error::new(std::io::ErrorKind::NotFound, "file not found"))
    ///     .bucket("my-bucket")
    ///     .path("path/to/file.txt")
    ///     .build();
    /// ```
    pub fn builder<E>(engine: &'static str, kind: StorageErrorKind, error: E) -> StorageErrorBuilder
    where
        E: Into<Box<dyn StdError + Send + Sync + 'static>>,
    {
        StorageErrorBuilder {
            engine,
            kind,
            source: error.into(),
            bucket: None,
            path: None,
            context: None,
        }
    }

    /// Returns a boxed closure that creates a storage error from a downstream error.
    ///
    /// This is useful with `.map_err()` for simple error conversion.
    ///
    /// # Example
    ///
    /// ```rust
    /// use storage_driver::{StorageError, StorageErrorKind};
    ///
    /// fn operation() -> Result<(), StorageError> {
    ///     std::fs::File::open("file.txt")
    ///         .map_err(StorageError::with("local", StorageErrorKind::Io))?;
    ///     Ok(())
    /// }
    /// ```
    pub fn with<E>(
        engine: &'static str,
        kind: StorageErrorKind,
    ) -> Box<dyn FnOnce(E) -> StorageError + Send + Sync>
    where
        E: Into<Box<dyn StdError + Send + Sync + 'static>>,
    {
        Box::new(move |error: E| StorageError::new(engine, kind, error))
    }

    /// Returns the error kind.
    pub fn kind(&self) -> StorageErrorKind {
        self.kind
    }

    /// Returns the storage engine name.
    pub fn engine(&self) -> &'static str {
        self.engine
    }

    /// Returns the bucket name, if available.
    pub fn bucket(&self) -> Option<&str> {
        self.bucket.as_deref()
    }

    /// Returns the file path, if available.
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    /// Returns additional context, if available.
    pub fn context(&self) -> Option<&str> {
        self.context.as_deref()
    }

    /// Returns whether this error is likely retryable.
    pub fn is_retryable(&self) -> bool {
        self.kind.is_retryable()
    }

    /// Returns whether this error indicates a client-side fault.
    pub fn is_client_fault(&self) -> bool {
        self.kind.is_client_fault()
    }

    /// Returns whether this error indicates a server-side fault.
    pub fn is_server_fault(&self) -> bool {
        self.kind.is_server_fault()
    }

    /// Returns a reference to the captured backtrace.
    pub fn backtrace(&self) -> &Backtrace {
        &self.traces.backtrace
    }

    /// Returns a reference to the captured span trace.
    ///
    /// The span trace provides the tracing span context at the point where
    /// this error was created, showing the logical async call stack.
    pub fn span_trace(&self) -> &SpanTrace {
        &self.traces.span_trace
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Storage error [{}] from {}", self.kind, self.engine)?;

        if let Some(bucket) = &self.bucket {
            write!(f, " (bucket: {})", bucket)?;
        }

        if let Some(path) = &self.path {
            write!(f, " (path: {})", path)?;
        }

        if let Some(context) = &self.context {
            write!(f, " ({})", context)?;
        }

        write!(f, ": {}", self.source)
    }
}

/// Builder for constructing `StorageError` with optional context fields.
///
/// The builder is created with all required fields already provided via
/// `StorageError::builder()`, and this builder allows adding optional context.
///
/// # Example
///
/// ```rust
/// use storage_driver::{StorageError, StorageErrorKind};
///
/// let error = StorageError::builder(
///     "s3",
///     StorageErrorKind::NotFound,
///     std::io::Error::new(std::io::ErrorKind::NotFound, "file not found")
/// )
///     .bucket("my-bucket")
///     .path("path/to/file.txt")
///     .context("download operation")
///     .build();
/// ```
#[derive(Debug)]
pub struct StorageErrorBuilder {
    kind: StorageErrorKind,
    engine: &'static str,
    source: Box<dyn StdError + Send + Sync + 'static>,
    bucket: Option<String>,
    path: Option<String>,
    context: Option<String>,
}

impl StorageErrorBuilder {
    /// Set the bucket name.
    pub fn bucket(mut self, bucket: impl Into<String>) -> Self {
        self.bucket = Some(bucket.into());
        self
    }

    /// Set the file path.
    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Set additional context.
    pub fn context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(context.into());
        self
    }

    /// Build the `StorageError`.
    ///
    /// This never panics as all required fields are guaranteed to be present.
    pub fn build(self) -> StorageError {
        StorageError {
            kind: self.kind,
            engine: self.engine,
            bucket: self.bucket,
            path: self.path,
            context: self.context,
            source: self.source,
            traces: Box::new(ErrorTrace::capture()),
        }
    }
}
