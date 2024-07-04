mod application;
mod bucket;
mod client;
mod download;
mod errors;
mod file;
mod multi;
mod upload;

/// The name of the storage driver.
const B2_STORAGE_NAME: &str = "B2";

/// URL Scheme which should be registered for this storage driver.
const B2_STORAGE_SCHEME: &str = "b2";

/// The maximum file size for a single file upload.
///
/// This is a limitation of the B2 API. Nominally, this values is 5GB,
/// but we can split up smaller files if we want, so we do that here.
const B2_LARGE_FILE_SIZE: usize = 1024 * 1024 * 1024; // 1GB

/// Number of file parts to simultaneously upload.
const B2_DEFAULT_CONCURRENCY: usize = 4;

/// Number of upload retries
const B2_UPLOAD_RETRIES: usize = 5;

/// Default timeout for regular requests
const B2_DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Default connect timeout
const B2_DEFAULT_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub use crate::application::B2ApplicationKey;
pub use crate::client::B2Client;
pub use crate::errors::{B2Error, B2RequestError};
pub use crate::multi::{B2MultiClient, B2MultiConfig};
