//! Github API object models.

use api_client::{Authentication, RequestExt, Secret};
use chrono::{DateTime, Utc};
use serde::Deserialize;

pub mod commits;

pub use commits::Commit;

/// Github API response for a single installation.
#[derive(Debug, Deserialize)]
pub struct Installation {
    /// Installation ID.
    pub id: u64,

    /// Account associated with the installation.
    pub account: Account,
}

/// Account associated with an installation.
#[derive(Debug, Deserialize)]
pub struct Account {
    /// Installation title
    pub title: Option<String>,

    /// Account ID.
    pub id: i64,

    /// Account login.
    pub login: String,
}

/// API credentials for access to a Github installation.
#[derive(Debug, Clone, Deserialize)]
pub struct InstallationAccess {
    /// Installation access token
    pub(crate) token: Secret,

    /// Token expiration time.
    pub expires_at: DateTime<Utc>,
}

impl InstallationAccess {
    /// Check if the access token is expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at < Utc::now()
    }
}

impl Authentication for InstallationAccess {
    fn authenticate<B>(&self, builder: http::Request<B>) -> http::Request<B> {
        builder.bearer_auth(self.token.revealed())
    }
}
