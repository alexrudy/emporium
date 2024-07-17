//! Commit data models.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A commit object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commit {
    /// The SHA of the commit.
    pub sha: String,

    /// The commit details.
    pub commit: CommitDetails,
}

/// The author and message for a commit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitDetails {
    /// The author of the commit.
    pub author: AuthorCommitDetails,
    /// The commit message.
    pub message: String,
}

/// The author and date for a commit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorCommitDetails {
    /// Author name
    pub name: String,
    /// Author email
    pub email: String,
    /// The date of the commit.
    pub date: DateTime<Utc>,
}
