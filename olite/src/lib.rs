//! SQLite-backed [`SessionStore`](oath::server::SessionStore) and
//! [`UserStore`](oath::server::UserStore) implementations for
//! [`oath::server`].
//!
//! Open a [`Database`] once, then build both stores from it; they share
//! one connection and one file:
//!
//! ```no_run
//! # fn main() -> Result<(), olite::Error> {
//! use std::time::Duration;
//! use olite::{Database, SqliteSessionStore, SqliteUserStore};
//!
//! #[derive(serde::Serialize, serde::Deserialize)]
//! struct Profile {
//!     display_name: Option<String>,
//! }
//!
//! let db = Database::open("auth.sqlite3")?;
//! let sessions = SqliteSessionStore::new(db.clone(), Duration::from_secs(60 * 60 * 48));
//! let users = SqliteUserStore::<Profile>::new(db);
//! # Ok(())
//! # }
//! ```
//!
//! Tables are prefixed with `oath_`, so the database can be shared with
//! application tables. The schema is created (and migrated) when the
//! [`Database`] is opened.

mod db;
mod session;
mod user;

pub use self::db::{Database, Error};
pub use self::session::SqliteSessionStore;
pub use self::user::SqliteUserStore;
