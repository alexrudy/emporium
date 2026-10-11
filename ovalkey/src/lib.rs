//! Valkey-backed [`SessionStore`](oath::server::SessionStore) and
//! [`UserStore`](oath::server::UserStore) implementations for
//! [`oath::server`]. Redis works too: only basic `GET`/`SET`/`DEL`
//! commands are used.
//!
//! Connect once, then build both stores from the [`Valkey`] handle; they
//! share one auto-reconnecting, multiplexed connection:
//!
//! ```no_run
//! # async fn example() -> Result<(), ovalkey::Error> {
//! use std::time::Duration;
//! use ovalkey::{Valkey, ValkeySessionStore, ValkeyUserStore};
//!
//! #[derive(serde::Serialize, serde::Deserialize)]
//! struct Profile {
//!     display_name: Option<String>,
//! }
//!
//! let valkey = Valkey::connect("redis://127.0.0.1:6379").await?;
//! let sessions = ValkeySessionStore::new(valkey.clone(), Duration::from_secs(60 * 60 * 48));
//! let users = ValkeyUserStore::<Profile>::new(valkey);
//! # Ok(())
//! # }
//! ```
//!
//! # Keys
//!
//! With the default `oath` prefix:
//!
//! - `oath:session:{id}`: a session, as JSON, expiring after the store's
//!   TTL (Valkey drops it; nothing needs pruning).
//! - `oath:user:{provider}:{username}`: a user record, as JSON, with no
//!   expiry. Provider ids can't contain `:`, so keys can't collide.
//!
//! User records are meant to be durable: run Valkey with persistence
//! enabled and an eviction policy (like the default `noeviction`, or a
//! `volatile-*` one) that won't evict keys without a TTL.

mod client;
mod session;
mod user;

pub use self::client::{Error, Valkey};
pub use self::session::ValkeySessionStore;
pub use self::user::ValkeyUserStore;

#[cfg(test)]
mod testing {
    use oath::server::SessionId;

    use crate::Valkey;

    /// Environment variable naming the Valkey server to test against,
    /// e.g. `redis://127.0.0.1:6379`.
    pub(crate) const TEST_URL_VAR: &str = "OVALKEY_TEST_URL";

    /// Connects to the test server under a fresh key prefix, or returns
    /// `None` (skipping the test) when [`TEST_URL_VAR`] isn't set.
    pub(crate) async fn valkey() -> Option<Valkey> {
        let Ok(url) = std::env::var(TEST_URL_VAR) else {
            eprintln!("skipping: set {TEST_URL_VAR} to run tests against Valkey");
            return None;
        };
        let valkey = Valkey::connect(url.as_str())
            .await
            .expect("connect to test Valkey");
        Some(valkey.with_prefix(format!("ovalkey-test-{}", SessionId::generate().as_str())))
    }
}
