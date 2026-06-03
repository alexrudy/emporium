//! Shared application state threaded through axum handlers.

use std::sync::Arc;

use minijinja::Environment;
use oath::server::{InMemorySessionStore, JsonFileUserStore};
use storage::LocalDriver;

use crate::config::Config;
use crate::user::AppUser;

/// `axum::extract::State` value handed to every ott handler.
///
/// All fields are cheap to clone — they hold `Arc`s under the hood —
/// so handler signatures can take `State<AppState>` rather than wrap
/// the whole thing in another `Arc`.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub templates: Arc<Environment<'static>>,
    pub sessions: InMemorySessionStore,
    pub users: JsonFileUserStore<LocalDriver, AppUser>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("config", &self.config)
            .field("sessions", &"<InMemorySessionStore>")
            .field("users", &self.users)
            .finish_non_exhaustive()
    }
}
