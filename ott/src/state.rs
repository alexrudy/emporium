//! Shared application state threaded through axum handlers.

use std::sync::Arc;

use minijinja::Environment;
use oath::server::{InMemorySessionStore, JsonFileUserStore};
use serde::Serialize;
use storage::LocalDriver;

use crate::config::Config;
use crate::user::AppUser;

/// A provider as shown on the home page.
#[derive(Debug, Clone, Serialize)]
pub struct ProviderLink {
    /// Human-readable name, for the "Sign in with X" button.
    pub name: String,
    /// Path of the provider's login route.
    pub login_path: String,
    /// The redirect URI to register with the provider.
    pub callback_uri: String,
}

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
    /// Registered providers, in registration order.
    pub providers: Arc<[ProviderLink]>,
    /// Name of the session cookie set by the OAuth2 router.
    pub session_cookie: Arc<str>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("config", &self.config)
            .field("sessions", &"<InMemorySessionStore>")
            .field("users", &self.users)
            .field("providers", &self.providers)
            .finish_non_exhaustive()
    }
}
