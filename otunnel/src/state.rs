use axum::extract::FromRef;
use cookie::Key;

use crate::config::Config;

#[derive(Debug, Clone)]
pub struct AppState {
    pub inner: otool::state::AppState,
}

impl AppState {
    pub async fn new(config: Config) -> Result<Self, otool::store::StoreError> {
        Ok(Self {
            inner: otool::state::AppState::new(config.oath, config.providers, config.sessions)
                .await?,
        })
    }
}

impl FromRef<AppState> for Key {
    fn from_ref(input: &AppState) -> Self {
        Key::from(input.inner.sessions.key.revealed().as_bytes())
    }
}
