use std::time::Duration;

use axum::extract::FromRef;
use cookie::Key;
use http::{
    Uri,
    uri::{Authority, Scheme},
};
use oath::server::InMemorySessionStore;

use crate::config::Config;

#[derive(Debug, Clone)]
pub struct AppState {
    pub config: Config,
    pub sessions: InMemorySessionStore,
    pub upstream: Authority,
}

impl AppState {
    pub fn new(config: Config, upstream: Authority) -> Self {
        Self {
            config,
            sessions: InMemorySessionStore::new(Duration::from_hours(48)),
            upstream,
        }
    }

    pub fn rewrite_uri(&self, uri: &Uri) -> Uri {
        let mut rewritten = uri.clone().into_parts();
        rewritten.scheme.get_or_insert(Scheme::HTTP);
        rewritten.authority = Some(self.upstream.clone());
        Uri::from_parts(rewritten).expect("invalid upstream authority")
    }
}

impl FromRef<AppState> for Key {
    fn from_ref(input: &AppState) -> Self {
        Key::from(input.config.sessions.key.revealed().as_bytes())
    }
}
