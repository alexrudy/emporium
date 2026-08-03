use axum::extract::FromRef;
use cookie::Key;
use http::{
    Uri,
    uri::{Authority, Scheme},
};

use crate::config::Config;

#[derive(Debug, Clone)]
pub struct AppState {
    pub inner: otool::state::AppState,
    pub upstream: Authority,
}

impl AppState {
    pub fn new(config: Config, upstream: Authority) -> Self {
        Self {
            inner: otool::state::AppState::new(config.oath, config.provider, config.sessions),
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
        Key::from(input.inner.sessions.key.revealed().as_bytes())
    }
}
