use std::{
    convert::Infallible,
    sync::{Arc, RwLock},
};

use axum::extract::FromRequestParts;
use cookie::{Cookie, Key};

#[derive(Debug, Clone)]
pub struct CookieJar {
    jar: Arc<RwLock<cookie::CookieJar>>,
}

impl CookieJar {
    fn new(jar: cookie::CookieJar) -> Self {
        Self {
            jar: Arc::new(RwLock::new(jar)),
        }
    }

    /// Returns the cookie with the given name, if it exists.
    #[expect(dead_code)]
    pub fn get(&self, name: &str) -> Option<Cookie<'static>> {
        self.jar.read().ok().and_then(|jar| jar.get(name).cloned())
    }

    /// Returns the signed cookie with the given name, if it exists.
    pub fn signed(&self, name: &str, key: &Key) -> Option<Cookie<'static>> {
        self.jar
            .read()
            .ok()
            .and_then(|jar| jar.signed(key).get(name))
    }
}

impl<S> FromRequestParts<S> for CookieJar
where
    S: Sync + 'static,
{
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        if let Some(jar) = parts.extensions.get::<CookieJar>() {
            return Ok(jar.clone());
        }

        let mut jar = cookie::CookieJar::new();
        for hv in parts.headers.get_all(http::header::COOKIE) {
            let Ok(s) = hv.to_str() else { continue };
            for part in s.split(';').map(str::trim) {
                if part.is_empty() {
                    continue;
                }
                if let Ok(cookie) = Cookie::parse(part.to_owned()) {
                    jar.add_original(cookie);
                }
            }
        }

        let jar = CookieJar::new(jar);
        parts.extensions.insert(jar.clone());
        Ok(jar)
    }
}
