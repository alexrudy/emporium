use std::{borrow::Cow, env::VarError, fmt, ops::Deref};

use http::{header::InvalidHeaderValue, HeaderValue};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// An API Key for a service. Generally any semi-secret item.
///
/// This wrapper just prevents the key from appearing in debug reprs.
///
/// Use [Secret::revealed] to get the underlying value.
#[derive(Clone, Deserialize, Serialize)]
#[serde(from = "String")]
pub struct Secret(Cow<'static, str>);

impl Secret {
    pub fn from_env(var: &str) -> Result<Self, VarError> {
        let value = std::env::var(var)?;
        Ok(Secret(value.into()))
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        if let Cow::Owned(ref mut s) = self.0 {
            s.zeroize()
        }
    }
}

/// Tiny wrapper struct to indicate that the inner object should
/// be directly printed in fmt::Debug implementations.
struct DirectDebug<D>(D);

impl<D> fmt::Debug for DirectDebug<D>
where
    D: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Secret").field(&DirectDebug("****")).finish()
    }
}

impl Secret {
    /// Expose the underlying value of this API Key
    pub fn revealed(&self) -> &str {
        self.0.deref()
    }

    pub fn to_header(&self) -> Result<HeaderValue, InvalidHeaderValue> {
        let mut header = HeaderValue::try_from(self.revealed())?;
        header.set_sensitive(true);
        Ok(header)
    }

    pub fn bearer(&self) -> Result<HeaderValue, InvalidHeaderValue> {
        let mut header = HeaderValue::try_from(format!("Bearer {}", self.revealed()))?;
        header.set_sensitive(true);
        Ok(header)
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        Secret(s.to_owned().into())
    }
}

impl From<Cow<'static, str>> for Secret {
    fn from(inner: Cow<'static, str>) -> Self {
        Secret(inner)
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Secret(value.into())
    }
}

impl From<&'static str> for Secret {
    fn from(value: &'static str) -> Self {
        Secret(value.into())
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn secret_hidden_debug() {
        let key = "secret garden";
        let apikey = Secret::from(key);

        // Check that the debug doesn't reveal the secret
        assert!(!format!("{apikey:?}").contains("secret garden"));

        // Match the debug format exactly
        assert_eq!(&format!("{apikey:?}"), "Secret(****)");

        // Check that we can still access the underlying key
        assert_eq!(apikey.revealed(), key);
    }
}
