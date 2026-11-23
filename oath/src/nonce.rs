//! Nonce Support to guard against replay attacks

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jaws::crypto::p521::elliptic_curve::subtle::ConstantTimeEq;
use rand::{TryRng as _, rngs::SysRng};
use secret::Secret;
use serde::{Deserialize, Serialize};

/// A
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Nonce(Secret);

impl Nonce {
    /// Generate a fresh state token from 32 random bytes drawn from
    /// [`SysRng`], encoded as 43 base64url characters (no padding).
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        SysRng
            .try_fill_bytes(&mut bytes)
            .expect("SysRng must provide random bytes");
        Self(Secret::from(URL_SAFE_NO_PAD.encode(bytes)))
    }

    /// Wrap an existing string as a state token. The string is treated as
    /// opaque; no validation is performed.
    pub fn from_secret(secret: impl Into<Secret>) -> Self {
        Self(secret.into())
    }

    /// Reveal the underlying token text so it can be placed in an
    /// authorization request URL.
    pub fn revealed(&self) -> &str {
        self.0.revealed()
    }

    /// Constant-time compare against a value returned by the
    /// authorization server. Returns `true` if they match.
    pub fn verify(&self, returned: &str) -> bool {
        self.0
            .revealed()
            .as_bytes()
            .ct_eq(returned.as_bytes())
            .into()
    }
}
