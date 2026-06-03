//! RFC 8628 — Device Authorization grant.
//!
//! The flow has two halves: [`crate::endpoint::TokenEndpoint::start_device_flow`]
//! makes the device authorization request and returns a
//! [`DeviceAuthorizationResponse`] containing the user code; then
//! [`crate::endpoint::TokenEndpoint::poll_device_token`] polls the token
//! endpoint until the user authorizes, denies, or the code expires.
//!
//! Device-flow-specific OAuth2 error codes (RFC 8628 §3.5) appear as
//! [`crate::TokenErrorCode::Other`] with the string values
//! `authorization_pending`, `slow_down`, `access_denied`, and
//! `expired_token`. The two polling-control codes are handled inside the
//! polling loop; the rest surface as [`crate::Error::TokenError`].

use secret::Secret;
use serde::Deserialize;

/// Token-endpoint request using the device-code grant.
#[derive(Debug, Clone)]
pub struct DeviceCodeRequest {
    device_code: Secret,
}

impl DeviceCodeRequest {
    /// Build a request from a device code returned by
    /// [`DeviceAuthorizationResponse`].
    pub fn new(device_code: impl Into<Secret>) -> Self {
        Self {
            device_code: device_code.into(),
        }
    }

    pub(crate) fn into_fields(self) -> Vec<(&'static str, String)> {
        vec![
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:device_code".to_owned(),
            ),
            ("device_code", self.device_code.revealed().to_owned()),
        ]
    }
}

/// Response from the device authorization endpoint (RFC 8628 §3.2).
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceAuthorizationResponse {
    /// The device verification code (kept secret — used only for polling).
    pub device_code: Secret,
    /// The end-user verification code, displayed to the user.
    pub user_code: String,
    /// The URL the user visits to enter their code.
    pub verification_uri: String,
    /// Optional URL that pre-fills the user code via a query string.
    #[serde(default)]
    pub verification_uri_complete: Option<String>,
    /// Lifetime of the device + user code in seconds.
    pub expires_in: u64,
    /// Minimum interval between successive polls, in seconds. Defaults to 5.
    #[serde(default = "default_interval")]
    pub interval: u64,
}

fn default_interval() -> u64 {
    5
}
