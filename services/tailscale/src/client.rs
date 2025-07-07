use std::{borrow::Cow, net::IpAddr};

use api_client::{response::ResponseBodyExt as _, ApiClient, Authentication, Secret};
use camino::Utf8PathBuf;
use serde::Deserialize;
use thiserror::Error;

const TAILSCALE_API_BASE: &str = "https://api.tailscale.com/api/v2/";

/// Tailscale API configuration
#[derive(Debug, Clone, Deserialize)]
pub struct TailscaleConfiguration {
    /// Tailscale API token
    pub token: Option<Secret>,

    /// Tailscale network
    pub tailnet: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TailscaleApiAuth(Secret);

impl Authentication for TailscaleApiAuth {
    fn authenticate<B>(&self, mut req: http::Request<B>) -> http::Request<B> {
        let value = api_client::basic_auth(self.0.revealed(), None::<&str>);
        req.headers_mut().append(http::header::AUTHORIZATION, value);
        req
    }
}

/// Tailscale API client
#[derive(Debug, Clone)]
pub struct TailscaleClient {
    inner: ApiClient<TailscaleApiAuth>,
    tailnet: Option<String>,
}

impl TailscaleClient {
    /// Create a new tailscale client from the environment
    pub fn from_env() -> Self {
        let token = std::env::var("TAILSCALE_API_KEY").expect("Valid environment variable");
        TailscaleClient {
            inner: ApiClient::new(
                TAILSCALE_API_BASE.parse().unwrap(),
                TailscaleApiAuth(Secret::from(token)),
            ),
            tailnet: std::env::var("TAILSCALE_NET").ok(),
        }
    }

    /// Create a new tailscale client
    pub fn new<S: Into<Cow<'static, str>>>(token: S, tailnet: Option<String>) -> Self {
        TailscaleClient {
            inner: ApiClient::new(
                TAILSCALE_API_BASE.parse().unwrap(),
                TailscaleApiAuth(Secret::from(token.into())),
            ),
            tailnet,
        }
    }

    /// Access the inner API client.
    pub fn api_client(&self) -> &ApiClient<TailscaleApiAuth> {
        &self.inner
    }

    fn tailnet_endpoint(&self, endpoint: &str) -> Utf8PathBuf {
        let mut path = Utf8PathBuf::from("tailnet/");
        path.push(self.tailnet.as_deref().unwrap_or("-"));
        path.push(endpoint);
        path
    }

    /// Get the list of devices on the tailscale network
    pub async fn devices(&self) -> Result<Vec<Device>, TailscaleAPIError> {
        let resp = self
            .inner
            .get(self.tailnet_endpoint("devices").as_str())
            .send()
            .await
            .map_err(TailscaleAPIError::RequestError)?;

        let devices: Vec<Device> = resp.json().await.map_err(TailscaleAPIError::BodyError)?;

        Ok(devices)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Device {
    // name: String,
    pub addresses: Vec<IpAddr>,
}

#[derive(Debug, Error)]
pub enum TailscaleAPIError {
    #[error("Request error: {0}")]
    RequestError(#[source] hyperdriver::client::Error),

    #[error("Response error: {0}")]
    BodyError(#[source] Box<dyn std::error::Error + Send + Sync>),
}
