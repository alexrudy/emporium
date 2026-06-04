//! An API Client for sending email with MailGun

use std::sync::LazyLock;

use api_client::{
    ApiClient, Authentication, RequestBuilder, basic_auth,
    response::{ResponseBodyExt as _, ResponseExt as _},
};
use http::Uri;
use hyperdriver::Body;
use secret::Secret;
use serde::de::DeserializeOwned;

use self::{
    error::{MailGunApiError, MailGunError},
    mail::{Message, MessageResponse},
};

pub mod error;
pub mod mail;

static MAILGUN_API: LazyLock<Uri> =
    LazyLock::new(|| "https://api.mailgun.net/v3/".parse().unwrap());

/// Results from the MailGun API can be errors or data.
pub type Result<T, E = MailGunError> = std::result::Result<T, E>;

/// Authentication for the MailGun API.
///
/// Uses basic auth with the `api` username and the token as the password.
#[derive(Debug, Clone)]
pub struct ApiAuthentication {
    token: Secret,
}

impl ApiAuthentication {
    /// Creates a new `ApiAuthentication` with the given token.
    pub fn new(token: impl Into<Secret>) -> Self {
        Self {
            token: token.into(),
        }
    }

    pub(crate) fn header_value(&self) -> http::HeaderValue {
        basic_auth("api", Some(self.token.revealed()))
    }
}

impl Authentication for ApiAuthentication {
    fn authenticate<B>(&self, mut req: http::Request<B>) -> http::Request<B> {
        req.headers_mut()
            .insert(http::header::AUTHORIZATION, self.header_value());

        req
    }
}

/// A client for the Linode API.
#[derive(Debug, Clone)]
pub struct MailgunClient {
    inner: ApiClient<ApiAuthentication>,
}

impl MailgunClient {
    /// Create a new MailGun client from the `MAILGUN_API_TOKEN` environment variable.
    pub fn from_env() -> Self {
        let token =
            std::env::var("MAILGUN_API_TOKEN").expect("MAILGUN_API_TOKEN environment variable");
        MailgunClient {
            inner: ApiClient::new(MAILGUN_API.clone(), ApiAuthentication::new(token)),
        }
    }

    /// Create a new Linode client from a token.
    pub fn new<S: Into<Secret>>(token: S) -> Self {
        MailgunClient {
            inner: ApiClient::new(MAILGUN_API.clone(), ApiAuthentication::new(token)),
        }
    }

    /// Access the inner API Client
    pub fn api_client(&self) -> &ApiClient<ApiAuthentication> {
        &self.inner
    }

    async fn execute(&self, request: http::Request<Body>) -> Result<String> {
        let resp = self.inner.execute(request).await?;
        let status = resp.status();
        let body = resp.text().await.map_err(api_client::Error::ResponseBody)?;

        if !status.is_success() {
            tracing::error!("Error response from MailGun: {:?}", status);

            let errors = serde_json::de::from_str(&body)?;
            return Err(MailGunApiError::new(status, errors).into());
        }

        Ok(body)
    }

    async fn execute_and_deserialize<T>(&self, builder: RequestBuilder) -> Result<T>
    where
        T: DeserializeOwned + Send + 'static,
    {
        let body = self
            .execute(builder.build().map_err(api_client::Error::from)?)
            .await?;
        Ok(serde_json::de::from_str(&body)?)
    }

    /// Send an email using the MailGun API.
    pub async fn send_email(&self, domain: &str, message: &Message) -> Result<MessageResponse> {
        let endpoint = format!("{}/messages", domain);
        let form = formdata::to_form(message)?;
        let builder = self
            .inner
            .post(&endpoint)
            .header(http::header::CONTENT_TYPE, form.content_type())
            .body(form.into_bytes());
        self.execute_and_deserialize(builder).await
    }
}
