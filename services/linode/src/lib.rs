//! A client for the Linode API.

use std::borrow::Cow;
use std::fmt;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::time::Duration;

use api_client::response::ResponseBodyExt as _;
use api_client::response::ResponseExt as _;
use api_client::uri::UriExtension as _;
use api_client::ApiClient;
use api_client::BearerAuth;
use api_client::PaginatedData;
use api_client::RequestBuilder;
use api_client::Secret;
use futures::stream::StreamExt;
use futures::Stream;
use futures::TryStreamExt;
use hyperdriver::Body;
use thiserror::Error;

use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde::Serialize;

/// Results from the Linode API can be errors or data.
pub type Result<T, E = LinodeError> = std::result::Result<T, E>;

/// An empty hashmap, useful for deserializing empty objects
/// in JSON responses from the Linode API.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct Empty(std::collections::HashMap<String, ()>);

/// A client for the Linode API.
#[derive(Debug, Clone)]
pub struct LinodeClient {
    inner: ApiClient<BearerAuth>,
}

impl LinodeClient {
    /// Create a new Linode client from the `LINODE_API_TOKEN` environment variable.
    pub fn from_env() -> Self {
        let token =
            std::env::var("LINODE_API_TOKEN").expect("LINODE_API_TOKEN environment variable");
        LinodeClient {
            inner: ApiClient::new_bearer_auth(
                "https://api.linode.com/v4/".parse().unwrap(),
                Secret::from(token),
            ),
        }
    }

    /// Create a new Linode client from a configuration.
    pub fn from_config(config: &LinodeConfiguration) -> Self {
        LinodeClient {
            inner: ApiClient::new_bearer_auth(
                "https://api.linode.com/v4/".parse().unwrap(),
                config.token.clone(),
            ),
        }
    }

    /// Create a new Linode client from a token.
    pub fn new<S: Into<Cow<'static, str>>>(token: S) -> Self {
        LinodeClient {
            inner: ApiClient::new_bearer_auth(
                "https://api.linode.com/v4/".parse().unwrap(),
                Secret::from(token.into()),
            ),
        }
    }

    async fn execute(&self, request: http::Request<Body>) -> Result<String> {
        let resp = self.inner.execute(request).await?;
        let status = resp.status();
        let body = resp.text().await.map_err(api_client::Error::ResponseBody)?;

        if !status.is_success() {
            tracing::error!("Error response from linode: {:?}", status);

            let errors = serde_json::de::from_str(&body)?;
            return Err(LinodeApiError::new(status, errors).into());
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

    #[allow(unused)]
    async fn get<T>(&self, endpoint: &str) -> Result<T>
    where
        T: DeserializeOwned + Send + 'static,
    {
        let request = self.inner.get(endpoint);
        self.execute_and_deserialize(request).await
    }

    fn get_paginated<T>(
        &self,
        endpoint: &str,
    ) -> api_client::Paginated<BearerAuth, T, PaginatedData<T, Paginator>> {
        let request = self
            .inner
            .get(endpoint)
            .body(Body::empty())
            .build()
            .unwrap();
        api_client::Paginated::new(self.inner.clone(), request)
    }

    async fn post<D, T>(&self, endpoint: &str, data: &D) -> Result<T>
    where
        D: Serialize + Send,
        T: DeserializeOwned + Send + 'static,
    {
        let request = self.inner.post(endpoint).json(data)?;
        self.execute_and_deserialize(request).await
    }

    async fn put<D, T>(&self, endpoint: &str, data: &D) -> Result<T>
    where
        D: Serialize + Send,
        T: DeserializeOwned + Send + Sync + 'static,
    {
        let request = self.inner.put(endpoint).json(data)?;
        self.execute_and_deserialize(request).await
    }

    async fn delete<T>(&self, endpoint: &str) -> Result<T>
    where
        T: DeserializeOwned + Send + 'static,
    {
        let request = self.inner.delete(endpoint);
        self.execute_and_deserialize(request).await
    }

    /// List all Linode instances.
    #[tracing::instrument(skip(self))]
    pub async fn list_lindoe_instances(&self) -> impl Stream<Item = Result<Instance>> {
        self.get_paginated("linode/instances")
            .map_ok(Instance::new)
            .map_err(|error| LinodeError::Request(api_client::Error::ResponseBody(error)))
    }

    /// List all domains managed by Linode.
    #[tracing::instrument(skip(self))]
    pub fn list_linode_domains(&self) -> Paginated<Domain> {
        self.get_paginated("domains")
    }

    /// Get a linode domain by its ID.
    pub async fn get_linode_domain_by_id(&self, id: &DomainID) -> Result<Domain> {
        self.get(&format!("domains/{id}/")).await
    }

    /// Get a linode domain by its name.
    #[tracing::instrument(skip(self))]
    pub async fn get_linode_domain(&self, domain: &str) -> Result<Option<Domain>> {
        match self
            .get_paginated("domains")
            .try_filter(|item: &Domain| std::future::ready(item.domain() == domain))
            .next()
            .await
        {
            Some(Ok(domain)) => Ok(Some(domain)),
            Some(Err(err)) => Err(api_client::Error::ResponseBody(err).into()),
            None => Ok(None),
        }
    }

    /// List all records for a domain.
    #[tracing::instrument(skip(self))]
    pub fn list_linode_domain_records(
        &self,
        domain: &Domain,
    ) -> impl futures::Stream<Item = Result<Record>> {
        let endpoint = format!("domains/{}/records", domain.id());
        let id = domain.id();

        let records: Paginated<GetDomainRecord> = self.get_paginated(&endpoint);
        records.map(move |record| {
            let record = record.map_err(api_client::Error::ResponseBody)?;
            Ok(Record::new(record, id))
        })
    }

    /// Create a new domain record in Linode.
    pub async fn create_linode_domain_record(
        &self,
        domain: &Domain,
        record: &RecordType,
        name: &SubDomain,
        target: &str,
    ) -> Result<Record> {
        let endpoint = format!("domains/{}/records", domain.id());
        let record = CreateDomainRecord {
            r#type: *record,
            target: target.into(),
            name: name.with_domain(domain),
            ttl: Duration::from_secs(60 * 60),
        };

        let record: GetDomainRecord = self.post(&endpoint, &record).await?;
        tracing::debug!("Created domain {:?} to {}", record.r#type, record.target);
        Ok(Record::new(record, domain.id()))
    }

    /// Get a domain record by its name and type.
    #[tracing::instrument(skip(self))]
    pub async fn get_linode_domain_record(
        &self,
        domain: &Domain,
        record: &RecordType,
        name: &SubDomain,
    ) -> Result<Option<Record>> {
        let record = self
            .list_linode_domain_records(domain)
            .filter_map(|rec| std::future::ready(rec.ok()))
            .filter(move |rec| std::future::ready(rec.name() == name && rec.r#type() == record))
            .next()
            .await;

        Ok(record)
    }

    /// Update a domain record in Linode.
    #[tracing::instrument(skip(self))]
    pub async fn set_linode_domain_record(
        &self,
        recordid: &RecordID,
        record: &RecordType,
        name: &SubDomain,
        target: &str,
    ) -> Result<()> {
        let domain = self.get_linode_domain_by_id(&recordid.domain()).await?;

        let endpoint = format!("domains/{}/records/{}", recordid.domain(), recordid.record);
        let record = UpdateDomainRecord {
            r#type: *record,
            target: target.into(),
            name: name.with_domain(&domain),
        };

        let record: GetDomainRecord = self.put(&endpoint, &record).await?;
        tracing::debug!("Updated domain {:?} to {}", record.r#type, record.target);
        Ok(())
    }

    /// Delete a domain record in Linode.
    pub async fn delete_linode_domain_record(&self, recordid: &RecordID) -> Result<()> {
        let endpoint = format!("domains/{}/records/{}", recordid.domain(), recordid.record);

        let id = *recordid;
        self.delete::<Empty>(&endpoint).await?;

        tracing::debug!("Deleted domain record {}", id);
        Ok(())
    }
}

/// Errors that can occur when interacting with the Linode API.
#[derive(Debug, Error)]
pub enum LinodeError {
    /// An error returned by the Linode API.
    #[error("Linode API Error: {0}")]
    ApiError(#[from] LinodeApiError),

    /// An error occured while sending the HTTP request.
    #[error("Request Error: {0}")]
    Request(#[from] api_client::error::Error),

    /// An error occured while deserializing the response body.
    #[error(transparent)]
    Serde(#[from] serde_json::Error),

    /// A resource was not found.
    #[error("{kind} not found: {value}")]
    NotFound {
        /// The reource kind
        kind: &'static str,
        /// The value that was not found
        value: String,
    },

    /// A request was sent for a record that does not match
    /// the domain it belongs to.
    #[error("Domain {0} does not match record {1}")]
    DomainMismatch(DomainID, RecordID),
}

/// A Linode API error message.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiError {
    reason: String,
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("reason: ")?;
        f.write_str(&self.reason)
    }
}

/// A Linode API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ErrorResponse {
    /// A list of errors returned by the Linode API.
    pub errors: Vec<ApiError>,
}

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Linode API Errors: \n")?;
        for error in &self.errors {
            f.write_str(&error.reason)?;
            f.write_str("\n")?;
        }
        Ok(())
    }
}

/// Error response from the Linode API, including HTTP status code and error messages.
#[derive(Debug, Clone)]
pub struct LinodeApiError {
    status: http::StatusCode,
    errors: Vec<ApiError>,
}

impl LinodeApiError {
    /// Create a new Linode API error.
    pub fn new(status: http::StatusCode, errors: ErrorResponse) -> Self {
        Self {
            status,
            errors: errors.errors,
        }
    }
}

impl fmt::Display for LinodeApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "{} {} API Errors: \n",
            self.status.as_u16(),
            self.status.as_str()
        ))?;
        for error in &self.errors {
            f.write_str(&error.reason)?;
            f.write_str("\n")?;
        }
        Ok(())
    }
}

impl std::error::Error for LinodeApiError {}

/// Configuration for the Linode API.
#[derive(Debug, Clone, Deserialize)]
pub struct LinodeConfiguration {
    /// API token
    pub token: Secret,
}

impl LinodeConfiguration {
    /// Create a new Linode API client from this configuration.
    pub fn client(&self) -> LinodeClient {
        LinodeClient::from_config(self)
    }
}

/// Newtype wrapper for IDs returned by linode, which are usize.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Hash)]
pub struct LinodeID(usize);

impl fmt::Display for LinodeID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Kinds of subdomain that can be created in Linode domain records.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(into = "String")]
pub enum SubDomain {
    /// A specific, named subdomain.
    Named(String),

    /// The "empty" subdomain, which is the root domain.
    Root,

    /// A wildcard subdomain, which matches any subdomain.
    Wildcard,
}

impl fmt::Display for SubDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl SubDomain {
    /// Get the string form of the subdomain with the given domain.
    pub fn with_domain(&self, domain: &Domain) -> String {
        match self {
            SubDomain::Named(name) => format!("{}.{}", name.trim_end_matches('.'), domain.name()),
            SubDomain::Root => domain.name().into(),
            SubDomain::Wildcard => format!("*.{}", domain.name()),
        }
    }

    /// Get the string form of the subdomain for use in DNS records.
    pub fn as_str(&self) -> &str {
        match self {
            SubDomain::Named(name) => name.as_str(),
            SubDomain::Root => "@",
            SubDomain::Wildcard => "*",
        }
    }
}

impl PartialEq<str> for SubDomain {
    fn eq(&self, other: &str) -> bool {
        match other {
            "" => self == &SubDomain::Root,
            "@" => self == &SubDomain::Root,
            "*" => self == &SubDomain::Wildcard,
            _ => self.as_str() == other,
        }
    }
}

impl PartialEq<SubDomain> for str {
    fn eq(&self, other: &SubDomain) -> bool {
        other.eq(self)
    }
}

impl From<&str> for SubDomain {
    fn from(value: &str) -> Self {
        match value {
            "" => SubDomain::Root,
            "@" => SubDomain::Root,
            "*" => SubDomain::Wildcard,
            _ => SubDomain::Named(value.into()),
        }
    }
}

impl From<String> for SubDomain {
    fn from(value: String) -> Self {
        match value.as_str() {
            "" => SubDomain::Root,
            "@" => SubDomain::Root,
            "*" => SubDomain::Wildcard,
            _ => SubDomain::Named(value),
        }
    }
}

/// DNS record types that can be created in Linode domain records.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[allow(clippy::upper_case_acronyms)]
pub enum RecordType {
    /// A record type that maps a domain to an IPv4 address.
    A,

    /// A record type that maps a domain to an IPv6 address.
    AAAA,

    /// A record type that maps a domain to another domain.
    CNAME,

    /// A record type that stores arbitrary text data.
    TXT,

    /// A record type that stores service location data.
    SRV,

    /// A record type that stores mail exchange data.
    MX,

    /// A record type that stores name server data.
    NS,

    /// A record type that stores certificate authority data.
    CAA,

    /// A record type that stores pointer data.
    PTR,
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            RecordType::A => "A",
            RecordType::AAAA => "AAAA",
            RecordType::CNAME => "CNAME",
            RecordType::TXT => "TXT",
            RecordType::SRV => "SRV",
            RecordType::MX => "MX",
            RecordType::NS => "NS",
            RecordType::CAA => "CAA",
            RecordType::PTR => "PTR",
        };

        f.write_str(name)
    }
}

#[derive(Debug, Deserialize)]
struct GetDomainRecord {
    r#type: RecordType,
    name: String,
    target: String,
    id: LinodeID,
}

#[derive(Debug, Serialize)]
struct CreateDomainRecord {
    r#type: RecordType,
    target: String,
    name: String,

    #[serde(rename = "ttl_sec", serialize_with = "crate::serialize::ttl")]
    ttl: std::time::Duration,
}

#[derive(Debug, Serialize)]
struct UpdateDomainRecord {
    r#type: RecordType,
    target: String,
    name: String,
}

/// A Linode domain record.
#[derive(Debug, Clone)]
pub struct Record {
    r#type: RecordType,
    name: String,
    target: String,
    id: RecordID,
}

impl Record {
    fn new(get: GetDomainRecord, domain: DomainID) -> Self {
        Self {
            r#type: get.r#type,
            name: get.name,
            target: get.target,
            id: RecordID::new(domain, get.id),
        }
    }

    /// The ID of the record.
    pub fn id(&self) -> RecordID {
        self.id
    }

    /// The name of the record.
    pub fn name(&self) -> &str {
        self.name.as_ref()
    }

    /// The subdomain of the record.
    pub fn subdomain(&self) -> SubDomain {
        self.name.as_str().into()
    }

    /// The target of the record.
    pub fn target(&self) -> &str {
        self.target.as_ref()
    }

    /// The target of the record as an IP address.
    pub fn addr(&self) -> Option<IpAddr> {
        self.target.parse::<IpAddr>().ok()
    }

    /// The type of the record.
    pub fn r#type(&self) -> &RecordType {
        &self.r#type
    }
}

/// A Linode domain.
#[derive(Debug, Clone, Deserialize)]
pub struct Domain {
    id: DomainID,

    #[serde(rename = "domain")]
    name: String,
}

impl Domain {
    /// The ID of the domain.
    pub fn id(&self) -> DomainID {
        self.id
    }

    /// The name of the domain.
    pub fn name(&self) -> &str {
        self.name.as_ref()
    }

    /// The domain name.
    pub fn domain(&self) -> &str {
        self.name.as_ref()
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.id, self.name())
    }
}

/// The ID of a Linode domain.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Hash)]
pub struct DomainID(LinodeID);

impl fmt::Display for DomainID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The ID of a Linode domain record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecordID {
    domain: DomainID,
    record: LinodeID,
}

impl RecordID {
    fn new(domain: DomainID, record: LinodeID) -> Self {
        Self { domain, record }
    }

    /// The domain ID of the record.
    pub fn domain(&self) -> DomainID {
        self.domain
    }

    /// The record ID.
    pub fn id(&self) -> LinodeID {
        self.record
    }
}

impl fmt::Display for RecordID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.record)
    }
}

/// The status of a Linode instance.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstanceStatus {
    /// The instance is running.
    Running,

    /// The instance is offline.
    Offline,

    /// The instance is booting.
    Booting,

    /// The instance is rebooting.
    Rebooting,

    /// The instance is shutting down.
    ShuttingDown,

    /// The instance is being provisioned.
    Provisioning,

    /// The instance is being deleted.
    Deleting,

    /// The instance is being migrated.
    Migrating,

    /// The instance is being rebuilt.
    Rebuilding,

    /// The instance is being cloned.
    Cloning,

    /// The instance is being restored from a backup.
    Restoring,

    /// The instance is stopped.
    Stopped,
}

#[derive(Debug, Deserialize)]
struct GetInstance {
    id: LinodeID,
    ipv6: Option<Ipv6Addr>,
    ipv4: Vec<Ipv4Addr>,
    label: String,
    status: InstanceStatus,
    image: String,
}

/// A Linode instance.
#[derive(Debug, Clone)]
pub struct Instance {
    id: LinodeID,
    ipv6: Option<Ipv6Addr>,
    ipv4: Ipv4Addr,
    label: String,
    status: InstanceStatus,
    image: String,
}

impl Instance {
    fn new(instance: GetInstance) -> Self {
        Self {
            id: instance.id,
            ipv6: instance.ipv6,
            ipv4: *instance
                .ipv4
                .iter()
                .find(|i| !i.is_private())
                .expect("At least one public IP Address"),
            label: instance.label,
            status: instance.status,
            image: instance.image,
        }
    }

    /// The ID of the instance.
    pub fn id(&self) -> LinodeID {
        self.id
    }

    /// The IPv6 address of the instance.
    pub fn ipv6(&self) -> Option<Ipv6Addr> {
        self.ipv6
    }

    /// The IPv4 address of the instance.
    pub fn ipv4(&self) -> Ipv4Addr {
        self.ipv4
    }

    /// A custom label for the instance.
    pub fn label(&self) -> &str {
        self.label.as_ref()
    }

    /// The status of the instance.
    pub fn status(&self) -> InstanceStatus {
        self.status
    }

    /// The name of the image used to create the instance.
    pub fn image(&self) -> &str {
        self.image.as_ref()
    }
}

mod serialize {

    /// TTL values in seconds which linode accepts.
    const TLL_VALUES: [u64; 12] = [
        300, 3600, 7200, 14400, 28800, 57600, 86400, 172800, 345600, 604800, 1209600, 2419200,
    ];

    pub(crate) fn ttl<S>(ttl: &std::time::Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut ttl = ttl.as_secs();

        if !TLL_VALUES.contains(&ttl) {
            for candidate in &TLL_VALUES {
                if *candidate > ttl {
                    ttl = *candidate;
                    break;
                }
            }
        }

        serializer.serialize_u64(ttl)
    }
}

/// A paginator for paged Linode API responses.
#[derive(Debug, Clone, Deserialize)]
pub struct Paginator {
    page: usize,
    pages: usize,

    #[allow(unused)]
    results: usize,
}

impl api_client::PaginationInfo for Paginator {
    fn page(&self) -> Option<usize> {
        Some(self.page)
    }

    fn pages(&self) -> Option<usize> {
        Some(self.pages)
    }

    fn next(&self, mut req: http::Request<Body>) -> Option<http::Request<Body>> {
        if self.page < self.pages {
            {
                let url = req.uri_mut();
                *url = url
                    .clone()
                    .replace_query("page", &format!("{}", self.page + 1));
            }

            Some(req)
        } else {
            None
        }
    }
}

/// A paginated response from the Linode API.
pub type Paginated<T> = api_client::Paginated<BearerAuth, T, PaginatedData<T, Paginator>>;

#[cfg(test)]
#[allow(dead_code, clippy::diverging_sub_expression)]
mod tests {
    use super::*;

    static_assertions::assert_impl_all!(LinodeClient: Send, Sync);
    static_assertions::assert_impl_all!(LinodeError: Send, Sync);

    fn require_send<T: Send>(_t: &T) {}
    fn require_sync<T: Sync>(_t: &T) {}
    fn require_unpin<T: Unpin>(_t: &T) {}

    struct Invalid;

    trait AmbiguousIfSend<A> {
        fn some_item(&self) {}
    }
    impl<T: ?Sized> AmbiguousIfSend<()> for T {}
    impl<T: ?Sized + Send> AmbiguousIfSend<Invalid> for T {}

    trait AmbiguousIfSync<A> {
        fn some_item(&self) {}
    }
    impl<T: ?Sized> AmbiguousIfSync<()> for T {}
    impl<T: ?Sized + Sync> AmbiguousIfSync<Invalid> for T {}

    trait AmbiguousIfUnpin<A> {
        fn some_item(&self) {}
    }
    impl<T: ?Sized> AmbiguousIfUnpin<()> for T {}
    impl<T: ?Sized + Unpin> AmbiguousIfUnpin<Invalid> for T {}

    macro_rules! into_todo {
        ($typ:ty) => {{
            let x: $typ = todo!();
            x
        }};
    }

    macro_rules! async_assert_fn_send {
        (Send & $(!)?Sync & $(!)?Unpin, $value:expr) => {
            require_send(&$value);
        };
        (!Send & $(!)?Sync & $(!)?Unpin, $value:expr) => {
            AmbiguousIfSend::some_item(&$value);
        };
    }
    macro_rules! async_assert_fn_sync {
        ($(!)?Send & Sync & $(!)?Unpin, $value:expr) => {
            require_sync(&$value);
        };
        ($(!)?Send & !Sync & $(!)?Unpin, $value:expr) => {
            AmbiguousIfSync::some_item(&$value);
        };
    }
    macro_rules! async_assert_fn_unpin {
        ($(!)?Send & $(!)?Sync & Unpin, $value:expr) => {
            require_unpin(&$value);
        };
        ($(!)?Send & $(!)?Sync & !Unpin, $value:expr) => {
            AmbiguousIfUnpin::some_item(&$value);
        };
    }

    macro_rules! async_assert_fn {
        ($($f:ident $(< $($generic:ty),* > )? )::+($($arg:ty),*): $($tok:tt)*) => {
            #[allow(unreachable_code)]
            #[allow(unused_variables)]
            const _: fn() = || {
                let f = $($f $(::<$($generic),*>)? )::+( $( into_todo!($arg) ),* );
                async_assert_fn_send!($($tok)*, f);
                async_assert_fn_sync!($($tok)*, f);
                async_assert_fn_unpin!($($tok)*, f);
            };
        };
    }

    async_assert_fn!(LinodeClient::execute_and_deserialize<String>(_, _): Send & !Sync & !Unpin);
}
