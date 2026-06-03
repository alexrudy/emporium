//! A reverse proxy with OAuth protection

use std::path::PathBuf;

use chateau::client::{
    ConnectionManagerLayer,
    conn::{service::ClientExecutorService, transport::tcp::TcpTransport},
};
use clap::Parser;
use cookie::Key;
use eyre::Context as _;
use http::{HeaderName, StatusCode};
use hyperdriver::{
    client::conn::{dns::GaiResolver, protocol::Http1Builder},
    service::Http1ChecksLayer,
};
use hyproxy::{
    headers::{SetViaHeaderLayer, StripHopByHopLayer, via::ViaAddress},
    upgrade::ProxyUpgradeLayer,
};
use oath::server::OAuth2Router;
use tower_http::{
    catch_panic::CatchPanicLayer, propagate_header::PropagateHeaderLayer,
    request_id::SetRequestIdLayer, sensitive_headers::SetSensitiveHeadersLayer, trace::TraceLayer,
};

use self::{
    config::Config,
    proxy::{ProxyLayer, ProxyRequestId},
    state::AppState,
    user::NoOpUserStore,
};

mod auth;
mod config;
mod cookies;
mod proxy;
mod state;
mod user;

#[derive(Debug, clap::Parser)]
struct Cli {
    /// Path to a configuration file
    #[clap(long)]
    config: Option<PathBuf>,

    /// Upstream authority
    upstream: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    install_tracing();

    let args = Cli::parse();

    let config = if let Some(path) = args.config {
        Config::from_file(path)?
    } else {
        Config::from_env()?
    };

    eprintln!("{}", serde_json::to_string_pretty(&config)?);

    let state = AppState::new(config.clone(), args.upstream.parse()?);

    let middleware = tower::ServiceBuilder::new()
        .layer(CatchPanicLayer::new())
        .layer(SetSensitiveHeadersLayer::new(vec![
            http::header::AUTHORIZATION,
            http::header::COOKIE,
            http::header::SET_COOKIE,
            http::header::PROXY_AUTHORIZATION,
            http::header::WWW_AUTHENTICATE,
            http::header::PROXY_AUTHENTICATE,
        ]))
        .layer(PropagateHeaderLayer::new(HeaderName::from_static(
            "x-request-id",
        )))
        .layer(SetRequestIdLayer::new(
            HeaderName::from_static("x-proxy-request-id"),
            ProxyRequestId,
        ))
        .layer(TraceLayer::new_for_http());

    let service = tower::ServiceBuilder::new()
        .layer(axum::error_handling::HandleErrorLayer::new(
            |error| async move {
                tracing::error!(%error, "internal server error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal server error occured",
                )
            },
        ))
        .layer(ProxyLayer::new(state.clone()))
        .layer(StripHopByHopLayer::new(true))
        .layer(SetViaHeaderLayer::new(
            ViaAddress::named("otunnel").unwrap(),
        ))
        .layer(ProxyUpgradeLayer::new())
        .layer(ConnectionManagerLayer::new(
            TcpTransport::new(GaiResolver::new(), config.tcp.clone().into()),
            Http1Builder::new(),
        ))
        .layer(Http1ChecksLayer::new())
        .service(ClientExecutorService::new());

    let router = build_router(&config, &state)
        .await?
        .fallback_service(service)
        .layer(middleware);
    let listener = tokio::net::TcpListener::bind(config.server.bind_addr)
        .await
        .with_context(|| format!("binding {bind_addr}", bind_addr = config.server.bind_addr))?;

    tracing::info!(
        "listening on {bind_addr}",
        bind_addr = config.server.bind_addr
    );
    axum::serve(listener, router.into_make_service()).await?;

    Ok(())
}

fn install_tracing() {
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::fmt;
    fmt().with_env_filter(EnvFilter::from_default_env()).init();
}

async fn build_router(config: &Config, state: &AppState) -> eyre::Result<axum::Router> {
    let endpoint = config
        .provider
        .provider()
        .await
        .wrap_err("building endpoint from configuration")?;

    let oauth = OAuth2Router::new(
        endpoint,
        state.sessions.clone(),
        NoOpUserStore::new(),
        user::identity_resolver(),
        Key::from(config.sessions.key.revealed().as_bytes()),
    );

    Ok(oauth.config(config.oath.clone()).into_router())
}
