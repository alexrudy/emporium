//! OAuth client that works with the nginx-auth protocol

use std::path::PathBuf;

use axum::{response::IntoResponse, routing::get};
use clap::Parser;
use eyre::Context as _;
use http::{HeaderName, StatusCode};
use otool::{auth::OptionalCurrentUser, build_router, state::AppState};
use systemd_connector::sockets;
use tower_http::{
    catch_panic::CatchPanicLayer, propagate_header::PropagateHeaderLayer,
    sensitive_headers::SetSensitiveHeadersLayer, trace::TraceLayer,
};

use self::config::Config;

mod config;

#[derive(Debug, Parser)]
struct Cli {
    /// Path to a configuration file
    #[clap(long)]
    config: Option<PathBuf>,

    /// Enable systemd socket activation
    systemd: bool,
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

    let state = AppState::new(config.oath, config.provider, config.sessions);

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
        .layer(TraceLayer::new_for_http());

    tracing::info!("Proxy verification at {}", config.verify_route);
    let router = build_router(&state)
        .await?
        .into_router()
        .route(&config.verify_route, get(handle_verify))
        .layer(middleware)
        .with_state(state);

    let listener = if args.systemd {
        let sockets = sockets().context("Unable to bind to systemd")?;
        let socket = sockets
            .into_iter()
            .next()
            .ok_or_else(|| eyre::eyre!("No systemd sockets available"))?;
        let listener_std = socket.listener().context("Converting to TCP listener")?;
        tokio::net::TcpListener::from_std(listener_std).context("Converting to Tokio listener")?
    } else {
        tokio::net::TcpListener::bind(config.server.bind_addr)
            .await
            .with_context(|| format!("binding {bind_addr}", bind_addr = config.server.bind_addr))?
    };

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

async fn handle_verify(OptionalCurrentUser(user): OptionalCurrentUser) -> impl IntoResponse {
    if let Some(user) = user {
        tracing::debug!("verify: {}", user.username);
        StatusCode::NO_CONTENT.into_response()
    } else {
        StatusCode::FORBIDDEN.into_response()
    }
}
