//! OAuth client that works with the nginx-auth protocol

use std::{
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::net::UnixListener,
    },
    path::PathBuf,
    str::FromStr,
    sync::Arc,
};

use axum::{response::IntoResponse, routing::get};
use clap::Parser;
use eyre::Context as _;
use http::{HeaderName, StatusCode};
use hyperdriver::{
    Server,
    server::{ServerProtocolExt, conn::Acceptor},
};
use oath::server::TrustedHeader;
use otool::{auth::OptionalCurrentUser, build_router, state::AppState};
use systemd_connector::sockets;
use tower::ServiceExt;
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
    #[clap(long)]
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

    tracing::info!("Proxy verification at {}", config.server.verify_route);
    let mut oauth_router = build_router(&state).await?;
    if let Some(trusted_header) = &config.server.trusted_header {
        let extract = TrustedHeader::from(
            http::HeaderName::from_str(trusted_header).context("Invalid trusted header")?,
        );
        oauth_router = oauth_router.redirect(Arc::new(extract));
    }
    let router = oauth_router
        .into_router()
        .route(&config.server.verify_route, get(handle_verify))
        .layer(middleware)
        .with_state(state);

    #[allow(unsafe_code)]
    let acceptor: Acceptor = if args.systemd {
        let sockets = sockets().context("Unable to bind to systemd")?;
        let socket = sockets
            .into_iter()
            .next()
            .ok_or_else(|| eyre::eyre!("No systemd sockets available"))?;
        let listener_std = unsafe { UnixListener::from_raw_fd(socket.as_raw_fd()) };
        listener_std.set_nonblocking(true)?;
        let listener = tokio::net::UnixListener::from_std(listener_std)
            .context("Converting to Tokio listener")?;
        tracing::info!("listening on systemd socket",);
        listener.into()
    } else {
        let listener = tokio::net::TcpListener::bind(config.server.bind_addr)
            .await
            .with_context(|| format!("binding {bind_addr}", bind_addr = config.server.bind_addr))?;
        tracing::info!(
            "listening on {bind_addr}",
            bind_addr = config.server.bind_addr
        );
        listener.into()
    };

    let server =
        Server::builder::<http::Request<hyperdriver::Body>>()
            .with_acceptor(acceptor)
            .with_shared_service(router.into_service().map_request(
                |req: http::Request<hyperdriver::Body>| req.map(axum::body::Body::new),
            ))
            .with_http1()
            .with_tokio();

    server.await?;

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
